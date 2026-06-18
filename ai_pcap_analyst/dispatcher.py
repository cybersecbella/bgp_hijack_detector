"""
dispatcher.py — Packet dispatcher for AI PCAP Analyst
=======================================================
Routes packets from a PCAP file or live interface to the
correct detector module based on protocol and port.

Supported detectors:
    - dns_exfil.py   (UDP port 53)
    - beaconing.py   (TCP/UDP flows)
    - bgp_hijack.py  (TCP port 179)

Usage:
    from ai_pcap_analyst.dispatcher import dispatch_pcap, dispatch_live
    results = dispatch_pcap("capture.pcap")
"""
from __future__ import annotations

import os
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

try:
    from scapy.all import IP, TCP, UDP, DNS, sniff, rdpcap
    _SCAPY = True
except ImportError:
    _SCAPY = False


# ── Port constants ────────────────────────────────────────────────────────────
PORT_DNS = 53
PORT_BGP = 179

# ── Packet counters for progress reporting ────────────────────────────────────

@dataclass
class DispatchStats:
    total:      int = 0
    dns:        int = 0
    bgp:        int = 0
    tcp_flows:  int = 0
    udp_flows:  int = 0
    skipped:    int = 0
    errors:     int = 0


# ── Flow tracker ─────────────────────────────────────────────────────────────
# Groups packets into flows by (src_ip, dst_ip, dst_port, proto)
# Used by the beaconing detector which needs per-flow timing

@dataclass
class Flow:
    src_ip:     str
    dst_ip:     str
    dst_port:   int
    proto:      str
    timestamps: list[float] = field(default_factory=list)
    packet_count: int = 0

    def add_packet(self, timestamp: float):
        self.timestamps.append(timestamp)
        self.packet_count += 1

    @property
    def flow_key(self) -> tuple:
        return (self.src_ip, self.dst_ip, self.dst_port, self.proto)


class FlowTracker:
    """Tracks network flows and their packet timestamps."""

    def __init__(self):
        self._flows: dict[tuple, Flow] = {}

    def add_packet(self, src_ip: str, dst_ip: str,
                   dst_port: int, proto: str, timestamp: float):
        key = (src_ip, dst_ip, dst_port, proto)
        if key not in self._flows:
            self._flows[key] = Flow(
                src_ip=src_ip, dst_ip=dst_ip,
                dst_port=dst_port, proto=proto,
            )
        self._flows[key].add_packet(timestamp)

    def get_flows(self) -> list[Flow]:
        return list(self._flows.values())

    def get_flows_by_port(self, port: int) -> list[Flow]:
        return [f for f in self._flows.values() if f.dst_port == port]

    def clear(self):
        self._flows.clear()


# ── DNS packet bucket ─────────────────────────────────────────────────────────

class DnsBucket:
    """Collects DNS packets for batch analysis."""

    def __init__(self):
        self.packets = []

    def add(self, packet):
        self.packets.append(packet)

    def count(self) -> int:
        return len(self.packets)


# ── BGP packet bucket ─────────────────────────────────────────────────────────

class BgpBucket:
    """Collects BGP packets with their source IPs."""

    def __init__(self):
        self.packets: list[tuple] = []   # (packet, src_ip)

    def add(self, packet, src_ip: str):
        self.packets.append((packet, src_ip))

    def count(self) -> int:
        return len(self.packets)


# ── Main dispatcher ───────────────────────────────────────────────────────────

class PacketDispatcher:
    """
    Routes packets to the appropriate detector.

    Usage:
        dispatcher = PacketDispatcher()
        dispatcher.process_pcap("capture.pcap")

        dns_bucket   = dispatcher.dns_bucket
        bgp_bucket   = dispatcher.bgp_bucket
        flow_tracker = dispatcher.flow_tracker
    """

    def __init__(self, verbose: bool = True):
        self.verbose      = verbose
        self.dns_bucket   = DnsBucket()
        self.bgp_bucket   = BgpBucket()
        self.flow_tracker = FlowTracker()
        self.stats        = DispatchStats()

    def _process_packet(self, packet) -> None:
        """Route a single packet to the correct bucket/tracker."""
        self.stats.total += 1

        try:
            if not packet.haslayer(IP):
                self.stats.skipped += 1
                return

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            ts     = float(packet.time)

            # ── DNS (UDP port 53) → dns_exfil detector ────────────────────
            if packet.haslayer(UDP):
                udp   = packet[UDP]
                sport = int(udp.sport)
                dport = int(udp.dport)

                if dport == PORT_DNS or sport == PORT_DNS:
                    if packet.haslayer(DNS):
                        self.dns_bucket.add(packet)
                        self.stats.dns += 1

                # All UDP flows → beaconing detector
                self.flow_tracker.add_packet(
                    src_ip, dst_ip, dport, "UDP", ts
                )
                self.stats.udp_flows += 1

            # ── TCP ───────────────────────────────────────────────────────
            elif packet.haslayer(TCP):
                tcp   = packet[TCP]
                sport = int(tcp.sport)
                dport = int(tcp.dport)

                # BGP (TCP port 179) → bgp_hijack detector
                if dport == PORT_BGP or sport == PORT_BGP:
                    self.bgp_bucket.add(packet, src_ip)
                    self.stats.bgp += 1

                # All TCP flows → beaconing detector
                self.flow_tracker.add_packet(
                    src_ip, dst_ip, dport, "TCP", ts
                )
                self.stats.tcp_flows += 1

            else:
                self.stats.skipped += 1

        except Exception as e:
            self.stats.errors += 1
            if self.verbose:
                print(f"[dispatcher] Error processing packet: {e}")

    def process_pcap(self, pcap_path: str) -> DispatchStats:
        """
        Load and dispatch all packets from a PCAP file.
        Returns dispatch statistics.
        """
        if not _SCAPY:
            raise ImportError("scapy not installed: pip install scapy")

        path = Path(pcap_path)
        if not path.exists():
            raise FileNotFoundError(f"PCAP not found: {pcap_path}")

        if self.verbose:
            print(f"[dispatcher] Loading: {pcap_path}")

        packets = rdpcap(str(path))

        if self.verbose:
            print(f"[dispatcher] Dispatching {len(packets)} packets...")

        for pkt in packets:
            self._process_packet(pkt)

        if self.verbose:
            self._print_stats()

        return self.stats

    def process_live(self, interface: str = "eth0",
                     timeout: int = 60,
                     packet_count: int = 0) -> DispatchStats:
        """
        Capture and dispatch live packets from a network interface.

        Args:
            interface:    Network interface name (eth0, en0, etc.)
            timeout:      Stop after this many seconds (0 = run forever)
            packet_count: Stop after this many packets (0 = run forever)
        """
        if not _SCAPY:
            raise ImportError("scapy not installed: pip install scapy")

        if self.verbose:
            print(f"[dispatcher] Live capture on {interface} "
                  f"(timeout={timeout}s)...")

        sniff_kwargs = {
            "iface":  interface,
            "filter": "ip",
            "prn":    self._process_packet,
            "store":  False,
        }
        if timeout > 0:
            sniff_kwargs["timeout"] = timeout
        if packet_count > 0:
            sniff_kwargs["count"] = packet_count

        sniff(**sniff_kwargs)

        if self.verbose:
            self._print_stats()

        return self.stats

    def reset(self):
        """Clear all buckets and reset stats (reuse dispatcher for multiple PCAPs)."""
        self.dns_bucket   = DnsBucket()
        self.bgp_bucket   = BgpBucket()
        self.flow_tracker = FlowTracker()
        self.stats        = DispatchStats()

    def _print_stats(self):
        s = self.stats
        print(f"[dispatcher] Results:")
        print(f"  Total packets : {s.total}")
        print(f"  DNS queries   : {s.dns}")
        print(f"  BGP updates   : {s.bgp}")
        print(f"  TCP flows     : {s.tcp_flows}")
        print(f"  UDP flows     : {s.udp_flows}")
        print(f"  Skipped       : {s.skipped}")
        if s.errors:
            print(f"  Errors        : {s.errors}")


# ── Convenience functions ─────────────────────────────────────────────────────

def dispatch_pcap(pcap_path: str,
                  verbose: bool = True) -> PacketDispatcher:
    """
    Load a PCAP file and dispatch all packets.
    Returns the dispatcher with populated buckets ready for analysis.

    Usage:
        d = dispatch_pcap("capture.pcap")
        dns_findings    = analyze_dns_bucket(d.dns_bucket)
        beacon_findings = analyze_flow_tracker(d.flow_tracker)
        bgp_findings    = analyze_bgp_bucket(d.bgp_bucket)
    """
    dispatcher = PacketDispatcher(verbose=verbose)
    dispatcher.process_pcap(pcap_path)
    return dispatcher


def dispatch_live(interface: str = "eth0",
                  timeout: int = 60,
                  verbose: bool = True) -> PacketDispatcher:
    """
    Capture live traffic and dispatch packets.
    Returns the dispatcher with populated buckets.
    """
    dispatcher = PacketDispatcher(verbose=verbose)
    dispatcher.process_live(interface=interface, timeout=timeout)
    return dispatcher


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: python dispatcher.py <pcap_file>")
        print("       python dispatcher.py live [interface] [timeout_seconds]")
        sys.exit(1)

    mode = sys.argv[1]

    if mode == "live":
        iface   = sys.argv[2] if len(sys.argv) > 2 else "eth0"
        timeout = int(sys.argv[3]) if len(sys.argv) > 3 else 60
        d = dispatch_live(interface=iface, timeout=timeout)
    else:
        d = dispatch_pcap(mode)

    print("\n[dispatcher] Bucket summary:")
    print(f"  DNS packets : {d.dns_bucket.count()}")
    print(f"  BGP packets : {d.bgp_bucket.count()}")
    print(f"  Flows       : {len(d.flow_tracker.get_flows())}")