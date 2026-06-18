"""
beaconing.py — Statistical C2 beaconing detector
Identifies processes/IPs communicating at suspiciously regular intervals.
ATT&CK: T1071 — Application Layer Protocol
        T1029 — Scheduled Transfer
"""
from __future__ import annotations
import json
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

import numpy as np
from scipy import stats

try:
    from scapy.all import IP, TCP, UDP, rdpcap, sniff
    _SCAPY = True
except ImportError:
    _SCAPY = False

# ── Detection thresholds ──────────────────────────────────────────────────────
CV_THRESHOLD        = 0.15   # coefficient of variation below this = beacon
MIN_PACKETS         = 8      # minimum packets to analyze a flow
MIN_INTERVAL        = 1.0    # seconds — ignore sub-second bursts
MAX_INTERVAL        = 3600.0 # seconds — ignore connections > 1 hour apart
AUTOCORR_THRESHOLD  = 0.7    # autocorrelation above this = periodic

# Known C2 / backdoor ports
SUSPICIOUS_PORTS = {4444, 4445, 1337, 31337, 8888, 9999, 1234,
                    12345, 6666, 5555, 2222, 8000}

ATTCK = {
    "beaconing": {"id": "T1071",  "name": "Application Layer Protocol",
                  "tactic": "Command and Control"},
    "scheduled": {"id": "T1029",  "name": "Scheduled Transfer",
                  "tactic": "Exfiltration"},
    "c2_port":   {"id": "T1571",  "name": "Non-Standard Port",
                  "tactic": "Command and Control"},
}


@dataclass
class BeaconFinding:
    src_ip:       str
    dst_ip:       str
    dst_port:     int
    proto:        str
    packet_count: int
    mean_interval: float     # seconds
    std_interval:  float     # seconds
    cv:            float     # coefficient of variation
    autocorr:      float     # lag-1 autocorrelation
    jitter_pct:    float     # jitter as % of mean
    reasons:       list[str]
    attck_tags:    list[dict]
    risk_score:    int

    def to_dict(self) -> dict:
        return {
            "type":           "c2_beaconing",
            "src_ip":         self.src_ip,
            "dst_ip":         self.dst_ip,
            "dst_port":       self.dst_port,
            "proto":          self.proto,
            "packet_count":   self.packet_count,
            "mean_interval":  round(self.mean_interval, 3),
            "std_interval":   round(self.std_interval, 3),
            "cv":             round(self.cv, 4),
            "autocorr":       round(self.autocorr, 4),
            "jitter_pct":     round(self.jitter_pct, 2),
            "reasons":        self.reasons,
            "attck_tags":     self.attck_tags,
            "risk_score":     self.risk_score,
            "beacon_interval": f"{self.mean_interval:.1f}s "
                               f"(±{self.std_interval:.1f}s)",
        }


def _compute_beacon_stats(timestamps: list[float]) -> dict:
    """Compute statistical metrics on a list of packet timestamps."""
    if len(timestamps) < MIN_PACKETS:
        return {}

    ts = sorted(timestamps)
    intervals = np.diff(ts)

    # Filter out sub-second and > 1 hour intervals
    intervals = intervals[
        (intervals >= MIN_INTERVAL) & (intervals <= MAX_INTERVAL)
    ]
    if len(intervals) < MIN_PACKETS - 1:
        return {}

    mean   = float(np.mean(intervals))
    std    = float(np.std(intervals))
    cv     = std / mean if mean > 0 else 999.0

    # Lag-1 autocorrelation — high = intervals are periodic
    if len(intervals) > 2:
        autocorr = float(np.corrcoef(intervals[:-1], intervals[1:])[0, 1])
    else:
        autocorr = 0.0

    jitter_pct = (std / mean * 100) if mean > 0 else 100.0

    return {
        "mean":       mean,
        "std":        std,
        "cv":         cv,
        "autocorr":   autocorr,
        "jitter_pct": jitter_pct,
        "count":      len(intervals) + 1,
    }


def _analyze_flow(
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    proto: str,
    timestamps: list[float],
) -> Optional[BeaconFinding]:
    """Analyze a single network flow for beaconing behavior."""
    s = _compute_beacon_stats(timestamps)
    if not s:
        return None

    reasons:   list[str]  = []
    attck_tags: list[dict] = []
    risk_score = 0

    # Rule 1: low coefficient of variation = consistent timing
    if s["cv"] < CV_THRESHOLD:
        reasons.append(
            f"CV={s['cv']:.4f} < threshold {CV_THRESHOLD} — "
            f"packet intervals are suspiciously consistent "
            f"(mean {s['mean']:.1f}s ± {s['std']:.1f}s)"
        )
        attck_tags.append(ATTCK["beaconing"])
        risk_score += 45

    # Rule 2: high autocorrelation = periodic pattern
    if s["autocorr"] > AUTOCORR_THRESHOLD:
        reasons.append(
            f"Autocorrelation={s['autocorr']:.3f} > {AUTOCORR_THRESHOLD} — "
            f"interval pattern is strongly periodic"
        )
        attck_tags.append(ATTCK["scheduled"])
        risk_score += 30

    # Rule 3: known C2 port
    if dst_port in SUSPICIOUS_PORTS:
        reasons.append(
            f"Destination port {dst_port} is a known C2/backdoor port"
        )
        attck_tags.append(ATTCK["c2_port"])
        risk_score += 35

    if not reasons:
        return None

    # Deduplicate
    seen: set[str] = set()
    unique_tags = []
    for t in attck_tags:
        if t["id"] not in seen:
            unique_tags.append(t)
            seen.add(t["id"])

    return BeaconFinding(
        src_ip        = src_ip,
        dst_ip        = dst_ip,
        dst_port      = dst_port,
        proto         = proto,
        packet_count  = s["count"],
        mean_interval = s["mean"],
        std_interval  = s["std"],
        cv            = s["cv"],
        autocorr      = s["autocorr"],
        jitter_pct    = s["jitter_pct"],
        reasons       = reasons,
        attck_tags    = unique_tags,
        risk_score    = min(risk_score, 100),
    )


def analyze_pcap(pcap_path: str) -> list[BeaconFinding]:
    """Analyze a PCAP file for C2 beaconing patterns."""
    if not _SCAPY:
        raise ImportError("scapy not installed")

    print(f"[beaconing] Analyzing: {pcap_path}")
    # rdpcap avoids the tcpdump/BPF dependency that sniff(filter=) requires on Windows.
    # The packet loop below already filters on IP/TCP/UDP layers.
    packets = rdpcap(pcap_path)

    # Group timestamps by flow (src_ip, dst_ip, dst_port, proto)
    flows: dict[tuple, list[float]] = defaultdict(list)

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        src = pkt[IP].src
        dst = pkt[IP].dst
        ts  = float(pkt.time)

        if pkt.haslayer(TCP):
            port = pkt[TCP].dport
            proto = "TCP"
        elif pkt.haslayer(UDP):
            port = pkt[UDP].dport
            proto = "UDP"
        else:
            continue

        flows[(src, dst, port, proto)].append(ts)

    findings = []
    for (src, dst, port, proto), timestamps in flows.items():
        result = _analyze_flow(src, dst, port, proto, timestamps)
        if result:
            findings.append(result)

    # Sort by risk score descending
    findings.sort(key=lambda f: f.risk_score, reverse=True)
    print(f"[beaconing] Found {len(findings)} suspicious flows")
    return findings


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python beaconing.py <pcap_file>")
        sys.exit(1)
    results = analyze_pcap(sys.argv[1])
    for r in results:
        print(json.dumps(r.to_dict(), indent=2))