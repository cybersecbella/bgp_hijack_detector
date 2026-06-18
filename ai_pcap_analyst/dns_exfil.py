"""
dns_exfil.py — DNS exfiltration detector
Detects data exfiltration via unusually long or high-entropy DNS subdomains.
ATT&CK: T1048.003 — Exfiltration Over Alternative Protocol: DNS
        T1071.004 — Application Layer Protocol: DNS
"""
from __future__ import annotations
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Optional

try:
    from scapy.all import DNS, DNSQR, IP, UDP, rdpcap, sniff
    from scapy.layers.dns import DNSRR
    _SCAPY = True
except ImportError:
    _SCAPY = False

# ── Thresholds ────────────────────────────────────────────────────────────────
ENTROPY_THRESHOLD  = 3.5    # above this = suspicious (base64 ~3.9, words ~2.5)
LENGTH_THRESHOLD   = 30     # subdomain label length above this = suspicious
QUERY_RATE_WINDOW  = 60     # seconds to track query rate per domain
QUERY_RATE_LIMIT   = 50     # queries per window = suspicious volume

# ── Known legitimate high-entropy domains (allowlist) ────────────────────────
ALLOWLIST = {
    "google.com", "googleapis.com", "gstatic.com",
    "cloudflare.com", "amazonaws.com", "azure.com",
    "akamaitechnologies.com", "fastly.net",
}

# ── ATT&CK mapping ────────────────────────────────────────────────────────────
ATTCK = {
    "high_entropy":  {"id": "T1048.003", "name": "Exfiltration Over DNS",
                      "tactic": "Exfiltration"},
    "long_subdomain": {"id": "T1071.004", "name": "DNS Application Layer Protocol",
                       "tactic": "Command and Control"},
    "high_volume":   {"id": "T1048.003", "name": "Exfiltration Over DNS (high volume)",
                      "tactic": "Exfiltration"},
}


@dataclass
class DnsExfilFinding:
    src_ip:       str
    dst_ip:       str
    domain:       str
    subdomain:    str
    entropy:      float
    label_length: int
    reasons:      list[str]
    attck_tags:   list[dict]
    risk_score:   int
    raw_query:    str

    def to_dict(self) -> dict:
        return {
            "type":         "dns_exfiltration",
            "src_ip":       self.src_ip,
            "dst_ip":       self.dst_ip,
            "domain":       self.domain,
            "subdomain":    self.subdomain,
            "entropy":      round(self.entropy, 3),
            "label_length": self.label_length,
            "reasons":      self.reasons,
            "attck_tags":   self.attck_tags,
            "risk_score":   self.risk_score,
            "raw_query":    self.raw_query,
        }


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string. Higher = more random."""
    if not s:
        return 0.0
    counts = Counter(s.lower())
    length = len(s)
    return -sum(
        (c / length) * math.log2(c / length)
        for c in counts.values()
    )


def extract_subdomain(fqdn: str) -> tuple[str, str]:
    """
    Split a fully-qualified domain name into (subdomain, apex_domain).
    e.g. 'abc123.evil.com' → ('abc123', 'evil.com')
    """
    fqdn = fqdn.rstrip(".").strip()
    if fqdn.startswith("b'") and fqdn.endswith("'"):
        fqdn = fqdn[2:-1]   # strip Python bytes repr if present
    parts = fqdn.split(".")
    if len(parts) <= 2:
        return ("", fqdn)
    apex    = ".".join(parts[-2:])
    subdomain = ".".join(parts[:-2])
    return (subdomain, apex)


def is_allowlisted(domain: str) -> bool:
    """Check if apex domain is in the known-good allowlist."""
    return any(domain.endswith(a) for a in ALLOWLIST)


def analyze_dns_packet(packet) -> Optional[DnsExfilFinding]:
    """
    Analyze a single DNS query packet for exfiltration indicators.
    Returns a DnsExfilFinding if suspicious, None if clean.
    """
    if not (packet.haslayer(DNS) and packet.haslayer(DNSQR)):
        return None

    dns_layer = packet[DNS]
    if dns_layer.qr != 0:      # only analyze queries, not responses
        return None

    try:
        query    = dns_layer.qd.qname.decode("utf-8", errors="replace").rstrip(".").strip()
        src_ip   = packet[IP].src if packet.haslayer(IP) else "unknown"
        dst_ip   = packet[IP].dst if packet.haslayer(IP) else "unknown"
    except Exception:
        return None

    subdomain, apex = extract_subdomain(query)

    if is_allowlisted(apex) or not subdomain:
        return None

    # Score each label (part between dots) separately
    labels  = subdomain.split(".")
    reasons: list[str] = []
    attck_tags: list[dict] = []
    risk_score = 0

    for label in labels:
        if not label:
            continue

        ent = shannon_entropy(label)
        lng = len(label)

        if ent >= ENTROPY_THRESHOLD:
            reasons.append(
                f"Label '{label[:20]}...' has high entropy {ent:.2f} "
                f"(threshold {ENTROPY_THRESHOLD}) — likely base64/hex encoded data"
            )
            attck_tags.append(ATTCK["high_entropy"])
            risk_score += 40

        if lng >= LENGTH_THRESHOLD:
            reasons.append(
                f"Label '{label[:20]}...' length {lng} exceeds threshold "
                f"{LENGTH_THRESHOLD} — unusually long for legitimate DNS"
            )
            attck_tags.append(ATTCK["long_subdomain"])
            risk_score += 30

    if not reasons:
        return None

    # Deduplicate ATT&CK tags
    seen_ids: set[str] = set()
    unique_tags = []
    for t in attck_tags:
        if t["id"] not in seen_ids:
            unique_tags.append(t)
            seen_ids.add(t["id"])

    # Max entropy across all labels (for reporting)
    max_entropy = max(shannon_entropy(l) for l in labels if l)
    max_length  = max(len(l) for l in labels if l)

    return DnsExfilFinding(
        src_ip       = src_ip,
        dst_ip       = dst_ip,
        domain       = apex,
        subdomain    = subdomain,
        entropy      = max_entropy,
        label_length = max_length,
        reasons      = reasons,
        attck_tags   = unique_tags,
        risk_score   = min(risk_score, 100),
        raw_query    = query,
    )


def analyze_pcap(pcap_path: str) -> list[DnsExfilFinding]:
    """Analyze a PCAP file for DNS exfiltration."""
    if not _SCAPY:
        raise ImportError("scapy not installed: pip install scapy")

    print(f"[dns_exfil] Analyzing: {pcap_path}")
    # rdpcap avoids the tcpdump/BPF dependency that sniff(filter=) requires on Windows.
    # analyze_dns_packet already gates on DNS/DNSQR layers, so no pre-filter needed.
    packets = rdpcap(pcap_path)
    findings = []

    for pkt in packets:
        result = analyze_dns_packet(pkt)
        if result:
            findings.append(result)

    print(f"[dns_exfil] Found {len(findings)} suspicious DNS queries")
    return findings


def live_monitor(interface: str = "eth0", timeout: int = 60) -> list[DnsExfilFinding]:
    """Monitor live DNS traffic on an interface."""
    if not _SCAPY:
        raise ImportError("scapy not installed: pip install scapy")

    print(f"[dns_exfil] Monitoring {interface} for {timeout}s...")
    findings = []

    def callback(pkt):
        result = analyze_dns_packet(pkt)
        if result:
            findings.append(result)
            print(f"  [ALERT] DNS exfil from {result.src_ip}: "
                  f"{result.raw_query[:60]} (entropy={result.entropy:.2f})")

    sniff(iface=interface, filter="udp port 53",
          prn=callback, timeout=timeout, store=False)
    return findings


if __name__ == "__main__":
    import sys, json
    if len(sys.argv) < 2:
        print("Usage: python dns_exfil.py <pcap_file>")
        sys.exit(1)
    results = analyze_pcap(sys.argv[1])
    for r in results:
        print(json.dumps(r.to_dict(), indent=2))