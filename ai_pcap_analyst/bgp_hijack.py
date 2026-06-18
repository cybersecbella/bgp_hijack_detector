"""
bgp_hijack.py — BGP route hijack detector with RPKI validation
Monitors BGP UPDATE messages and validates against RPKI ROAs.
ATT&CK: T1599 — Network Boundary Bridging
        T1205 — Traffic Signaling
"""
from __future__ import annotations
import json
import time
from dataclasses import dataclass
from typing import Optional

import requests

try:
    from scapy.all import rdpcap, sniff, IP
    from scapy.contrib.bgp import BGPUpdate, BGPPathAttr
    _SCAPY = True
except ImportError:
    _SCAPY = False

# ── RPKI validation API (RIPE NCC — free, no key required) ───────────────────
RPKI_API = "https://stat.ripe.net/data/rpki-validation/data.json"
RPKI_CACHE: dict[str, dict] = {}   # cache results to avoid rate limiting
CACHE_TTL = 3600                   # seconds

# ── BGP port ──────────────────────────────────────────────────────────────────
BGP_PORT = 179

ATTCK = {
    "hijack": {"id": "T1599", "name": "Network Boundary Bridging",
               "tactic": "Defense Evasion"},
    "signal": {"id": "T1205", "name": "Traffic Signaling",
               "tactic": "Defense Evasion"},
}


@dataclass
class BgpFinding:
    src_ip:          str
    announced_prefix: str
    origin_asn:      int
    rpki_status:     str     # "valid" | "invalid" | "not-found" | "error"
    rpki_detail:     str
    reasons:         list[str]
    attck_tags:      list[dict]
    risk_score:      int

    def to_dict(self) -> dict:
        return {
            "type":              "bgp_hijack",
            "src_ip":            self.src_ip,
            "announced_prefix":  self.announced_prefix,
            "origin_asn":        self.origin_asn,
            "rpki_status":       self.rpki_status,
            "rpki_detail":       self.rpki_detail,
            "reasons":           self.reasons,
            "attck_tags":        self.attck_tags,
            "risk_score":        self.risk_score,
        }


def validate_rpki(prefix: str, origin_asn: int) -> dict:
    """
    Validate a BGP announcement against RPKI using the RIPE NCC API.
    Returns dict with 'status' and 'detail'.
    Caches results for CACHE_TTL seconds.
    """
    cache_key = f"{prefix}:{origin_asn}"
    if cache_key in RPKI_CACHE:
        cached = RPKI_CACHE[cache_key]
        if time.time() - cached["_ts"] < CACHE_TTL:
            return cached

    try:
        resp = requests.get(
            RPKI_API,
            params={"resource": origin_asn, "prefix": prefix},
            timeout=10,
        )
        data = resp.json()
        validations = data.get("data", {}).get("validations", [])

        if not validations:
            result = {"status": "not-found",
                      "detail": "No ROA found for this prefix/ASN"}
        else:
            v = validations[0]
            status = v.get("status", "unknown")
            result = {
                "status": status,
                "detail": (
                    f"ROA status: {status}. "
                    f"Validated origins: {v.get('validated_route', {})}"
                ),
            }
    except requests.RequestException as e:
        result = {"status": "error", "detail": f"RPKI API error: {e}"}

    result["_ts"] = time.time()
    RPKI_CACHE[cache_key] = result
    return result


def analyze_bgp_update(packet, src_ip: str) -> Optional[BgpFinding]:
    """
    Analyze a BGP UPDATE packet for hijack indicators.
    Validates announced prefixes against RPKI.
    """
    if not packet.haslayer(BGPUpdate):
        return None

    update = packet[BGPUpdate]
    reasons:    list[str]  = []
    attck_tags: list[dict] = []
    risk_score = 0

    # Extract announced prefixes and origin ASN
    try:
        nlri       = getattr(update, "nlri", [])
        path_attrs = getattr(update, "path_attr", [])

        # Parse origin ASN from raw AS_PATH bytes (4-byte ASN format).
        # Scapy defaults to use_2_bytes_asn=True which misparses 4-byte fields,
        # so we read the attribute bytes directly instead of trusting segment_value.
        origin_asn = 0
        for attr in path_attrs:
            if hasattr(attr, "type_code") and attr.type_code == 2:
                raw = bytes(attr.attribute)
                # Walk segments: [seg_type(1), seg_count(1), ASN(4)*seg_count, ...]
                offset = 0
                while offset + 2 <= len(raw):
                    seg_type  = raw[offset]
                    seg_count = raw[offset + 1]
                    asn_size  = 4
                    seg_end   = offset + 2 + seg_count * asn_size
                    if seg_type == 2 and seg_count > 0 and seg_end <= len(raw):
                        # Rightmost ASN in last AS_SEQUENCE is the origin
                        asn_off    = offset + 2 + (seg_count - 1) * asn_size
                        origin_asn = int.from_bytes(raw[asn_off:asn_off + asn_size], "big")
                    offset = seg_end
                break

        for prefix_entry in nlri:
            # Scapy's BGPNLRI_IPv4.prefix already embeds the length ("208.65.152.0/22")
            prefix_str = str(getattr(prefix_entry, "prefix", ""))
            if "/" in prefix_str:
                cidr   = prefix_str
                length = int(prefix_str.split("/")[1])
            else:
                length = int(getattr(prefix_entry, "pfxlen", 0))
                cidr   = f"{prefix_str}/{length}" if prefix_str else ""

            if not cidr or not origin_asn:
                continue

            # Validate against RPKI
            rpki   = validate_rpki(cidr, origin_asn)
            status = rpki.get("status", "error")

            if status == "invalid":
                reasons.append(
                    f"RPKI INVALID: AS{origin_asn} is NOT authorized to "
                    f"announce {cidr}. This is a confirmed BGP hijack."
                )
                attck_tags.append(ATTCK["hijack"])
                risk_score += 90

            elif status == "not-found":
                reasons.append(
                    f"RPKI NOT FOUND: No ROA exists for {cidr} from AS{origin_asn}. "
                    f"Unverifiable announcement — possible hijack."
                )
                attck_tags.append(ATTCK["signal"])
                risk_score += 40

            # Suspicious: very specific prefix (hijackers use /24+ to win routing)
            if length >= 24 and status != "valid":
                reasons.append(
                    f"Highly specific prefix /{length} announced for {cidr} — "
                    f"attackers use more-specific prefixes to hijack routing"
                )
                risk_score += 20

    except Exception as e:
        return None

    if not reasons:
        return None

    seen: set[str] = set()
    unique_tags = []
    for t in attck_tags:
        if t["id"] not in seen:
            unique_tags.append(t)
            seen.add(t["id"])

    rpki_status = rpki.get("status", "unknown")
    rpki_detail = rpki.get("detail", "")

    return BgpFinding(
        src_ip           = src_ip,
        announced_prefix = cidr if 'cidr' in dir() else "unknown",
        origin_asn       = origin_asn,
        rpki_status      = rpki_status,
        rpki_detail      = rpki_detail,
        reasons          = reasons,
        attck_tags       = unique_tags,
        risk_score       = min(risk_score, 100),
    )


def analyze_pcap(pcap_path: str) -> list[BgpFinding]:
    """Analyze a PCAP for BGP hijacking events."""
    if not _SCAPY:
        raise ImportError("scapy not installed")

    print(f"[bgp_hijack] Analyzing: {pcap_path}")
    # rdpcap avoids the tcpdump/BPF dependency that sniff(filter=) requires on Windows.
    # analyze_bgp_update already gates on the BGPUpdate layer.
    packets = rdpcap(pcap_path)
    findings = []

    for pkt in packets:
        src = pkt[IP].src if pkt.haslayer(IP) else "unknown"
        result = analyze_bgp_update(pkt, src)
        if result:
            findings.append(result)

    print(f"[bgp_hijack] Found {len(findings)} suspicious BGP announcements")
    return findings


if __name__ == "__main__":
    import sys, json
    if len(sys.argv) < 2:
        print("Usage: python bgp_hijack.py <pcap_file>")
        sys.exit(1)
    results = analyze_pcap(sys.argv[1])
    for r in results:
        print(json.dumps(r.to_dict(), indent=2))