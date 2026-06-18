"""
ai_analyzer.py — AI-powered PCAP flow analyzer
================================================
Extracts network flows using pyshark, summarizes traffic patterns,
and sends them to a LangChain chain for threat narrative generation.

This module focuses on flows that the other detectors don't specifically
target — HTTP/S, SMB, RDP, and other application-layer protocols.

ATT&CK coverage:
    T1041  — Exfiltration Over C2 Channel
    T1071  — Application Layer Protocol
    T1090  — Proxy
    T1105  — Ingress Tool Transfer

Usage:
    from ai_pcap_analyst.ai_analyzer import analyze_pcap, analyze_flows
    findings = analyze_pcap("capture.pcap")
"""
from __future__ import annotations

import json
import os
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

# ── Scapy ─────────────────────────────────────────────────────────────────────
try:
    from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, rdpcap
    try:
        from scapy.layers.http import HTTPRequest
        _HTTP = True
    except ImportError:
        _HTTP = False
    _SCAPY = True
except ImportError:
    _SCAPY = False
    print("[ai_analyzer] scapy not installed: pip install scapy")

# ── LangChain ─────────────────────────────────────────────────────────────────
try:
    from langchain_anthropic import ChatAnthropic
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_core.output_parsers import StrOutputParser
    _LANGCHAIN = True
except ImportError:
    _LANGCHAIN = False
    print("[ai_analyzer] langchain not installed: pip install langchain-anthropic")


# ── Constants ─────────────────────────────────────────────────────────────────
DEFAULT_MODEL  = os.environ.get("VOL_AI_MODEL", "claude-sonnet-4-6")
MAX_TOKENS     = 1024
MAX_FLOWS      = 50    # cap flows sent to LLM to avoid token overflow

# Ports to classify by protocol name
PORT_NAMES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-alt", 8443: "HTTPS-alt",
}

# Suspicious ports that warrant extra scrutiny
SUSPICIOUS_PORTS = {
    4444, 4445, 1337, 31337, 8888, 9999,
    1234, 12345, 6666, 5555, 2222,
}

# ATT&CK mappings for flow analysis
ATTCK = {
    "c2_exfil":    {"id": "T1041",  "name": "Exfiltration Over C2 Channel",
                    "tactic": "Exfiltration"},
    "app_layer":   {"id": "T1071",  "name": "Application Layer Protocol",
                    "tactic": "Command and Control"},
    "proxy":       {"id": "T1090",  "name": "Proxy",
                    "tactic": "Command and Control"},
    "tool_transfer":{"id": "T1105", "name": "Ingress Tool Transfer",
                    "tactic": "Command and Control"},
    "rdp":         {"id": "T1021.001", "name": "Remote Desktop Protocol",
                    "tactic": "Lateral Movement"},
    "smb":         {"id": "T1021.002", "name": "SMB/Windows Admin Shares",
                    "tactic": "Lateral Movement"},
}

# ── System prompt ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """\
You are a senior network forensics analyst with 15 years of experience
analyzing network packet captures for malware, intrusions, and data exfiltration.

You receive a JSON summary of network flows extracted from a PCAP file.
Each flow includes: source IP, destination IP, destination port, protocol,
packet count, total bytes, duration, and any protocol-specific details.

Your job is to:
1. Identify suspicious flows that warrant further investigation
2. Explain WHY each flow is suspicious in plain English
3. Map findings to MITRE ATT&CK techniques
4. Suggest the specific next investigative step for each finding
5. Give an overall threat assessment (CRITICAL / HIGH / MEDIUM / LOW / CLEAN)

Format your response as:

OVERALL ASSESSMENT: [level]
SUMMARY: [2-3 sentences for a non-technical stakeholder]

FINDINGS:
[For each suspicious flow:]
[SEVERITY] [src_ip] → [dst_ip]:[port]
Reason: [why this is suspicious]
ATT&CK: [T-number] — [technique name]
Next step: [specific action]

CLEAN FLOWS: [count] flows appear normal and are not detailed here.
"""

ANALYSIS_PROMPT = ChatPromptTemplate.from_messages([
    ("system", SYSTEM_PROMPT),
    ("human", """\
Analyze these network flows from a PCAP capture:

{flows_json}

Additional context: {context}

Identify threats, explain findings, and map to ATT&CK.
"""),
])


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class NetworkFlow:
    """Represents a single network flow extracted from a PCAP."""
    src_ip:       str
    dst_ip:       str
    src_port:     int
    dst_port:     int
    proto:        str
    packet_count: int       = 0
    total_bytes:  int       = 0
    duration_sec: float     = 0.0
    protocol_name: str      = ""
    details:      dict      = field(default_factory=dict)
    first_seen:   float     = 0.0
    last_seen:    float     = 0.0
    is_suspicious: bool     = False
    suspicious_reasons: list[str] = field(default_factory=list)
    attck_tags:   list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "src_ip":          self.src_ip,
            "dst_ip":          self.dst_ip,
            "src_port":        self.src_port,
            "dst_port":        self.dst_port,
            "proto":           self.proto,
            "protocol_name":   self.protocol_name or PORT_NAMES.get(self.dst_port, "unknown"),
            "packet_count":    self.packet_count,
            "total_bytes":     self.total_bytes,
            "duration_sec":    round(self.duration_sec, 2),
            "bytes_per_sec":   round(self.total_bytes / max(self.duration_sec, 0.001), 2),
            "is_suspicious":   self.is_suspicious,
            "suspicious_reasons": self.suspicious_reasons,
            "attck_tags":      self.attck_tags,
            "details":         self.details,
        }


@dataclass
class AiAnalyzerFinding:
    """A finding from the AI PCAP analyzer."""
    flows_analyzed:  int
    suspicious_count: int
    ai_narrative:    str
    flows:           list[dict]
    attck_tags:      list[dict]
    risk_level:      str

    def to_dict(self) -> dict:
        return {
            "type":             "ai_pcap_analysis",
            "flows_analyzed":   self.flows_analyzed,
            "suspicious_count": self.suspicious_count,
            "ai_narrative":     self.ai_narrative,
            "top_flows":        self.flows[:10],
            "attck_tags":       self.attck_tags,
            "risk_level":       self.risk_level,
            "risk_score":       {
                "CRITICAL": 90, "HIGH": 65,
                "MEDIUM": 35,   "LOW": 10, "CLEAN": 0,
            }.get(self.risk_level, 0),
        }


# ── Flow extractor ────────────────────────────────────────────────────────────

class FlowExtractor:
    """
    Extracts and aggregates network flows from a PCAP using pyshark.
    Groups packets into flows by (src_ip, dst_ip, dst_port, proto).
    """

    def __init__(self):
        self._flows: dict[tuple, NetworkFlow] = {}

    def extract_from_pcap(self, pcap_path: str,
                          display_filter: str = "") -> list[NetworkFlow]:
        """Extract flows from a PCAP file using Scapy rdpcap."""
        if not _SCAPY:
            raise ImportError("scapy not installed: pip install scapy")

        print(f"[ai_analyzer] Extracting flows from: {pcap_path}")
        if display_filter:
            print(f"[ai_analyzer] Note: display_filter ignored (tshark unavailable; using Scapy)")

        packets = rdpcap(pcap_path)
        packet_count = 0
        for pkt in packets:
            try:
                self._process_packet(pkt)
                packet_count += 1
            except Exception:
                continue

        print(f"[ai_analyzer] Processed {packet_count} packets -> "
              f"{len(self._flows)} flows")
        return list(self._flows.values())

    def _process_packet(self, pkt) -> None:
        """Extract flow info from a single Scapy packet."""
        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        ts     = float(pkt.time)
        length = len(pkt)

        src_port = 0
        dst_port = 0
        proto    = "OTHER"

        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            proto    = "TCP"
        elif pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            proto    = "UDP"
        elif pkt.haslayer(ICMP):
            proto = "ICMP"

        flow_key = (
            min(src_ip, dst_ip),
            max(src_ip, dst_ip),
            dst_port,
            proto,
        )

        if flow_key not in self._flows:
            details    = {}
            proto_name = PORT_NAMES.get(dst_port, "")

            if _HTTP and pkt.haslayer(HTTPRequest):
                proto_name = "HTTP"
                req = pkt[HTTPRequest]
                details["http_host"]   = getattr(req, "Host",   b"").decode(errors="replace")
                details["http_method"] = getattr(req, "Method", b"").decode(errors="replace")
                details["http_uri"]    = getattr(req, "Path",   b"").decode(errors="replace")[:100]

            elif pkt.haslayer(DNSQR):
                proto_name = "DNS"
                try:
                    details["dns_query"] = pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
                except Exception:
                    pass

            self._flows[flow_key] = NetworkFlow(
                src_ip        = src_ip,
                dst_ip        = dst_ip,
                src_port      = src_port,
                dst_port      = dst_port,
                proto         = proto,
                protocol_name = proto_name,
                details       = details,
                first_seen    = ts,
                last_seen     = ts,
            )

        flow              = self._flows[flow_key]
        flow.packet_count += 1
        flow.total_bytes  += length
        flow.last_seen     = max(flow.last_seen, ts)
        flow.first_seen    = min(flow.first_seen, ts)
        flow.duration_sec  = flow.last_seen - flow.first_seen


# ── Suspicious flow scorer ────────────────────────────────────────────────────

class FlowScorer:
    """
    Applies heuristic rules to identify suspicious flows
    before sending to the LLM. This reduces false positives
    and keeps the LLM prompt focused on genuinely suspicious traffic.
    """

    def score(self, flows: list[NetworkFlow]) -> list[NetworkFlow]:
        """Apply all scoring rules to a list of flows."""
        for flow in flows:
            self._apply_rules(flow)
        return flows

    def _apply_rules(self, flow: NetworkFlow) -> None:
        """Apply suspicious flow detection rules."""
        reasons    = []
        attck_tags = []

        # Rule 1: known suspicious destination port
        if flow.dst_port in SUSPICIOUS_PORTS:
            reasons.append(
                f"Destination port {flow.dst_port} is associated "
                f"with known C2 frameworks (Metasploit, Cobalt Strike)"
            )
            attck_tags.append(ATTCK["app_layer"])

        # Rule 2: large data transfer to external IP
        if (flow.total_bytes > 10_000_000          # > 10MB
                and not flow.dst_ip.startswith(("10.", "192.168.", "172."))):
            reasons.append(
                f"Large outbound transfer: {flow.total_bytes / 1_000_000:.1f}MB "
                f"to external IP {flow.dst_ip} — possible data exfiltration"
            )
            attck_tags.append(ATTCK["c2_exfil"])

        # Rule 3: RDP to external IP
        if (flow.dst_port == 3389
                and not flow.dst_ip.startswith(("10.", "192.168.", "172."))):
            reasons.append(
                f"RDP connection to external IP {flow.dst_ip} — "
                f"unusual for legitimate traffic"
            )
            attck_tags.append(ATTCK["rdp"])

        # Rule 4: SMB to external IP (data staging / lateral movement)
        if (flow.dst_port == 445
                and not flow.dst_ip.startswith(("10.", "192.168.", "172."))):
            reasons.append(
                f"SMB traffic to external IP {flow.dst_ip} — "
                f"possible lateral movement or data staging"
            )
            attck_tags.append(ATTCK["smb"])

        # Rule 5: Telnet (unencrypted remote access)
        if flow.dst_port == 23:
            reasons.append(
                "Telnet detected — unencrypted remote access protocol, "
                "credentials transmitted in plaintext"
            )
            attck_tags.append(ATTCK["app_layer"])

        # Rule 6: Unusually high packet rate
        if (flow.packet_count > 1000
                and flow.duration_sec > 0
                and flow.packet_count / flow.duration_sec > 100):
            reasons.append(
                f"High packet rate: {flow.packet_count / flow.duration_sec:.0f} "
                f"packets/sec — possible port scan or DoS"
            )

        # Rule 7: HTTP (not HTTPS) with large payload
        if flow.dst_port == 80 and flow.total_bytes > 1_000_000:
            reasons.append(
                f"Large HTTP (unencrypted) transfer: "
                f"{flow.total_bytes / 1_000_000:.1f}MB — "
                f"possible tool download or exfiltration"
            )
            attck_tags.append(ATTCK["tool_transfer"])

        # Rule 8: Long-duration low-volume connection (C2 keep-alive)
        if (flow.duration_sec > 3600       # > 1 hour
                and flow.packet_count < 100):
            reasons.append(
                f"Long-duration ({flow.duration_sec / 3600:.1f}h) "
                f"low-volume ({flow.packet_count} packets) connection — "
                f"consistent with C2 keep-alive channel"
            )
            attck_tags.append(ATTCK["app_layer"])

        if reasons:
            flow.is_suspicious      = True
            flow.suspicious_reasons = reasons
            # Deduplicate ATT&CK tags
            seen: set[str] = set()
            for t in attck_tags:
                if t["id"] not in seen:
                    flow.attck_tags.append(t)
                    seen.add(t["id"])


# ── AI analysis chain ─────────────────────────────────────────────────────────

def build_analysis_chain():
    """Build the LangChain chain for flow analysis."""
    if not _LANGCHAIN:
        raise ImportError("langchain not installed")

    llm = ChatAnthropic(
        model      = DEFAULT_MODEL,
        temperature = 0,
        max_tokens  = MAX_TOKENS,
    )
    return ANALYSIS_PROMPT | llm | StrOutputParser()


def analyze_flows_with_ai(
    flows:   list[NetworkFlow],
    context: str = "",
) -> str:
    """
    Send flow summaries to Claude for threat narrative.
    Only sends suspicious flows + a statistical summary of clean ones.
    """
    if not _LANGCHAIN:
        return "[AI analysis unavailable — install langchain-anthropic]"

    suspicious = [f for f in flows if f.is_suspicious]
    clean      = [f for f in flows if not f.is_suspicious]

    if not suspicious:
        return ("No suspicious flows detected. "
                f"Analyzed {len(flows)} total flows — all appear normal.")

    # Build payload for LLM (cap at MAX_FLOWS to avoid token overflow)
    payload = {
        "suspicious_flows": [f.to_dict() for f in suspicious[:MAX_FLOWS]],
        "clean_flow_count": len(clean),
        "total_flows":      len(flows),
        "suspicious_count": len(suspicious),
    }

    # Add top talkers summary
    top_talkers = sorted(flows, key=lambda f: f.total_bytes, reverse=True)[:5]
    payload["top_talkers_by_bytes"] = [
        {
            "src": f.src_ip,
            "dst": f.dst_ip,
            "bytes": f.total_bytes,
            "proto": f.protocol_name or f.proto,
        }
        for f in top_talkers
    ]

    if not context:
        context = (
            f"PCAP contains {len(flows)} total flows. "
            f"{len(suspicious)} are flagged as suspicious by heuristic rules. "
            f"Top destination ports: "
            + ", ".join(
                str(p) for p in sorted(
                    {f.dst_port for f in flows[:20]}
                )[:8]
            )
        )

    chain = build_analysis_chain()
    return chain.invoke({
        "flows_json": json.dumps(payload, indent=2),
        "context":    context,
    })


# ── Main entry points ─────────────────────────────────────────────────────────

def analyze_pcap(
    pcap_path:      str,
    display_filter: str = "",
    context:        str = "",
    use_ai:         bool = True,
) -> AiAnalyzerFinding:
    """
    Full pipeline: PCAP → flow extraction → scoring → AI analysis.

    Args:
        pcap_path:      Path to the PCAP file
        display_filter: Optional Wireshark display filter (e.g. "tcp.port==443")
        context:        Additional context for the AI (e.g. "this is a Windows
                        workstation in a healthcare network")
        use_ai:         Set False to skip LLM call (faster, for testing)

    Returns:
        AiAnalyzerFinding with flows, AI narrative, and ATT&CK tags
    """
    if not _SCAPY:
        raise ImportError("pyshark not installed: pip install pyshark")

    print(f"\n[ai_analyzer] Analyzing: {pcap_path}")

    # Step 1: Extract flows
    extractor = FlowExtractor()
    flows     = extractor.extract_from_pcap(pcap_path, display_filter)

    # Step 2: Score for suspiciousness
    scorer    = FlowScorer()
    flows     = scorer.score(flows)

    suspicious = [f for f in flows if f.is_suspicious]
    print(f"[ai_analyzer] {len(suspicious)}/{len(flows)} flows flagged as suspicious")

    # Step 3: AI analysis
    if use_ai and os.environ.get("ANTHROPIC_API_KEY"):
        print("[ai_analyzer] Sending to Claude for threat narrative...")
        narrative = analyze_flows_with_ai(flows, context)
    elif not os.environ.get("ANTHROPIC_API_KEY"):
        narrative = (
            "[AI narrative skipped — set ANTHROPIC_API_KEY in .env]\n"
            f"Heuristic summary: {len(suspicious)} suspicious flows detected.\n"
            + "\n".join(
                f"  • {f.src_ip} → {f.dst_ip}:{f.dst_port} — "
                + "; ".join(f.suspicious_reasons[:1])
                for f in suspicious[:5]
            )
        )
    else:
        narrative = (
            f"[AI analysis skipped]\n"
            f"{len(suspicious)} suspicious flows detected by heuristics."
        )

    # Collect all ATT&CK tags
    all_tags: list[dict] = []
    seen_ids: set[str]   = set()
    for flow in suspicious:
        for tag in flow.attck_tags:
            if tag["id"] not in seen_ids:
                all_tags.append(tag)
                seen_ids.add(tag["id"])

    # Determine overall risk level
    if len(suspicious) == 0:
        risk = "CLEAN"
    elif any(f.dst_port in SUSPICIOUS_PORTS for f in suspicious):
        risk = "CRITICAL"
    elif len(suspicious) >= 5:
        risk = "HIGH"
    elif len(suspicious) >= 2:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return AiAnalyzerFinding(
        flows_analyzed   = len(flows),
        suspicious_count = len(suspicious),
        ai_narrative     = narrative,
        flows            = [f.to_dict() for f in suspicious[:20]],
        attck_tags       = all_tags,
        risk_level       = risk,
    )


def analyze_flows(
    flows:   list[NetworkFlow],
    context: str = "",
) -> AiAnalyzerFinding:
    """
    Analyze pre-extracted flows (skips the extraction step).
    Useful when flows come from the dispatcher's FlowTracker.
    """
    scorer = FlowScorer()
    flows  = scorer.score(flows)

    suspicious = [f for f in flows if f.is_suspicious]

    if os.environ.get("ANTHROPIC_API_KEY"):
        narrative = analyze_flows_with_ai(flows, context)
    else:
        narrative = f"{len(suspicious)} suspicious flows detected (no AI key set)."

    all_tags: list[dict] = []
    seen_ids: set[str]   = set()
    for flow in suspicious:
        for tag in flow.attck_tags:
            if tag["id"] not in seen_ids:
                all_tags.append(tag)
                seen_ids.add(tag["id"])

    risk = ("CRITICAL" if any(f.dst_port in SUSPICIOUS_PORTS for f in suspicious)
            else "HIGH" if len(suspicious) >= 5
            else "MEDIUM" if len(suspicious) >= 2
            else "LOW" if suspicious
            else "CLEAN")

    return AiAnalyzerFinding(
        flows_analyzed   = len(flows),
        suspicious_count = len(suspicious),
        ai_narrative     = narrative,
        flows            = [f.to_dict() for f in suspicious[:20]],
        attck_tags       = all_tags,
        risk_level       = risk,
    )


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    # Windows console defaults to cp1252; Claude responses contain Unicode arrows etc.
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    if len(sys.argv) < 2:
        print("Usage: python ai_analyzer.py <pcap_file> [display_filter]")
        print("       python ai_analyzer.py capture.pcap 'tcp.port==443'")
        sys.exit(1)

    pcap   = sys.argv[1]
    filt   = sys.argv[2] if len(sys.argv) > 2 else ""
    result = analyze_pcap(pcap, display_filter=filt)

    print("\n" + "=" * 55)
    print(f"RISK LEVEL: {result.risk_level}")
    print(f"Flows analyzed: {result.flows_analyzed}")
    print(f"Suspicious:     {result.suspicious_count}")
    if result.attck_tags:
        print(f"ATT&CK TTPs:    {', '.join(t['id'] for t in result.attck_tags)}")
    print("\nAI NARRATIVE:")
    print(result.ai_narrative)
