"""
langchain_agent.py — LangChain threat narrative agent
======================================================
Receives aggregated findings from all detectors and produces:
    1. Plain-English threat narrative for analysts
    2. Executive summary for non-technical stakeholders
    3. Formal incident report section
    4. Prioritized remediation steps

The agent uses tool calling to query different aspects of the findings
rather than dumping everything into one prompt — this produces more
focused, accurate analysis.

Usage:
    from ai_pcap_analyst.langchain_agent import run_threat_agent
    narrative = run_threat_agent(aggregated_report_dict)

    # Or use the full agent with tool calling:
    from ai_pcap_analyst.langchain_agent import build_agent, run_agent_repl
    executor = build_agent(report)
    run_agent_repl(executor)
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any
from dotenv import load_dotenv

load_dotenv()

# ── LangChain imports ─────────────────────────────────────────────────────────
try:
    from langchain_anthropic import ChatAnthropic
    from langchain_core.tools import tool
    from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
    from langchain_core.output_parsers import StrOutputParser
    from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
    from langchain_community.chat_message_histories import ChatMessageHistory
    from langgraph.prebuilt import create_react_agent
    _LANGCHAIN = True
except ImportError:
    _LANGCHAIN = False
    print("[langchain_agent] LangChain not installed.")
    print("Run: pip install langchain langchain-anthropic langchain-core")


# ── Config ────────────────────────────────────────────────────────────────────
DEFAULT_MODEL = os.environ.get("VOL_AI_MODEL", "claude-sonnet-4-6")
MAX_TOKENS    = 2048


# ── System prompts ────────────────────────────────────────────────────────────

ANALYST_SYSTEM = """\
You are a senior network forensics analyst with 15 years of experience
investigating network intrusions, malware C2 channels, and data exfiltration.

You have access to findings from an automated PCAP analysis pipeline that
detected anomalies using four detectors:
  - BGP hijack detector (RPKI validation)
  - C2 beaconing detector (statistical timing analysis)
  - DNS exfiltration detector (Shannon entropy)
  - AI flow analyzer (heuristic + protocol analysis)

Use the available tools to query specific aspects of the findings.
When you find something critical, automatically investigate it further
by calling additional tools.

Always:
  - Reference specific IPs, ports, domains, and timestamps from the data
  - Map findings to MITRE ATT&CK T-numbers
  - End every finding with a concrete next step
  - Connect related findings (e.g. same src_ip appearing in beacon + DNS exfil)
"""

EXECUTIVE_SYSTEM = """\
You are a cybersecurity communications expert writing for a non-technical
C-suite audience. Translate technical security findings into clear business
language.

Rules:
  - No acronyms without explanation
  - Focus on business risk: what data was at risk, what systems were affected
  - Explain attacker intent simply ("the attacker was trying to steal data")
  - 3 paragraphs maximum
  - End with 3 bullet points: immediate actions required
  - Never use the words: exfiltration, TTPs, vectors, artifacts, IOCs
"""

REPORT_SYSTEM = """\
You are writing the Network Analysis section of a formal incident response
report. Use professional report language. Be precise and cite evidence.

Format:
  Finding [N]: [Short title]
  Severity: [CRITICAL/HIGH/MEDIUM/LOW]
  Source: [which detector flagged this]
  Evidence: [specific IPs, ports, timestamps, packet counts]
  Analysis: [what it means, 2-3 sentences]
  ATT&CK: [T-number] — [name] ([tactic])
  Recommendation: [specific remediation]
"""


# ── Tool factory ──────────────────────────────────────────────────────────────

def build_tools(report: dict) -> list:
    """
    Build LangChain tools bound to a specific aggregated report.
    Each tool queries a different aspect of the findings.
    """

    findings     = report.get("findings", [])
    summary      = report.get("summary", {})
    generated_at = report.get("generated_at", "unknown")
    pcap_file    = report.get("pcap_file", "unknown")

    @tool
    def get_investigation_summary() -> str:
        """
        Get a high-level summary of all findings: total count,
        severity breakdown, unique ATT&CK TTPs, and tactic coverage.
        Always call this first to understand the scope of the incident.
        """
        return json.dumps({
            "pcap_file":       pcap_file,
            "analyzed_at":     generated_at,
            "total_findings":  summary.get("total_findings", 0),
            "critical":        summary.get("critical", 0),
            "high":            summary.get("high", 0),
            "medium":          summary.get("medium", 0),
            "low":             summary.get("low", 0),
            "unique_ttps":     summary.get("unique_ttps", []),
            "tactic_coverage": summary.get("tactic_coverage", {}),
        }, indent=2)

    @tool
    def get_critical_findings() -> str:
        """
        Get all CRITICAL severity findings in detail.
        These are the highest priority items requiring immediate action.
        Call this after get_investigation_summary when critical > 0.
        """
        critical = [
            f for f in findings
            if f.get("risk_level") == "CRITICAL"
            or f.get("risk_score", 0) >= 80
        ]
        if not critical:
            return json.dumps({"message": "No CRITICAL findings detected."})
        return json.dumps(critical[:10], indent=2)

    @tool
    def get_high_findings() -> str:
        """
        Get all HIGH severity findings.
        Review these after addressing CRITICAL findings.
        """
        high = [
            f for f in findings
            if f.get("risk_level") == "HIGH"
            or 55 <= f.get("risk_score", 0) < 80
        ]
        if not high:
            return json.dumps({"message": "No HIGH findings detected."})
        return json.dumps(high[:10], indent=2)

    @tool
    def get_findings_by_type(finding_type: str) -> str:
        """
        Get all findings of a specific type.
        finding_type options:
          'dns_exfiltration'  — DNS-based data exfiltration
          'c2_beaconing'      — Command and control beaconing
          'bgp_hijack'        — BGP route hijacking
          'ai_pcap_analysis'  — General flow analysis findings
        """
        valid_types = {
            "dns_exfiltration", "c2_beaconing",
            "bgp_hijack", "ai_pcap_analysis",
        }
        if finding_type not in valid_types:
            return json.dumps({
                "error": f"Invalid type. Choose from: {', '.join(valid_types)}"
            })

        typed = [f for f in findings if f.get("type") == finding_type]
        if not typed:
            return json.dumps({"message": f"No {finding_type} findings detected."})
        return json.dumps(typed[:10], indent=2)

    @tool
    def get_findings_by_ip(ip_address: str) -> str:
        """
        Get all findings involving a specific IP address (source or destination).
        Useful for pivoting: if one IP appears in multiple findings,
        it is likely the attacker's machine or a compromised host.
        """
        related = [
            f for f in findings
            if f.get("src_ip") == ip_address
            or f.get("dst_ip") == ip_address
        ]
        if not related:
            return json.dumps({
                "message": f"No findings involving IP: {ip_address}"
            })
        return json.dumps({
            "ip":       ip_address,
            "count":    len(related),
            "findings": related,
        }, indent=2)

    @tool
    def get_attck_coverage() -> str:
        """
        Get a breakdown of which MITRE ATT&CK tactics and techniques
        were detected across all findings. Use this to understand the
        scope of the attack and what the attacker was trying to accomplish.
        """
        tactic_map: dict[str, list[str]] = {}
        all_techniques: list[dict] = []

        for finding in findings:
            for tag in finding.get("attck_tags", []):
                tid    = tag.get("id", "")
                tactic = tag.get("tactic", "Unknown")
                name   = tag.get("name", "")

                if tid:
                    tactic_map.setdefault(tactic, [])
                    if tid not in tactic_map[tactic]:
                        tactic_map[tactic].append(tid)
                        all_techniques.append({
                            "id": tid, "name": name, "tactic": tactic
                        })

        return json.dumps({
            "total_techniques":  len(all_techniques),
            "tactic_coverage":   tactic_map,
            "all_techniques":    all_techniques,
        }, indent=2)

    @tool
    def get_top_source_ips() -> str:
        """
        Get the top source IP addresses by finding count.
        An IP that appears in many findings is likely the attacker's
        machine or a heavily compromised internal host.
        """
        ip_counts: dict[str, int] = {}
        ip_types:  dict[str, set] = {}

        for finding in findings:
            src = finding.get("src_ip", "")
            if src:
                ip_counts[src] = ip_counts.get(src, 0) + 1
                ip_types.setdefault(src, set())
                ip_types[src].add(finding.get("type", "unknown"))

        top = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        return json.dumps({
            "top_source_ips": [
                {
                    "ip":             ip,
                    "finding_count":  count,
                    "finding_types":  list(ip_types.get(ip, set())),
                }
                for ip, count in top
            ]
        }, indent=2)

    @tool
    def get_dns_exfil_details() -> str:
        """
        Get detailed DNS exfiltration findings including the specific
        subdomain queries, their Shannon entropy scores, and the domains
        being used for exfiltration. High entropy = encoded data in DNS.
        """
        dns_findings = [
            f for f in findings
            if f.get("type") == "dns_exfiltration"
        ]
        if not dns_findings:
            return json.dumps({"message": "No DNS exfiltration detected."})

        # Sort by entropy score descending
        dns_findings.sort(
            key=lambda f: f.get("entropy", 0), reverse=True
        )

        return json.dumps({
            "count":          len(dns_findings),
            "top_findings":   dns_findings[:8],
            "unique_domains": list({
                f.get("domain", "") for f in dns_findings
            }),
            "unique_src_ips": list({
                f.get("src_ip", "") for f in dns_findings
            }),
        }, indent=2)

    @tool
    def get_beaconing_details() -> str:
        """
        Get C2 beaconing findings with statistical details.
        Shows the beacon interval, coefficient of variation (CV),
        and destination IPs/ports. Low CV = highly regular = malware.
        """
        beacon_findings = [
            f for f in findings
            if f.get("type") == "c2_beaconing"
        ]
        if not beacon_findings:
            return json.dumps({"message": "No C2 beaconing detected."})

        # Sort by CV ascending (lowest CV = most suspicious)
        beacon_findings.sort(key=lambda f: f.get("cv", 999))

        return json.dumps({
            "count":        len(beacon_findings),
            "top_beacons":  beacon_findings[:8],
            "unique_c2_ips": list({
                f.get("dst_ip", "") for f in beacon_findings
            }),
            "beacon_intervals": [
                {
                    "src":      f.get("src_ip"),
                    "dst":      f.get("dst_ip"),
                    "port":     f.get("dst_port"),
                    "interval": f.get("beacon_interval", "unknown"),
                    "cv":       f.get("cv"),
                }
                for f in beacon_findings[:5]
            ],
        }, indent=2)

    @tool
    def correlate_findings() -> str:
        """
        Look for connections between different finding types.
        For example: does the same IP appear in both beaconing AND
        DNS exfiltration findings? That strongly suggests one compromised
        host is performing multiple attack techniques.
        """
        # Build IP → finding types map
        ip_to_types: dict[str, list[str]] = {}
        ip_to_findings: dict[str, list[dict]] = {}

        for finding in findings:
            src = finding.get("src_ip", "")
            dst = finding.get("dst_ip", "")
            ftype = finding.get("type", "unknown")

            for ip in [src, dst]:
                if ip and ip != "unknown":
                    ip_to_types.setdefault(ip, [])
                    ip_to_findings.setdefault(ip, [])
                    if ftype not in ip_to_types[ip]:
                        ip_to_types[ip].append(ftype)
                    ip_to_findings[ip].append(finding)

        # Find IPs in multiple finding types (high suspicion)
        multi_type_ips = {
            ip: types
            for ip, types in ip_to_types.items()
            if len(types) > 1
        }

        if not multi_type_ips:
            return json.dumps({
                "message":     "No IP addresses appear in multiple finding types.",
                "implication": "Findings may be from different hosts or unrelated incidents.",
            })

        correlations = []
        for ip, types in multi_type_ips.items():
            correlations.append({
                "ip":            ip,
                "finding_types": types,
                "count":         len(ip_to_findings.get(ip, [])),
                "assessment":    (
                    f"IP {ip} appears in {len(types)} finding types "
                    f"({', '.join(types)}) — HIGH probability of being "
                    f"a compromised host performing multiple attack techniques"
                ),
                "attck_implication": (
                    "Multi-stage attack observed. Consider TTPs: "
                    + ", ".join(
                        tag["id"]
                        for f in ip_to_findings.get(ip, [])
                        for tag in f.get("attck_tags", [])
                    )[:100]
                ),
            })

        return json.dumps({
            "correlated_ips": correlations,
            "total_correlated": len(correlations),
        }, indent=2)

    return [
        get_investigation_summary,
        get_critical_findings,
        get_high_findings,
        get_findings_by_type,
        get_findings_by_ip,
        get_attck_coverage,
        get_top_source_ips,
        get_dns_exfil_details,
        get_beaconing_details,
        correlate_findings,
    ]


# ── Agent builder ─────────────────────────────────────────────────────────────
def build_agent(
    report:    dict,
    model:     str  = DEFAULT_MODEL,
    streaming: bool = True,
    memory_k:  int  = 8,
):
    """
    Build a LangGraph agent bound to a specific analysis report.
    LangGraph replaced AgentExecutor in LangChain 1.x.
    """
    if not _LANGCHAIN:
        raise ImportError("LangChain not installed")

    tools = build_tools(report)
    llm   = ChatAnthropic(
        model       = model,
        temperature = 0,
        max_tokens  = MAX_TOKENS,
    )

    # LangGraph agent — simpler and more reliable than AgentExecutor
    agent = create_react_agent(
        model        = llm,
        tools        = tools,
        prompt       = ANALYST_SYSTEM,
    )
    return agent


# ── Simple chain (no tool calling) ───────────────────────────────────────────

def run_threat_agent(
    report:  dict,
    mode:    str = "analyst",   # "analyst" | "executive" | "report"
    stream:  bool = True,
) -> str:
    """
    Simple (non-agent) version: send the full report to Claude
    and return a narrative. Faster than the agent but less adaptive.

    Use this for automated pipelines. Use build_agent() for interactive use.
    """
    if not _LANGCHAIN:
        return "[LangChain not installed — install langchain-anthropic]"

    if not os.environ.get("ANTHROPIC_API_KEY"):
        return "[ANTHROPIC_API_KEY not set in .env]"

    system_map = {
        "analyst":   ANALYST_SYSTEM,
        "executive": EXECUTIVE_SYSTEM,
        "report":    REPORT_SYSTEM,
    }

    system = system_map.get(mode, ANALYST_SYSTEM)

    # Build a focused payload — only send what matters
    summary    = report.get("summary", {})
    findings   = report.get("findings", [])
    priority   = [
        f for f in findings
        if f.get("risk_level") in ("CRITICAL", "HIGH")
        or f.get("risk_score", 0) >= 55
    ][:15]

    payload = {
        "pcap_file":        report.get("pcap_file", "unknown"),
        "analyzed_at":      report.get("generated_at", "unknown"),
        "statistics": {
            "total_findings": summary.get("total_findings", 0),
            "critical":       summary.get("critical", 0),
            "high":           summary.get("high", 0),
            "medium":         summary.get("medium", 0),
            "unique_ttps":    summary.get("unique_ttps", []),
        },
        "priority_findings": priority,
    }

    prompt_template = ChatPromptTemplate.from_messages([
        ("system", system),
        ("human", (
            "Analyze these network forensics findings from an automated "
            "PCAP analysis pipeline and provide your assessment:\n\n"
            "{findings_json}"
        )),
    ])

    llm = ChatAnthropic(
        model       = DEFAULT_MODEL,
        temperature = 0,
        max_tokens  = MAX_TOKENS,
        streaming   = stream,
    )
    chain = prompt_template | llm | StrOutputParser()

    return chain.invoke({"findings_json": json.dumps(payload, indent=2)})


def generate_full_report(report: dict) -> dict:
    """
    Generate all three report formats (analyst, executive, formal)
    in one call. Returns a dict with all three narratives.
    """
    print("\n[langchain_agent] Generating analyst narrative...")
    analyst = run_threat_agent(report, mode="analyst")

    print("\n[langchain_agent] Generating executive summary...")
    executive = run_threat_agent(report, mode="executive")

    print("\n[langchain_agent] Generating formal report section...")
    formal = run_threat_agent(report, mode="report")

    return {
        "analyst_narrative":   analyst,
        "executive_summary":   executive,
        "formal_report_section": formal,
        "generated_at":        datetime.now(timezone.utc).isoformat(),
    }


# ── Interactive REPL ──────────────────────────────────────────────────────────

REPL_HELP = """
Commands:
  summary       — get overall finding statistics
  critical      — show all CRITICAL findings
  high          — show all HIGH findings
  dns           — DNS exfiltration details
  beaconing     — C2 beaconing details
  correlate     — find IPs in multiple findings
  attck         — ATT&CK tactic coverage
  executive     — generate executive summary
  report        — generate formal report section
  clear         — clear conversation history
  exit          — quit

Or ask any question in plain English:
  "Which IP is most suspicious?"
  "What should I do first?"
  "Explain the beaconing finding to me"
  "Are any findings related to each other?"
"""

SHORTCUT_MAP = {
    "summary":   "Call get_investigation_summary and summarize the findings",
    "critical":  "Call get_critical_findings and explain each one",
    "high":      "Call get_high_findings and explain each one",
    "dns":       "Call get_dns_exfil_details and explain the DNS exfiltration findings",
    "beaconing": "Call get_beaconing_details and explain the C2 beaconing findings",
    "correlate": "Call correlate_findings and explain any connections between findings",
    "attck":     "Call get_attck_coverage and explain what tactics the attacker used",
}

def run_agent_repl(report: dict, model: str = DEFAULT_MODEL):
    """
    Run an interactive REPL using LangGraph agent.
    """
    if not _LANGCHAIN:
        print("[error] LangChain not installed")
        return

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("[error] ANTHROPIC_API_KEY not set in .env")
        return

    agent        = build_agent(report, model=model)
    chat_history = []

    print("\n" + "=" * 55)
    print("  AI PCAP Analyst — Threat Investigation Agent")
    print(f"  PCAP: {report.get('pcap_file', 'unknown')}")
    print(f"  Findings: {report.get('summary', {}).get('total_findings', 0)}")
    print("  Type 'help' for commands, 'exit' to quit")
    print("=" * 55 + "\n")

    while True:
        try:
            query = input(">> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not query:
            continue

        if query.lower() in ("exit", "quit"):
            print("Goodbye.")
            break

        if query.lower() == "help":
            print(REPL_HELP)
            continue

        if query.lower() == "clear":
            chat_history.clear()
            print("[conversation history cleared]")
            continue

        if query.lower() in ("executive", "exec"):
            print("\n[generating executive summary...]\n")
            print(run_threat_agent(report, mode="executive"))
            print()
            continue

        if query.lower() == "report":
            print("\n[generating formal report section...]\n")
            print(run_threat_agent(report, mode="report"))
            print()
            continue

        # Expand shortcuts
        full_query = SHORTCUT_MAP.get(query.lower(), query)

        try:
            print()
            # Add user message to history
            chat_history.append(HumanMessage(content=full_query))

            # Invoke LangGraph agent
            result = agent.invoke({"messages": chat_history})

            # Extract response
            messages = result.get("messages", [])
            if messages:
                response = messages[-1].content
                print(response)
                # Add AI response to history
                chat_history.append(AIMessage(content=response))

                # Trim history
                if len(chat_history) > memory_k * 2:
                    chat_history = chat_history[-(memory_k * 2):]

            print("\n" + "─" * 55 + "\n")

        except KeyboardInterrupt:
            print("\n[interrupted]")
        except Exception as e:
            print(f"\n[error] {type(e).__name__}: {e}")


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    # Accept a pre-built aggregated report JSON file
    if len(sys.argv) < 2:
        print("Usage: python langchain_agent.py <report.json> [mode]")
        print("       mode: analyst (default) | executive | report | interactive")
        sys.exit(1)

    report_path = sys.argv[1]
    mode        = sys.argv[2] if len(sys.argv) > 2 else "analyst"

    with open(report_path) as f:
        report = json.load(f)

    if mode == "interactive":
        run_agent_repl(report)
    elif mode == "all":
        result = generate_full_report(report)
        print("\n=== ANALYST NARRATIVE ===")
        print(result["analyst_narrative"])
        print("\n=== EXECUTIVE SUMMARY ===")
        print(result["executive_summary"])
        print("\n=== FORMAL REPORT SECTION ===")
        print(result["formal_report_section"])
    else:
        narrative = run_threat_agent(report, mode=mode)
        print(narrative)
