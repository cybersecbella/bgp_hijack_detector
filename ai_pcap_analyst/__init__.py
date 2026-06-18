"""
ai_pcap_analyst — AI-powered network forensics pipeline
Usage:
    python -m ai_pcap_analyst analyze capture.pcap
    python -m ai_pcap_analyst analyze capture.pcap --format html
    python -m ai_pcap_analyst live --interface eth0 --timeout 120
"""
from ai_pcap_analyst.dns_exfil  import analyze_pcap as dns_analyze
from ai_pcap_analyst.beaconing  import analyze_pcap as beacon_analyze
from ai_pcap_analyst.bgp_hijack import analyze_pcap as bgp_analyze
from ai_pcap_analyst.aggregator import aggregate
from ai_pcap_analyst.langchain_agent import run_threat_agent
from ai_pcap_analyst.thehive_export  import export_report


def analyze(pcap_path: str, export_thehive: bool = False,
            output_format: str = "json") -> dict:
    """
    Full pipeline: PCAP → all detectors → aggregation → AI narrative → report.
    """
    print(f"\n[ai_pcap_analyst] Starting analysis: {pcap_path}")
    print("=" * 55)

    # Run all detectors
    dns_findings    = dns_analyze(pcap_path)
    beacon_findings = beacon_analyze(pcap_path)
    bgp_findings    = bgp_analyze(pcap_path)

    # Aggregate
    report = aggregate(dns_findings, beacon_findings,
                       bgp_findings, pcap_file=pcap_path)

    print(f"\n[ai_pcap_analyst] Summary:")
    print(f"  Total findings : {report.total_findings}")
    print(f"  Critical       : {report.critical}")
    print(f"  High           : {report.high}")
    print(f"  Unique TTPs    : {', '.join(report.unique_ttps) or 'none'}")

    # AI narrative
    report_dict   = report.to_dict()
    ai_narrative  = run_threat_agent(report_dict)
    report_dict["ai_narrative"] = ai_narrative

    # Export to TheHive
    if export_thehive:
        export_report(report_dict, ai_narrative=ai_narrative)

    return report_dict