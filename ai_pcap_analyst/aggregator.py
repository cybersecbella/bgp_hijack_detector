"""
aggregator.py — Combines findings from all detectors into one report
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class AggregatedReport:
    generated_at:    str
    pcap_file:       str
    total_findings:  int
    critical:        int
    high:            int
    medium:          int
    low:             int
    unique_ttps:     list[str]
    tactic_coverage: dict[str, list[str]]
    findings:        list[dict]

    def to_dict(self) -> dict:
        return {
            "generated_at":    self.generated_at,
            "pcap_file":       self.pcap_file,
            "total_findings":  self.total_findings,
            "critical":        self.critical,
            "high":            self.high,
            "medium":          self.medium,
            "low":             self.low,
            "unique_ttps":     self.unique_ttps,
            "tactic_coverage": self.tactic_coverage,
            "findings":        self.findings,
        }


def risk_level(score: int) -> str:
    if score >= 80: return "CRITICAL"
    if score >= 55: return "HIGH"
    if score >= 30: return "MEDIUM"
    return "LOW"


def aggregate(
    dns_findings:      list,
    beacon_findings:   list,
    bgp_findings:      list,
    pcap_file:         str = "unknown",
) -> AggregatedReport:
    """Combine all module findings into a single structured report."""
    all_findings = (
        [f.to_dict() for f in dns_findings] +
        [f.to_dict() for f in beacon_findings] +
        [f.to_dict() for f in bgp_findings]
    )

    # Sort by risk score descending
    all_findings.sort(key=lambda f: f.get("risk_score", 0), reverse=True)

    # Count by severity
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        level = risk_level(f.get("risk_score", 0))
        counts[level] += 1
        f["risk_level"] = level

    # Collect unique TTPs
    all_ttp_ids: set[str] = set()
    tactic_cov: dict[str, list[str]] = {}
    for f in all_findings:
        for tag in f.get("attck_tags", []):
            tid    = tag.get("id", "")
            tactic = tag.get("tactic", "Unknown")
            if tid:
                all_ttp_ids.add(tid)
                tactic_cov.setdefault(tactic, [])
                if tid not in tactic_cov[tactic]:
                    tactic_cov[tactic].append(tid)

    return AggregatedReport(
        generated_at    = datetime.now(timezone.utc).isoformat(),
        pcap_file       = pcap_file,
        total_findings  = len(all_findings),
        critical        = counts["CRITICAL"],
        high            = counts["HIGH"],
        medium          = counts["MEDIUM"],
        low             = counts["LOW"],
        unique_ttps     = sorted(all_ttp_ids),
        tactic_coverage = tactic_cov,
        findings        = all_findings,
    )