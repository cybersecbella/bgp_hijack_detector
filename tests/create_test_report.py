import json
from datetime import datetime, timezone

report = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "pcap_file": "tests/sample_pcaps/combined_incident.pcap",
    "summary": {
        "total_findings": 5,
        "critical": 2,
        "high": 2,
        "medium": 1,
        "low": 0,
        "unique_ttps": ["T1041", "T1071", "T1205", "T1599"],
        "tactic_coverage": {
            "Exfiltration": ["T1041"],
            "Command and Control": ["T1071"],
            "Defense Evasion": ["T1205", "T1599"],
        }
    },
    "findings": [
        {
            "type": "bgp_hijack",
            "risk_level": "CRITICAL",
            "risk_score": 90,
            "src_ip": "202.59.0.1",
            "dst_ip": "63.218.44.1",
            "announced_prefix": "208.65.153.0/24",
            "origin_asn": 17557,
            "rpki_status": "invalid",
            "rpki_detail": "AS17557 is not authorized to announce 208.65.153.0/24",
            "reasons": [
                "RPKI INVALID: AS17557 (Pakistan Telecom) is NOT authorized to announce 208.65.153.0/24",
                "Highly specific /24 prefix — attackers use more-specific prefixes to win routing"
            ],
            "attck_tags": [
                {"id": "T1599", "name": "Network Boundary Bridging", "tactic": "Defense Evasion"},
                {"id": "T1205", "name": "Traffic Signaling", "tactic": "Defense Evasion"}
            ]
        },
        {
            "type": "c2_beaconing",
            "risk_level": "CRITICAL",
            "risk_score": 85,
            "src_ip": "198.51.100.42",
            "dst_ip": "208.65.153.251",
            "dst_port": 80,
            "proto": "TCP",
            "cv": 0.024,
            "mean_interval": 60.1,
            "std_interval": 1.4,
            "beacon_interval": "60.1s (+-1.4s)",
            "packet_count": 30,
            "reasons": [
                "CV=0.024 below threshold 0.15 — intervals are suspiciously consistent",
                "Autocorrelation=0.91 above threshold 0.7 — strongly periodic"
            ],
            "attck_tags": [
                {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
                {"id": "T1029", "name": "Scheduled Transfer", "tactic": "Exfiltration"}
            ]
        },
        {
            "type": "dns_exfiltration",
            "risk_level": "HIGH",
            "risk_score": 70,
            "src_ip": "192.168.1.100",
            "dst_ip": "8.8.8.8",
            "domain": "evil.com",
            "subdomain": "aGVsbG8gd29ybGQ=",
            "entropy": 3.906,
            "label_length": 16,
            "raw_query": "aGVsbG8gd29ybGQ=.evil.com",
            "reasons": [
                "Label has high entropy 3.906 — likely base64 encoded data",
                "Label length 16 — unusually long for legitimate DNS"
            ],
            "attck_tags": [
                {"id": "T1048.003", "name": "Exfiltration Over DNS", "tactic": "Exfiltration"}
            ]
        }
    ]
}

with open("tests/test_report.json", "w") as f:
    json.dump(report, f, indent=2)

print("Written tests/test_report.json")

# Verify it was written correctly
with open("tests/test_report.json") as f:
    verify = json.load(f)
print(f"Verified: {verify['summary']['total_findings']} findings, "
      f"{verify['summary']['critical']} critical")