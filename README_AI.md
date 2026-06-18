# AI PCAP Analyst — Network Forensics Enhancements
> Built by [cybersecbella](https://cybersecbella.com) |
> Fork of [secdev/scapy](https://github.com/secdev/scapy)

A network forensics pipeline built on top of Scapy. Detects BGP hijacking, C2 beaconing, DNS exfiltration, and suspicious traffic patterns — then exports findings to TheHive with plain-English AI-generated threat narratives.

## What it does

Feed it a PCAP file and get back:
- **BGP hijack alerts** — RPKI-validated route announcements flagged by origin ASN
- **C2 beaconing detection** — statistical analysis of packet timing (low CV = malware)
- **DNS exfiltration alerts** — high-entropy subdomains flagged with Shannon entropy score
- **AI threat narrative** — Claude explains every finding in plain English

---

## Quickstart

### 1. Clone and install
```bash
git clone https://github.com/cybersecbella/scapy
cd scapy
pip install -r requirements_ai.txt
```

### 2. Set your API key
```bash
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env
```

### 3. Analyze a PCAP
```bash
python -m ai_pcap_analyst analyze suspicious.pcap
```

### 4. dns_exfil -  returns potential data exfiltration attempts masquerading as legitimate DNS queries
```
python ai_pcap_analyst/dns_exfil.py tests/sample_pcaps/dns_test.pcap
```

### 5. beaconing.py - looks for periodic communication patterns and suspicious port usage within network traffic
```
python ai_pcap_analyst/beaconing.py tests/sample_pcaps/monitoring_beaconing.pcap
```

### 6. bgp_hijack.py - returns the prefix and ASN; checks validation status 
```
python ai_pcap_analyst/bgp_hijack.py tests/sample_pcaps/pakistan_telecom_bgp_hijack.pcap
```




---

## Modules

| File | Description | ATT&CK |
|------|-------------|--------|
| `dns_exfil.py` | Shannon entropy + label length detection | T1048.003, T1071.004 |
| `beaconing.py` | CV + autocorrelation on packet intervals | T1071, T1029 |
| `bgp_hijack.py` | RPKI validation via RIPE NCC API | T1599, T1205 |
| `aggregator.py` | Combines findings + risk scoring | — |
| `langchain_agent.py` | Claude AI threat narrative | — |

---

## Detection methods explained

**DNS exfiltration** — attackers encode stolen data as base64 in DNS
subdomains (`aGVsbG8=.evil.com`). Detected by measuring Shannon entropy
of each subdomain label — legitimate domains score ~2.5, encoded data
scores ~3.9+.

**C2 beaconing** — malware checks in at regular intervals (e.g. every
60 seconds). Detected by measuring the coefficient of variation (CV) of
inter-packet timing — human traffic has CV > 0.5, malware beacons have
CV < 0.15.

**BGP hijacking** — attackers announce IP prefixes they don't own to
redirect traffic. Detected by validating each announcement against RPKI
(Resource Public Key Infrastructure) using the free RIPE NCC API.

---

## ATT&CK coverage

| Technique | ID | Detected by |
|-----------|-----|-------------|
| Exfiltration Over DNS | T1048.003 | dns_exfil.py |
| DNS Application Layer Protocol | T1071.004 | dns_exfil.py |
| C2 Application Layer Protocol | T1071 | beaconing.py |
| Scheduled Transfer | T1029 | beaconing.py |
| Non-Standard Port | T1571 | beaconing.py |
| Network Boundary Bridging | T1599 | bgp_hijack.py |
| Traffic Signaling | T1205 | bgp_hijack.py |

---

## Requirements

- Python 3.9+
- Anthropic API key ([get one here](https://console.anthropic.com))
- Wireshark / tshark (for pyshark live capture)

---

## Test PCAPs

Good sources for test PCAP files:

- [Malware Traffic Analysis](https://malware-traffic-analysis.net) —
  real malware captures including Cobalt Strike beacons
- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures)
- [MemLabs](https://github.com/stuxnet999/MemLabs) — CTF challenges
  including network captures

---

## Project structure
scapy/

├── ai_pcap_analyst/

│   ├── init.py          # main entry point + pipeline orchestrator

│   ├── dns_exfil.py         # DNS exfiltration detector

│   ├── beaconing.py         # C2 beaconing detector

│   ├── bgp_hijack.py        # BGP hijack + RPKI validator

│   ├── aggregator.py        # finding aggregator + risk scoring

│   ├── langchain_agent.py   # LangChain AI threat narrative agent

├── tests/

│   ├── test_dns_exfil.py

│   ├── test_beaconing.py

│   └── test_bgp.py

├── .env                     # API keys (gitignored)

├── requirements_ai.txt      # additional dependencies

└── README_AI.md             # this file

## Blog writeups

Full walkthroughs at [cybersecbella.com](https://cybersecbella.com)