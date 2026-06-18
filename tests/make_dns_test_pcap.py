"""Generate a small DNS test PCAP with exfil-like queries for dns_exfil.py testing."""
from scapy.all import IP, UDP, DNS, DNSQR, wrpcap

# Labels must cross at least one threshold to fire:
#   ENTROPY_THRESHOLD  = 3.5  (base64 random data is ~3.9)
#   LENGTH_THRESHOLD   = 30   (label chars)
queries = [
    # Long base64 payload (>30 chars, high entropy) — should trigger both
    "SGVsbG9Xb3JsZERhdGFFeGZpbHRyYXRpb24.evil.com",
    # Hex-encoded payload (>30 chars, entropy ~4.0)
    "48656c6c6f576f726c64546573744461.evil.com",
    # Short benign label — should NOT trigger
    "normal.evil.com",
]

pkts = [
    IP(src="192.168.1.100", dst="8.8.8.8") /
    UDP(dport=53) /
    DNS(rd=1, qd=DNSQR(qname=q))
    for q in queries
]

out = "tests/sample_pcaps/dns_test.pcap"
wrpcap(out, pkts)
print(f"Written {len(pkts)} packets to {out}")
