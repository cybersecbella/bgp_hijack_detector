"""
generate_test_pcaps.py — Pakistan Telecom / YouTube BGP Hijack Simulation
==========================================================================
Simulates the February 24, 2008 BGP hijacking incident where Pakistan
Telecom (AS17557) accidentally announced YouTube's prefix (208.65.153.0/24)
to its upstream provider PCCW Global (AS3491), causing YouTube traffic to
be redirected to Pakistan and blackholed for ~2 hours globally.

Timeline of the real incident (all times UTC, February 24, 2008):
  18:47  Pakistan Telecom (AS17557) announces 208.65.153.0/24 to PCCW
  18:48  PCCW (AS3491) propagates the announcement globally
  18:49  Within 2 minutes, YouTube traffic begins routing to Pakistan
  20:07  YouTube (AS36561) fights back: announces 208.65.153.0/24 itself
  20:18  YouTube announces more-specific /25 prefixes to win routing
  20:51  PCCW disconnects AS17557, withdraws hijacked prefix
  21:00  Full service restored

Real ASNs used:
  AS17557  Pakistan Telecom (the hijacker)
  AS3491   PCCW Global (upstream that propagated without validation)
  AS36561  YouTube (victim)
  AS15169  Google (YouTube's parent AS)
  AS1299   Telia (major transit that accepted the route from PCCW)
  AS3356   Level3 (another major transit affected)

Real prefixes:
  208.65.152.0/22   YouTube's legitimate aggregate prefix
  208.65.153.0/24   Hijacked prefix (more specific, wins routing)
  208.65.153.0/25   YouTube's counter-announcement (more specific still)
  208.65.153.128/25 YouTube's counter-announcement (other half)

YouTube's real IPs in 2008:
  208.65.153.251    www.youtube.com
  208.65.153.253    www.youtube.com
  208.65.153.238    www.youtube.com

Usage:
    python tests/generate_test_pcaps.py

Output files (saved to tests/sample_pcaps/):
    pakistan_telecom_bgp_hijack.pcap   Full simulation of the incident
    bgp_legitimate_baseline.pcap       Normal BGP traffic for comparison
    youtube_victim_traffic.pcap        User traffic hitting the blackhole
    combined_incident.pcap             All of the above merged + timestamped

Run your detectors against them:
    python ai_pcap_analyst/bgp_hijack.py tests/sample_pcaps/pakistan_telecom_bgp_hijack.pcap
    python ai_pcap_analyst/beaconing.py  tests/sample_pcaps/youtube_victim_traffic.pcap
    python ai_pcap_analyst/dns_exfil.py  tests/sample_pcaps/combined_incident.pcap
"""

import random
import struct
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Scapy imports ──────────────────────────────────────────────────────────────
try:
    from scapy.all import (
        IP, TCP, UDP, Raw, Ether,
        wrpcap, DNS, DNSQR, DNSRR,
    )
    from scapy.contrib.bgp import (
        BGPHeader, BGPOpen, BGPUpdate,
        BGPPathAttr, BGPNLRIIPv4,
    )
    _BGP_CONTRIB = True
except ImportError:
    _BGP_CONTRIB = False
    print("[warning] BGP contrib not available — using raw TCP for BGP packets")
    from scapy.all import IP, TCP, UDP, Raw, Ether, wrpcap, DNS, DNSQR, DNSRR

# ── Output directory ───────────────────────────────────────────────────────────
OUTPUT_DIR = Path("tests/sample_pcaps")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# REAL INCIDENT DATA (verified from RIPE NCC RIS study and Renesys analysis)
# ─────────────────────────────────────────────────────────────────────────────

# Real ASNs
AS_PAKISTAN_TELECOM = 17557   # the hijacker
AS_PCCW_GLOBAL      = 3491    # upstream that propagated without validation
AS_YOUTUBE          = 36561   # victim (also seen as AS36351 in some records)
AS_GOOGLE           = 15169   # YouTube parent
AS_TELIA            = 1299    # major transit that accepted hijacked route
AS_LEVEL3           = 3356    # another transit affected
AS_COGENT           = 174     # another transit

# Real prefixes
PREFIX_YOUTUBE_AGGREGATE = "208.65.152.0"    # /22 — YouTube's real announcement
PREFIX_HIJACKED          = "208.65.153.0"    # /24 — what Pakistan Telecom announced
PREFIX_YOUTUBE_COUNTER_A = "208.65.153.0"    # /25 — YouTube's counter /25
PREFIX_YOUTUBE_COUNTER_B = "208.65.153.128"  # /25 — YouTube's other /25

# Real YouTube IPs in 208.65.153.0/24
YOUTUBE_IPS = ["208.65.153.251", "208.65.153.253", "208.65.153.238"]

# Real router IPs (simulated — realistic for the ASes involved)
ROUTER_PAKISTAN = "202.59.0.1"      # Pakistan Telecom edge router
ROUTER_PCCW     = "63.218.44.1"     # PCCW Global router (Hong Kong)
ROUTER_TELIA    = "213.248.70.1"    # Telia router (Stockholm)
ROUTER_LEVEL3   = "4.69.138.1"      # Level3 router
ROUTER_YOUTUBE  = "72.14.198.1"     # YouTube/Google router
ROUTER_COGENT   = "38.104.85.1"     # Cogent router

# Simulated user IPs — people trying to reach YouTube
USER_IPS = [
    "85.17.43.2",      # Netherlands
    "212.77.100.3",    # Poland
    "194.50.8.4",      # France
    "81.57.149.5",     # Belgium
    "109.74.205.6",    # UK
    "79.140.57.7",     # Germany
    "151.15.200.8",    # Italy
]

# Real incident timestamp: 18:47 UTC, February 24, 2008
INCIDENT_START = datetime(2008, 2, 24, 18, 47, 0, tzinfo=timezone.utc).timestamp()


# ─────────────────────────────────────────────────────────────────────────────
# BGP PACKET BUILDERS
# Build raw BGP UPDATE packets that simulate the hijack announcements.
# BGP runs over TCP port 179. Each UPDATE message contains:
#   - NLRI (Network Layer Reachability Info): the prefix being announced
#   - PATH ATTRIBUTES: AS_PATH, NEXT_HOP, ORIGIN
# ─────────────────────────────────────────────────────────────────────────────

def build_bgp_open(src_ip: str, dst_ip: str,
                   asn: int, timestamp: float) -> "IP":
    """
    Build a BGP OPEN message — the handshake before UPDATE messages.
    BGP peers exchange OPEN messages to establish a session.
    """
    # BGP OPEN: marker(16) + length(2) + type(1) + version(1) +
    #           my_as(2) + hold_time(2) + bgp_id(4) + opt_len(1)
    bgp_id = bytes(map(int, src_ip.split(".")))
    payload = (
        b"\xff" * 16 +           # marker (all ones)
        struct.pack(">H", 29) +  # length
        b"\x01" +                # type: OPEN
        b"\x04" +                # version: 4
        struct.pack(">H", asn) + # my ASN
        struct.pack(">H", 180) + # hold time: 3 minutes
        bgp_id +                 # BGP identifier
        b"\x00"                  # optional parameters length
    )
    pkt = (
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=random.randint(1024, 65535), dport=179,
            flags="PA", seq=random.randint(1000, 9999)) /
        Raw(load=payload)
    )
    pkt.time = timestamp
    return pkt


def build_bgp_update_announcement(
    src_ip:     str,
    dst_ip:     str,
    prefix:     str,
    prefix_len: int,
    origin_asn: int,
    as_path:    list[int],
    next_hop:   str,
    timestamp:  float,
) -> "IP":
    """
    Build a BGP UPDATE packet announcing a prefix.

    This is the core of the hijack:
    Pakistan Telecom (AS17557) sends an UPDATE to PCCW (AS3491)
    announcing 208.65.153.0/24 with AS_PATH [17557].

    BGP UPDATE structure:
    - Withdrawn routes length (2 bytes) = 0 (no withdrawals)
    - Path attributes length (2 bytes)
    - Path attributes:
        ORIGIN (type 1): IGP = 0x00
        AS_PATH (type 2): sequence of ASNs
        NEXT_HOP (type 3): IP of next hop router
    - NLRI: prefix/len being announced
    """
    # ORIGIN attribute: INCOMPLETE (0x02) — Pakistan Telecom
    # was announcing a prefix they didn't own = INCOMPLETE origin
    origin_attr = b"\x40\x01\x01\x02"

    # AS_PATH attribute: sequence type (2) with our ASes
    # Format: flags(1) + type(1) + length(1) + seg_type(1) +
    #         seg_len(1) + ASNs(4 each)
    as_path_bytes = b""
    for asn in as_path:
        as_path_bytes += struct.pack(">I", asn)
    as_path_segment = (
        b"\x02" +                              # segment type: AS_SEQUENCE
        struct.pack("B", len(as_path)) +       # segment length (# of ASNs)
        as_path_bytes
    )
    as_path_attr = (
        b"\x40\x02" +                          # flags + type
        struct.pack("B", len(as_path_segment)) +
        as_path_segment
    )

    # NEXT_HOP attribute: the router's IP
    nh_bytes = bytes(map(int, next_hop.split(".")))
    next_hop_attr = b"\x40\x03\x04" + nh_bytes

    # Combine all path attributes
    path_attrs = origin_attr + as_path_attr + next_hop_attr

    # NLRI: prefix (variable length, packed to minimum bytes)
    prefix_bytes = bytes(map(int, prefix.split(".")))
    # Only include bytes needed for the prefix length
    bytes_needed  = (prefix_len + 7) // 8
    prefix_packed = bytes([prefix_len]) + prefix_bytes[:bytes_needed]

    # Full BGP UPDATE message
    payload = (
        b"\xff" * 16 +                            # marker
        struct.pack(">H", 23 + len(path_attrs) +
                    len(prefix_packed)) +          # total length
        b"\x02" +                                 # type: UPDATE
        struct.pack(">H", 0) +                    # withdrawn routes length = 0
        struct.pack(">H", len(path_attrs)) +      # path attributes length
        path_attrs +                              # path attributes
        prefix_packed                             # NLRI
    )

    pkt = (
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=random.randint(1024, 65535), dport=179,
            flags="PA", seq=random.randint(10000, 99999)) /
        Raw(load=payload)
    )
    pkt.time = timestamp
    return pkt


def build_bgp_withdrawal(
    src_ip:     str,
    dst_ip:     str,
    prefix:     str,
    prefix_len: int,
    timestamp:  float,
) -> "IP":
    """
    Build a BGP UPDATE with a withdrawal (removing a previously announced prefix).
    This simulates PCCW withdrawing Pakistan Telecom's hijacked route at 20:51 UTC.
    """
    prefix_bytes = bytes(map(int, prefix.split(".")))
    bytes_needed = (prefix_len + 7) // 8
    withdrawn    = bytes([prefix_len]) + prefix_bytes[:bytes_needed]

    payload = (
        b"\xff" * 16 +
        struct.pack(">H", 23 + len(withdrawn)) +
        b"\x02" +                               # type: UPDATE
        struct.pack(">H", len(withdrawn)) +     # withdrawn routes length
        withdrawn +                             # withdrawn prefix
        struct.pack(">H", 0)                    # path attributes length = 0
    )

    pkt = (
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=random.randint(1024, 65535), dport=179,
            flags="PA", seq=random.randint(10000, 99999)) /
        Raw(load=payload)
    )
    pkt.time = timestamp
    return pkt


# ─────────────────────────────────────────────────────────────────────────────
# INCIDENT SIMULATION
# Recreates the full sequence of BGP events from the incident timeline
# ─────────────────────────────────────────────────────────────────────────────

def simulate_pakistan_telecom_hijack() -> list:
    """
    Simulate the full Pakistan Telecom / YouTube BGP hijack incident.

    Phases:
      Phase 1 (T+0):     Baseline — YouTube legitimately announces 208.65.152.0/22
      Phase 2 (T+0):     Pakistan Telecom announces hijacked /24 to PCCW
      Phase 3 (T+1min):  PCCW propagates hijacked route to global peers
      Phase 4 (T+80min): YouTube fights back with /24 announcement
      Phase 5 (T+91min): YouTube announces /25 sub-prefixes to win routing
      Phase 6 (T+124min):PCCW withdraws Pakistan Telecom's routes
    """
    packets = []
    t = INCIDENT_START  # 18:47 UTC, February 24, 2008

    print("[simulator] Building Pakistan Telecom / YouTube BGP hijack simulation...")
    print(f"[simulator] Incident start: 18:47 UTC, February 24, 2008")

    # ── Phase 1: Baseline BGP session (T-5 minutes) ──────────────────────────
    # YouTube legitimately announces its aggregate 208.65.152.0/22
    print("[simulator] Phase 1: YouTube's legitimate prefix announcements...")

    baseline_time = t - 300   # 5 minutes before hijack

    # YouTube → PCCW: legitimate aggregate announcement
    packets.append(build_bgp_update_announcement(
        src_ip     = ROUTER_YOUTUBE,
        dst_ip     = ROUTER_PCCW,
        prefix     = PREFIX_YOUTUBE_AGGREGATE,
        prefix_len = 22,
        origin_asn = AS_YOUTUBE,
        as_path    = [AS_YOUTUBE],
        next_hop   = ROUTER_YOUTUBE,
        timestamp  = baseline_time,
    ))

    # PCCW → Telia: propagating YouTube's legitimate route
    packets.append(build_bgp_update_announcement(
        src_ip     = ROUTER_PCCW,
        dst_ip     = ROUTER_TELIA,
        prefix     = PREFIX_YOUTUBE_AGGREGATE,
        prefix_len = 22,
        origin_asn = AS_YOUTUBE,
        as_path    = [AS_PCCW_GLOBAL, AS_YOUTUBE],
        next_hop   = ROUTER_PCCW,
        timestamp  = baseline_time + 2,
    ))

    # ── Phase 2: THE HIJACK — Pakistan Telecom announces /24 (T+0) ───────────
    # This is the key packet: AS17557 sends a more-specific /24
    # covering 208.65.153.0-255 (a subset of YouTube's /22)
    print("[simulator] Phase 2: HIJACK — Pakistan Telecom announces 208.65.153.0/24...")
    print(f"            AS{AS_PAKISTAN_TELECOM} → AS{AS_PCCW_GLOBAL}: "
          f"208.65.153.0/24 (more specific than YouTube's /22)")

    # Pakistan Telecom → PCCW: THE HIJACKED ANNOUNCEMENT
    # AS_PATH: [17557] — Pakistan Telecom is the origin
    # This is more specific than YouTube's /22, so BGP longest-prefix-match
    # will route ALL traffic for 208.65.153.0/24 to Pakistan Telecom
    hijack_pkt = build_bgp_update_announcement(
        src_ip     = ROUTER_PAKISTAN,
        dst_ip     = ROUTER_PCCW,
        prefix     = PREFIX_HIJACKED,
        prefix_len = 24,
        origin_asn = AS_PAKISTAN_TELECOM,
        as_path    = [AS_PAKISTAN_TELECOM],
        next_hop   = ROUTER_PAKISTAN,
        timestamp  = t,             # 18:47:00 UTC
    )
    packets.append(hijack_pkt)

    # ── Phase 3: PCCW propagates without validation (T+1 minute) ─────────────
    # Critical failure: PCCW accepts and re-advertises to ALL peers
    # without checking if AS17557 is authorized to announce 208.65.153.0/24
    print("[simulator] Phase 3: PCCW propagates hijacked route globally "
          "(no RPKI validation)...")

    propagation_time = t + 60  # T+1 minute = 18:48 UTC

    # PCCW → Telia: propagating hijacked route
    packets.append(build_bgp_update_announcement(
        src_ip     = ROUTER_PCCW,
        dst_ip     = ROUTER_TELIA,
        prefix     = PREFIX_HIJACKED,
        prefix_len = 24,
        origin_asn = AS_PAKISTAN_TELECOM,
        as_path    = [AS_PCCW_GLOBAL, AS_PAKISTAN_TELECOM],
        next_hop   = ROUTER_PCCW,
        timestamp  = propagation_time,
    ))

    # PCCW → Level3: propagating hijacked route
    packets.append(build_bgp_update_announcement(
        src_ip     = ROUTER_PCCW,
        dst_ip     = ROUTER_LEVEL3,
        prefix     = PREFIX_HIJACKED,
        prefix_len = 24,
        origin_asn = AS_PAKISTAN_TELECOM,
        as_path    = [AS_PCCW_GLOBAL, AS_PAKISTAN_TELECOM],
        next_hop   = ROUTER_PCCW,
        timestamp  = propagation_time + 5,
    ))

    # PCCW → Cogent: propagating hijacked route
    packets.append(build_bgp_update_announcement(
        src_ip     = ROUTER_PCCW,
        dst_ip     = ROUTER_COGENT,
        prefix     = PREFIX_HIJACKED,
        prefix_len = 24,
        origin_asn = AS_PAKISTAN_TELECOM,
        as_path    = [AS_PCCW_GLOBAL, AS_PAKISTAN_TELECOM],
        next_hop   = ROUTER_PCCW,
        timestamp  = propagation_time + 8,
    ))

    # Telia propagates further — the route is now global
    packets.append(build_bgp_update_announcement(
        src_ip     = ROUTER_TELIA,
        dst_ip     = ROUTER_LEVEL3,
        prefix     = PREFIX_HIJACKED,
        prefix_len = 24,
        origin_asn = AS_PAKISTAN_TELECOM,
        as_path    = [AS_TELIA, AS_PCCW_GLOBAL, AS_PAKISTAN_TELECOM],
        next_hop   = ROUTER_TELIA,
        timestamp  = propagation_time + 15,
    ))

    # ── Phase 4: YouTube fights back — announces same /24 (T+80 min) ─────────
    # YouTube announces the exact same /24 to compete with Pakistan Telecom
    # But with equal prefix length, AS path length decides — some traffic
    # still goes to Pakistan Telecom via shorter paths
    print("[simulator] Phase 4: YouTube counter-announces 208.65.153.0/24...")

    youtube_counter_time = t + (80 * 60)  # T+80 minutes = 20:07 UTC

    packets.append(build_bgp_update_announcement(
        src_ip     = ROUTER_YOUTUBE,
        dst_ip     = ROUTER_PCCW,
        prefix     = PREFIX_HIJACKED,
        prefix_len = 24,
        origin_asn = AS_YOUTUBE,
        as_path    = [AS_YOUTUBE],
        next_hop   = ROUTER_YOUTUBE,
        timestamp  = youtube_counter_time,
    ))

    # ── Phase 5: YouTube announces /25 sub-prefixes (T+91 min) ───────────────
    # Longest-prefix-match: /25 beats /24, so YouTube wins routing
    # This is how YouTube finally took back its traffic
    print("[simulator] Phase 5: YouTube announces /25 sub-prefixes to win routing...")
    print(f"            208.65.153.0/25 and 208.65.153.128/25 "
          f"(longest prefix match beats Pakistan's /24)")

    subprefix_time = t + (91 * 60)  # T+91 minutes = 20:18 UTC

    # YouTube announces 208.65.153.0/25 (first half)
    packets.append(build_bgp_update_announcement(
        src_ip     = ROUTER_YOUTUBE,
        dst_ip     = ROUTER_PCCW,
        prefix     = PREFIX_YOUTUBE_COUNTER_A,
        prefix_len = 25,
        origin_asn = AS_YOUTUBE,
        as_path    = [AS_YOUTUBE],
        next_hop   = ROUTER_YOUTUBE,
        timestamp  = subprefix_time,
    ))

    # YouTube announces 208.65.153.128/25 (second half)
    packets.append(build_bgp_update_announcement(
        src_ip     = ROUTER_YOUTUBE,
        dst_ip     = ROUTER_PCCW,
        prefix     = PREFIX_YOUTUBE_COUNTER_B,
        prefix_len = 25,
        origin_asn = AS_YOUTUBE,
        as_path    = [AS_YOUTUBE],
        next_hop   = ROUTER_YOUTUBE,
        timestamp  = subprefix_time + 2,
    ))

    # PCCW propagates YouTube's /25s globally
    packets.append(build_bgp_update_announcement(
        src_ip     = ROUTER_PCCW,
        dst_ip     = ROUTER_TELIA,
        prefix     = PREFIX_YOUTUBE_COUNTER_A,
        prefix_len = 25,
        origin_asn = AS_YOUTUBE,
        as_path    = [AS_PCCW_GLOBAL, AS_YOUTUBE],
        next_hop   = ROUTER_PCCW,
        timestamp  = subprefix_time + 10,
    ))

    # ── Phase 6: PCCW disconnects Pakistan Telecom (T+124 min) ───────────────
    # PCCW finally withdraws all routes from AS17557 at 20:51 UTC
    print("[simulator] Phase 6: PCCW withdraws Pakistan Telecom's hijacked route...")

    withdrawal_time = t + (124 * 60)  # T+124 minutes = 20:51 UTC

    # PCCW withdraws the hijacked /24
    packets.append(build_bgp_withdrawal(
        src_ip     = ROUTER_PCCW,
        dst_ip     = ROUTER_TELIA,
        prefix     = PREFIX_HIJACKED,
        prefix_len = 24,
        timestamp  = withdrawal_time,
    ))

    packets.append(build_bgp_withdrawal(
        src_ip     = ROUTER_PCCW,
        dst_ip     = ROUTER_LEVEL3,
        prefix     = PREFIX_HIJACKED,
        prefix_len = 24,
        timestamp  = withdrawal_time + 3,
    ))

    packets.append(build_bgp_withdrawal(
        src_ip     = ROUTER_PCCW,
        dst_ip     = ROUTER_COGENT,
        prefix     = PREFIX_HIJACKED,
        prefix_len = 24,
        timestamp  = withdrawal_time + 5,
    ))

    print(f"[simulator] Generated {len(packets)} BGP packets covering "
          f"the full incident timeline")
    return packets


# ─────────────────────────────────────────────────────────────────────────────
# VICTIM TRAFFIC SIMULATION
# Simulates user traffic hitting the blackhole during the outage
# ─────────────────────────────────────────────────────────────────────────────

def simulate_victim_traffic() -> list:
    """
    Simulate user HTTP/DNS traffic hitting the YouTube blackhole
    during the hijack period (18:48 - 20:51 UTC).

    Users around the world try to reach YouTube's IPs
    (208.65.153.251, 208.65.153.253, 208.65.153.238).
    Their packets are routed to Pakistan Telecom and blackholed.
    This shows up as connection timeouts and TCP retransmissions.
    """
    packets = []
    t = INCIDENT_START + 120   # 2 minutes after hijack starts

    print("[simulator] Building victim traffic (users hitting the blackhole)...")

    # Simulate ~2 hours of failed connection attempts
    # Users try every 30-60 seconds when YouTube doesn't load
    for minute in range(0, 120, 2):   # every 2 minutes for 2 hours
        ts = t + (minute * 60)

        for user_ip in USER_IPS:
            youtube_ip = random.choice(YOUTUBE_IPS)

            # DNS query for www.youtube.com
            dns_pkt = (
                IP(src=user_ip, dst="8.8.8.8") /
                UDP(sport=random.randint(1024, 65535), dport=53) /
                DNS(rd=1, qd=DNSQR(qname="www.youtube.com", qtype="A"))
            )
            dns_pkt.time = ts
            packets.append(dns_pkt)

            # DNS response (resolves to YouTube's real IP)
            dns_resp = (
                IP(src="8.8.8.8", dst=user_ip) /
                UDP(sport=53, dport=dns_pkt[UDP].sport) /
                DNS(
                    qr=1, aa=0, rd=1, ra=1,
                    qd=DNSQR(qname="www.youtube.com"),
                    an=DNSRR(
                        rrname="www.youtube.com",
                        type="A",
                        rdata=youtube_ip,
                        ttl=300,
                    ),
                )
            )
            dns_resp.time = ts + 0.05
            packets.append(dns_resp)

            # TCP SYN to YouTube IP (goes to Pakistan — blackholed)
            syn_pkt = (
                IP(src=user_ip, dst=youtube_ip, ttl=64) /
                TCP(
                    sport=random.randint(1024, 65535),
                    dport=80,
                    flags="S",
                    seq=random.randint(100000, 999999),
                )
            )
            syn_pkt.time = ts + 0.1
            packets.append(syn_pkt)

            # TCP SYN retransmit (no response from blackhole)
            syn_retry = (
                IP(src=user_ip, dst=youtube_ip, ttl=64) /
                TCP(
                    sport=syn_pkt[TCP].sport,
                    dport=80,
                    flags="S",
                    seq=syn_pkt[TCP].seq,
                )
            )
            syn_retry.time = ts + 3.0    # 3 second retransmit timeout
            packets.append(syn_retry)

            # Second retransmit
            syn_retry2 = syn_retry.copy()
            syn_retry2.time = ts + 9.0   # exponential backoff
            packets.append(syn_retry2)

    print(f"[simulator] Generated {len(packets)} victim traffic packets")
    return packets


# ─────────────────────────────────────────────────────────────────────────────
# BASELINE LEGITIMATE BGP
# Normal BGP traffic before the incident — used as a comparison
# ─────────────────────────────────────────────────────────────────────────────

def simulate_legitimate_bgp_baseline() -> list:
    """
    Simulate normal BGP traffic before the hijack.
    Your BGP hijack detector should NOT flag these.
    Useful for testing that your detector has low false positives.
    """
    packets = []
    t = INCIDENT_START - 600   # 10 minutes before incident

    print("[simulator] Building legitimate BGP baseline (should NOT trigger alerts)...")

    # Google/YouTube legitimate aggregate announcement
    packets.append(build_bgp_update_announcement(
        src_ip     = ROUTER_YOUTUBE,
        dst_ip     = ROUTER_PCCW,
        prefix     = PREFIX_YOUTUBE_AGGREGATE,
        prefix_len = 22,
        origin_asn = AS_YOUTUBE,
        as_path    = [AS_YOUTUBE],
        next_hop   = ROUTER_YOUTUBE,
        timestamp  = t,
    ))

    # Telia announcing its own legitimate prefix
    packets.append(build_bgp_update_announcement(
        src_ip     = ROUTER_TELIA,
        dst_ip     = ROUTER_PCCW,
        prefix     = "213.248.64.0",
        prefix_len = 19,
        origin_asn = AS_TELIA,
        as_path    = [AS_TELIA],
        next_hop   = ROUTER_TELIA,
        timestamp  = t + 30,
    ))

    # Level3 announcing its own legitimate prefix
    packets.append(build_bgp_update_announcement(
        src_ip     = ROUTER_LEVEL3,
        dst_ip     = ROUTER_PCCW,
        prefix     = "4.0.0.0",
        prefix_len = 8,
        origin_asn = AS_LEVEL3,
        as_path    = [AS_LEVEL3],
        next_hop   = ROUTER_LEVEL3,
        timestamp  = t + 60,
    ))

    print(f"[simulator] Generated {len(packets)} legitimate BGP packets")
    return packets


# ─────────────────────────────────────────────────────────────────────────────
# BEACONING SIMULATION (bonus)
# Simulates what a monitoring system or malware might look like during the outage
# ─────────────────────────────────────────────────────────────────────────────

def simulate_monitoring_beaconing() -> list:
    """
    Simulate a network monitoring tool checking YouTube connectivity
    every 60 seconds during the outage. This has regular timing
    (low CV) which the beaconing detector will flag.

    This is intentionally ambiguous — regular monitoring traffic
    looks statistically identical to C2 beaconing. A good analyst
    correlates this with the BGP events to determine it's monitoring,
    not malware. That's the teaching point for your blog article.
    """
    packets = []
    t = INCIDENT_START + 60   # start monitoring 1 minute after hijack

    print("[simulator] Building monitoring beaconing (regular 60s checks)...")

    monitor_ip = "198.51.100.42"   # simulated monitoring server

    for i in range(30):   # 30 checks over 30 minutes
        jitter = random.uniform(-1.5, 1.5)   # ±1.5 second jitter
        ts     = t + (i * 60) + jitter

        # HTTP check to YouTube
        for youtube_ip in YOUTUBE_IPS:
            pkt = (
                IP(src=monitor_ip, dst=youtube_ip) /
                TCP(sport=random.randint(1024, 65535), dport=80, flags="S")
            )
            pkt.time = ts
            packets.append(pkt)

    print(f"[simulator] Generated {len(packets)} monitoring beaconing packets "
          f"(CV will be very low — analyst must determine context)")
    return packets


# ─────────────────────────────────────────────────────────────────────────────
# WRITE PCAP FILES
# ─────────────────────────────────────────────────────────────────────────────

def write_pcap(packets: list, filename: str) -> str:
    """Sort by timestamp and write to PCAP file."""
    packets.sort(key=lambda p: float(p.time) if hasattr(p, "time") else 0)
    path = OUTPUT_DIR / filename
    wrpcap(str(path), packets)
    size_kb = path.stat().st_size / 1024
    print(f"  Written: {path} ({len(packets)} packets, {size_kb:.1f} KB)")
    return str(path)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("=" * 65)
    print("  Pakistan Telecom / YouTube BGP Hijack — PCAP Simulator")
    print("  Incident: February 24, 2008, 18:47 UTC")
    print("=" * 65)
    print()

    # Generate all packet sets
    bgp_packets      = simulate_pakistan_telecom_hijack()
    victim_packets   = simulate_victim_traffic()
    baseline_packets = simulate_legitimate_bgp_baseline()
    beacon_packets   = simulate_monitoring_beaconing()

    print()
    print("[simulator] Writing PCAP files...")

    # Write individual PCAPs
    write_pcap(bgp_packets,      "pakistan_telecom_bgp_hijack.pcap")
    write_pcap(victim_packets,   "youtube_victim_traffic.pcap")
    write_pcap(baseline_packets, "bgp_legitimate_baseline.pcap")
    write_pcap(beacon_packets,   "monitoring_beaconing.pcap")

    # Write combined PCAP with everything
    all_packets = bgp_packets + victim_packets + baseline_packets + beacon_packets
    write_pcap(all_packets, "combined_incident.pcap")

    print()
    print("=" * 65)
    print("DONE — Test PCAPs saved to tests/sample_pcaps/")
    print()
    print("Run your detectors:")
    print()
    print("  # Should flag: BGP hijack by AS17557, RPKI invalid")
    print("  python ai_pcap_analyst/bgp_hijack.py \\")
    print("         tests/sample_pcaps/pakistan_telecom_bgp_hijack.pcap")
    print()
    print("  # Should flag: regular 60s intervals, low CV = beaconing")
    print("  python ai_pcap_analyst/beaconing.py \\")
    print("         tests/sample_pcaps/monitoring_beaconing.pcap")
    print()
    print("  # Should NOT flag: legitimate YouTube /22 announcement")
    print("  python ai_pcap_analyst/bgp_hijack.py \\")
    print("         tests/sample_pcaps/bgp_legitimate_baseline.pcap")
    print()
    print("  # Full pipeline on the complete incident")
    print("  python -c \"")
    print("  from ai_pcap_analyst import analyze")
    print("  import json")
    print("  r = analyze('tests/sample_pcaps/combined_incident.pcap')")
    print("  print(json.dumps(r['summary'], indent=2))")
    print("  \"")
    print()
    print("Blog connection points:")
    print("  1. The BGP hijack PCAP proves your detector catches")
    print("     exactly what happened to YouTube in 2008")
    print("  2. The victim traffic PCAP shows TCP retransmissions")
    print("     that would appear in any affected network's logs")
    print("  3. The beaconing PCAP teaches the key analyst lesson:")
    print("     regular timing = suspicious BUT context matters")
    print("     (monitoring vs C2 requires correlation with BGP events)")
    print("=" * 65)


if __name__ == "__main__":
    main()
