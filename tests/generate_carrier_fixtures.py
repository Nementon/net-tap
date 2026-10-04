#!/usr/bin/env python3
"""
generate_carrier_fixtures.py - Carrier-Grade Protocol Fixture Generator for Net-Tap
Generates synthetic enterprise and telecom carrier traffic covering L2 to L7.
"""
import os
import sys

try:
    from scapy.all import (
        Ether, Dot1Q, IP, IPv6, TCP, UDP, ARP, ICMP, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo,
        ICMPv6NDOptSrcLLAddr, ICMPv6NDOptMTU, ICMPv6NDOptRDNSS, ICMPv6ND_NS, ICMPv6ND_NA,
        ICMPv6ND_RS, ICMPv6PacketTooBig, ICMPv6ND_Redirect,
        VXLAN, STP, Dot3, LLC, SNAP, wrpcap, Raw, DNS, DNSQR
    )
    from scapy.layers.tls.all import TLS, TLSClientHello, TLS_Ext_ServerName, ServerName
except ImportError as err:
    sys.stderr.write(f"ERROR: Scapy is required to generate test fixtures ({err}).\n")
    sys.stderr.write("Install scapy via: pip install scapy or apt-get install python3-scapy\n")
    sys.exit(1)

packets = []

# 1. IEEE 802.1Q Single Tag & 802.1ad / Legacy QinQ
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / Dot1Q(vlan=10) / IP(src="10.10.1.1", dst="10.10.1.254") / TCP(sport=54321, dport=80, flags="S"))
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02", type=0x88a8) / Dot1Q(vlan=100) / Dot1Q(vlan=200) / IP(src="10.200.1.5", dst="10.200.1.1") / TCP(sport=5000, dport=443, flags="SA"))
# Legacy QinQ (0x9100)
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02", type=0x9100) / Dot1Q(vlan=300) / Dot1Q(vlan=400) / IP(src="10.200.2.5", dst="10.200.2.1") / TCP(sport=5001, dport=443, flags="A"))
# Legacy QinQ (0x9200)
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02", type=0x9200) / Dot1Q(vlan=600) / Dot1Q(vlan=700) / IP(src="10.200.3.5", dst="10.200.3.1") / TCP(sport=5002, dport=443, flags="S"))

# 1b. Jumbo Frame with 802.1Q Tag (MTU 9000 envelope)
jumbo_payload = b"\xaa" * 8900
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / Dot1Q(vlan=500) / IP(src="10.50.0.1", dst="10.50.0.2") / UDP(sport=9999, dport=9999) / Raw(load=jumbo_payload))

# 2. ARP request & reply
packets.append(Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc="10.10.1.1", pdst="10.10.1.254", hwsrc="02:00:00:00:00:01"))
packets.append(Ether(src="02:00:00:00:00:fe", dst="02:00:00:00:00:01") / ARP(op=2, psrc="10.10.1.254", pdst="10.10.1.1", hwsrc="02:00:00:00:00:fe"))

# 3. Infrastructure: LLDP (0x88cc) & CDP
lldp_raw = b"\x02\x07\x04\x00\x11\x22\x33\x44\x55\x04\x03\x05Gi1/0/1\x06\x02\x00\x78\x00\x00"
packets.append(Ether(src="00:11:22:33:44:55", dst="01:80:c2:00:00:0e", type=0x88cc) / Raw(load=lldp_raw))

cdp_raw = b"\x02\xb4\x00\x00\x00\x01\x00\x0cswitch-01\x00\x02\x00\x09Gi1/0/1"
packets.append(Ether(src="00:11:22:33:44:55", dst="01:00:0c:cc:cc:cc") / LLC(dsap=0xaa, ssap=0xaa, ctrl=3) / SNAP(OUI=0x00000c, code=0x2000) / Raw(load=cdp_raw))

# 4. Spanning Tree Protocol (STP BPDU)
packets.append(Dot3(src="00:11:22:33:44:55", dst="01:80:c2:00:00:00") / LLC(dsap=0x42, ssap=0x42, ctrl=3) / STP())

# 5. Security: IEEE 802.1X EAPOL (0x888e) - EAP-Request/Identity (RFC 3748)
eapol_req = b"\x01\x00\x00\x05\x01\x01\x00\x05\x01"  # Version 1, Type 0 (EAP-Packet), Len 5, Code 1 (Request), Id 1, Len 5, Type 1 (Identity)
packets.append(Ether(src="02:00:00:00:00:aa", dst="01:80:c2:00:00:03", type=0x888e) / Raw(load=eapol_req))

# 6. IPv6 SLAAC Router Advertisement (RFC 4861) with MTU and RDNSS options
ra = (
    Ether(src="02:00:00:00:00:fe", dst="33:33:00:00:00:01") /
    IPv6(src="fe80::1", dst="ff02::1") /
    ICMPv6ND_RA(routerlifetime=1800) /
    ICMPv6NDOptPrefixInfo(prefix="2001:db8:beef::", prefixlen=64, validlifetime=86400, preferredlifetime=14400) /
    ICMPv6NDOptMTU(mtu=1500) /
    ICMPv6NDOptRDNSS(dns=["2001:db8:beef::53"]) /
    ICMPv6NDOptSrcLLAddr(lladdr="02:00:00:00:00:fe")
)
packets.append(ra)

# 6b. IPv6 Router Solicitation
packets.append(Ether(src="02:00:00:00:00:01", dst="33:33:00:00:00:02") / IPv6(src="fe80::100", dst="ff02::2") / ICMPv6ND_RS())

# 7. IPv6 Global host unicast traffic
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:fe") / IPv6(src="2001:db8:beef::100", dst="2001:db8:beef::1") / TCP(sport=49152, dport=443, flags="S"))

# 7b. IPv6 Unique Local Address (ULA) host traffic (RFC 4193)
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:fe") / IPv6(src="fd00:beef:10::100", dst="fd00:beef:10::1") / TCP(sport=50000, dport=80, flags="S"))

# 7c. IPv6 Neighbor Discovery NS/NA & Redirect
packets.append(Ether(src="02:00:00:00:00:01", dst="33:33:ff:00:00:01") / IPv6(src="2001:db8:beef::100", dst="ff02::1:ff00:1") / ICMPv6ND_NS(tgt="2001:db8:beef::1"))
packets.append(Ether(src="02:00:00:00:00:fe", dst="02:00:00:00:00:01") / IPv6(src="2001:db8:beef::1", dst="2001:db8:beef::100") / ICMPv6ND_NA(tgt="2001:db8:beef::1", R=1, S=1, O=1))
packets.append(Ether(src="02:00:00:00:00:fe", dst="02:00:00:00:00:01") / IPv6(src="fe80::1", dst="fe80::100") / ICMPv6ND_Redirect(tgt="fe80::2", dst="2001:db8:beef::2"))

# 7d. IPv6 Packet Too Big (PTB) - PMTUD (RFC 4443)
packets.append(Ether(src="02:00:00:00:00:fe", dst="02:00:00:00:00:01") / IPv6(src="fe80::1", dst="2001:db8:beef::100") / ICMPv6PacketTooBig(mtu=1280) / (IPv6(src="2001:db8:beef::100", dst="2001:db8:beef::1") / UDP(sport=5000, dport=5000)))

# 7e. IPv6 Extension Headers (Hop-by-Hop & Fragmentation)
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:fe") / IPv6(src="2001:db8:beef::200", dst="2001:db8:beef::1", nh=0) / Raw(load=b"\x11\x00\x01\x04\x00\x00\x00\x00") / UDP(sport=5001, dport=5001) / Raw(load=b"hbh_payload"))
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:fe") / IPv6(src="2001:db8:beef::201", dst="2001:db8:beef::1", nh=44) / Raw(load=b"\x11\x00\x00\x00\x00\x00\x12\x34") / UDP(sport=5002, dport=5002) / Raw(load=b"frag_payload"))

# 8. FHRP: VRRPv3 (IP Proto 112) & HSRP (UDP 1985)
vrrp_raw = b"\x31\x01\x64\x01\x00\x00\x0a\x0a\x01\x01"
packets.append(Ether(src="00:00:5e:00:01:01", dst="01:00:5e:00:00:12") / IP(src="10.10.1.254", dst="224.0.0.18", proto=112, ttl=255) / Raw(load=vrrp_raw))

hsrp_raw = b"\x00\x00\x01\x00\x00\x03\x00\x00\x00\x00\x00\x00\x0a\x0a\x01\xfe"
packets.append(Ether(src="00:00:0c:07:ac:01", dst="01:00:5e:00:00:02") / IP(src="10.10.1.253", dst="224.0.0.2") / UDP(sport=1985, dport=1985) / Raw(load=hsrp_raw))

# 9. Telecom & Mobile Tunnels: GTP-U (UDP 2152), GTP-C (UDP 2123), Geneve (UDP 6081), GRE (IP 47), SCTP (IP 132)
gtpu_raw = b"\x30\xff\x00\x28\x00\x00\x00\x01" + b"\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x00\x00\x0a\x00\x00\x01\x0a\x00\x00\x02"
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="192.168.10.1", dst="192.168.10.2") / UDP(sport=2152, dport=2152) / Raw(load=gtpu_raw))

# GTP-U Echo Request (port 2152)
gtpu_echo = b"\x30\x01\x00\x04\x00\x00\x00\x00"
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="192.168.10.1", dst="192.168.10.2") / UDP(sport=2152, dport=2152) / Raw(load=gtpu_echo))

gtpc_raw = b"\x48\x01\x00\x20\x00\x00\x00\x00\x00\x00\x01\x00"
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="192.168.10.1", dst="192.168.10.2") / UDP(sport=2123, dport=2123) / Raw(load=gtpc_raw))

geneve_raw = b"\x00\x00\x65\x58\x00\x12\x34\x00"
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="192.168.10.1", dst="192.168.10.2") / UDP(sport=6081, dport=6081) / Raw(load=geneve_raw))

gre_raw = b"\x00\x00\x08\x00" + b"\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x00\x00\x0a\x00\x00\x01\x0a\x00\x00\x02"
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="192.168.10.1", dst="192.168.10.2", proto=47) / Raw(load=gre_raw))

sctp_raw = b"\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00"
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="192.168.10.1", dst="192.168.10.2", proto=132) / Raw(load=sctp_raw))

# 9b. SCTP over IPv6
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:fe") / IPv6(src="2001:db8:beef::100", dst="2001:db8:beef::1", nh=132) / Raw(load=sctp_raw))

# 9c. SCTP with HEARTBEAT chunk (Chunk Type 4)
sctp_hb = b"\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x08\x01\x02\x03\x04"
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="192.168.10.1", dst="192.168.10.2", proto=132) / Raw(load=sctp_hb))

# 10. Overlay: VXLAN (UDP 4789)
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="172.16.1.1", dst="172.16.1.2") / UDP(sport=50000, dport=4789) / VXLAN(vni=5001) / Ether(src="02:00:00:00:00:11", dst="02:00:00:00:00:22") / IP(src="192.168.100.1", dst="192.168.100.2") / TCP(sport=8080, dport=80, flags="S"))

# 11. TCP Connection Matrix: RST, FIN, PSH, URG, and Zero-Window
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="10.10.1.1", dst="10.10.1.254") / TCP(sport=54321, dport=80, flags="R"))
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="10.10.1.1", dst="10.10.1.254") / TCP(sport=54321, dport=80, flags="FA"))
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="10.10.1.1", dst="10.10.1.254") / TCP(sport=54321, dport=80, flags="PA"))
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="10.10.1.1", dst="10.10.1.254") / TCP(sport=54321, dport=80, flags="U", urgptr=1))
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="10.10.1.1", dst="10.10.1.254") / TCP(sport=54321, dport=80, flags="A", window=0))
# Zero-Window Probe (ACK with window=0 and 1 byte payload)
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="10.10.1.1", dst="10.10.1.254") / TCP(sport=54321, dport=80, flags="A", window=0, seq=100) / Raw(load=b"\x00"))

# 12. DHCP / BOOTP packet with Option 12 Hostname (srv-dc01) and Option 81 FQDN (srv-dc01.corp.internal)
dhcp_fqdn = b"srv-dc01.corp.internal"
opt81 = b"\x51" + bytes([len(dhcp_fqdn) + 3]) + b"\x00\x00\x00" + dhcp_fqdn
dhcp_raw = (
    b"\x01\x01\x06\x00\x12\x34\x56\x78\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\xaa" +
    (b"\x00" * 202) +
    b"\x63\x82\x53\x63\x35\x01\x01\x0c\x08srv-dc01" + opt81 + b"\xff"
)
packets.append(Ether(src="02:00:00:00:00:aa", dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / Raw(load=dhcp_raw))

# 12b. DHCPv6 Solicit (UDP 546 -> 547)
dhcp6_raw = b"\x01\x12\x34\x56\x00\x01\x00\x0e\x00\x01\x00\x01\x20\x00\x00\x00\x02\x00\x00\x00\x00\x01"
packets.append(Ether(src="02:00:00:00:00:01", dst="33:33:00:01:00:02") / IPv6(src="fe80::100", dst="ff02::1:2") / UDP(sport=546, dport=547) / Raw(load=dhcp6_raw))

# 13. DNS Query
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:fe") / IP(src="10.10.1.1", dst="10.10.1.254") / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname="api.internal.network")))

# 14. SNMP v2c GetRequest with community 'public'
snmp_raw = b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x12\x34\x56\x78\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:fe") / IP(src="10.10.1.1", dst="10.10.1.254") / UDP(sport=50001, dport=161) / Raw(load=snmp_raw))

# 15. OSPFv2 Hello (Router ID: 10.255.255.1) and OSPFv2 LS Update (Adv Router: 10.255.255.2)
ospf_hdr = b"\x02\x01\x00\x2c\x0a\xff\xff\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
ospf_body = b"\xff\xff\xff\x00\x00\x0a\x02\x01\x00\x00\x00\x28\x0a\x0a\x01\x01\x00\x00\x00\x00"
packets.append(Ether(src="02:00:00:00:00:01", dst="01:00:5e:00:00:05") / IP(src="10.10.1.1", dst="224.0.0.5", proto=89, ttl=1) / Raw(load=ospf_hdr + ospf_body))

# OSPFv2 Link State Update with LSA Header (Adv Router: 10.255.255.2)
ospf_lsu_hdr = b"\x02\x04\x00\x30\x0a\xff\xff\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
ospf_lsa_hdr = b"\x00\x00\x00\x01" + b"\x00\x0a\x02\x01\x0a\xff\xff\x02\x0a\xff\xff\x02\x80\x00\x00\x01\x00\x00\x00\x1c"
packets.append(Ether(src="02:00:00:00:00:01", dst="01:00:5e:00:00:05") / IP(src="10.10.1.1", dst="224.0.0.5", proto=89, ttl=1) / Raw(load=ospf_lsu_hdr + ospf_lsa_hdr))

# 15b. OSPFv3 Hello over IPv6 (Router ID: 10.255.255.3)
ospfv3_hdr = b"\x03\x01\x00\x24\x0a\xff\xff\x03\x00\x00\x00\x00\x00\x00\x00\x00"
ospfv3_body = b"\x00\x00\x00\x01\x01\x00\x00\x13\x00\x0a\x00\x28\x00\x00\x00\x00\x00\x00\x00\x00"
packets.append(Ether(src="02:00:00:00:00:01", dst="33:33:00:00:00:05") / IPv6(src="fe80::100", dst="ff02::5", nh=89) / Raw(load=ospfv3_hdr + ospfv3_body))

# 16. BGP OPEN (My AS: 65001 with 4-byte AS capability) and BGP UPDATE (AS_PATH: 65002)
# Length: 45 bytes (19 fixed + 10 body + 16 opt params), Opt Parm Len: 16
bgp_open = (
    b"\xff" * 16 +
    b"\x00\x2d\x01\x04\xfd\xe9\x00\xb4\x0a\x0a\x01\x01" +
    b"\x10" +
    b"\x02\x06\x01\x04\x00\x01\x00\x01" +
    b"\x02\x06\x41\x04\x00\x00\xfd\xe9"
)
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:fe") / IP(src="10.10.1.1", dst="10.10.1.254") / TCP(sport=51790, dport=179, flags="PA", seq=1, ack=1) / Raw(load=bgp_open))

bgp_upd = (
    b"\xff" * 16 +
    b"\x00\x2b\x02" +
    b"\x00\x00" +
    b"\x00\x12" +
    b"\x40\x01\x01\x00" +
    b"\x40\x02\x06\x02\x01\x00\x00\xfd\xea" +
    b"\x40\x03\x04\x0a\x0a\x01\x01"
)
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:fe") / IP(src="10.10.1.1", dst="10.10.1.254") / TCP(sport=51790, dport=179, flags="PA", seq=46, ack=1) / Raw(load=bgp_upd))

# 17. TLS 1.2 ClientHello with SNI (login.microsoftonline.com)
tls_pkt = (
    Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:fe") /
    IP(src="10.10.1.1", dst="10.10.1.254") /
    TCP(sport=52000, dport=443, flags="PA") /
    TLS(msg=[TLSClientHello(ext=[TLS_Ext_ServerName(servernames=[ServerName(servername="login.microsoftonline.com")])])])
)
packets.append(tls_pkt)

# 18. MPLS Unicast (Label 1001, Exp 0, S 1, TTL 64)
mpls_hdr = b"\x00\x3e\x91\x40"
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02", type=0x8847) / Raw(load=mpls_hdr) / IP(src="10.50.1.1", dst="10.50.1.2") / TCP(sport=80, dport=80, flags="S"))

# 18b. Multi-label MPLS (Transport Label 1001, BoS=0 + VPN Service Label 2001, BoS=1)
mpls_multi = b"\x00\x3e\x90\x40\x00\x7d\x11\x40"
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02", type=0x8847) / Raw(load=mpls_multi) / IP(src="10.50.2.1", dst="10.50.2.2") / UDP(sport=8080, dport=8080) / Raw(load=b"mpls_vpn_data"))

# 18c. MPLS Downstream Multicast (0x8848)
mpls_mcast_hdr = b"\x00\x3e\x91\x40"
packets.append(Ether(src="02:00:00:00:00:01", dst="01:00:5e:01:01:01", type=0x8848) / Raw(load=mpls_mcast_hdr) / IP(src="10.50.3.1", dst="224.1.1.1") / UDP(sport=9000, dport=9000))

# 19. IS-IS Routing Protocol PDU
isis_raw = b"\x83\x1b\x01\x00\x11\x01\x00\x00"
packets.append(Ether(src="02:00:00:00:00:01", dst="01:80:c2:00:00:14") / LLC(dsap=0xfe, ssap=0xfe, ctrl=3) / Raw(load=isis_raw))

# 20. BFD Control Packet - Single-Hop (UDP 3784) & Multi-Hop (UDP 4784)
bfd_raw = b"\x20\x00\x00\x18\x00\x00\x00\x01\x00\x00\x00\x02\x00\x0f\x42\x40\x00\x0f\x42\x40\x00\x00\x00\x00"
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:fe") / IP(src="10.10.1.1", dst="10.10.1.254") / UDP(sport=49152, dport=3784) / Raw(load=bfd_raw))

bfd_mh_raw = b"\x20\x00\x00\x18\x00\x00\x00\x02\x00\x00\x00\x03\x00\x0f\x42\x40\x00\x0f\x42\x40\x00\x00\x00\x00"
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:fe") / IP(src="10.10.1.1", dst="10.10.1.254") / UDP(sport=49153, dport=4784) / Raw(load=bfd_mh_raw))

# 20b. S-BFD Control Packet (UDP 7784)
sbfd_raw = b"\x20\x00\x00\x18\x00\x00\x00\x04\x00\x00\x00\x05\x00\x0f\x42\x40\x00\x0f\x42\x40\x00\x00\x00\x00"
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:fe") / IP(src="10.10.1.1", dst="10.10.1.254") / UDP(sport=49154, dport=7784) / Raw(load=sbfd_raw))

# 21. Path MTU Discovery (ICMP Type 3 Code 4 - Need to Frag)
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:fe") / IP(src="10.10.1.254", dst="10.10.1.1") / ICMP(type=3, code=4, nexthopmtu=1400) / (IP(src="10.10.1.1", dst="8.8.8.8") / UDP(sport=5000, dport=5000)))

# 22. IPv6 in IPv4 (6in4 / proto 41)
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="10.50.0.1", dst="10.50.0.2", proto=41) / IPv6(src="2001:db8:beef::1", dst="2001:db8:beef::2") / UDP(sport=5000, dport=5000))

# 23. IPv4 in IPv6 (4in6 / next-header 4)
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:fe") / IPv6(src="2001:db8:beef::1", dst="2001:db8:beef::2", nh=4) / IP(src="10.60.0.1", dst="10.60.0.2") / UDP(sport=6000, dport=6000))

# 24. SRv6 Segment Routing Header (Routing Type 4)
srh_bytes = b"\x11\x04\x04\x01\x00\x01\x00\x00" + b"\x20\x01\x0d\xb8\xbe\xef\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" + b"\x20\x01\x0d\xb8\xbe\xef\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:fe") / IPv6(src="2001:db8:beef::100", dst="2001:db8:beef::1", nh=43) / Raw(load=srh_bytes) / UDP(sport=7000, dport=7000) / Raw(load=b"srv6_data"))

# 25. Fragmented IPv4 Packet Train (MF=1 then MF=0)
frag_id = 0xbeef
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:fe") / IP(src="10.10.1.1", dst="10.10.1.254", id=frag_id, flags="MF", frag=0) / UDP(sport=8888, dport=8888, len=108) / Raw(load=b"A"*80))
packets.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:fe") / IP(src="10.10.1.1", dst="10.10.1.254", id=frag_id, flags=0, frag=11) / Raw(load=b"B"*20))

# Resolve output path dynamically
script_dir = os.path.dirname(os.path.abspath(__file__))
output_file = os.path.join(script_dir, "fixtures", "synthetic_carrier_trace.pcap")
os.makedirs(os.path.dirname(output_file), exist_ok=True)
wrpcap(output_file, packets)
print(f"Successfully generated {len(packets)} carrier frames in {output_file}")
