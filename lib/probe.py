#!/usr/bin/env python3
"""
lib/probe.py - Raw Packet Injection & Active Probe Engine for Net-Tap
Part of the Net-Tap Carrier-Grade Passive Monitor & Telemetry Suite.

Provides raw AF_PACKET packet generation for active lab discovery:
- Raw Layer 2 injection with SO_MARK (0x7a9) for selective kernel egress filtering
- Arbitrary 802.1Q single-tagging and 802.1ad (QinQ) double-tagging
- Paced transmission rate-limiting and structured JSONL audit trail logging
"""

import argparse
import datetime
import errno
import ipaddress
import json
import os
import random
import socket
import struct
import sys
import time

try:
    from scapy.all import (
        Ether, Dot1Q, ARP, IP, IPv6, ICMP, UDP, BOOTP, DHCP, TCP,
        ICMPv6ND_NS, ICMPv6ND_RS, Raw
    )
except ImportError as err:
    sys.stderr.write(f"ERROR: Scapy is required for net-tap probe ({err}).\n")
    sys.exit(1)

SO_MARK = 36  # Linux SO_MARK socket option
PROBE_FWMARK = 0x7a9  # 1961 - Net-Tap fwmark identifier


def get_iface_mac(iface: str) -> str:
    """Retrieve physical MAC address of interface from sysfs."""
    try:
        with open(f"/sys/class/net/{iface}/address", "r") as f:
            mac = f.read().strip()
            if mac and len(mac) == 17:
                return mac
    except Exception:
        pass
    return "02:00:00:aa:bb:cc"


def get_link_local_ipv6(iface: str) -> str:
    """Extract or construct link-local IPv6 address for interface."""
    try:
        with open(f"/sys/class/net/{iface}/address", "r") as f:
            mac_str = f.read().strip()
            octets = [int(x, 16) for x in mac_str.split(":")]
            octets[0] ^= 0x02  # Invert universal/local bit
            eui64 = f"{octets[0]:02x}{octets[1]:02x}:{octets[2]:02x}ff:fe{octets[3]:02x}:{octets[4]:02x}{octets[5]:02x}"
            return f"fe80::{eui64}"
    except Exception:
        return "fe80::1"


def wrap_l2(payload, dst_mac: str, src_mac: str, vlan: int = None, qinq: tuple = None):
    """Encapsulate payload in Ethernet, optional 802.1Q, or 802.1ad QinQ."""
    if qinq and len(qinq) == 2:
        s_vid, c_vid = qinq
        return Ether(src=src_mac, dst=dst_mac, type=0x88a8) / Dot1Q(vlan=s_vid) / Dot1Q(vlan=c_vid) / payload
    elif vlan is not None and vlan > 0:
        return Ether(src=src_mac, dst=dst_mac) / Dot1Q(vlan=vlan) / payload
    else:
        return Ether(src=src_mac, dst=dst_mac) / payload


def create_probe_socket(iface: str) -> socket.socket:
    """Open an AF_PACKET raw socket stamped with SO_MARK 0x7a9."""
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sock.setsockopt(socket.SOL_SOCKET, SO_MARK, PROBE_FWMARK)
        sock.bind((iface, 0))
        return sock
    except PermissionError:
        sys.stderr.write("ERROR: Raw socket creation requires root privileges (CAP_NET_RAW).\n")
        sys.exit(1)
    except OSError as e:
        sys.stderr.write(f"ERROR: Failed to bind raw socket on interface '{iface}': {e}\n")
        sys.exit(1)


def parse_args():
    parser = argparse.ArgumentParser(description="Net-Tap Active Probing Engine")
    parser.add_argument("-i", "--interface", required=True, help="Target interface")
    parser.add_argument("-t", "--type", required=True,
                        choices=["arp", "ndp", "dhcp", "pmtu", "tcp_syn"],
                        help="Probe type")
    parser.add_argument("--target", default="", help="Target IP, subnet, or CIDR")
    parser.add_argument("--ports", default="22,80,443", help="Target TCP ports (comma-separated)")
    parser.add_argument("--vlan", type=int, default=None, help="802.1Q VLAN ID (1-4094)")
    parser.add_argument("--qinq", default="", help="QinQ tags as s_tag,c_tag (e.g., 100,200)")
    parser.add_argument("--vlans", default="", help="List of VLANs to probe (comma-separated)")
    parser.add_argument("--rate", type=int, default=50, help="Max packets per second")
    parser.add_argument("--timeout", type=int, default=5, help="Probe timeout in seconds")
    parser.add_argument("--audit-file", required=True, help="Path to JSONL audit log")
    parser.add_argument("--audit-id", default="", help="Audit correlation ID")
    return parser.parse_args()


def log_audit(audit_f, audit_id: str, probe_type: str, target: str, vlan: int, qinq: str,
              src_mac: str, dst_mac: str, seq: int, extra: dict = None):
    """Record an audit trail entry for every transmitted packet."""
    entry = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "audit_id": audit_id,
        "probe_type": probe_type,
        "target": str(target),
        "vlan": vlan,
        "qinq": qinq if qinq else None,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "seq": seq
    }
    if extra:
        entry.update(extra)
    audit_f.write(json.dumps(entry) + "\n")
    audit_f.flush()


def main():
    args = parse_args()
    iface = args.interface
    src_mac = get_iface_mac(iface)
    src_ll = get_link_local_ipv6(iface)
    audit_id = args.audit_id or f"probe_{int(time.time())}_{os.getpid()}"

    # Parse VLAN configurations
    vlan_list = []
    if args.vlans:
        try:
            vlan_list = [int(v.strip()) for v in args.vlans.split(",") if v.strip()]
        except ValueError:
            sys.stderr.write("ERROR: Malformed --vlans list. Expected comma-separated integers.\n")
            sys.exit(1)
    elif args.vlan is not None:
        vlan_list = [args.vlan]
    else:
        vlan_list = [None]  # Untagged

    qinq_tuple = None
    if args.qinq:
        try:
            parts = [int(x.strip()) for x in args.qinq.split(",")]
            if len(parts) == 2:
                qinq_tuple = (parts[0], parts[1])
            else:
                raise ValueError()
        except ValueError:
            sys.stderr.write("ERROR: Malformed --qinq value. Expected 's_tag,c_tag' (e.g. 100,200).\n")
            sys.exit(1)

    # Prepare audit log
    os.makedirs(os.path.dirname(os.path.abspath(args.audit_file)), exist_ok=True)
    audit_f = open(args.audit_file, "a", encoding="utf-8")

    sock = create_probe_socket(iface)
    pacing_interval = 1.0 / max(1, args.rate)
    packet_count = 0
    seq = 0

    try:
        for vid in vlan_list:
            if args.type == "arp":
                target_net = args.target or "192.168.1.0/24"
                try:
                    net = ipaddress.ip_network(target_net, strict=False)
                    hosts = list(net.hosts()) if net.num_addresses > 1 else [net.network_address]
                except ValueError as err:
                    sys.stderr.write(f"ERROR: Invalid IPv4 target '{target_net}': {err}\n")
                    sys.exit(1)

                src_ip = "0.0.0.0"
                for host in hosts:
                    seq += 1
                    arp_req = ARP(op=1, hwsrc=src_mac, psrc=src_ip, pdst=str(host))
                    pkt = wrap_l2(arp_req, dst_mac="ff:ff:ff:ff:ff:ff", src_mac=src_mac, vlan=vid, qinq=qinq_tuple)
                    sock.send(bytes(pkt))
                    log_audit(audit_f, audit_id, "arp", str(host), vid, args.qinq, src_mac, "ff:ff:ff:ff:ff:ff", seq)
                    packet_count += 1
                    time.sleep(pacing_interval)

            elif args.type == "ndp":
                target_str = args.target.strip() if args.target else "ff02::2"
                if target_str in ("all-routers", "ff02::2", ""):
                    # Router Solicitation
                    seq += 1
                    rs = IPv6(src=src_ll, dst="ff02::2") / ICMPv6ND_RS()
                    pkt = wrap_l2(rs, dst_mac="33:33:00:00:00:02", src_mac=src_mac, vlan=vid, qinq=qinq_tuple)
                    sock.send(bytes(pkt))
                    log_audit(audit_f, audit_id, "ndp_rs", "ff02::2", vid, args.qinq, src_mac, "33:33:00:00:00:02", seq)
                    packet_count += 1
                else:
                    # Target Neighbor Solicitation
                    try:
                        tgt_ip = ipaddress.IPv6Address(target_str)
                    except ValueError:
                        sys.stderr.write(f"ERROR: Invalid IPv6 target '{target_str}'.\n")
                        sys.exit(1)
                    # Compute solicited-node multicast address and MAC
                    last_24 = tgt_ip.exploded[-7:].replace(":", "")
                    sn_mcast_ip = f"ff02::1:ff{last_24[:2]}:{last_24[2:]}"
                    sn_mcast_mac = f"33:33:ff:{last_24[:2]}:{last_24[2:4]}:{last_24[4:6]}"
                    seq += 1
                    ns = IPv6(src=src_ll, dst=sn_mcast_ip) / ICMPv6ND_NS(tgt=str(tgt_ip))
                    pkt = wrap_l2(ns, dst_mac=sn_mcast_mac, src_mac=src_mac, vlan=vid, qinq=qinq_tuple)
                    sock.send(bytes(pkt))
                    log_audit(audit_f, audit_id, "ndp_ns", str(tgt_ip), vid, args.qinq, src_mac, sn_mcast_mac, seq)
                    packet_count += 1

            elif args.type == "dhcp":
                # RFC 2131 DHCPDISCOVER broadcast
                seq += 1
                xid = random.randint(1, 0xFFFFFFFF)
                mac_bytes = bytes.fromhex(src_mac.replace(":", "")) + b"\x00" * 10
                bootp_payload = BOOTP(chaddr=mac_bytes, xid=xid, flags=0x8000) / DHCP(options=[("message-type", "discover"), "end"])
                ip_udp = IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / bootp_payload
                pkt = wrap_l2(ip_udp, dst_mac="ff:ff:ff:ff:ff:ff", src_mac=src_mac, vlan=vid, qinq=qinq_tuple)
                sock.send(bytes(pkt))
                log_audit(audit_f, audit_id, "dhcp", "255.255.255.255", vid, args.qinq, src_mac, "ff:ff:ff:ff:ff:ff", seq,
                          {"xid": hex(xid)})
                packet_count += 1
                time.sleep(pacing_interval)

            elif args.type == "pmtu":
                target_ip = args.target or "192.168.1.1"
                sizes = [1500, 2000, 4000, 9000]
                pid = os.getpid() & 0xFFFF
                for sz in sizes:
                    seq += 1
                    header_len = 14 + (4 if vid else 0) + (8 if qinq_tuple else 0) + 20 + 8
                    payload_len = max(0, sz - header_len)
                    icmp_echo = IP(src="192.0.2.2", dst=target_ip, flags="DF") / ICMP(type=8, id=pid, seq=seq) / Raw(b"X" * payload_len)
                    pkt = wrap_l2(icmp_echo, dst_mac="ff:ff:ff:ff:ff:ff", src_mac=src_mac, vlan=vid, qinq=qinq_tuple)
                    try:
                        sock.send(bytes(pkt))
                        log_audit(audit_f, audit_id, "pmtu", target_ip, vid, args.qinq, src_mac, "ff:ff:ff:ff:ff:ff", seq,
                                  {"probed_mtu": sz, "payload_len": payload_len, "status": "transmitted"})
                        packet_count += 1
                    except OSError as err:
                        if getattr(err, "errno", None) in (errno.EMSGSIZE, 90):
                            log_audit(audit_f, audit_id, "pmtu", target_ip, vid, args.qinq, src_mac, "ff:ff:ff:ff:ff:ff", seq,
                                      {"probed_mtu": sz, "payload_len": payload_len, "status": "local_mtu_exceeded"})
                        else:
                            raise
                    time.sleep(pacing_interval)

            elif args.type == "tcp_syn":
                target_ip = args.target or "192.168.1.1"
                port_list = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
                for port in port_list:
                    seq += 1
                    sport = random.randint(30000, 60000)
                    syn_pkt = IP(src="192.0.2.2", dst=target_ip) / TCP(sport=sport, dport=port, flags="S", seq=random.randint(1000, 500000))
                    pkt = wrap_l2(syn_pkt, dst_mac="ff:ff:ff:ff:ff:ff", src_mac=src_mac, vlan=vid, qinq=qinq_tuple)
                    sock.send(bytes(pkt))
                    log_audit(audit_f, audit_id, "tcp_syn", target_ip, vid, args.qinq, src_mac, "ff:ff:ff:ff:ff:ff", seq,
                              {"dport": port, "sport": sport})
                    packet_count += 1
                    time.sleep(pacing_interval)

    finally:
        sock.close()
        audit_f.close()

    print(f"Probe execution finished: {packet_count} packet(s) transmitted across {len(vlan_list)} VLAN profile(s).")


if __name__ == "__main__":
    main()
