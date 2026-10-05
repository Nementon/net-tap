#!/usr/bin/env python3
"""
lib/probe.py - Raw Packet Injection & Active Probe Engine for Net-Tap
Part of the Net-Tap Carrier-Grade Passive Monitor & Telemetry Suite.

Provides raw AF_PACKET packet generation for active lab discovery:
- Raw Layer 2 injection with SO_MARK (0x7a9 / 1961) for selective kernel egress filtering
- Wire-level watermarking (IPv6 Flow Label 1961, IPv4 IP ID 1961, Echo ID 1961)
- Symmetrical dual-stack IPv4 & IPv6 diagnostics (ARP, NDP, DHCPv4/v6, PMTUD, TCP SYN)
- Arbitrary 802.1Q single-tagging and 802.1ad (QinQ) double-tagging
- Paced transmission rate-limiting, timeout safety, and structured JSONL audit trail logging
"""

import argparse
import datetime
import errno
import fcntl
import ipaddress
import json
import os
import random
import socket
import struct
import subprocess
import sys
import time

try:
    from scapy.all import (
        Ether, Dot1Q, ARP, IP, IPv6, ICMP, UDP, BOOTP, DHCP, TCP,
        ICMPv6ND_NS, ICMPv6ND_RS, ICMPv6NDOptSrcLLAddr, ICMPv6EchoRequest, Raw
    )
except ImportError as err:
    sys.stderr.write(f"ERROR: Scapy is required for net-tap probe ({err}).\n")
    sys.exit(1)

SO_MARK = 36  # Linux SO_MARK socket option
PROBE_FWMARK = 0x7a9  # 1961 - Net-Tap fwmark & wire watermark identifier
SIOCGIFHWADDR = 0x8927  # Linux ioctl to get hardware MAC address


def get_iface_mac(iface: str) -> str:
    """Retrieve physical MAC address of interface using SIOCGIFHWADDR ioctl with sysfs fallback."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            info = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, struct.pack('256s', iface[:15].encode('utf-8')))
            mac = ':'.join(f'{b:02x}' for b in info[18:24])
            if mac and len(mac) == 17 and mac != "00:00:00:00:00:00":
                return mac
    except Exception:
        pass
    try:
        with open(f"/sys/class/net/{iface}/address", "r") as f:
            mac = f.read().strip()
            if mac and len(mac) == 17 and mac != "00:00:00:00:00:00":
                return mac
    except Exception:
        pass
    return "02:00:00:aa:bb:cc"


def get_link_local_ipv6(iface: str) -> str:
    """Query assigned link-local IPv6 address for interface with EUI-64 fallback."""
    try:
        if os.path.exists("/proc/net/if_inet6"):
            with open("/proc/net/if_inet6", "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 6 and parts[5] == iface:
                        raw_ip = parts[0]
                        if raw_ip.lower().startswith("fe80"):
                            chunks = [raw_ip[i:i+4] for i in range(0, 32, 4)]
                            return ipaddress.IPv6Address(":".join(chunks)).compressed
    except Exception:
        pass
    try:
        mac_str = get_iface_mac(iface)
        octets = [int(x, 16) for x in mac_str.split(":")]
        octets[0] ^= 0x02  # Invert universal/local bit
        eui64 = f"{octets[0]:02x}{octets[1]:02x}:{octets[2]:02x}ff:fe{octets[3]:02x}:{octets[4]:02x}{octets[5]:02x}"
        return f"fe80::{eui64}"
    except Exception:
        return "fe80::1"


def resolve_dst_mac(iface: str, target_ip: str, is_v6: bool) -> str:
    """Resolve destination MAC for target IP using kernel neighbor cache with RFC 2464/1112 fallback."""
    try:
        try:
            tgt_obj = ipaddress.ip_address(target_ip)
        except ValueError:
            return "33:33:00:00:00:01" if is_v6 else "ff:ff:ff:ff:ff:ff"

        if is_v6 and isinstance(tgt_obj, ipaddress.IPv6Address):
            if tgt_obj.is_multicast:
                # RFC 2464 Section 7: Ethernet MAC for IPv6 multicast is 33:33 + last 32 bits of IPv6 address
                last4 = tgt_obj.packed[-4:]
                return f"33:33:{last4[0]:02x}:{last4[1]:02x}:{last4[2]:02x}:{last4[3]:02x}"

            # Query kernel neighbor cache safely using argument list
            res = subprocess.run(["ip", "-6", "neigh", "show", "dev", iface, str(tgt_obj)],
                                 capture_output=True, text=True, check=False)
            for line in res.stdout.splitlines():
                parts = line.split()
                if "lladdr" in parts:
                    idx = parts.index("lladdr")
                    if idx + 1 < len(parts):
                        return parts[idx + 1]

            # Solicited-Node Multicast fallback (RFC 4291)
            last_24 = tgt_obj.exploded[-7:].replace(":", "")
            return f"33:33:ff:{last_24[:2]}:{last_24[2:4]}:{last_24[4:6]}"
        elif not is_v6 and isinstance(tgt_obj, ipaddress.IPv4Address):
            if str(tgt_obj) == "255.255.255.255":
                return "ff:ff:ff:ff:ff:ff"
            if tgt_obj.is_multicast:
                # RFC 1112: 01:00:5e: + lower 23 bits of IPv4 address
                octets = tgt_obj.packed
                mac_b = bytes([0x01, 0x00, 0x5e, octets[1] & 0x7f, octets[2], octets[3]])
                return ':'.join(f'{b:02x}' for b in mac_b)

            if os.path.exists("/proc/net/arp"):
                with open("/proc/net/arp", "r") as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 6 and parts[0] == str(tgt_obj) and parts[5] == iface:
                            if parts[3] != "00:00:00:00:00:00":
                                return parts[3]

            res = subprocess.run(["ip", "-4", "neigh", "show", "dev", iface, str(tgt_obj)],
                                 capture_output=True, text=True, check=False)
            for line in res.stdout.splitlines():
                parts = line.split()
                if "lladdr" in parts:
                    idx = parts.index("lladdr")
                    if idx + 1 < len(parts):
                        return parts[idx + 1]
            return "ff:ff:ff:ff:ff:ff"
        else:
            return "33:33:00:00:00:01" if is_v6 else "ff:ff:ff:ff:ff:ff"
    except Exception:
        return "33:33:00:00:00:01" if is_v6 else "ff:ff:ff:ff:ff:ff"


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
                        choices=["arp", "ndp", "dhcp", "dhcp6", "pmtu", "tcp_syn"],
                        help="Probe type")
    parser.add_argument("--target", default="", help="Target IP, subnet, or CIDR")
    parser.add_argument("--ports", default="22,80,443", help="Target TCP ports (comma-separated)")
    parser.add_argument("--vlan", default=None, help="802.1Q VLAN ID, list, or range (1-4094)")
    parser.add_argument("--qinq", default="", help="QinQ tags as s_tag,c_tag (e.g., 100,200)")
    parser.add_argument("--vlans", default="", help="List of VLANs to probe (comma-separated or ranges)")
    parser.add_argument("--rate", type=int, default=50, help="Max packets per second")
    parser.add_argument("--timeout", type=int, default=5, help="Probe timeout in seconds")
    parser.add_argument("--audit-file", required=True, help="Path to JSONL audit log")
    parser.add_argument("--audit-id", default="", help="Audit correlation ID")
    return parser.parse_args()


def parse_vlan_spec(spec: str) -> list:
    """Parse comma-separated VLAN IDs and hyphenated ranges (e.g. '100', '10-20', '10,20,100-105')."""
    vlans = []
    seen = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            sub = [p.strip() for p in part.split("-")]
            if len(sub) != 2:
                raise ValueError(f"Invalid range format '{part}'")
            start, end = int(sub[0]), int(sub[1])
            if start < 1 or end > 4094 or start > end:
                raise ValueError(f"Invalid range '{part}'. Values must be 1-4094 and start <= end.")
            for v in range(start, end + 1):
                if v not in seen:
                    seen.add(v)
                    vlans.append(v)
        else:
            v = int(part)
            if v < 1 or v > 4094:
                raise ValueError(f"VLAN ID {v} out of range 1-4094.")
            if v not in seen:
                seen.add(v)
                vlans.append(v)
    return vlans


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


def main():
    args = parse_args()
    iface = args.interface
    src_mac = get_iface_mac(iface)
    src_ll = get_link_local_ipv6(iface)
    audit_id = args.audit_id or f"probe_{int(time.time())}_{os.getpid()}"

    # Parse VLAN configurations
    vlan_list = []
    spec = args.vlans if args.vlans else (str(args.vlan) if args.vlan is not None else "")
    if spec:
        try:
            vlan_list = parse_vlan_spec(spec)
        except ValueError as err:
            sys.stderr.write(f"ERROR: {err}\n")
            sys.exit(1)
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
    deadline = time.monotonic() + max(1, args.timeout)

    try:
        for vid in vlan_list:
            if time.monotonic() > deadline:
                break

            if args.type == "arp":
                target_net = args.target or "192.168.1.0/24"
                try:
                    net = ipaddress.ip_network(target_net, strict=False)
                    if net.num_addresses > 65536:
                        sys.stderr.write(f"ERROR: Target subnet '{target_net}' is too large ({net.num_addresses} addresses). Max allowed probe CIDR is /16.\n")
                        sys.exit(1)
                    hosts_gen = net.hosts() if net.num_addresses > 1 else iter([net.network_address])
                except ValueError as err:
                    sys.stderr.write(f"ERROR: Invalid IPv4 target '{target_net}': {err}\n")
                    sys.exit(1)

                src_ip = "0.0.0.0"
                for host in hosts_gen:
                    if time.monotonic() > deadline:
                        break
                    seq += 1
                    arp_req = ARP(op=1, hwsrc=src_mac, psrc=src_ip, pdst=str(host))
                    pkt = wrap_l2(arp_req, dst_mac="ff:ff:ff:ff:ff:ff", src_mac=src_mac, vlan=vid, qinq=qinq_tuple)
                    try:
                        sock.send(bytes(pkt))
                    except OSError as err:
                        sys.stderr.write(f"WARNING: send failed on {iface}: {err}\n")
                        break
                    log_audit(audit_f, audit_id, "arp", str(host), vid, args.qinq, src_mac, "ff:ff:ff:ff:ff:ff", seq)
                    packet_count += 1
                    if packet_count % 50 == 0:
                        audit_f.flush()
                    time.sleep(pacing_interval)

            elif args.type == "ndp":
                target_str = args.target.strip() if args.target else "ff02::2"
                if "/" in target_str:
                    try:
                        net = ipaddress.ip_network(target_str, strict=False)
                        if net.prefixlen < 120:
                            offsets = [1, 2, 0xfe, 0xff, 0x100, 0x254]
                            probe_ips = [net.network_address + off for off in offsets]
                        else:
                            probe_ips = list(net.hosts())
                    except ValueError as err:
                        sys.stderr.write(f"ERROR: Invalid IPv6 subnet '{target_str}': {err}\n")
                        sys.exit(1)
                elif target_str in ("all-routers", "ff02::2", ""):
                    probe_ips = ["ff02::2"]
                elif target_str in ("all-nodes", "ff02::1"):
                    probe_ips = ["ff02::1"]
                else:
                    try:
                        probe_ips = [ipaddress.IPv6Address(target_str)]
                    except ValueError:
                        sys.stderr.write(f"ERROR: Invalid IPv6 target '{target_str}'.\n")
                        sys.exit(1)

                for tgt in probe_ips:
                    if time.monotonic() > deadline:
                        break
                    seq += 1
                    tgt_str = str(tgt)
                    if tgt_str == "ff02::2":
                        # RFC 4861 Sections 6.1.1 / 7.1.1: Hop Limit MUST be 255
                        rs = IPv6(src=src_ll, dst="ff02::2", fl=PROBE_FWMARK, hlim=255) / ICMPv6ND_RS() / ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
                        pkt = wrap_l2(rs, dst_mac="33:33:00:00:00:02", src_mac=src_mac, vlan=vid, qinq=qinq_tuple)
                        dst_mac = "33:33:00:00:00:02"
                        ptype = "ndp_rs"
                    elif tgt_str == "ff02::1":
                        echo = IPv6(src=src_ll, dst="ff02::1", fl=PROBE_FWMARK, hlim=255) / ICMPv6EchoRequest(id=PROBE_FWMARK, seq=seq)
                        pkt = wrap_l2(echo, dst_mac="33:33:00:00:00:01", src_mac=src_mac, vlan=vid, qinq=qinq_tuple)
                        dst_mac = "33:33:00:00:00:01"
                        ptype = "ndp_echo"
                    else:
                        last_24 = tgt.exploded[-7:].replace(":", "")
                        sn_mcast_ip = f"ff02::1:ff{last_24[:2]}:{last_24[2:]}"
                        sn_mcast_mac = f"33:33:ff:{last_24[:2]}:{last_24[2:4]}:{last_24[4:6]}"
                        # RFC 4861 Sections 6.1.1 / 7.1.1: Hop Limit MUST be 255
                        ns = IPv6(src=src_ll, dst=sn_mcast_ip, fl=PROBE_FWMARK, hlim=255) / ICMPv6ND_NS(tgt=tgt_str) / ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
                        pkt = wrap_l2(ns, dst_mac=sn_mcast_mac, src_mac=src_mac, vlan=vid, qinq=qinq_tuple)
                        dst_mac = sn_mcast_mac
                        ptype = "ndp_ns"

                    try:
                        sock.send(bytes(pkt))
                    except OSError as err:
                        sys.stderr.write(f"WARNING: send failed on {iface}: {err}\n")
                        break
                    log_audit(audit_f, audit_id, ptype, tgt_str, vid, args.qinq, src_mac, dst_mac, seq)
                    packet_count += 1
                    if packet_count % 50 == 0:
                        audit_f.flush()
                    time.sleep(pacing_interval)

            elif args.type == "dhcp":
                # RFC 2131 DHCPDISCOVER broadcast with IP ID watermark
                seq += 1
                xid = random.randint(1, 0xFFFFFFFF)
                mac_bytes = bytes.fromhex(src_mac.replace(":", "")) + b"\x00" * 10
                bootp_payload = BOOTP(chaddr=mac_bytes, xid=xid, flags=0x8000) / DHCP(options=[("message-type", "discover"), "end"])
                ip_udp = IP(src="0.0.0.0", dst="255.255.255.255", id=PROBE_FWMARK) / UDP(sport=68, dport=67) / bootp_payload
                pkt = wrap_l2(ip_udp, dst_mac="ff:ff:ff:ff:ff:ff", src_mac=src_mac, vlan=vid, qinq=qinq_tuple)
                try:
                    sock.send(bytes(pkt))
                except OSError as err:
                    sys.stderr.write(f"WARNING: send failed on {iface}: {err}\n")
                    break
                log_audit(audit_f, audit_id, "dhcp", "255.255.255.255", vid, args.qinq, src_mac, "ff:ff:ff:ff:ff:ff", seq,
                          {"xid": hex(xid)})
                packet_count += 1
                time.sleep(pacing_interval)

            elif args.type == "dhcp6":
                # RFC 8415 DHCPv6 Solicit (UDP 546 -> 547 to ff02::1:2, MAC 33:33:00:01:00:02)
                seq += 1
                trans_id = random.randint(1, 0xFFFFFF)
                duid = b"\x00\x03\x00\x01" + bytes.fromhex(src_mac.replace(":", ""))
                dhcp6_payload = struct.pack("!B", 1) + struct.pack("!I", trans_id)[1:]  # Type 1 = Solicit
                dhcp6_payload += struct.pack("!HH", 1, len(duid)) + duid  # Opt 1: Client ID
                dhcp6_payload += struct.pack("!HHH", 8, 2, 0)             # Opt 8: Elapsed Time (RFC 8415 Section 21.9)
                dhcp6_payload += struct.pack("!HHIII", 3, 12, 1, 0, 0)   # Opt 3: IA_NA
                dhcp6_payload += struct.pack("!HHIII", 25, 12, 1, 0, 0)  # Opt 25: IA_PD (Prefix Delegation)
                dhcp6_payload += struct.pack("!HH", 14, 0)               # Opt 14: Rapid Commit
                ip_udp = IPv6(src=src_ll, dst="ff02::1:2", fl=PROBE_FWMARK) / UDP(sport=546, dport=547) / Raw(load=dhcp6_payload)
                pkt = wrap_l2(ip_udp, dst_mac="33:33:00:01:00:02", src_mac=src_mac, vlan=vid, qinq=qinq_tuple)
                try:
                    sock.send(bytes(pkt))
                except OSError as err:
                    sys.stderr.write(f"WARNING: send failed on {iface}: {err}\n")
                    break
                log_audit(audit_f, audit_id, "dhcp6_solicit", "ff02::1:2", vid, args.qinq, src_mac, "33:33:00:01:00:02", seq,
                          {"trans_id": hex(trans_id)})
                packet_count += 1
                time.sleep(pacing_interval)

            elif args.type == "pmtu":
                is_v6 = ":" in (args.target or "")
                if is_v6:
                    target_ip = args.target or "2001:db8::1"
                    sizes = [1280, 1420, 1500, 2000, 4000, 9000]
                    dst_mac = resolve_dst_mac(iface, target_ip, True)
                else:
                    target_ip = args.target or "192.168.1.1"
                    sizes = [576, 1280, 1420, 1450, 1492, 1500, 2000, 4000, 9000]
                    dst_mac = resolve_dst_mac(iface, target_ip, False)

                for sz in sizes:
                    if time.monotonic() > deadline:
                        break
                    seq += 1
                    if is_v6:
                        # RFC 8200 IPv6 header is 40 bytes; ICMPv6 Echo is 8 bytes
                        payload_len = max(0, sz - 40 - 8)
                        echo_pkt = IPv6(src=src_ll, dst=target_ip, fl=PROBE_FWMARK) / ICMPv6EchoRequest(id=PROBE_FWMARK, seq=seq, data=b"X" * payload_len)
                    else:
                        # RFC 791 IPv4 header is 20 bytes; ICMP Echo is 8 bytes
                        payload_len = max(0, sz - 20 - 8)
                        echo_pkt = IP(src="192.0.2.2", dst=target_ip, id=PROBE_FWMARK, flags="DF") / ICMP(type=8, id=PROBE_FWMARK, seq=seq) / Raw(b"X" * payload_len)

                    pkt = wrap_l2(echo_pkt, dst_mac=dst_mac, src_mac=src_mac, vlan=vid, qinq=qinq_tuple)
                    try:
                        sock.send(bytes(pkt))
                        log_audit(audit_f, audit_id, "pmtu", target_ip, vid, args.qinq, src_mac, dst_mac, seq,
                                  {"probed_mtu": sz, "payload_len": payload_len, "ip_version": 6 if is_v6 else 4, "status": "transmitted"})
                        packet_count += 1
                    except OSError as err:
                        if getattr(err, "errno", None) in (errno.EMSGSIZE, 90):
                            log_audit(audit_f, audit_id, "pmtu", target_ip, vid, args.qinq, src_mac, dst_mac, seq,
                                       {"probed_mtu": sz, "payload_len": payload_len, "ip_version": 6 if is_v6 else 4, "status": "local_mtu_exceeded"})
                        else:
                            sys.stderr.write(f"WARNING: send failed on {iface}: {err}\n")
                            break
                    time.sleep(pacing_interval)

            elif args.type == "tcp_syn":
                is_v6 = ":" in (args.target or "")
                if is_v6:
                    target_ip = args.target or "2001:db8::1"
                    dst_mac = resolve_dst_mac(iface, target_ip, True)
                else:
                    target_ip = args.target or "192.168.1.1"
                    dst_mac = resolve_dst_mac(iface, target_ip, False)

                raw_ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
                port_list = [p for p in raw_ports if 1 <= p <= 65535]
                if not port_list:
                    port_list = [80]

                for port in port_list:
                    if time.monotonic() > deadline:
                        break
                    seq += 1
                    sport = random.randint(30000, 60000)
                    tcp_layer = TCP(sport=sport, dport=port, flags="S", seq=1961000)
                    if is_v6:
                        syn_pkt = IPv6(src=src_ll, dst=target_ip, fl=PROBE_FWMARK) / tcp_layer
                    else:
                        syn_pkt = IP(src="192.0.2.2", dst=target_ip, id=PROBE_FWMARK) / tcp_layer

                    pkt = wrap_l2(syn_pkt, dst_mac=dst_mac, src_mac=src_mac, vlan=vid, qinq=qinq_tuple)
                    try:
                        sock.send(bytes(pkt))
                    except OSError as err:
                        sys.stderr.write(f"WARNING: send failed on {iface}: {err}\n")
                        break
                    log_audit(audit_f, audit_id, "tcp_syn", target_ip, vid, args.qinq, src_mac, dst_mac, seq,
                              {"dport": port, "sport": sport, "ip_version": 6 if is_v6 else 4})
                    packet_count += 1
                    time.sleep(pacing_interval)

    finally:
        sock.close()
        audit_f.flush()
        audit_f.close()

    print(f"Probe execution finished: {packet_count} packet(s) transmitted across {len(vlan_list)} VLAN profile(s).")


if __name__ == "__main__":
    main()
