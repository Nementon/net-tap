#!/usr/bin/env python3
"""
tests/test_probe_unit.py - Comprehensive Unit & Mock Test Suite for Net-Tap Active Probing Engine
Tests all 10 active probe types, 802.1Q/802.1ad tagging, watermark compliance, and rate limiting
without requiring root privileges or real network interfaces.
"""

import errno
import io
import ipaddress
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# Ensure lib directory is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "lib")))

import probe
from scapy.all import (
    Ether, Dot1Q, ARP, IP, IPv6, ICMP, UDP, BOOTP, DHCP, TCP,
    ICMPv6ND_RS, ICMPv6ND_NA, ICMPv6EchoRequest, DNS
)


class TestProbeUnit(unittest.TestCase):

    def test_parse_vlan_spec(self):
        """Test single, list, range, and combined VLAN specification parsing."""
        self.assertEqual(probe.parse_vlan_spec("100"), [100])
        self.assertEqual(probe.parse_vlan_spec("10,20,30"), [10, 20, 30])
        self.assertEqual(probe.parse_vlan_spec("10-14"), [10, 11, 12, 13, 14])
        self.assertEqual(probe.parse_vlan_spec("10,20-22,50"), [10, 20, 21, 22, 50])

        # Test range deduplication
        self.assertEqual(probe.parse_vlan_spec("10,10,11-12"), [10, 11, 12])

        # Test invalid inputs
        with self.assertRaises(ValueError):
            probe.parse_vlan_spec("0")
        with self.assertRaises(ValueError):
            probe.parse_vlan_spec("4095")
        with self.assertRaises(ValueError):
            probe.parse_vlan_spec("20-10")
        with self.assertRaises(ValueError):
            probe.parse_vlan_spec("abc")

    def test_get_iface_mac_validation(self):
        """Test MAC address retrieval and explicit format validation."""
        valid_mac = "aa:bb:cc:dd:ee:ff"
        self.assertEqual(probe.get_iface_mac("dummy0", valid_mac), valid_mac)

        # Invalid MAC formats should not be accepted as explicit overrides
        invalid_macs = ["notamac", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:ff:11", "zz:bb:cc:dd:ee:ff"]
        for inv in invalid_macs:
            result = probe.get_iface_mac("nonexistent_iface_xyz", inv)
            self.assertEqual(result, "02:00:00:aa:bb:cc")

    def test_wrap_l2_encapsulation(self):
        """Test Ethernet, 802.1Q single-tag, and 802.1ad QinQ encapsulation."""
        dummy_payload = IP(src="192.168.1.1", dst="192.168.1.2") / ICMP()
        src_mac = "02:00:00:00:00:01"
        dst_mac = "02:00:00:00:00:02"

        # 1. Untagged
        pkt_untagged = probe.wrap_l2(dummy_payload, dst_mac=dst_mac, src_mac=src_mac)
        self.assertEqual(pkt_untagged[Ether].src, src_mac)
        self.assertEqual(pkt_untagged[Ether].dst, dst_mac)
        self.assertFalse(pkt_untagged.haslayer(Dot1Q))

        # 2. 802.1Q Single-Tagged
        pkt_vlan = probe.wrap_l2(dummy_payload, dst_mac=dst_mac, src_mac=src_mac, vlan=100, pcp=3, dei=1)
        self.assertTrue(pkt_vlan.haslayer(Dot1Q))
        self.assertEqual(pkt_vlan[Dot1Q].vlan, 100)
        self.assertEqual(pkt_vlan[Dot1Q].prio, 3)
        self.assertEqual(pkt_vlan[Dot1Q].id, 1)

        # 3. 802.1ad QinQ Double-Tagged
        pkt_qinq = probe.wrap_l2(dummy_payload, dst_mac=dst_mac, src_mac=src_mac, qinq=(200, 300), pcp=5, dei=0, qinq_tpid=0x88a8)
        self.assertEqual(pkt_qinq[Ether].type, 0x88a8)
        self.assertTrue(pkt_qinq.haslayer(Dot1Q))
        dot1q_layers = []
        curr = pkt_qinq
        while curr.haslayer(Dot1Q):
            dot1q_layers.append(curr[Dot1Q])
            curr = curr[Dot1Q].payload
        self.assertEqual(len(dot1q_layers), 2)
        self.assertEqual(dot1q_layers[0].vlan, 200)  # Outer S-VLAN
        self.assertEqual(dot1q_layers[1].vlan, 300)  # Inner C-VLAN

    def test_log_audit_formatting(self):
        """Test structured JSONL audit trail logging."""
        out = io.StringIO()
        probe.log_audit(
            out, audit_id="audit_test_123", probe_type="arp",
            target="192.168.1.50", vlan=100, qinq="200,300",
            src_mac="02:00:00:00:00:01", dst_mac="ff:ff:ff:ff:ff:ff",
            seq=1, extra={"custom_field": "val"}
        )
        line = out.getvalue().strip()
        data = json.loads(line)
        self.assertEqual(data["audit_id"], "audit_test_123")
        self.assertEqual(data["probe_type"], "arp")
        self.assertEqual(data["target"], "192.168.1.50")
        self.assertEqual(data["vlan"], 100)
        self.assertEqual(data["qinq"], "200,300")
        self.assertEqual(data["src_mac"], "02:00:00:00:00:01")
        self.assertEqual(data["dst_mac"], "ff:ff:ff:ff:ff:ff")
        self.assertEqual(data["seq"], 1)
        self.assertEqual(data["custom_field"], "val")
        self.assertTrue("timestamp" in data)

    @patch("socket.socket")
    def test_create_probe_socket_watermark(self, mock_socket_cls):
        """Test that create_probe_socket sets SO_MARK 0x7a9 (1961)."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        sock = probe.create_probe_socket("dummy0")
        self.assertEqual(sock, mock_sock)
        mock_socket_cls.assert_called_once_with(probe.socket.AF_PACKET, probe.socket.SOCK_RAW)
        mock_sock.setsockopt.assert_called_once_with(
            probe.socket.SOL_SOCKET, probe.SO_MARK, probe.PROBE_FWMARK
        )
        mock_sock.bind.assert_called_once_with(("dummy0", 0))

    def test_resolve_dst_mac_rfc2464_unicast(self):
        """Verify RFC 2464 compliant fallback for unresolved IPv6 unicast targets."""
        with patch("subprocess.run") as mock_sub:
            # Simulate neighbor cache miss
            mock_sub.return_value = MagicMock(returncode=1, stdout="", splitlines=lambda: [])

            # For a unicast IPv6 target, default fallback should be RFC 2464 compliant all-nodes multicast
            dst_mac = probe.resolve_dst_mac("dummy0", "2001:db8::50", is_v6=True)
            self.assertEqual(dst_mac, "33:33:00:00:00:01")

            # With broadcast mode explicitly enabled, fallback is ff:ff:ff:ff:ff:ff
            dst_mac_bcast = probe.resolve_dst_mac("dummy0", "2001:db8::50", is_v6=True, fallback_mode="broadcast")
            self.assertEqual(dst_mac_bcast, "ff:ff:ff:ff:ff:ff")

            # For an actual multicast IPv6 target, multicast MAC is returned
            mcast_mac = probe.resolve_dst_mac("dummy0", "ff02::1", is_v6=True)
            self.assertEqual(mcast_mac, "33:33:00:00:00:01")

    @patch("probe.create_probe_socket")
    def test_main_arp_scan_execution(self, mock_create_sock):
        """Test ARP probe packet generation with mock socket."""
        mock_sock = MagicMock()
        mock_create_sock.return_value = mock_sock
        captured_packets = []
        mock_sock.send.side_effect = lambda b: captured_packets.append(Ether(b))

        with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
            audit_path = tf.name

        test_args = [
            "probe.py", "-i", "dummy0", "-t", "arp",
            "--target", "192.168.1.0/30",
            "--rate", "500", "--timeout", "2",
            "--audit-file", audit_path, "--audit-id", "test_arp"
        ]
        try:
            with patch.object(sys, "argv", test_args):
                probe.main()

            # /30 has 2 usable host addresses (192.168.1.1, 192.168.1.2)
            self.assertEqual(len(captured_packets), 2)
            for pkt in captured_packets:
                self.assertTrue(pkt.haslayer(ARP))
                self.assertEqual(pkt[ARP].op, 1)  # ARP Who-has
                self.assertEqual(pkt[Ether].dst, "ff:ff:ff:ff:ff:ff")

            with open(audit_path, "r") as f:
                lines = f.readlines()
            self.assertEqual(len(lines), 2)
            first_entry = json.loads(lines[0])
            self.assertEqual(first_entry["probe_type"], "arp")
            self.assertEqual(first_entry["target"], "192.168.1.1")
        finally:
            if os.path.exists(audit_path):
                os.unlink(audit_path)

    @patch("probe.create_probe_socket")
    def test_main_tcp_syn_options_and_isn(self, mock_create_sock):
        """Test TCP SYN probe packet generation with MSS/WScale/SACK options and watermarked ISN."""
        mock_sock = MagicMock()
        mock_create_sock.return_value = mock_sock
        captured_packets = []
        mock_sock.send.side_effect = lambda b: captured_packets.append(Ether(b))

        with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
            audit_path = tf.name

        test_args = [
            "probe.py", "-i", "dummy0", "-t", "tcp_syn",
            "--target", "192.168.1.10", "--ports", "80,443",
            "--rate", "500", "--timeout", "2",
            "--audit-file", audit_path, "--audit-id", "test_tcp"
        ]
        try:
            with patch.object(sys, "argv", test_args):
                probe.main()

            self.assertEqual(len(captured_packets), 2)
            isns = []
            for pkt in captured_packets:
                self.assertTrue(pkt.haslayer(TCP))
                self.assertEqual(pkt[TCP].flags, "S")
                self.assertEqual(pkt[IP].id, probe.PROBE_FWMARK)  # Wire watermark 1961

                # Verify options exist
                opt_names = [opt[0] for opt in pkt[TCP].options]
                self.assertIn("MSS", opt_names)
                self.assertIn("WScale", opt_names)
                self.assertIn("SAckOK", opt_names)
                self.assertIn("Timestamp", opt_names)

                # Check ISN starts near 1961000 and is not static
                isns.append(pkt[TCP].seq)

            # Assert ISNs differ across ports to prevent stateful firewall collisions
            self.assertNotEqual(isns[0], isns[1])
        finally:
            if os.path.exists(audit_path):
                os.unlink(audit_path)

    @patch("probe.create_probe_socket")
    def test_main_ndp_scan_execution(self, mock_create_sock):
        """Test NDP Router Solicitation and Echo probes with RFC 4861 Hop Limit 255."""
        mock_sock = MagicMock()
        mock_create_sock.return_value = mock_sock
        captured_packets = []
        mock_sock.send.side_effect = lambda b: captured_packets.append(Ether(b))

        with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
            audit_path = tf.name

        # 1. Router Solicitation (all-routers)
        test_args = [
            "probe.py", "-i", "dummy0", "-t", "ndp",
            "--target", "all-routers",
            "--rate", "500", "--timeout", "2",
            "--audit-file", audit_path, "--audit-id", "test_ndp_rs"
        ]
        try:
            with patch.object(sys, "argv", test_args):
                probe.main()

            self.assertEqual(len(captured_packets), 1)
            rs_pkt = captured_packets[0]
            self.assertTrue(rs_pkt.haslayer(IPv6))
            self.assertTrue(rs_pkt.haslayer(ICMPv6ND_RS))
            self.assertEqual(rs_pkt[IPv6].hlim, 255)  # RFC 4861 mandate
            self.assertEqual(rs_pkt[IPv6].fl, probe.PROBE_FWMARK)  # Watermark 1961
            self.assertEqual(rs_pkt[Ether].dst, "33:33:00:00:00:02")
        finally:
            if os.path.exists(audit_path):
                os.unlink(audit_path)

    @patch("probe.create_probe_socket")
    def test_main_dhcpv4_and_dhcpv6_probes(self, mock_create_sock):
        """Test RFC 2131 DHCPv4 Discover and RFC 8415 DHCPv6 Solicit frames."""
        mock_sock = MagicMock()
        mock_create_sock.return_value = mock_sock
        captured_packets = []
        mock_sock.send.side_effect = lambda b: captured_packets.append(Ether(b))

        with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
            audit_path = tf.name

        # DHCPv4
        test_args_v4 = [
            "probe.py", "-i", "dummy0", "-t", "dhcp",
            "--rate", "500", "--timeout", "2",
            "--audit-file", audit_path, "--audit-id", "test_dhcpv4"
        ]
        try:
            with patch.object(sys, "argv", test_args_v4):
                probe.main()
            self.assertEqual(len(captured_packets), 1)
            v4_pkt = captured_packets[0]
            self.assertTrue(v4_pkt.haslayer(BOOTP))
            self.assertTrue(v4_pkt.haslayer(DHCP))
            self.assertEqual(v4_pkt[Ether].dst, "ff:ff:ff:ff:ff:ff")
            self.assertEqual(v4_pkt[BOOTP].flags, 0x8000)  # Broadcast flag
        finally:
            if os.path.exists(audit_path):
                os.unlink(audit_path)

        captured_packets.clear()
        # DHCPv6
        test_args_v6 = [
            "probe.py", "-i", "dummy0", "-t", "dhcp6",
            "--rate", "500", "--timeout", "2",
            "--audit-file", audit_path, "--audit-id", "test_dhcpv6"
        ]
        try:
            with patch.object(sys, "argv", test_args_v6):
                probe.main()
            self.assertEqual(len(captured_packets), 1)
            v6_pkt = captured_packets[0]
            self.assertTrue(v6_pkt.haslayer(IPv6))
            self.assertEqual(v6_pkt[IPv6].dst, "ff02::1:2")
            self.assertEqual(v6_pkt[UDP].dport, 547)
            self.assertEqual(v6_pkt[Ether].dst, "33:33:00:01:00:02")
        finally:
            if os.path.exists(audit_path):
                os.unlink(audit_path)

    @patch("probe.create_probe_socket")
    def test_main_eapol_snmp_dns_probes(self, mock_create_sock):
        """Test IEEE 802.1X EAPOL, SNMP sysDescr, and DNS CHAOS TXT queries."""
        mock_sock = MagicMock()
        mock_create_sock.return_value = mock_sock
        captured_packets = []
        mock_sock.send.side_effect = lambda b: captured_packets.append(Ether(b))

        with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
            audit_path = tf.name

        # 1. EAPOL-Start
        test_args_eapol = [
            "probe.py", "-i", "dummy0", "-t", "eapol",
            "--audit-file", audit_path, "--audit-id", "test_eapol"
        ]
        try:
            with patch.object(sys, "argv", test_args_eapol):
                probe.main()
            self.assertEqual(len(captured_packets), 1)
            eapol_pkt = captured_packets[0]
            self.assertEqual(eapol_pkt[Ether].type, 0x888e)
            self.assertEqual(eapol_pkt[Ether].dst, "01:80:c2:00:00:03")
        finally:
            if os.path.exists(audit_path):
                os.unlink(audit_path)

        captured_packets.clear()
        # 2. DNS CHAOS TXT
        test_args_dns = [
            "probe.py", "-i", "dummy0", "-t", "dns", "--target", "192.168.1.1",
            "--audit-file", audit_path, "--audit-id", "test_dns"
        ]
        try:
            with patch.object(sys, "argv", test_args_dns):
                probe.main()
            self.assertEqual(len(captured_packets), 1)
            dns_pkt = captured_packets[0]
            self.assertTrue(dns_pkt.haslayer(DNS))
            self.assertEqual(dns_pkt[DNS].id, probe.PROBE_FWMARK)  # Watermark 1961
            self.assertEqual(dns_pkt[DNS].qd.qclass, 3)  # CHAOS
            self.assertEqual(dns_pkt[DNS].qd.qname, b"version.bind.")
        finally:
            if os.path.exists(audit_path):
                os.unlink(audit_path)

        captured_packets.clear()
        # 3. SNMP sysDescr query
        test_args_snmp = [
            "probe.py", "-i", "dummy0", "-t", "snmp", "--target", "192.168.1.1",
            "--community", "public",
            "--audit-file", audit_path, "--audit-id", "test_snmp"
        ]
        try:
            with patch.object(sys, "argv", test_args_snmp):
                probe.main()
            self.assertEqual(len(captured_packets), 1)
            snmp_pkt = captured_packets[0]
            self.assertTrue(snmp_pkt.haslayer(UDP))
            self.assertEqual(snmp_pkt[UDP].dport, 161)
            self.assertTrue(snmp_pkt.haslayer(probe.snmp.SNMP))
            self.assertEqual(snmp_pkt[probe.snmp.SNMP].community, b"public")
            self.assertEqual(snmp_pkt[probe.snmp.SNMP].PDU.id, probe.PROBE_FWMARK)
        finally:
            if os.path.exists(audit_path):
                os.unlink(audit_path)

    @patch("probe.create_probe_socket")
    def test_main_nbns_probe(self, mock_create_sock):
        """Test NetBIOS Name Service (NBNS) node status probe on UDP port 137."""
        mock_sock = MagicMock()
        mock_create_sock.return_value = mock_sock
        captured_packets = []
        mock_sock.send.side_effect = lambda b: captured_packets.append(Ether(b))

        with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
            audit_path = tf.name

        test_args_nbns = [
            "probe.py", "-i", "dummy0", "-t", "nbns", "--target", "192.168.1.50",
            "--audit-file", audit_path, "--audit-id", "test_nbns"
        ]
        try:
            with patch.object(sys, "argv", test_args_nbns):
                probe.main()
            self.assertEqual(len(captured_packets), 1)
            nbns_pkt = captured_packets[0]
            self.assertTrue(nbns_pkt.haslayer(UDP))
            self.assertEqual(nbns_pkt[UDP].dport, 137)
            # NetBIOS transaction ID is watermarked with 1961
            payload = bytes(nbns_pkt[UDP].payload)
            trans_id = struct.unpack("!H", payload[:2])[0]
            self.assertEqual(trans_id, probe.PROBE_FWMARK)
        finally:
            if os.path.exists(audit_path):
                os.unlink(audit_path)

    @patch("probe.create_probe_socket")
    def test_main_pmtu_ipv4_and_ipv6_probes(self, mock_create_sock):
        """Test IPv4 PMTU (DF bit set, ID 1961) and IPv6 PMTU (Flow Label 1961, stepped sizes)."""
        mock_sock = MagicMock()
        mock_create_sock.return_value = mock_sock
        captured_packets = []
        mock_sock.send.side_effect = lambda b: captured_packets.append(Ether(b))

        with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
            audit_path = tf.name

        # 1. IPv4 PMTU
        test_args_v4 = [
            "probe.py", "-i", "dummy0", "-t", "pmtu", "--target", "192.168.1.1",
            "--rate", "500", "--timeout", "2",
            "--audit-file", audit_path, "--audit-id", "test_pmtu_v4"
        ]
        try:
            with patch.object(sys, "argv", test_args_v4):
                probe.main()
            self.assertEqual(len(captured_packets), 9)  # 9 stepped sizes
            for pkt in captured_packets:
                self.assertTrue(pkt.haslayer(IP))
                self.assertTrue(pkt.haslayer(ICMP))
                self.assertEqual(pkt[IP].id, probe.PROBE_FWMARK)  # Watermark 1961
                self.assertEqual(pkt[IP].flags, "DF")  # DF bit set for PMTUD (RFC 1191)
                self.assertEqual(pkt[ICMP].id, probe.PROBE_FWMARK)  # Watermark 1961
        finally:
            if os.path.exists(audit_path):
                os.unlink(audit_path)

        captured_packets.clear()
        # 2. IPv6 PMTU
        test_args_v6 = [
            "probe.py", "-i", "dummy0", "-t", "pmtu", "--target", "2001:db8::1",
            "--rate", "500", "--timeout", "2",
            "--audit-file", audit_path, "--audit-id", "test_pmtu_v6"
        ]
        try:
            with patch.object(sys, "argv", test_args_v6):
                probe.main()
            self.assertEqual(len(captured_packets), 8)  # 8 stepped sizes (1280+)
            for pkt in captured_packets:
                self.assertTrue(pkt.haslayer(IPv6))
                self.assertTrue(pkt.haslayer(probe.ICMPv6EchoRequest))
                self.assertEqual(pkt[IPv6].fl, probe.PROBE_FWMARK)  # Flow label watermark 1961
                self.assertEqual(pkt[probe.ICMPv6EchoRequest].id, probe.PROBE_FWMARK)  # Watermark 1961
        finally:
            if os.path.exists(audit_path):
                os.unlink(audit_path)

    def test_source_ip_resolution(self):
        """Test IPv4 and IPv6 source resolution with explicit overrides and on-subnet derivations."""
        # IPv4 Explicit override
        self.assertEqual(probe.resolve_source_ip("dummy0", "192.168.1.1", explicit_src="10.0.0.1"), "10.0.0.1")
        # IPv4 On-subnet derivation for gateway target
        derived = probe.resolve_source_ip("dummy0", "192.168.50.1")
        self.assertEqual(derived, "192.168.50.253")
        # IPv6 Explicit override
        self.assertEqual(probe.resolve_source_ipv6("dummy0", "2001:db8::1", explicit_src="2001:db8::99"), "2001:db8::99")

    def test_get_iface_mac_fallback_sysfs_and_default(self):
        """Test sysfs address file reading and default fallback when ioctl fails."""
        with patch("socket.socket") as mock_sock_cls, \
             patch("builtins.open", unittest.mock.mock_open(read_data="00:11:22:33:44:55\n")):
            mock_sock_cls.side_effect = OSError("ioctl failed")
            mac = probe.get_iface_mac("eth_test")
            self.assertEqual(mac, "00:11:22:33:44:55")

        with patch("socket.socket") as mock_sock_cls, \
             patch("builtins.open", side_effect=OSError("no sysfs")):
            mock_sock_cls.side_effect = OSError("ioctl failed")
            mac = probe.get_iface_mac("eth_test")
            self.assertEqual(mac, "02:00:00:aa:bb:cc")

    def test_get_link_local_ipv6_variants(self):
        """Test procfs if_inet6 parsing, EUI-64 derivation, and fallback."""
        inet6_data = "fe80000000000000020000fffeaabbcc 02 40 20 80 eth0\n"
        with patch("os.path.exists", return_value=True), \
             patch("builtins.open", unittest.mock.mock_open(read_data=inet6_data)):
            ll = probe.get_link_local_ipv6("eth0")
            self.assertEqual(ll, str(ipaddress.IPv6Address("fe80::200:ff:feaa:bbcc")))

        with patch("os.path.exists", return_value=False), \
             patch("probe.get_iface_mac", return_value="00:11:22:33:44:55"):
            ll = probe.get_link_local_ipv6("eth0")
            self.assertTrue(ll.startswith("fe80::"))
            self.assertIn("ff:fe", ll)

        with patch("os.path.exists", return_value=False), \
             patch("probe.get_iface_mac", side_effect=Exception("error")):
            ll = probe.get_link_local_ipv6("eth0")
            self.assertEqual(ll, "fe80::1")

    def test_resolve_source_ip_variants(self):
        """Test IP interface parsing, testnet 192.0.2.x, and gateway target derivations."""
        ip_addr_out = "    inet 10.10.10.5/24 brd 10.10.10.255 scope global eth0"
        with patch("subprocess.run") as mock_sub:
            mock_sub.return_value = MagicMock(stdout=ip_addr_out)
            self.assertEqual(probe.resolve_source_ip("eth0"), "10.10.10.5")

        with patch("subprocess.run", side_effect=Exception("no ip command")):
            self.assertEqual(probe.resolve_source_ip("eth0", target_ip="192.0.2.1"), "192.0.2.2")
            self.assertEqual(probe.resolve_source_ip("eth0", target_ip="192.0.2.2"), "192.0.2.1")
            self.assertEqual(probe.resolve_source_ip("eth0", target_ip="192.168.1.254"), "192.168.1.2")
            self.assertEqual(probe.resolve_source_ip("eth0", target_ip="192.168.1.2"), "192.168.1.3")
            self.assertEqual(probe.resolve_source_ip("eth0", target_ip="192.168.1.10"), "192.168.1.2")
            self.assertEqual(probe.resolve_source_ip("eth0", target_ip=""), "192.0.2.2")

    def test_resolve_source_ipv6_variants(self):
        """Test IPv6 global address interface lookup and link-local fallback."""
        ip6_addr_out = "    inet6 2001:db8:acad::1/64 scope global dynamic"
        with patch("subprocess.run") as mock_sub:
            mock_sub.return_value = MagicMock(stdout=ip6_addr_out)
            src = probe.resolve_source_ipv6("eth0", target_ip="2001:db8:acad::100")
            self.assertEqual(src, "2001:db8:acad::1")

        with patch("subprocess.run", side_effect=Exception("error")), \
             patch("probe.get_link_local_ipv6", return_value="fe80::1"):
            src = probe.resolve_source_ipv6("eth0", target_ip="fe80::50")
            self.assertEqual(src, "fe80::1")

    def test_resolve_dst_mac_cache_and_protocols(self):
        """Test destination MAC resolution caching, IPv4 mcast/bcast, route lookup, proc arp, and preflight."""
        self.assertEqual(probe.resolve_dst_mac("eth0", "255.255.255.255", is_v6=False), "ff:ff:ff:ff:ff:ff")
        self.assertEqual(probe.resolve_dst_mac("eth0", "224.0.0.5", is_v6=False), "01:00:5e:00:00:05")
        self.assertEqual(probe.resolve_dst_mac("eth0", "ff02::2", is_v6=True), "33:33:00:00:00:02")

        probe.MAC_RESOLUTION_CACHE[("dummy_cache", "10.0.0.1", False, None, None, 0, 0, 0x88a8, "multicast")] = "11:22:33:44:55:66"
        self.assertEqual(probe.resolve_dst_mac("dummy_cache", "10.0.0.1", is_v6=False), "11:22:33:44:55:66")

        self.assertEqual(probe.resolve_dst_mac("eth0", "invalid_ip", is_v6=False), "ff:ff:ff:ff:ff:ff")
        self.assertEqual(probe.resolve_dst_mac("eth0", "invalid_ip", is_v6=True), "33:33:00:00:00:01")

        with patch("subprocess.run") as mock_sub:
            mock_sub.side_effect = [
                MagicMock(returncode=0, stdout="8.8.8.8 via 192.168.1.1 dev eth0 src 192.168.1.50\n"),
                MagicMock(returncode=0, stdout="192.168.1.1 dev eth0 lladdr 00:aa:bb:cc:dd:ee REACHABLE\n")
            ]
            gw_mac = probe.resolve_dst_mac("eth_route_test", "8.8.8.8", is_v6=False)
            self.assertEqual(gw_mac, "00:aa:bb:cc:dd:ee")

        proc_arp = "IP address       HW type     Flags       HW address            Mask     Device\n192.168.1.200    0x1         0x2         00:50:56:c0:00:08     *        eth_arp\n"
        with patch("subprocess.run", return_value=MagicMock(returncode=1, stdout="")), \
             patch("os.path.exists", return_value=True), \
             patch("builtins.open", unittest.mock.mock_open(read_data=proc_arp)):
            mac = probe.resolve_dst_mac("eth_arp", "192.168.1.200", is_v6=False)
            self.assertEqual(mac, "00:50:56:c0:00:08")

        mock_raw_sock = MagicMock()
        mock_raw_sock.__enter__.return_value = mock_raw_sock
        na_reply = Ether(src="aa:bb:cc:11:22:33", dst="02:00:00:aa:bb:cc") / IPv6(src="2001:db8::9", dst="fe80::1") / ICMPv6ND_NA(tgt="2001:db8::9")
        mock_raw_sock.recv.return_value = bytes(na_reply)

        with patch("subprocess.run", return_value=MagicMock(returncode=1, stdout="")), \
             patch("socket.socket", return_value=mock_raw_sock):
            resolved = probe.resolve_dst_mac(
                "eth_preflight", "2001:db8::9", is_v6=True,
                src_mac="02:00:00:aa:bb:cc", src_ip="fe80::1"
            )
            self.assertEqual(resolved, "aa:bb:cc:11:22:33")

        mock_raw_sock_arp = MagicMock()
        mock_raw_sock_arp.__enter__.return_value = mock_raw_sock_arp
        arp_reply = Ether(src="bb:cc:dd:22:33:44", dst="02:00:00:aa:bb:cc") / ARP(op=2, hwsrc="bb:cc:dd:22:33:44", psrc="192.168.99.50")
        mock_raw_sock_arp.recv.return_value = bytes(arp_reply)

        with patch("subprocess.run", return_value=MagicMock(returncode=1, stdout="")), \
             patch("socket.socket", return_value=mock_raw_sock_arp):
            resolved_arp = probe.resolve_dst_mac(
                "eth_preflight_arp", "192.168.99.50", is_v6=False,
                src_mac="02:00:00:aa:bb:cc", src_ip="192.168.99.1"
            )
            self.assertEqual(resolved_arp, "bb:cc:dd:22:33:44")

    def test_create_probe_socket_permission_and_os_error(self):
        """Test create_probe_socket error handling for PermissionError and OSError."""
        with patch("sys.stderr", new_callable=io.StringIO):
            with patch("socket.socket", side_effect=PermissionError("Permission denied")):
                with self.assertRaises(SystemExit) as cm:
                    probe.create_probe_socket("eth0")
                self.assertEqual(cm.exception.code, 1)

            with patch("socket.socket", side_effect=OSError("Device not configured")):
                with self.assertRaises(SystemExit) as cm:
                    probe.create_probe_socket("eth0")
                self.assertEqual(cm.exception.code, 1)

    @patch("probe.create_probe_socket")
    def test_main_tcp_syn_ipv6(self, mock_create_sock):
        """Test IPv6 TCP SYN probe transmission."""
        mock_sock = MagicMock()
        mock_create_sock.return_value = mock_sock
        captured_packets = []
        mock_sock.send.side_effect = lambda b: captured_packets.append(Ether(b))

        with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
            audit_path = tf.name

        test_args = [
            "probe.py", "-i", "dummy0", "-t", "tcp_syn",
            "--target", "2001:db8::10", "--ports", "8080",
            "--rate", "500", "--timeout", "2",
            "--audit-file", audit_path, "--audit-id", "test_tcp_v6"
        ]
        try:
            with patch.object(sys, "argv", test_args):
                probe.main()
            self.assertEqual(len(captured_packets), 1)
            pkt = captured_packets[0]
            self.assertTrue(pkt.haslayer(IPv6))
            self.assertTrue(pkt.haslayer(TCP))
            self.assertEqual(pkt[TCP].dport, 8080)
            self.assertEqual(pkt[IPv6].fl, probe.PROBE_FWMARK)
        finally:
            if os.path.exists(audit_path):
                os.unlink(audit_path)

    @patch("probe.create_probe_socket")
    def test_main_pmtu_emsgsize_handling(self, mock_create_sock):
        """Test PMTU probe logging of local_mtu_exceeded when EMSGSIZE is raised."""
        mock_sock = MagicMock()
        mock_create_sock.return_value = mock_sock

        def fake_send(b):
            err = OSError(errno.EMSGSIZE, "Message too long")
            err.errno = errno.EMSGSIZE
            raise err

        mock_sock.send.side_effect = fake_send

        with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
            audit_path = tf.name

        test_args = [
            "probe.py", "-i", "dummy0", "-t", "pmtu",
            "--target", "192.168.1.1",
            "--rate", "500", "--timeout", "2",
            "--audit-file", audit_path, "--audit-id", "test_pmtu_emsgsize"
        ]
        try:
            with patch.object(sys, "argv", test_args):
                probe.main()

            with open(audit_path, "r") as f:
                lines = f.readlines()
            self.assertGreater(len(lines), 0)
            first_entry = json.loads(lines[0])
            self.assertEqual(first_entry["status"], "local_mtu_exceeded")
        finally:
            if os.path.exists(audit_path):
                os.unlink(audit_path)

    @patch("probe.create_probe_socket")
    def test_main_qinq_pcp_dei_attributes(self, mock_create_sock):
        """Test active probe execution with QinQ tags, 802.1p PCP, and DEI bits."""
        mock_sock = MagicMock()
        mock_create_sock.return_value = mock_sock
        captured_packets = []
        mock_sock.send.side_effect = lambda b: captured_packets.append(Ether(b))

        with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
            audit_path = tf.name

        test_args = [
            "probe.py", "-i", "dummy0", "-t", "arp",
            "--target", "192.168.1.1",
            "--qinq", "100,200", "--pcp", "5", "--dei", "1",
            "--qinq-tpid", "0x9100",
            "--audit-file", audit_path, "--audit-id", "test_qinq_pcp"
        ]
        try:
            with patch.object(sys, "argv", test_args):
                probe.main()

            self.assertEqual(len(captured_packets), 1)
            pkt = captured_packets[0]
            self.assertEqual(pkt[Ether].type, 0x9100)
            self.assertTrue(pkt.haslayer(Dot1Q))
            outer = pkt[Dot1Q]
            self.assertEqual(outer.vlan, 100)
            self.assertEqual(outer.prio, 5)
            inner = outer.payload[Dot1Q]
            self.assertEqual(inner.vlan, 200)
            self.assertEqual(inner.prio, 5)
            self.assertEqual(inner.id, 1)
        finally:
            if os.path.exists(audit_path):
                os.unlink(audit_path)

    @patch("probe.create_probe_socket")
    def test_main_ndp_subnet_and_all_nodes(self, mock_create_sock):
        """Test NDP scanning against /124 subnet and all-nodes target."""
        mock_sock = MagicMock()
        mock_create_sock.return_value = mock_sock
        captured_packets = []
        mock_sock.send.side_effect = lambda b: captured_packets.append(Ether(b))

        with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
            audit_path = tf.name

        # 1. /124 subnet
        test_args_sub = [
            "probe.py", "-i", "dummy0", "-t", "ndp",
            "--target", "2001:db8::/124",
            "--rate", "500", "--timeout", "2",
            "--audit-file", audit_path, "--audit-id", "test_ndp_sub"
        ]
        try:
            with patch.object(sys, "argv", test_args_sub):
                probe.main()
            self.assertGreater(len(captured_packets), 1)
        finally:
            if os.path.exists(audit_path):
                os.unlink(audit_path)

        captured_packets.clear()
        # 2. all-nodes
        test_args_nodes = [
            "probe.py", "-i", "dummy0", "-t", "ndp",
            "--target", "all-nodes",
            "--rate", "500", "--timeout", "2",
            "--audit-file", audit_path, "--audit-id", "test_ndp_nodes"
        ]
        try:
            with patch.object(sys, "argv", test_args_nodes):
                probe.main()
            self.assertEqual(len(captured_packets), 1)
            pkt = captured_packets[0]
            self.assertTrue(pkt.haslayer(ICMPv6EchoRequest))
            self.assertEqual(pkt[Ether].dst, "33:33:00:00:00:01")
        finally:
            if os.path.exists(audit_path):
                os.unlink(audit_path)

    def test_main_validation_errors(self):
        """Test CLI validation exit codes on malformed inputs."""
        with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
            audit_path = tf.name

        error_cases = [
            ["probe.py", "-i", "dummy0", "-t", "arp", "--vlans", "9999", "--audit-file", audit_path],
            ["probe.py", "-i", "dummy0", "-t", "arp", "--qinq", "invalid", "--audit-file", audit_path],
            ["probe.py", "-i", "dummy0", "-t", "arp", "--target", "2001:db8::1", "--audit-file", audit_path],
            ["probe.py", "-i", "dummy0", "-t", "arp", "--target", "10.0.0.0/8", "--audit-file", audit_path],
            ["probe.py", "-i", "dummy0", "-t", "ndp", "--target", "192.168.1.1", "--audit-file", audit_path],
            ["probe.py", "-i", "dummy0", "-t", "nbns", "--target", "2001:db8::1", "--audit-file", audit_path],
            ["probe.py", "-i", "dummy0", "-t", "pmtu", "--target", "invalid_ip", "--audit-file", audit_path],
            ["probe.py", "-i", "dummy0", "-t", "tcp_syn", "--target", "invalid_ip", "--audit-file", audit_path],
            ["probe.py", "-i", "dummy0", "-t", "snmp", "--target", "invalid_ip", "--audit-file", audit_path],
            ["probe.py", "-i", "dummy0", "-t", "dns", "--target", "invalid_ip", "--audit-file", audit_path],
        ]

        try:
            for args in error_cases:
                with patch.object(sys, "argv", args), \
                     patch("sys.stderr.write"):
                    with self.assertRaises(SystemExit) as cm:
                        probe.main()
                    self.assertEqual(cm.exception.code, 1)
        finally:
            if os.path.exists(audit_path):
                os.unlink(audit_path)


    def test_get_iface_mac_ioctl_success(self):
        """Test successful ioctl SIOCGIFHWADDR query."""
        mock_sock = MagicMock()
        mock_sock.__enter__.return_value = mock_sock
        fake_info = b"\x00" * 18 + b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x00" * 200
        with patch("socket.socket", return_value=mock_sock), \
             patch("fcntl.ioctl", return_value=fake_info):
            mac = probe.get_iface_mac("eth_test")
            self.assertEqual(mac, "aa:bb:cc:dd:ee:ff")

    def test_resolve_dst_mac_ipv6_neigh(self):
        """Test destination MAC resolution via ip -6 neigh show."""
        with patch("subprocess.run") as mock_sub:
            mock_sub.side_effect = [
                MagicMock(returncode=0, stdout="2001:db8::1 dev eth_test_v6 src 2001:db8::2\n"),
                MagicMock(returncode=0, stdout="2001:db8::1 dev eth_test_v6 lladdr 33:44:55:66:77:88 REACHABLE\n")
            ]
            mac = probe.resolve_dst_mac("eth_test_v6", "2001:db8::1", is_v6=True)
            self.assertEqual(mac, "33:44:55:66:77:88")

    def test_parse_vlan_spec_extended_edges(self):
        """Test whitespace padding and malformed range tokens."""
        self.assertEqual(probe.parse_vlan_spec(" , 10, 20 , "), [10, 20])
        with self.assertRaises(ValueError):
            probe.parse_vlan_spec("10-20-30")

    @patch("probe.create_probe_socket")
    def test_main_snmp_and_dns_ipv6(self, mock_create_sock):
        """Test SNMP and DNS probes targeting IPv6 destination."""
        mock_sock = MagicMock()
        mock_create_sock.return_value = mock_sock
        captured_packets = []
        mock_sock.send.side_effect = lambda b: captured_packets.append(Ether(b))

        with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
            audit_path = tf.name

        test_args_snmp = [
            "probe.py", "-i", "dummy0", "-t", "snmp",
            "--target", "2001:db8::1",
            "--audit-file", audit_path, "--audit-id", "test_snmp_v6"
        ]
        try:
            with patch.object(sys, "argv", test_args_snmp):
                probe.main()
            self.assertEqual(len(captured_packets), 1)
            pkt = captured_packets[0]
            self.assertTrue(pkt.haslayer(IPv6))
            self.assertTrue(pkt.haslayer(UDP))
            self.assertEqual(pkt[UDP].dport, 161)
        finally:
            if os.path.exists(audit_path):
                os.unlink(audit_path)

        captured_packets.clear()
        test_args_dns = [
            "probe.py", "-i", "dummy0", "-t", "dns",
            "--target", "2001:db8::1",
            "--audit-file", audit_path, "--audit-id", "test_dns_v6"
        ]
        try:
            with patch.object(sys, "argv", test_args_dns):
                probe.main()
            self.assertEqual(len(captured_packets), 1)
            pkt = captured_packets[0]
            self.assertTrue(pkt.haslayer(IPv6))
            self.assertTrue(pkt.haslayer(UDP))
            self.assertEqual(pkt[UDP].dport, 53)
        finally:
            if os.path.exists(audit_path):
                os.unlink(audit_path)

    @patch("probe.create_probe_socket")
    def test_main_ndp_large_prefix(self, mock_create_sock):
        """Test NDP probing on /64 subnet stepping through offsets."""
        mock_sock = MagicMock()
        mock_create_sock.return_value = mock_sock
        captured_packets = []
        mock_sock.send.side_effect = lambda b: captured_packets.append(Ether(b))

        with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
            audit_path = tf.name

        test_args = [
            "probe.py", "-i", "dummy0", "-t", "ndp",
            "--target", "2001:db8:beef::/64",
            "--rate", "500", "--timeout", "2",
            "--audit-file", audit_path, "--audit-id", "test_ndp_64"
        ]
        try:
            with patch.object(sys, "argv", test_args):
                probe.main()
            self.assertEqual(len(captured_packets), 6)
        finally:
            if os.path.exists(audit_path):
                os.unlink(audit_path)

    @patch("probe.create_probe_socket")
    def test_main_send_error_graceful_handling(self, mock_create_sock):
        """Test that OSError during packet transmission is handled without unhandled exception."""
        mock_sock = MagicMock()
        mock_create_sock.return_value = mock_sock
        mock_sock.send.side_effect = OSError("Network is down")

        with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
            audit_path = tf.name

        probe_types = [
            ["-t", "arp", "--target", "192.168.1.1"],
            ["-t", "ndp", "--target", "ff02::2"],
            ["-t", "dhcp"],
            ["-t", "dhcp6"],
            ["-t", "tcp_syn", "--target", "192.168.1.1", "--ports", "bad,99999"],
            ["-t", "eapol"],
            ["-t", "snmp", "--target", "192.168.1.1"],
            ["-t", "dns", "--target", "192.168.1.1"],
            ["-t", "nbns", "--target", "192.168.1.1"],
        ]

        try:
            for p_args in probe_types:
                full_args = ["probe.py", "-i", "dummy0", "--audit-file", audit_path, "--qinq-tpid", "invalid"] + p_args
                with patch.object(sys, "argv", full_args), \
                     patch("sys.stderr.write"):
                    probe.main()
        finally:
            if os.path.exists(audit_path):
                os.unlink(audit_path)

    def test_main_audit_file_open_failure(self):
        """Test that audit file creation failure triggers clean exit."""
        with patch.object(sys, "argv", ["probe.py", "-i", "dummy0", "-t", "arp", "--audit-file", "/nonexistent/test.jsonl"]), \
             patch("os.open", side_effect=OSError("Read-only filesystem")), \
             patch("sys.stderr.write"):
            with self.assertRaises(SystemExit) as cm:
                probe.main()
            self.assertEqual(cm.exception.code, 1)


    def test_misc_resilience_and_edge_coverage(self):
        """Test fallback error branches in IP resolution and preflight sockets."""
        self.assertIsNotNone(probe.resolve_source_ip("eth0", explicit_src="notanip"))
        self.assertIsNotNone(probe.resolve_source_ip("eth0", target_ip="notanip"))
        self.assertIsNotNone(probe.resolve_source_ipv6("eth0", explicit_src="notanip"))

        with patch("subprocess.run", side_effect=Exception("route error")):
            self.assertIsNotNone(probe.resolve_source_ipv6("eth0", target_ip="2001:db8::1"))

        mock_to_sock = MagicMock()
        mock_to_sock.__enter__.return_value = mock_to_sock
        mock_to_sock.recv.side_effect = probe.socket.timeout("timed out")
        with patch("subprocess.run", return_value=MagicMock(returncode=1, stdout="")), \
             patch("socket.socket", return_value=mock_to_sock):
            mac_v6 = probe.resolve_dst_mac("eth_to_test", "2001:db8::beef", is_v6=True, src_mac="02:00:00:11:22:33", src_ip="fe80::1")
            self.assertEqual(mac_v6, "33:33:00:00:00:01")
            mac_v4 = probe.resolve_dst_mac("eth_to_test", "10.99.88.77", is_v6=False, src_mac="02:00:00:11:22:33", src_ip="10.99.88.1")
            self.assertEqual(mac_v4, "ff:ff:ff:ff:ff:ff")

    @patch("probe.create_probe_socket")
    def test_main_ndp_flush_interval(self, mock_create_sock):
        """Test NDP scanning across targets to trigger periodic audit flush."""
        mock_sock = MagicMock()
        mock_create_sock.return_value = mock_sock
        captured = []
        mock_sock.send.side_effect = lambda b: captured.append(b)

        with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
            audit_path = tf.name

        test_args = [
            "probe.py", "-i", "dummy0", "-t", "ndp",
            "--target", "2001:db8:ffff::/121",
            "--rate", "5000", "--timeout", "10",
            "--audit-file", audit_path, "--audit-id", "test_ndp_flush"
        ]
        try:
            with patch.object(sys, "argv", test_args):
                probe.main()
            self.assertGreaterEqual(len(captured), 50)
        finally:
            if os.path.exists(audit_path):
                os.unlink(audit_path)

    def test_darwin_bpf_socket_creation(self):
        """Test DarwinBPFSocket lifecycle and packet transmission on macOS."""
        mock_l2_sock = MagicMock()
        with patch.object(probe, "IS_DARWIN", True), \
             patch("scapy.config.conf.L2socket", return_value=mock_l2_sock):
            sock = probe.create_probe_socket("en0")
            self.assertIsNotNone(sock)
            sock.send(b"TESTPACKET")
            mock_l2_sock.send.assert_called_once_with(b"TESTPACKET")
            with sock:
                pass
            mock_l2_sock.close.assert_called()

    def test_darwin_bpf_socket_permission_denied(self):
        """Test DarwinBPFSocket handling of PermissionError when opening /dev/bpf."""
        with patch.object(probe, "IS_DARWIN", True), \
             patch("scapy.config.conf.L2socket", side_effect=PermissionError("Permission denied")), \
             patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            with self.assertRaises(SystemExit) as cm:
                probe.create_probe_socket("en0")
            self.assertEqual(cm.exception.code, 1)
            self.assertIn("BPF device access on macOS requires root privileges", mock_stderr.getvalue())

    def test_darwin_bpf_socket_device_exhaustion(self):
        """Test DarwinBPFSocket handling of device exhaustion or OS error."""
        with patch.object(probe, "IS_DARWIN", True), \
             patch("scapy.config.conf.L2socket", side_effect=OSError("No /dev/bpf available")), \
             patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            with self.assertRaises(SystemExit) as cm:
                probe.create_probe_socket("en0")
            self.assertEqual(cm.exception.code, 1)
            self.assertIn("Failed to open BPF socket on interface 'en0'", mock_stderr.getvalue())

    def test_darwin_route_and_neighbor_resolution(self):
        """Test Darwin route -n get, arp -an, and ndp -an resolution."""
        arp_out = "? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]\n"
        ndp_out = "Neighbor Linklayer Address Netif Expire St Flgs\n2001:db8::1 0:11:22:33:44:55 en0 23h59m50s S R\n"

        def fake_run(cmd, **kwargs):
            m = MagicMock()
            m.returncode = 0
            if cmd[:3] == ["route", "-n", "get"]:
                if len(cmd) >= 4 and cmd[3] == "192.168.1.50":
                    m.stdout = "   route to: 192.168.1.50\n    gateway: 192.168.1.1\n  interface: en0\n"
                else:
                    m.stdout = "   route to: 2001:db8::1\n  interface: en0\n"
            elif cmd == ["arp", "-an"]:
                m.stdout = arp_out
            elif cmd == ["ndp", "-an"]:
                m.stdout = ndp_out
            else:
                m.stdout = ""
            return m

        with patch.object(probe, "IS_DARWIN", True), \
             patch("subprocess.run", side_effect=fake_run):
            probe.MAC_RESOLUTION_CACHE.clear()
            mac_v4 = probe.resolve_dst_mac("en0", "192.168.1.50", is_v6=False)
            self.assertEqual(mac_v4, "00:11:22:33:44:55")

            probe.MAC_RESOLUTION_CACHE.clear()
            mac_v6 = probe.resolve_dst_mac("en0", "2001:db8::1", is_v6=True)
            self.assertEqual(mac_v6, "00:11:22:33:44:55")

    def test_darwin_iface_source_and_mac_resolution(self):
        """Test Darwin ifconfig parsing for MAC, IPv4, and IPv6."""
        ifconfig_out = """en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 00:11:22:aa:bb:cc
\tinet 192.168.1.100 netmask 0xffffff00 broadcast 192.168.1.255
\tinet6 fe80::100:200:300:400%en0 prefixlen 64 secured scopeid 0x6
\tinet6 2001:db8::100 prefixlen 64 autoconf secured
\tstatus: active
"""
        with patch.object(probe, "IS_DARWIN", True), \
             patch("subprocess.run", return_value=MagicMock(returncode=0, stdout=ifconfig_out)):
            mac = probe.get_iface_mac("en0")
            self.assertEqual(mac, "00:11:22:aa:bb:cc")

            src_ip = probe.resolve_source_ip("en0")
            self.assertEqual(src_ip, "192.168.1.100")

            src_ip6 = probe.resolve_source_ipv6("en0", target_ip="2001:db8::1")
            self.assertEqual(src_ip6, "2001:db8::100")


class TestPlatformHelpers(unittest.TestCase):
    def setUp(self):
        self.lib_darwin = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "lib", "platform_darwin.sh"))
        self.lib_linux = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "lib", "platform_linux.sh"))

    def test_darwin_stat_helpers(self):
        """Test Darwin platform_stat_owner, platform_stat_perm, platform_stat_nlinks, and platform_stat_mtime."""
        with tempfile.NamedTemporaryFile() as tmp:
            os.chmod(tmp.name, 0o644)
            cmd = f"""
            source "{self.lib_darwin}"
            echo "$(platform_stat_owner "{tmp.name}")|$(platform_stat_perm "{tmp.name}")|$(platform_stat_nlinks "{tmp.name}")|$(platform_stat_mtime "{tmp.name}")"
            """
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, check=True)
            owner, perm, nlinks, mtime = res.stdout.strip().split("|")
            self.assertEqual(int(owner), os.getuid())
            self.assertEqual(perm, "644")
            self.assertEqual(int(nlinks), 1)
            self.assertGreater(int(mtime), 0)

    def test_darwin_proc_helpers(self):
        """Test Darwin platform_proc_starttime, platform_proc_comm, and platform_proc_cmdline."""
        cmd = f"""
        source "{self.lib_darwin}"
        echo "$(platform_proc_comm "$$")|$(platform_proc_cmdline "$$")"
        """
        res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, check=True)
        comm, cmdline = res.stdout.strip().split("|", 1)
        self.assertIn("bash", comm.lower())
        self.assertIn("bash", cmdline.lower())

    def test_linux_stat_helpers(self):
        """Test Linux platform_stat_owner, platform_stat_perm, platform_stat_nlinks, and platform_stat_mtime."""
        with tempfile.NamedTemporaryFile() as tmp:
            os.chmod(tmp.name, 0o600)
            cmd = f"""
            source "{self.lib_linux}"
            echo "$(platform_stat_owner "{tmp.name}")|$(platform_stat_perm "{tmp.name}")|$(platform_stat_nlinks "{tmp.name}")|$(platform_stat_mtime "{tmp.name}")"
            """
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, check=True)
            owner, perm, nlinks, mtime = res.stdout.strip().split("|")
            self.assertEqual(int(owner), os.getuid())
            self.assertEqual(perm, "600")
            self.assertEqual(int(nlinks), 1)
            self.assertGreater(int(mtime), 0)

    def test_linux_proc_helpers(self):
        """Test Linux platform_proc_starttime, platform_proc_comm, and platform_proc_cmdline."""
        cmd = f"""
        source "{self.lib_linux}"
        echo "$(platform_proc_comm "$$")"
        """
        res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, check=True)
        self.assertIn("bash", res.stdout.strip().lower())


if __name__ == "__main__":
    unittest.main()

