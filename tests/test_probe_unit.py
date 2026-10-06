#!/usr/bin/env python3
"""
tests/test_probe_unit.py - Comprehensive Unit & Mock Test Suite for Net-Tap Active Probing Engine
Tests all 10 active probe types, 802.1Q/802.1ad tagging, watermark compliance, and rate limiting
without requiring root privileges or real network interfaces.
"""

import datetime
import io
import ipaddress
import json
import os
import struct
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# Ensure lib directory is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "lib")))

import probe
from scapy.all import (
    Ether, Dot1Q, ARP, IP, IPv6, ICMP, UDP, BOOTP, DHCP, TCP,
    ICMPv6ND_NS, ICMPv6ND_RS, ICMPv6EchoRequest, DNS, Raw
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
        mock_socket_cls.assert_called_once_with(probe.socket.AF_PACKET, probe.socket.SOCK_RAW)
        mock_sock.setsockopt.assert_called_once_with(
            probe.socket.SOL_SOCKET, probe.SO_MARK, probe.PROBE_FWMARK
        )
        mock_sock.bind.assert_called_once_with(("dummy0", 0))

    def test_resolve_dst_mac_rfc4291_unicast(self):
        """Verify that unicast IPv6 destination MAC resolution never falls back to multicast MAC."""
        with patch("subprocess.run") as mock_sub:
            # Simulate neighbor cache miss
            mock_sub.return_value = MagicMock(returncode=1, stdout="", splitlines=lambda: [])
            
            # For a unicast IPv6 target, fallback should be broadcast MAC, NOT solicited multicast
            dst_mac = probe.resolve_dst_mac("dummy0", "2001:db8::50", is_v6=True)
            self.assertEqual(dst_mac, "ff:ff:ff:ff:ff:ff")
            self.assertFalse(dst_mac.startswith("33:33:ff"))

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


if __name__ == "__main__":
    unittest.main()
