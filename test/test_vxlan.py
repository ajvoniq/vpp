#!/bin/env python

import unittest
import os
import socket

import scapy
import ipaddress
from scapy.all import *

import vpp_test
from vpp_test import *

class TestVxlan(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.v = VppTest()
        cls.v.create_links(2)

        # Create VXLAN VTEP on pg0, and put pg0 and pg1 in BD
        cls.v.cli(0, 'create vxlan tunnel src %s dst %s vni 1' %
                (cls.v.VPP_IP4S[0], cls.v.MY_IP4S[0]))
        cls.v.cli(0, 'set interface l2 bridge vxlan_tunnel0 1')
        cls.v.cli(0, 'set interface l2 bridge pg1 1')

    @classmethod
    def tearDownClass(cls):
        cls.v.quit()

    def tearDown(self):
        v = self.__class__.v
        v.cli(2, "show int")
        v.cli(2, "show trace")
        v.cli(2, "show hardware")
        v.cli(2, "show ip arp")
        v.cli(2, "show ip fib")
        v.cli(2, "show error")
        v.cli(2, "show run")
        v.cli(2, "show bridge-domain 1 detail")

    def test_decapBD(self):
        v = self.__class__.v
        pkts = []
        payload = ( Ether(src='00:00:00:00:00:01', dst='00:00:00:00:00:02') /
                IP(src='1.2.3.4', dst='4.3.2.1') /
                UDP(sport=10000, dport=20000) / Raw('\x00' * 100))
        p = ( Ether(src=v.MY_MACS[0], dst=v.VPP_MACS[0]) /
                IP(src=v.MY_IP4S[0], dst=v.VPP_IP4S[0]) /
                UDP(sport=4789, dport=4789, chksum=0) /
                '\x08\x00\x00\x00'/'\x00\x00\x01\x00' /
                payload)

        pkts.append(p)
        v.pg_arm(0, 1, pkts)
        v.pg_send()

        out = v.pg_read_output(1)
        self.assertEqual(len(out), 1, 'Invalid number of packets on '
                'output: %u' % len(out))

        pkt = out[0]
        # TODO: add error messages
        self.assertEqual(pkt[Ether].src, payload[Ether].src)
        self.assertEqual(pkt[Ether].dst, payload[Ether].dst)
        self.assertEqual(pkt[IP].src, payload[IP].src)
        self.assertEqual(pkt[IP].dst, payload[IP].dst)
        self.assertEqual(pkt[UDP].sport, payload[UDP].sport)
        self.assertEqual(pkt[UDP].dport, payload[UDP].dport)
        self.assertEqual(pkt[Raw], payload[Raw])

    def test_encapBD(self):
        '''Packet coming from pg1 through BD to VTEP.
        VXLAN encap is expected.
        '''
        v = self.__class__.v
        pkts = []
        vxlan_header = '\x08\x00\x00\x00' + '\x00\x00\x01\x00'
        payload = ( Ether(src='00:00:00:00:00:01', dst='00:00:00:00:00:02') /
                IP(src='1.2.3.4', dst='4.3.2.1') /
                UDP(sport=10000, dport=20000) / Raw('\x00' * 100))
        p = ( Ether(src=v.MY_MACS[0], dst=v.VPP_MACS[0]) /
                IP(src=v.MY_IP4S[0], dst=v.VPP_IP4S[0]) /
                UDP(sport=4789, dport=4789, chksum=0) /
                vxlan_header /
                payload)

        pkts.append(payload)
        v.pg_arm(1, 0, pkts)
        v.pg_send()

        out = v.pg_read_output(0)
        self.assertEqual(len(out), 1, 'Invalid number of packets on '
                'output: %u' % len(out))

        pkt = out[0]
        # TODO: add error messages
        self.assertEqual(pkt[Ether].src, v.VPP_MACS[0])
        self.assertEqual(pkt[Ether].dst, v.MY_MACS[0])
        self.assertEqual(pkt[IP].src, v.VPP_IP4S[0])
        self.assertEqual(pkt[IP].dst, v.MY_IP4S[0])
        self.assertEqual(pkt[UDP].dport, 4789)
        self.assertEqual(str(pkt[Raw]), vxlan_header + str(payload))

if __name__ == '__main__':
    unittest.main()
