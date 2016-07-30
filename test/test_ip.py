#!/bin/env python

import unittest
import os
import socket

import scapy
import ipaddress
from scapy.all import *

import vpp_test
from vpp_test import *

class TestIPv4(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.num_ifs = 3
        cls.v = VppTest()
        cls.v.create_links(cls.num_ifs)

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

    def test_sweep(self):
        v = self.__class__.v
        num_if = self.__class__.num_ifs
        pkts = []
        range_first = 64
        range_last = 2050

        for i in range (0, num_if):
            j = i + 1
            if j == num_if:
                j = 0
            pkts = []
            for n in range (range_first, range_last+1):
                p = ( Ether(dst=v.VPP_MACS[i],src=v.MY_MACS[i]) /
                      IP(src=v.MY_IP4S[i], dst=v.MY_IP4S[j]) /
                      UDP(sport=int(10000+n),dport=int(10000+n)) /
                      Raw('\x00' * (n-42)))
                pkts.append(p)
            v.pg_arm (i, i, pkts)


        # Start test
        v.cli(2, "trace add pg-input %u" % (num_if * 3))
        v.pg_send()
        v.cli(1, "show int")
        v.cli(2, "show trace")
        v.cli(1, "show hardware")
        v.cli(1, "show ip arp")
        v.cli(1, "show ip fib")
        v.cli(1, "show error")
        v.cli(1, "show run")

        # Process replies
        fail = False
        for i in range (0, num_if):
            pkts = rdpcap("/tmp/pg%u_out.pcap" % i)
            failed_sizes = []
            last_found = 0
            for n in range (range_first, range_last + 1):
                found = False
                for j in range(last_found, len(pkts)):
                    p = pkts[j]
                    if IP in p and p[IP].len + 14 == n: # More checks.... (src ip, dst ip, port)
                        found = True
                        last_found = j
                        break
                if not found:
                    fail = True
                    failed_sizes.append(n)
            if failed_sizes:
                t.log("pg%u lengths %s not OK" % (i, str(failed_sizes)))

        self.failIf(fail == True)


if __name__ == '__main__':
    unittest.main()
