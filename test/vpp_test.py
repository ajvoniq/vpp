#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import os
import subprocess
import scapy
from scapy.all import *


class VppTest:

    def __init__(self):
        self.pg_streams = []
        self.RED = '\033[91m'
        self.GREEN = '\033[92m'
        self.YELLOW = '\033[93m'
        self.LPURPLE = '\033[94m'
        self.END = '\033[0m'
        self.vpp_bin = os.getenv('VPP_TEST_BIN', "vpp")
        self.vpp_api_test_bin = os.getenv ("VPP_TEST_API_TEST_BIN", "vpp-api-test")

        self.MY_MACS = []
        self.MY_IP4S = []
        self.MY_IP6S = []
        self.VPP_MACS = []
        self.VPP_IP4S = []
        self.VPP_IP6S = []

        try:
            self.verbose = int (os.getenv ("V", 0))
        except:
            self.verbose = 0
        self.vpp = subprocess.Popen([self.vpp_bin, "unix", "nodaemon"], stderr=subprocess.PIPE)

    def create_links(self, num_if):
        for i in range (0, num_if):
            self.MY_MACS.append("00:00:00:00:ff:%02x" % i)
            self.MY_IP4S.append("172.16.%u.2" % i)
            self.VPP_IP4S.append("172.16.%u.1" % i)
            self.log("My MAC address is %s, IPv4 address is %s" %
                    (self.MY_MACS[i], self.MY_IP4S[i]))
            self.cli(0, "create packet-generator interface pg%u" % i)
            self.cli(0, "set interface state pg%u up" % i)
            self.cli(0, "set interface ip address pg%u %s/24" %
                    (i, self.VPP_IP4S[i]))

        ###############################################################################
        # Populate ARP table
        #
        ###############################################################################

        # Prepare ARP requests for all interfaces
        for i in range (0, num_if):
            arp_req = ( Ether(dst="ff:ff:ff:ff:ff:ff",src=self.MY_MACS[i]) /
                        ARP(op=ARP.who_has, pdst=self.VPP_IP4S[i],
                            psrc=self.MY_IP4S[i], hwsrc=self.MY_MACS[i]))
            self.pg_arm(i, i, arp_req)

        self.cli(2, "trace add pg-input %u" % (num_if * 3))
        self.pg_send()
        self.cli(2, "show int")
        self.cli(2, "show trace")
        self.cli(2, "show hardware")
        self.cli(2, "show ip arp")
        self.cli(2, "show ip fib")
        self.cli(2, "show error")

        # Process replies, store VPP's MAC addresses
        ok = 0
        for i in range (0, num_if):
            arp_reply = rdpcap("/tmp/pg%u_out.pcap" % i)[0]
            if  arp_reply[ARP].op == ARP.is_at:
                ok += 1
                self.VPP_MACS.append(arp_reply[ARP].hwsrc)
                self.log("VPP pg%u MAC address is %s " % ( i, self.VPP_MACS[i]))

        if  ok != num_if:
            raise RuntimeError('Number of ARP responses does not equal '
                               'ARP requests')

    def test_suite(self, s):
        print self.YELLOW
        print "------------------------------------------------------------------"
        print "-- %-60s --" % (s + " Test Suite")
        print "------------------------------------------------------------------" + self.END

    def test_name(self, s):
        self.testname = s

    def test_ok(self):
        if self.verbose > 0:
            print "------------------------------------------------------------------"
        print ("%-60s %sOK%s"  % (self.testname, self.GREEN, self.END))
        if self.verbose > 0:
            print "------------------------------------------------------------------"

    def test_fail(self):
        if self.verbose > 0:
            print "------------------------------------------------------------------"
        print ("%-60s %sFAIL%s"  % (self.testname, self.RED, self.END))
        if self.verbose > 0:
            print "------------------------------------------------------------------"

    def cli(self, v, s):
        if self.verbose < v:
            return
        p = subprocess.Popen([self.vpp_api_test_bin],stdout=subprocess.PIPE,stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        if self.verbose > 0:
            print "CLI: " + self.RED + s + self.END
        p.stdin.write('exec ' + s);
        out = p.communicate()[0]
        out = out.replace("vat# ", "", 2)
        if self.verbose > 0:
            if len (out) > 1:
                print self.YELLOW + out + self.END

    def pg_arm(self, i, o, pkts):
        os.system("sudo rm -f /tmp/pg%u_*.pcap" % i)
        os.system("sudo rm -f /tmp/pg%u_*.pcap" % o)
        wrpcap("/tmp/pg%u_in.pcap" % i, pkts)
        self.cli(0, "packet-generator new pcap /tmp/pg%u_in.pcap source pg%u name pcap%u" % (i, i, i))
        self.cli(0, "packet-generator capture pg%u pcap /tmp/pg%u_out.pcap" % (o, o))
        self.pg_streams.append('pcap%u' % i)

    def pg_send(self):
        self.cli(0, 'packet-generator enable')
        for stream in self.pg_streams:
            self.cli(0, 'packet-generator delete %s' % stream)
        self.pg_streams = []

    def pg_read_output(self, o):
        output = rdpcap("/tmp/pg%u_out.pcap" % o)
        return output

    def log (self, s):
        if self.verbose > 0:
            print "LOG: " + self.LPURPLE + s + self.END
    def quit (self):
        self.vpp.terminate()

    def __del__ (self):
        self.quit()

if __name__ == "__main__":
    t = VppTest()
    t.test_name("Sample test name")
    t.cli("show version verbose")
    t.test_ok()
    t.test_name("Sample test name 2")
    t.test_fail()
    t.quit()
