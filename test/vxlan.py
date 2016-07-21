#!/usr/bin/env python

import vpp_test
import os
import scapy
import socket
import ipaddress
from scapy.all import *
from vpp_test import *

MY_MACS = []
MY_IP4S = []
MY_IP6S = []
VPP_MACS = []
VPP_IP4S = []
VPP_IP6S = []

num_if = 2

t = VppTest()
t.test_suite("VXLAN")

for i in range (0, num_if):
    MY_MACS.append ("00:00:00:00:ff:%02x" % i)
    MY_IP4S.append ("172.16.%u.2" % i)
    VPP_IP4S.append ("172.16.%u.1" % i)
    t.log("My MAC address is %s, IPv4 address is %s" % (MY_MACS[i], MY_IP4S[i]))
    t.cli(0, "create packet-generator interface pg%u" % i)
    t.cli(0, "set interface state pg%u up" % i)
    t.cli(0, "set interface ip address pg%u %s/24" % (i, VPP_IP4S[i]))

###############################################################################
# Populate ARP table
#
###############################################################################

# Prepare ARP requests for all interfaces
for i in range (0, num_if):
    arp_req = ( Ether(dst="ff:ff:ff:ff:ff:ff",src=MY_MACS[i]) /
                ARP(op=ARP.who_has, pdst=VPP_IP4S[i], psrc=MY_IP4S[i],
                hwsrc=MY_MACS[i]))
    t.pg_arm(i, i, arp_req)

t.cli(2, "trace add pg-input %u" % (num_if * 3))
t.cli(0, "packet-generator enable")
t.cli(1, "show int")
t.cli(2, "show trace")
t.cli(1, "show hardware")
t.cli(1, "show ip arp")
t.cli(1, "show ip fib")
t.cli(1, "show error")

# Process replies, store VPP's MAC addresses
ok = 0
for i in range (0, num_if):
    arp_reply = rdpcap("/tmp/pg%u_out.pcap" % i)[0]
    if  arp_reply[ARP].op == ARP.is_at:
        ok += 1
        VPP_MACS.append(arp_reply[ARP].hwsrc)
        t.log("VPP pg%u MAC address is %s " % ( i, VPP_MACS[i]))

if  ok != num_if:
    t.test_fail()

###############################################################################
# VXLAN decap with BD
#
###############################################################################

t.test_name("VXLAN decap with BD")

t.cli(0, "create vxlan tunnel src %s dst %s vni 1" % (VPP_IP4S[0], MY_IP4S[0]))
t.cli(0, "set interface l2 bridge vxlan_tunnel0 1")
t.cli(0, "set interface l2 bridge pg1 1")

pkts = []
payload = ( Ether(src='00:00:00:00:00:01', dst='00:00:00:00:00:02') /
        IP(src='1.2.3.4', dst='4.3.2.1') /
        UDP(sport=10000, dport=20000) / Raw('\x00' * 100))
p = ( Ether(src=MY_MACS[0], dst=VPP_MACS[0]) /
        IP(src=MY_IP4S[0], dst=VPP_IP4S[0]) /
        UDP(sport=4789, dport=4789, chksum=0) /
        '\x08\x00\x00\x00'/'\x00\x00\x01\x00' /
        payload)

pkts.append(p)
t.pg_arm (0, 1, pkts)
t.cli(0, "packet-generator enable")

out = t.pg_read_output(1)
if len(out) != 1:
    t.log('Invalid number of packets on output: %u' % len(out))
    t.test_fail()
else:
    pkt = out[0]
    if pkt[Ether].src != payload[Ether].src or \
        pkt[Ether].dst != payload[Ether].dst or \
        pkt[IP].src != payload[IP].src or \
        pkt[IP].dst != payload[IP].dst or \
        pkt[UDP].sport != payload[UDP].sport or \
        pkt[UDP].dport != payload[UDP].dport or \
        pkt[Raw] != payload[Raw]:
            t.test_fail()
    else:
        t.test_ok()

## Start test
t.cli(2, "show int")
t.cli(2, "show trace")
t.cli(2, "show hardware")
t.cli(2, "show ip arp")
t.cli(2, "show ip fib")
t.cli(2, "show error")
t.cli(2, "show run")
t.cli(2, "show bridge-domain 1 detail")

###############################################################################
# VXLAN encap with BD
#
###############################################################################

t.test_name("VXLAN encap with BD")

pkts = []
p = ( Ether(src='00:00:00:00:00:01', dst='00:00:00:00:00:02') /
        IP(src='1.2.3.4', dst='4.3.2.1') /
        UDP(sport=10000, dport=20000) / Raw('\x00' * 100))
pkts.append(p)
t.pg_arm (1, 0, pkts)
t.cli(0, "packet-generator enable")

#p = ( Ether(src=MY_MACS[0], dst=VPP_MACS[0]) /
#        IP(src=MY_IP4S[0], dst=VPP_IP4S[0]) /
#        UDP(sport=4789, dport=4789, chksum=0) /
#        '\x08\x00\x00\x00'/'\x00\x00\x01\x00' /
#        payload)


out = t.pg_read_output(0)
if len(out) != 1:
    t.log('Invalid number of packets on output: %u' % len(out))
    t.test_fail()
else:
    pkt = out[0]

    if pkt[Ether].src != VPP_MACS[0] or \
        pkt[Ether].dst != MY_MACS[0] or \
        pkt[IP].src != VPP_IP4S[0] or \
        pkt[IP].dst != MY_IP4S[0] or \
        pkt[UDP].dport != 4789:
            t.log(0, "Invalid outer VXLAN header")
            t.test_fail()
    else:
        # Strip the VXLAN header
        vxlan_header = str(pkt[Raw])[:8]
        if vxlan_header != '\x08\x00\x00\x00\x00\x00\x01\x00':
            t.log(0, 'Invalid VXLAN header')
            t.test_fail()
        else:
            inner = Ether(str(pkt[Raw])[8:])
            if inner[Ether].src != payload[Ether].src or \
                inner[Ether].dst != payload[Ether].dst or \
                inner[IP].src != payload[IP].src or \
                inner[IP].dst != payload[IP].dst or \
                inner[UDP].sport != payload[UDP].sport or \
                inner[UDP].dport != payload[UDP].dport or \
                inner[Raw] != payload[Raw]:
                    t.log(0, 'Encapsulated packet malformed')
                    t.test_fail()
            else:
                t.test_ok()

## Start test
t.cli(2, "show int")
t.cli(2, "show trace")
t.cli(2, "show hardware")
t.cli(2, "show ip arp")
t.cli(2, "show ip fib")
t.cli(2, "show error")
t.cli(2, "show run")
t.cli(2, "show bridge-domain 1 detail")

t.quit()
