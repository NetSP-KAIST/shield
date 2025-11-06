#!/usr/bin/env python3

from scapy.all import *

# ICMP flood
p = Ether(dst="00:98:76:54:32:10",src="00:55:55:55:55:55")/IP(dst="0.0.0.0", src="0.0.0.0")/ICMP(type=8)
sendp(p, iface="veth1", count=512, inter=0.001)

# UDP flood
p = Ether(dst="00:98:76:54:32:10",src="00:55:55:55:55:55")/IP(dst="0.0.0.0", src="0.0.0.0")/UDP(dport=80, chksum=0)
sendp(p, iface="veth1", count=512, inter=0.001)

# DNS flood
p = Ether(dst="00:98:76:54:32:10",src="00:55:55:55:55:55")/IP(dst="0.0.0.0", src="0.0.0.0")/UDP(dport=53, chksum=0)
sendp(p, iface="veth1", count=512, inter=0.001)

# SYN flood
p = Ether(dst="00:98:76:54:32:10",src="00:55:55:55:55:55")/IP(dst="0.0.0.0", src="0.0.0.0")/TCP(flags="S")
sendp(p, iface="veth1", count=512, inter=0.001)
