#!/usr/bin/env python3

import sys
import os
import time
import threading
from scapy.all import *
from layered_cms import *
import random

parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
import setup
from crc import TofinoCRC32

victim_ip = "48.0.0.1"

def generate_distinct_ips(n: int) -> list[str]:
    seen_hash0 = set()
    seen_hash1 = set()
    result = []

    def int_to_ip(n: int) -> str:
        return f"{(n >> 24) & 0xFF}.{(n >> 16) & 0xFF}.{(n >> 8) & 0xFF}.{n & 0xFF}"

    i = 0   # IP starting from "0.0.0.0" to "255.255.255.255"
    while len(result) < n:
        ip = int_to_ip(i)
        reg_c2_key_a = TofinoCRC32.hash0(ip, victim_ip)
        reg_c2_key_b = TofinoCRC32.hash1(ip, victim_ip)
        key0 = reg_c2_key_a & (setup.LAYER3_ENTRY_SIZE-1)
        key1 = reg_c2_key_b & (setup.LAYER3_ENTRY_SIZE-1)

        if key0 not in seen_hash0 and key1 not in seen_hash1:
            seen_hash0.add(key0)
            seen_hash1.add(key1)
            result.append(ip)
        i += 1
        if i >= (1 << 32):  # prevent infinite loop
            raise RuntimeError("Ran out of unique IPs with distinct hashes")

    return result

def pick_numbers(l: int, r: int) -> list[int]:
    if l < 0 or r < 0 or l > r:
        raise ValueError(f"Condition not satisfiable: {l} and {r}")

    while True:
        nums = [random.randint(l, r) for _ in range(4)]
        if nums[1] + nums[2] <= r:  # DNS flood also count as UDP flood
            return nums

def send_ip_packet(ips: list[str]):
    iface = ptf.config['interfaces'][0][2]
    for ip in ips:
        pkt = Ether(dst="00:98:76:54:32:10",src="00:55:55:55:55:55")/IP(dst=victim_ip, src=ip)
        sendp(pkt, iface=iface, verbose=False)

def send_packets(ips: list[str], pktnum: list[list[int]]):
    if len(ips) != len(pktnum) or any(len(l) != 4 or any(not isinstance(x, int) for x in l) for l in pktnum):
        raise ValueError(f"Invalid list sizes: {ips} and {pktnum}")

    start_time = time.time()
    iface = ptf.config['interfaces'][0][2]
    for i, ip in enumerate(ips):
        # ICMP flood
        pkt = Ether(dst="00:98:76:54:32:10",src="00:55:55:55:55:55")/IP(dst=victim_ip, src=ip)/ICMP(type=8)
        if pktnum[i][0] > 0:
            sendpfast(pkt, iface=iface, count=pktnum[i][0])

        # UDP flood
        pkt = Ether(dst="00:98:76:54:32:10",src="00:55:55:55:55:55")/IP(dst=victim_ip, src=ip)/UDP(dport=80, chksum=0)
        if pktnum[i][1] > 0:
            sendpfast(pkt, iface=iface, count=pktnum[i][1])

        # DNS flood
        pkt = Ether(dst="00:98:76:54:32:10",src="00:55:55:55:55:55")/IP(dst=victim_ip, src=ip)/UDP(dport=53, chksum=0)
        if pktnum[i][2] > 0:
            sendpfast(pkt, iface=iface, count=pktnum[i][2])

        # SYN flood
        pkt = Ether(dst="00:98:76:54:32:10",src="00:55:55:55:55:55")/IP(dst=victim_ip, src=ip)/TCP(flags="S")
        if pktnum[i][3] > 0:
            sendpfast(pkt, iface=iface, count=pktnum[i][3])
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"Sent packets: {elapsed_time:.6f} seconds")

def read_dataplane(test, ip: str, overflow_counter: bool) -> list[int]:
    result = [[0] * 4 for _ in range(2)]

    reg_c2_key_a = TofinoCRC32.hash0(ip, victim_ip)
    reg_c2_key_b = TofinoCRC32.hash1(ip, victim_ip)
    key0 = reg_c2_key_a & (setup.LAYER1_ENTRY_SIZE-1)
    key1 = reg_c2_key_b & (setup.LAYER1_ENTRY_SIZE-1)

    for (data, key) in test.reg_c2_layer1_arr0_w1.entry_get(test.dev_tgt, [test.reg_c2_layer1_arr0_w1.make_key([gc.KeyTuple('$REGISTER_INDEX', key0)])], flags={'from_hw': True}):
        reg_c2_layer1_arr0_w1 = data.to_dict()['Ingress.reg_c2_layer1_arr0_w1.f1'][0]
    for (data, key) in test.reg_c2_layer1_arr1_w1.entry_get(test.dev_tgt, [test.reg_c2_layer1_arr1_w1.make_key([gc.KeyTuple('$REGISTER_INDEX', key1)])], flags={'from_hw': True}):
        reg_c2_layer1_arr1_w1 = data.to_dict()['Ingress.reg_c2_layer1_arr1_w1.f1'][0]
    for (data, key) in test.reg_c2_layer1_arr0_w2.entry_get(test.dev_tgt, [test.reg_c2_layer1_arr0_w2.make_key([gc.KeyTuple('$REGISTER_INDEX', key0)])], flags={'from_hw': True}):
        reg_c2_layer1_arr0_w2 = data.to_dict()['Ingress.reg_c2_layer1_arr0_w2.f1'][0]
    for (data, key) in test.reg_c2_layer1_arr1_w2.entry_get(test.dev_tgt, [test.reg_c2_layer1_arr1_w2.make_key([gc.KeyTuple('$REGISTER_INDEX', key1)])], flags={'from_hw': True}):
        reg_c2_layer1_arr1_w2 = data.to_dict()['Ingress.reg_c2_layer1_arr1_w2.f1'][0]
    reg_c2_layer1_arr0_w1_slice0 = (reg_c2_layer1_arr0_w1 & setup.LAYER1_DATA_0) >> (setup.LAYER1_BIT_SIZE*3)
    reg_c2_layer1_arr0_w1_slice1 = (reg_c2_layer1_arr0_w1 & setup.LAYER1_DATA_1) >> (setup.LAYER1_BIT_SIZE*2)
    reg_c2_layer1_arr0_w1_slice2 = (reg_c2_layer1_arr0_w1 & setup.LAYER1_DATA_2) >> (setup.LAYER1_BIT_SIZE*1)
    reg_c2_layer1_arr0_w1_slice3 =  reg_c2_layer1_arr0_w1 & setup.LAYER1_DATA_3
    reg_c2_layer1_arr1_w1_slice0 = (reg_c2_layer1_arr1_w1 & setup.LAYER1_DATA_0) >> (setup.LAYER1_BIT_SIZE*3)
    reg_c2_layer1_arr1_w1_slice1 = (reg_c2_layer1_arr1_w1 & setup.LAYER1_DATA_1) >> (setup.LAYER1_BIT_SIZE*2)
    reg_c2_layer1_arr1_w1_slice2 = (reg_c2_layer1_arr1_w1 & setup.LAYER1_DATA_2) >> (setup.LAYER1_BIT_SIZE*1)
    reg_c2_layer1_arr1_w1_slice3 =  reg_c2_layer1_arr1_w1 & setup.LAYER1_DATA_3
    reg_c2_layer1_arr0_w2_slice0 = (reg_c2_layer1_arr0_w2 & setup.LAYER1_DATA_0) >> (setup.LAYER1_BIT_SIZE*3)
    reg_c2_layer1_arr0_w2_slice1 = (reg_c2_layer1_arr0_w2 & setup.LAYER1_DATA_1) >> (setup.LAYER1_BIT_SIZE*2)
    reg_c2_layer1_arr0_w2_slice2 = (reg_c2_layer1_arr0_w2 & setup.LAYER1_DATA_2) >> (setup.LAYER1_BIT_SIZE*1)
    reg_c2_layer1_arr0_w2_slice3 =  reg_c2_layer1_arr0_w2 & setup.LAYER1_DATA_3
    reg_c2_layer1_arr1_w2_slice0 = (reg_c2_layer1_arr1_w2 & setup.LAYER1_DATA_0) >> (setup.LAYER1_BIT_SIZE*3)
    reg_c2_layer1_arr1_w2_slice1 = (reg_c2_layer1_arr1_w2 & setup.LAYER1_DATA_1) >> (setup.LAYER1_BIT_SIZE*2)
    reg_c2_layer1_arr1_w2_slice2 = (reg_c2_layer1_arr1_w2 & setup.LAYER1_DATA_2) >> (setup.LAYER1_BIT_SIZE*1)
    reg_c2_layer1_arr1_w2_slice3 =  reg_c2_layer1_arr1_w2 & setup.LAYER1_DATA_3
    reg_c2_layer1_arr0_slice0 = reg_c2_layer1_arr0_w1_slice0 + reg_c2_layer1_arr0_w2_slice0
    reg_c2_layer1_arr0_slice1 = reg_c2_layer1_arr0_w1_slice1 + reg_c2_layer1_arr0_w2_slice1
    reg_c2_layer1_arr0_slice2 = reg_c2_layer1_arr0_w1_slice2 + reg_c2_layer1_arr0_w2_slice2
    reg_c2_layer1_arr0_slice3 = reg_c2_layer1_arr0_w1_slice3 + reg_c2_layer1_arr0_w2_slice3
    reg_c2_layer1_arr1_slice0 = reg_c2_layer1_arr1_w1_slice0 + reg_c2_layer1_arr1_w2_slice0
    reg_c2_layer1_arr1_slice1 = reg_c2_layer1_arr1_w1_slice1 + reg_c2_layer1_arr1_w2_slice1
    reg_c2_layer1_arr1_slice2 = reg_c2_layer1_arr1_w1_slice2 + reg_c2_layer1_arr1_w2_slice2
    reg_c2_layer1_arr1_slice3 = reg_c2_layer1_arr1_w1_slice3 + reg_c2_layer1_arr1_w2_slice3

    for (data, key) in test.reg_c2_layer2_arr0_tg0.entry_get(test.dev_tgt, [test.reg_c2_layer2_arr0_tg0.make_key([gc.KeyTuple('$REGISTER_INDEX', key0 & (setup.LAYER2_ENTRY_SIZE-1))])], flags={'from_hw': True}):
        reg_c2_layer2_arr0_tg0 = data.to_dict()['Ingress.reg_c2_layer2_arr0_tg0.f1'][0]
    for (data, key) in test.reg_c2_layer2_arr1_tg0.entry_get(test.dev_tgt, [test.reg_c2_layer2_arr1_tg0.make_key([gc.KeyTuple('$REGISTER_INDEX', key1 & (setup.LAYER2_ENTRY_SIZE-1))])], flags={'from_hw': True}):
        reg_c2_layer2_arr1_tg0 = data.to_dict()['Ingress.reg_c2_layer2_arr1_tg0.f1'][0]
    for (data, key) in test.reg_c2_layer2_arr0_tg1.entry_get(test.dev_tgt, [test.reg_c2_layer2_arr0_tg1.make_key([gc.KeyTuple('$REGISTER_INDEX', key0 & (setup.LAYER2_ENTRY_SIZE-1))])], flags={'from_hw': True}):
        reg_c2_layer2_arr0_tg1 = data.to_dict()['Ingress.reg_c2_layer2_arr0_tg1.f1'][0]
    for (data, key) in test.reg_c2_layer2_arr1_tg1.entry_get(test.dev_tgt, [test.reg_c2_layer2_arr1_tg1.make_key([gc.KeyTuple('$REGISTER_INDEX', key1 & (setup.LAYER2_ENTRY_SIZE-1))])], flags={'from_hw': True}):
        reg_c2_layer2_arr1_tg1 = data.to_dict()['Ingress.reg_c2_layer2_arr1_tg1.f1'][0]
    reg_c2_layer2_arr0_slice0 = ((reg_c2_layer2_arr0_tg0 & setup.LAYER2_DATA_HI) >> setup.LAYER2_BIT_SIZE) << (setup.LAYER1_BIT_SIZE-1)
    reg_c2_layer2_arr0_slice1 =  (reg_c2_layer2_arr0_tg0 & setup.LAYER2_DATA_LO)                           << (setup.LAYER1_BIT_SIZE-1)
    reg_c2_layer2_arr0_slice2 = ((reg_c2_layer2_arr0_tg1 & setup.LAYER2_DATA_HI) >> setup.LAYER2_BIT_SIZE) << (setup.LAYER1_BIT_SIZE-1)
    reg_c2_layer2_arr0_slice3 =  (reg_c2_layer2_arr0_tg1 & setup.LAYER2_DATA_LO)                           << (setup.LAYER1_BIT_SIZE-1)
    reg_c2_layer2_arr1_slice0 = ((reg_c2_layer2_arr1_tg0 & setup.LAYER2_DATA_HI) >> setup.LAYER2_BIT_SIZE) << (setup.LAYER1_BIT_SIZE-1)
    reg_c2_layer2_arr1_slice1 =  (reg_c2_layer2_arr1_tg0 & setup.LAYER2_DATA_LO)                           << (setup.LAYER1_BIT_SIZE-1)
    reg_c2_layer2_arr1_slice2 = ((reg_c2_layer2_arr1_tg1 & setup.LAYER2_DATA_HI) >> setup.LAYER2_BIT_SIZE) << (setup.LAYER1_BIT_SIZE-1)
    reg_c2_layer2_arr1_slice3 =  (reg_c2_layer2_arr1_tg1 & setup.LAYER2_DATA_LO)                           << (setup.LAYER1_BIT_SIZE-1)

    for (data, key) in test.reg_c2_layer3_arr0_tg0.entry_get(test.dev_tgt, [test.reg_c2_layer3_arr0_tg0.make_key([gc.KeyTuple('$REGISTER_INDEX', key0 & (setup.LAYER3_ENTRY_SIZE-1))])], flags={'from_hw': True}):
        reg_c2_layer3_arr0_tg0 = data.to_dict()['Ingress.reg_c2_layer3_arr0_tg0.f1'][0]
    for (data, key) in test.reg_c2_layer3_arr1_tg0.entry_get(test.dev_tgt, [test.reg_c2_layer3_arr1_tg0.make_key([gc.KeyTuple('$REGISTER_INDEX', key1 & (setup.LAYER3_ENTRY_SIZE-1))])], flags={'from_hw': True}):
        reg_c2_layer3_arr1_tg0 = data.to_dict()['Ingress.reg_c2_layer3_arr1_tg0.f1'][0]
    for (data, key) in test.reg_c2_layer3_arr0_tg1.entry_get(test.dev_tgt, [test.reg_c2_layer3_arr0_tg1.make_key([gc.KeyTuple('$REGISTER_INDEX', key0 & (setup.LAYER3_ENTRY_SIZE-1))])], flags={'from_hw': True}):
        reg_c2_layer3_arr0_tg1 = data.to_dict()['Ingress.reg_c2_layer3_arr0_tg1.f1'][0]
    for (data, key) in test.reg_c2_layer3_arr1_tg1.entry_get(test.dev_tgt, [test.reg_c2_layer3_arr1_tg1.make_key([gc.KeyTuple('$REGISTER_INDEX', key1 & (setup.LAYER3_ENTRY_SIZE-1))])], flags={'from_hw': True}):
        reg_c2_layer3_arr1_tg1 = data.to_dict()['Ingress.reg_c2_layer3_arr1_tg1.f1'][0]
    reg_c2_layer3_arr0_slice0 = ((reg_c2_layer3_arr0_tg0 & setup.LAYER3_DATA_HI) >> setup.LAYER3_BIT_SIZE) << (setup.LAYER1_BIT_SIZE+setup.LAYER2_BIT_SIZE-2)
    reg_c2_layer3_arr0_slice1 =  (reg_c2_layer3_arr0_tg0 & setup.LAYER3_DATA_LO)                           << (setup.LAYER1_BIT_SIZE+setup.LAYER2_BIT_SIZE-2)
    reg_c2_layer3_arr0_slice2 = ((reg_c2_layer3_arr0_tg1 & setup.LAYER3_DATA_HI) >> setup.LAYER3_BIT_SIZE) << (setup.LAYER1_BIT_SIZE+setup.LAYER2_BIT_SIZE-2)
    reg_c2_layer3_arr0_slice3 =  (reg_c2_layer3_arr0_tg1 & setup.LAYER3_DATA_LO)                           << (setup.LAYER1_BIT_SIZE+setup.LAYER2_BIT_SIZE-2)
    reg_c2_layer3_arr1_slice0 = ((reg_c2_layer3_arr1_tg0 & setup.LAYER3_DATA_HI) >> setup.LAYER3_BIT_SIZE) << (setup.LAYER1_BIT_SIZE+setup.LAYER2_BIT_SIZE-2)
    reg_c2_layer3_arr1_slice1 =  (reg_c2_layer3_arr1_tg0 & setup.LAYER3_DATA_LO)                           << (setup.LAYER1_BIT_SIZE+setup.LAYER2_BIT_SIZE-2)
    reg_c2_layer3_arr1_slice2 = ((reg_c2_layer3_arr1_tg1 & setup.LAYER3_DATA_HI) >> setup.LAYER3_BIT_SIZE) << (setup.LAYER1_BIT_SIZE+setup.LAYER2_BIT_SIZE-2)
    reg_c2_layer3_arr1_slice3 =  (reg_c2_layer3_arr1_tg1 & setup.LAYER3_DATA_LO)                           << (setup.LAYER1_BIT_SIZE+setup.LAYER2_BIT_SIZE-2)

    for (data, key) in test.reg_c2_layer1_arr0_overflow_counter.entry_get(test.dev_tgt, [test.reg_c2_layer1_arr0_overflow_counter.make_key([gc.KeyTuple('$REGISTER_INDEX', key0)])], flags={'from_hw': True}):
        reg_c2_layer1_arr0_overflow_counter = data.to_dict()['Ingress.reg_c2_layer1_arr0_overflow_counter.f1'][0]
    for (data, key) in test.reg_c2_layer1_arr1_overflow_counter.entry_get(test.dev_tgt, [test.reg_c2_layer1_arr1_overflow_counter.make_key([gc.KeyTuple('$REGISTER_INDEX', key1)])], flags={'from_hw': True}):
        reg_c2_layer1_arr1_overflow_counter = data.to_dict()['Ingress.reg_c2_layer1_arr1_overflow_counter.f1'][0]
    reg_c2_layer1_arr0_w1_overflow_counter_slice0 = (reg_c2_layer1_arr0_overflow_counter >> 7) & 1
    reg_c2_layer1_arr0_w1_overflow_counter_slice1 = (reg_c2_layer1_arr0_overflow_counter >> 6) & 1
    reg_c2_layer1_arr0_w1_overflow_counter_slice2 = (reg_c2_layer1_arr0_overflow_counter >> 5) & 1
    reg_c2_layer1_arr0_w1_overflow_counter_slice3 = (reg_c2_layer1_arr0_overflow_counter >> 4) & 1
    reg_c2_layer1_arr0_w2_overflow_counter_slice0 = (reg_c2_layer1_arr0_overflow_counter >> 3) & 1
    reg_c2_layer1_arr0_w2_overflow_counter_slice1 = (reg_c2_layer1_arr0_overflow_counter >> 2) & 1
    reg_c2_layer1_arr0_w2_overflow_counter_slice2 = (reg_c2_layer1_arr0_overflow_counter >> 1) & 1
    reg_c2_layer1_arr0_w2_overflow_counter_slice3 = (reg_c2_layer1_arr0_overflow_counter >> 0) & 1
    reg_c2_layer1_arr1_w1_overflow_counter_slice0 = (reg_c2_layer1_arr1_overflow_counter >> 7) & 1
    reg_c2_layer1_arr1_w1_overflow_counter_slice1 = (reg_c2_layer1_arr1_overflow_counter >> 6) & 1
    reg_c2_layer1_arr1_w1_overflow_counter_slice2 = (reg_c2_layer1_arr1_overflow_counter >> 5) & 1
    reg_c2_layer1_arr1_w1_overflow_counter_slice3 = (reg_c2_layer1_arr1_overflow_counter >> 4) & 1
    reg_c2_layer1_arr1_w2_overflow_counter_slice0 = (reg_c2_layer1_arr1_overflow_counter >> 3) & 1
    reg_c2_layer1_arr1_w2_overflow_counter_slice1 = (reg_c2_layer1_arr1_overflow_counter >> 2) & 1
    reg_c2_layer1_arr1_w2_overflow_counter_slice2 = (reg_c2_layer1_arr1_overflow_counter >> 1) & 1
    reg_c2_layer1_arr1_w2_overflow_counter_slice3 = (reg_c2_layer1_arr1_overflow_counter >> 0) & 1
    reg_c2_layer1_arr0_overflow_counter_slice0 = reg_c2_layer1_arr0_w1_overflow_counter_slice0 | reg_c2_layer1_arr0_w2_overflow_counter_slice0
    reg_c2_layer1_arr0_overflow_counter_slice1 = reg_c2_layer1_arr0_w1_overflow_counter_slice1 | reg_c2_layer1_arr0_w2_overflow_counter_slice1
    reg_c2_layer1_arr0_overflow_counter_slice2 = reg_c2_layer1_arr0_w1_overflow_counter_slice2 | reg_c2_layer1_arr0_w2_overflow_counter_slice2
    reg_c2_layer1_arr0_overflow_counter_slice3 = reg_c2_layer1_arr0_w1_overflow_counter_slice3 | reg_c2_layer1_arr0_w2_overflow_counter_slice3
    reg_c2_layer1_arr1_overflow_counter_slice0 = reg_c2_layer1_arr1_w1_overflow_counter_slice0 | reg_c2_layer1_arr1_w2_overflow_counter_slice0
    reg_c2_layer1_arr1_overflow_counter_slice1 = reg_c2_layer1_arr1_w1_overflow_counter_slice1 | reg_c2_layer1_arr1_w2_overflow_counter_slice1
    reg_c2_layer1_arr1_overflow_counter_slice2 = reg_c2_layer1_arr1_w1_overflow_counter_slice2 | reg_c2_layer1_arr1_w2_overflow_counter_slice2
    reg_c2_layer1_arr1_overflow_counter_slice3 = reg_c2_layer1_arr1_w1_overflow_counter_slice3 | reg_c2_layer1_arr1_w2_overflow_counter_slice3

    for (data, key) in test.reg_c2_layer2_arr0_overflow_counter.entry_get(test.dev_tgt, [test.reg_c2_layer2_arr0_overflow_counter.make_key([gc.KeyTuple('$REGISTER_INDEX', key0 & (setup.LAYER2_ENTRY_SIZE-1))])], flags={'from_hw': True}):
        reg_c2_layer2_arr0_overflow_counter = data.to_dict()['Ingress.reg_c2_layer2_arr0_overflow_counter.f1'][0]
    for (data, key) in test.reg_c2_layer2_arr1_overflow_counter.entry_get(test.dev_tgt, [test.reg_c2_layer2_arr1_overflow_counter.make_key([gc.KeyTuple('$REGISTER_INDEX', key1 & (setup.LAYER2_ENTRY_SIZE-1))])], flags={'from_hw': True}):
        reg_c2_layer2_arr1_overflow_counter = data.to_dict()['Ingress.reg_c2_layer2_arr1_overflow_counter.f1'][0]
    reg_c2_layer2_arr0_w1_overflow_counter_slice0 = (reg_c2_layer2_arr0_overflow_counter >> 7) & 1
    reg_c2_layer2_arr0_w1_overflow_counter_slice1 = (reg_c2_layer2_arr0_overflow_counter >> 6) & 1
    reg_c2_layer2_arr0_w1_overflow_counter_slice2 = (reg_c2_layer2_arr0_overflow_counter >> 5) & 1
    reg_c2_layer2_arr0_w1_overflow_counter_slice3 = (reg_c2_layer2_arr0_overflow_counter >> 4) & 1
    reg_c2_layer2_arr0_w2_overflow_counter_slice0 = (reg_c2_layer2_arr0_overflow_counter >> 3) & 1
    reg_c2_layer2_arr0_w2_overflow_counter_slice1 = (reg_c2_layer2_arr0_overflow_counter >> 2) & 1
    reg_c2_layer2_arr0_w2_overflow_counter_slice2 = (reg_c2_layer2_arr0_overflow_counter >> 1) & 1
    reg_c2_layer2_arr0_w2_overflow_counter_slice3 = (reg_c2_layer2_arr0_overflow_counter >> 0) & 1
    reg_c2_layer2_arr1_w1_overflow_counter_slice0 = (reg_c2_layer2_arr1_overflow_counter >> 7) & 1
    reg_c2_layer2_arr1_w1_overflow_counter_slice1 = (reg_c2_layer2_arr1_overflow_counter >> 6) & 1
    reg_c2_layer2_arr1_w1_overflow_counter_slice2 = (reg_c2_layer2_arr1_overflow_counter >> 5) & 1
    reg_c2_layer2_arr1_w1_overflow_counter_slice3 = (reg_c2_layer2_arr1_overflow_counter >> 4) & 1
    reg_c2_layer2_arr1_w2_overflow_counter_slice0 = (reg_c2_layer2_arr1_overflow_counter >> 3) & 1
    reg_c2_layer2_arr1_w2_overflow_counter_slice1 = (reg_c2_layer2_arr1_overflow_counter >> 2) & 1
    reg_c2_layer2_arr1_w2_overflow_counter_slice2 = (reg_c2_layer2_arr1_overflow_counter >> 1) & 1
    reg_c2_layer2_arr1_w2_overflow_counter_slice3 = (reg_c2_layer2_arr1_overflow_counter >> 0) & 1
    reg_c2_layer2_arr0_overflow_counter_slice0 = reg_c2_layer2_arr0_w1_overflow_counter_slice0 | reg_c2_layer2_arr0_w2_overflow_counter_slice0
    reg_c2_layer2_arr0_overflow_counter_slice1 = reg_c2_layer2_arr0_w1_overflow_counter_slice1 | reg_c2_layer2_arr0_w2_overflow_counter_slice1
    reg_c2_layer2_arr0_overflow_counter_slice2 = reg_c2_layer2_arr0_w1_overflow_counter_slice2 | reg_c2_layer2_arr0_w2_overflow_counter_slice2
    reg_c2_layer2_arr0_overflow_counter_slice3 = reg_c2_layer2_arr0_w1_overflow_counter_slice3 | reg_c2_layer2_arr0_w2_overflow_counter_slice3
    reg_c2_layer2_arr1_overflow_counter_slice0 = reg_c2_layer2_arr1_w1_overflow_counter_slice0 | reg_c2_layer2_arr1_w2_overflow_counter_slice0
    reg_c2_layer2_arr1_overflow_counter_slice1 = reg_c2_layer2_arr1_w1_overflow_counter_slice1 | reg_c2_layer2_arr1_w2_overflow_counter_slice1
    reg_c2_layer2_arr1_overflow_counter_slice2 = reg_c2_layer2_arr1_w1_overflow_counter_slice2 | reg_c2_layer2_arr1_w2_overflow_counter_slice2
    reg_c2_layer2_arr1_overflow_counter_slice3 = reg_c2_layer2_arr1_w1_overflow_counter_slice3 | reg_c2_layer2_arr1_w2_overflow_counter_slice3

    # print(hex(reg_c2_layer1_arr0_w1_slice0), hex(reg_c2_layer1_arr0_w2_slice0), hex(reg_c2_layer1_arr0_slice0), reg_c2_layer1_arr0_overflow_counter_slice0, hex(reg_c2_layer2_arr0_slice0), reg_c2_layer2_arr0_overflow_counter_slice0, hex(reg_c2_layer3_arr0_slice0))
    # print(hex(reg_c2_layer1_arr0_w1_slice1), hex(reg_c2_layer1_arr0_w2_slice1), hex(reg_c2_layer1_arr0_slice1), reg_c2_layer1_arr0_overflow_counter_slice1, hex(reg_c2_layer2_arr0_slice1), reg_c2_layer2_arr0_overflow_counter_slice1, hex(reg_c2_layer3_arr0_slice1))
    # print(hex(reg_c2_layer1_arr0_w1_slice2), hex(reg_c2_layer1_arr0_w2_slice2), hex(reg_c2_layer1_arr0_slice2), reg_c2_layer1_arr0_overflow_counter_slice2, hex(reg_c2_layer2_arr0_slice2), reg_c2_layer2_arr0_overflow_counter_slice2, hex(reg_c2_layer3_arr0_slice2))
    # print(hex(reg_c2_layer1_arr0_w1_slice3), hex(reg_c2_layer1_arr0_w2_slice3), hex(reg_c2_layer1_arr0_slice3), reg_c2_layer1_arr0_overflow_counter_slice3, hex(reg_c2_layer2_arr0_slice3), reg_c2_layer2_arr0_overflow_counter_slice3, hex(reg_c2_layer3_arr0_slice3))

    if overflow_counter:
        result[0][0] = reg_c2_layer1_arr0_slice0 + (reg_c2_layer2_arr0_slice0 if reg_c2_layer1_arr0_overflow_counter_slice0 else 0) + (reg_c2_layer3_arr0_slice0 if reg_c2_layer1_arr0_overflow_counter_slice0 and reg_c2_layer2_arr0_overflow_counter_slice0 else 0)
        result[0][1] = reg_c2_layer1_arr0_slice1 + (reg_c2_layer2_arr0_slice1 if reg_c2_layer1_arr0_overflow_counter_slice1 else 0) + (reg_c2_layer3_arr0_slice1 if reg_c2_layer1_arr0_overflow_counter_slice1 and reg_c2_layer2_arr0_overflow_counter_slice1 else 0)
        result[0][2] = reg_c2_layer1_arr0_slice2 + (reg_c2_layer2_arr0_slice2 if reg_c2_layer1_arr0_overflow_counter_slice2 else 0) + (reg_c2_layer3_arr0_slice2 if reg_c2_layer1_arr0_overflow_counter_slice2 and reg_c2_layer2_arr0_overflow_counter_slice2 else 0)
        result[0][3] = reg_c2_layer1_arr0_slice3 + (reg_c2_layer2_arr0_slice3 if reg_c2_layer1_arr0_overflow_counter_slice3 else 0) + (reg_c2_layer3_arr0_slice3 if reg_c2_layer1_arr0_overflow_counter_slice3 and reg_c2_layer2_arr0_overflow_counter_slice3 else 0)

        result[1][0] = reg_c2_layer1_arr1_slice0 + (reg_c2_layer2_arr1_slice0 if reg_c2_layer1_arr1_overflow_counter_slice0 else 0) + (reg_c2_layer3_arr1_slice0 if reg_c2_layer1_arr1_overflow_counter_slice0 and reg_c2_layer2_arr1_overflow_counter_slice0 else 0)
        result[1][1] = reg_c2_layer1_arr1_slice1 + (reg_c2_layer2_arr1_slice1 if reg_c2_layer1_arr1_overflow_counter_slice1 else 0) + (reg_c2_layer3_arr1_slice1 if reg_c2_layer1_arr1_overflow_counter_slice1 and reg_c2_layer2_arr1_overflow_counter_slice1 else 0)
        result[1][2] = reg_c2_layer1_arr1_slice2 + (reg_c2_layer2_arr1_slice2 if reg_c2_layer1_arr1_overflow_counter_slice2 else 0) + (reg_c2_layer3_arr1_slice2 if reg_c2_layer1_arr1_overflow_counter_slice2 and reg_c2_layer2_arr1_overflow_counter_slice2 else 0)
        result[1][3] = reg_c2_layer1_arr1_slice3 + (reg_c2_layer2_arr1_slice3 if reg_c2_layer1_arr1_overflow_counter_slice3 else 0) + (reg_c2_layer3_arr1_slice3 if reg_c2_layer1_arr1_overflow_counter_slice3 and reg_c2_layer2_arr1_overflow_counter_slice3 else 0)
    else:
        result[0][0] = reg_c2_layer1_arr0_slice0 + reg_c2_layer2_arr0_slice0 + reg_c2_layer3_arr0_slice0
        result[0][1] = reg_c2_layer1_arr0_slice1 + reg_c2_layer2_arr0_slice1 + reg_c2_layer3_arr0_slice1
        result[0][2] = reg_c2_layer1_arr0_slice2 + reg_c2_layer2_arr0_slice2 + reg_c2_layer3_arr0_slice2
        result[0][3] = reg_c2_layer1_arr0_slice3 + reg_c2_layer2_arr0_slice3 + reg_c2_layer3_arr0_slice3

        result[1][0] = reg_c2_layer1_arr1_slice0 + reg_c2_layer2_arr1_slice0 + reg_c2_layer3_arr1_slice0
        result[1][1] = reg_c2_layer1_arr1_slice1 + reg_c2_layer2_arr1_slice1 + reg_c2_layer3_arr1_slice1
        result[1][2] = reg_c2_layer1_arr1_slice2 + reg_c2_layer2_arr1_slice2 + reg_c2_layer3_arr1_slice2
        result[1][3] = reg_c2_layer1_arr1_slice3 + reg_c2_layer2_arr1_slice3 + reg_c2_layer3_arr1_slice3

    return result

# Send test packets from swports[0] to swports[1]
# Send periodic packets for global_timeN_reg update from swports[1] to swports[0]
class PeriodicSender:
    def __init__(self, test, interval):
        self.test = test
        self.pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb", type=0)
        self.interval = interval
        self._stop_event = threading.Event()
        self._thread = None

    def _send_loop(self):
        while not self._stop_event.is_set():
            send_packet(self.test, self.test.swports[1], self.pkt)
            time.sleep(self.interval)

    def start(self):
        if self._thread and self._thread.is_alive():
            print("PeriodicSender is already running.")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._send_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join()

def wait_until_global_time_changes(test, gt_index, interval):
    if not 1 <= gt_index <= 3:
        raise ValueError(f"Invalid gt_index: {gt_index}")

    global_time_str = f"reg_global_time{gt_index}"
    global_time_reg = [test.reg_global_time1, test.reg_global_time2, test.reg_global_time3][gt_index-1]

    for (data, key) in global_time_reg.entry_get(test.dev_tgt, [global_time_reg.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])], flags={'from_hw': True}):
        old_global_time = data.to_dict()[f'Ingress.{global_time_str}.f1'][0]

    while True:
        time.sleep(interval)
        for (data, key) in global_time_reg.entry_get(test.dev_tgt, [global_time_reg.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])], flags={'from_hw': True}):
            new_global_time = data.to_dict()[f'Ingress.{global_time_str}.f1'][0]
        if new_global_time != old_global_time:
            return new_global_time
