#!/usr/bin/env python3
import os
from scapy.all import wrpcap, Ether, IP
from tqdm import tqdm
from crc import TofinoCRC32
import setup

manager_src_ip = "10.0.0.1" # Fixed or rotate as needed
def find_distinct_dst_ip() -> list[str]:
    found0 = {}
    found1 = {}
    max_val = 2**32 # Maximum number of IPs

    def int_to_ip(n: int) -> str:
        return f"{(n >> 24) & 0xFF}.{(n >> 16) & 0xFF}.{(n >> 8) & 0xFF}.{n & 0xFF}"

    for dst_ip_int in range(max_val):
        dst_ip = int_to_ip(dst_ip_int)
        reg_c2_key_a = TofinoCRC32.hash0(manager_src_ip, dst_ip)
        reg_c2_key_b = TofinoCRC32.hash1(manager_src_ip, dst_ip)
        key0 = reg_c2_key_a & (setup.LAYER1_ENTRY_SIZE-1)
        key1 = reg_c2_key_b & (setup.LAYER1_ENTRY_SIZE-1)
        if key0 not in found0 and key1 not in found1:
            found0[key0] = dst_ip
            found1[key1] = dst_ip
            if len(found0) == setup.LAYER1_ENTRY_SIZE:
                break
    return list(found0.values())

def write_management_pcap():
    distinct_dst_ip = find_distinct_dst_ip()
    packets = []
    src_mac = "00:98:76:54:32:10"
    dst_mac = "00:55:55:55:55:55"   # or some router/switch MAC

    for dst_ip in tqdm(distinct_dst_ip):
        pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=manager_src_ip, dst=dst_ip)
        # pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=manager_src_ip, dst=dst_ip) / TCP(flags="S")
        # pkt = pkt / Raw(b"\x00" * max(60 - len(pkt), 0))
        packets.append(pkt)

    path = os.path.dirname(os.path.realpath(__file__))
    wrpcap(f"{path}/management_packets_{setup.LAYER1_ENTRY_SIZE_EXP}.pcap", packets)

if __name__ == "__main__":
    write_management_pcap()
