#!/usr/bin/python3

##
## Control plane that support adaptive memory management
## 

import os
import sys
import pdb

##
## Params
## 

# TARGET_INTERFACE = "veth250" # Use Tofino-model for simulation: note that the model performance (pps) is low to make overflow
# TARGET_INTERFACE = "ens1" # Use bfrt_kpkt module for use user level interface with Tofino (CPU_PCIE)
TARGET_INTERFACE = "enp4s0f1" # Use bfrt_kpkt module for use user level interface with Tofino (CPU_ETHERNET, port:64)
THRESHOLD_APP1 = 11
THRESHOLD_APP2 = 11
THRESHOLD_APP3 = 11
THRESHOLD_APP4 = 11
GLOBAL_TIME_1_BITS = 33
WINDOW_SIZE_1_NS = 1 << GLOBAL_TIME_1_BITS # nanoseconds
WINDOW_SIZE_1 = WINDOW_SIZE_1_NS / 1e9 # seconds
THRESHOLDS = [THRESHOLD_APP1, THRESHOLD_APP2, THRESHOLD_APP3, THRESHOLD_APP4]
ENABLE_MIN_SHARE = True
MIN_SHARE = 5


# This is optional if you use proper PYTHONPATH

SDE_INSTALL   = os.environ['SDE_INSTALL']
SDE_PYTHON2   = os.path.join(SDE_INSTALL, 'lib', 'python2.7', 'site-packages')
sys.path.append(SDE_PYTHON2)
sys.path.append(os.path.join(SDE_PYTHON2, 'tofino'))

PYTHON3_VER   = '{}.{}'.format(
    sys.version_info.major,
    sys.version_info.minor)
SDE_PYTHON3   = os.path.join(SDE_INSTALL, 'lib', 'python' + PYTHON3_VER,
                             'site-packages')
sys.path.append(SDE_PYTHON3)
sys.path.append(os.path.join(SDE_PYTHON3, 'tofino'))
sys.path.append(os.path.join(SDE_PYTHON3, 'tofino', 'bfrt_grpc'))

# bfrt grpc
import grpc
import bfrt_grpc.client as gc
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2

# test utils
from ptf import config
import ptf.testutils as testutils
# from bfruntime_client_base_tests import BfRuntimeTest

# Others
from tabulate import tabulate
import time
import itertools
import threading
import math
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether
from functools import partial
from cms import CountMinSketch
from co_monitor import CoMonitor
from crc import TofinoCRC32
import random

# For 4 apps in a register
old_cms_values = [{} for _ in range(4)]
# counter
n_processed_pkts = 0
processed_packet_counts = []
lock = threading.Lock()


# Callback of sniff(), parse the packet and send to co-monitoring
def packet_callback(packet, target, bfrt_info, co_monitor):
    # Parse the packet and print the information: IP
    src_ip = None
    dst_ip = None
    proto = None
    src_port = None
    dst_port = None
    identifier = None

    global n_processed_pkts
    with lock:
        n_processed_pkts += 1

    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        identifier = ip_layer.id
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto
        # print(f"IP Packet: src={src_ip}, dst={dst_ip}, proto={proto}")
        
        # Parse the packet and print the information: TCP or UDP
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            # print(f"TCP Segment: sport={src_port}, dport={dst_port}")
        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            # print(f"UDP Segment: sport={src_port}, dport={dst_port}")
        elif packet.haslayer(ICMP):
            icmp_layer = packet.getlayer(ICMP)
            src_port = 0 # ICMP has no port
            dst_port = 0 
            # print(f"[Sniffer] ICMP Packet: type={icmp_layer.type}, code={icmp_layer.code}, id={icmp_layer.id}, seq={icmp_layer.seq}")
        else:
            print("[Sniffer] Non-TCP/UDP/ICMP Packet captured")
            packet.show()
    else:
        print("[Sniffer] Non-IP Packet captured")
        # Occasionally IPV6 Packet captured...
        # packet.show()
        return

    if src_ip == "0.0.0.0" and dst_ip == "255.255.255.255":
        print("[Sniffer] Broadcast packet ignored (src=0.0.0.0, dst=255.255.255.255)")
        return  # Ignore broadcast packet

    # Extract data from ID field
    flow_time_window = (identifier >> 15) & 0x1

    arr1_app1_flood = (identifier >> 13) & 0x1
    arr1_app2_flood = (identifier >> 12) & 0x1
    arr1_app3_flood = (identifier >> 11) & 0x1
    arr1_app4_flood = (identifier >> 10) & 0x1

    arr2_app1_flood = (identifier >> 8) & 0x1
    arr2_app2_flood = (identifier >> 7) & 0x1
    arr2_app3_flood = (identifier >> 6) & 0x1
    arr2_app4_flood = (identifier >> 5) & 0x1

    arr3_app1_flood = (identifier >> 3) & 0x1
    arr3_app2_flood = (identifier >> 2) & 0x1
    arr3_app3_flood = (identifier >> 1) & 0x1
    arr3_app4_flood = (identifier >> 0) & 0x1

    # update_array_index = [arr1_flood, arr2_flood, arr3_flood]
    app1_overflow_data = [arr1_app1_flood, arr2_app1_flood, arr3_app1_flood]
    app2_overflow_data = [arr1_app2_flood, arr2_app2_flood, arr3_app2_flood]
    app3_overflow_data = [arr1_app3_flood, arr2_app3_flood, arr3_app3_flood]
    app4_overflow_data = [arr1_app4_flood, arr2_app4_flood, arr3_app4_flood]
    overflowed_datas = [app1_overflow_data, app2_overflow_data, app3_overflow_data, app4_overflow_data]

    # crc_result = TofinoCRC32.hash0(src_ip, dst_ip)
    # print(f"Computed reg_c2_key_a: 0x{crc_result:08X}")
    # crc_result = TofinoCRC32.hash1(src_ip, dst_ip)
    # print(f"Computed reg_c2_key_b: 0x{crc_result:08X}")
    
    # print(f"[DEBUG][Co-monitor] Update CMS: src={src_ip}, dst={dst_ip}")
    for i, overflowed_data in enumerate(overflowed_datas):
        # For task id i, update CMS
        read_value = co_monitor.update(i, [src_ip, dst_ip, src_port, dst_port, proto], overflowed_data, flow_time_window)
        
        cms_indexes = co_monitor.cms[0][i].keys((src_ip, dst_ip))  
        # old_value = min([old_cms_values[i].get((depth_idx, cms_index), 0) for depth_idx, cms_index in enumerate(cms_indexes)])
        old_value = min([old_cms_values[i].get((depth, cms_index), 0) for depth, cms_index in zip(range(len(cms_indexes)), cms_indexes)])

        total_value = read_value + old_value
        
        # Check if the read value exceeds the threshold
        # TODO: Add the blocklist management: e.g.,release blocklist after a certain time
        if total_value > THRESHOLDS[i]:
            print(f"[Co-monitor] Task {i} - Read value: {read_value}, Old value: {old_value}, Total value: {total_value}")
            try:
                print(f"[Co-monitor] Task {i} - Add to Blocklist: has filtered: IP_PAIR({src_ip}, {dst_ip})")
                blocklist = bfrt_info.table_get('SwitchIngress.check_blocklist')
                blocklist.info.key_field_annotation_add('hdr.ipv4.src_addr', 'ipv4')
                blocklist.info.key_field_annotation_add('hdr.ipv4.dst_addr', 'ipv4')

                key = blocklist.make_key([
                    gc.KeyTuple('hdr.ipv4.src_addr', src_ip),
                    gc.KeyTuple('hdr.ipv4.dst_addr', dst_ip)
                ])
                data = blocklist.make_data([], 'SwitchIngress.drop_packet')

                try:
                    blocklist.entry_add(target, [key], [data])  
                except gc.BfruntimeRpcException as e:
                    if "ALREADY_EXISTS" in str(e):
                        print("[Co-monitor] Entry already exists, modifying instead.")
                        blocklist.entry_mod(target, [key], [data])  
                    else:
                        raise e  
            except Exception as e:
                print("[Co-monitor] ERROR: Failed to update blocklist table entry:", e)
                sys.exit()



def change_adaptive_memory(current_counter_sizes, n_tasks, current_cp_max):
    ideal_shares = [0] * n_tasks
    for task_id in range(n_tasks):
        # "data plane bit usage" "- 1" : carry bit for check overflow
        ideal_shares[task_id] = current_counter_sizes[task_id]-1 + bits_used(current_cp_max[task_id])
    # register_size = 32
    register_size = sum(current_counter_sizes)
    base_shares = calculate_shares(register_size, ideal_shares, ENABLE_MIN_SHARE)

    return base_shares


def calculate_shares(register_size: int, ideal_shares: list[float], is_min_share: bool):
    if is_min_share:
        min_share = MIN_SHARE
        if min_share*len(ideal_shares) > register_size:
            raise ValueError("Cannot distribute shares while respecting the minimum share and total sum requirement.")

    denom = sum(ideal_shares)
    denom = denom if denom > 0 else 1
    effective_register_size = register_size - len(ideal_shares)
    ideal_shares = [x / denom * effective_register_size for x in ideal_shares]
    base_shares = [math.floor(x) for x in ideal_shares]
    remaining = effective_register_size - sum(base_shares)
    decimals = list_elementwise_sub(ideal_shares, base_shares)
    while remaining > 0:
        sorted_indices = sorted(range(len(decimals)), key=lambda i: decimals[i], reverse=True)
        base_shares[sorted_indices[0]] += 1
        decimals[sorted_indices[0]] -= 1
        remaining -= 1

    if is_min_share:
        min_share -= 1
        deficit = 0
        for i in range(len(base_shares)):
            if base_shares[i] < min_share:
                deficit += (min_share - base_shares[i])
                base_shares[i] = min_share
                decimals[i] = float('inf')
        while deficit > 0:
            sorted_indices = sorted(range(len(decimals)), key=lambda i: (decimals[i], -base_shares[i]))
            for i in range(len(base_shares)):
                if base_shares[sorted_indices[i]] > min_share:
                    base_shares[sorted_indices[i]] -= 1
                    decimals[sorted_indices[i]] += 1
                    deficit -= 1
                    break

    return [x + 1 for x in base_shares]

def bits_used(n: int) -> float:
    return math.log2(n)+1 if n > 0 else 0

def bit_to_num (n: int):
    return n.bit_length()

def list_elementwise_add(list1: list[int], list2: list[int]) -> list[int]:
    if len(list1) != len(list2):
        raise ValueError(f"Two lists have different sizes: {len(list1)} and {len(list2)}")
    return [x + y for x, y in zip(list1, list2)]

def list_elementwise_sub(list1: list[int], list2: list[int]) -> list[int]:
    if len(list1) != len(list2):
        raise ValueError(f"Two lists have different sizes: {len(list1)} and {len(list2)}")
    return [x - y for x, y in zip(list1, list2)]


def calc_dyn_table(new_slice):
    total_bits = sum(new_slice)
    if total_bits != 32:
        raise ValueError(f"Total bits is {total_bits}, not 32 bits register!!")
    increment_vals = []
    for bits in new_slice:
        total_bits -= bits
        increment_vals.append(1 << total_bits)
    return increment_vals

def calc_dyn_resubmit(new_slice):
    mask = 0
    total_bits = sum(new_slice)
    current_bit = total_bits

    for bits in new_slice:
        current_bit -= bits
        mask |= ((1 << (bits - 1)) - 1) << current_bit

    return mask

def update_dyn_table(bfrt_info, target, icmp_only, udp_only, syn_only, dnsq_only, resub_to_update, target_global_time):
    reg_c2_dyn = bfrt_info.table_get('SwitchIngress.reg_c2_dyn_table')
    keys = []
    datas = []
    c2_flags = ["icmpq_flag", "udp_flag", "syn_flag", "dnsq_flag", "resubmit_flag"]
    combinations = itertools.product([0, 1], repeat=len(c2_flags))

    for combo in combinations:
        flag_values = dict(zip(c2_flags, combo))
        if flag_values["resubmit_flag"] == 1:
            to_update_value = resub_to_update
            key = reg_c2_dyn.make_key([
                gc.KeyTuple('icmpq_flag', flag_values["icmpq_flag"]),
                gc.KeyTuple('udp_flag', flag_values["udp_flag"]),
                gc.KeyTuple('syn_flag', flag_values["syn_flag"]),
                gc.KeyTuple('dnsq_flag', flag_values["dnsq_flag"]),
                gc.KeyTuple('ig_intr_md.resubmit_flag', 1),
                gc.KeyTuple('global_time1', target_global_time) 
            ])
            keys.append(key)
            datas.append(reg_c2_dyn.make_data([gc.DataTuple('slices', to_update_value)], 'SwitchIngress.reg_c2_reset'))
            continue
        else:
            to_update_value = 0x0
            if flag_values["icmpq_flag"] == 1:
                to_update_value += icmp_only
            if flag_values["udp_flag"] == 1:
                to_update_value += udp_only
            if flag_values["syn_flag"] == 1:
                to_update_value += syn_only
            if flag_values["dnsq_flag"] == 1:
                to_update_value += dnsq_only
            key = reg_c2_dyn.make_key([
                gc.KeyTuple('icmpq_flag', flag_values["icmpq_flag"]),
                gc.KeyTuple('udp_flag', flag_values["udp_flag"]),
                gc.KeyTuple('syn_flag', flag_values["syn_flag"]),
                gc.KeyTuple('dnsq_flag', flag_values["dnsq_flag"]),
                gc.KeyTuple('ig_intr_md.resubmit_flag', 0),
                gc.KeyTuple('global_time1', target_global_time) 
            ])
            keys.append(key)
            datas.append(reg_c2_dyn.make_data([gc.DataTuple('slices', to_update_value)], 'SwitchIngress.reg_c2_merge'))
            continue
    try:
        reg_c2_dyn.entry_mod(target, keys, datas)
    except Exception as e:
        print("[Resource Manager] ERROR: Failed to update table entry:", e)
        sys.exit()

def calc_slicing_table(new_slice):
    masks = []
    total_bits = sum(new_slice)

    # Carry bit mask
    carry_mask = sum(1 << (total_bits - sum(new_slice[:i]) - 1) for i in range(len(new_slice)))
    masks.append(carry_mask)

    # Masks for each app
    current_bit = total_bits
    for bits in new_slice:
        current_bit -= bits
        mask = ((1 << bits) - 1) << current_bit
        masks.append(mask)

    return masks

def update_slicing_table(bfrt_info, target, mask1, mask2, mask3, mask4, mask5, target_global_time):
    slicing = bfrt_info.table_get('SwitchIngress.reg_c2_slicing_table')
    slicing_flags = ["icmpq_flag", "udp_flag", "syn_flag", "dnsq_flag"]
    combinations = itertools.product([0, 1], repeat=len(slicing_flags))
    keys = []
    datas = []
    for combo in combinations:
        flag_values = dict(zip(slicing_flags, combo))
        if flag_values["icmpq_flag"] == 1 \
            or flag_values["udp_flag"] == 1 \
            or flag_values["syn_flag"] == 1 \
            or flag_values["dnsq_flag"] == 1:
            key = slicing.make_key([
                gc.KeyTuple('icmpq_flag', flag_values["icmpq_flag"]),
                gc.KeyTuple('udp_flag', flag_values["udp_flag"]),
                gc.KeyTuple('syn_flag', flag_values["syn_flag"]),
                gc.KeyTuple('dnsq_flag', flag_values["dnsq_flag"]),
                gc.KeyTuple('global_time1', target_global_time)
            ])
            keys.append(key)
            datas.append(slicing.make_data([gc.DataTuple('mask1', mask1),
                                            gc.DataTuple('mask2', mask2),
                                            gc.DataTuple('mask3', mask3),
                                            gc.DataTuple('mask4', mask4),
                                            gc.DataTuple('mask5', mask5)], 
                                            'SwitchIngress.extract_reg_c2_slicing_action'))
    try:
        slicing.entry_mod(target, keys, datas)
    except Exception as e:
        print("[Resource Manager] ERROR: Failed to update table entry:", e)
        sys.exit()

def calc_overflow_table(new_slice):
    flood_flags = []
    total_bits = sum(new_slice)
    current_bit = total_bits

    for bits in new_slice:
        current_bit -= bits
        flood_flag = 1 << (current_bit + bits - 1)
        flood_flags.append(flood_flag)

    return flood_flags

old_keys = []

def update_overflow_table(bfrt_info, target, slice, mode, target_global_time):
    check_overflow = bfrt_info.table_get('SwitchIngress.reg_c2_overflow_table')
    app1_flood_value, app2_flood_value, app3_flood_value, app4_flood_value = calc_overflow_table(slice)
    flood_values = [
        app1_flood_value,  # app1_flood
        app2_flood_value,  # app2_flood
        app3_flood_value,  # app3_flood
        app4_flood_value   # app4_flood
    ]
    possible_flood_values = [0] + [sum(combo) for i in range(1, len(flood_values) + 1) 
                            for combo in itertools.combinations(flood_values, i)]

    global old_keys

    keys = []
    datas = []
    new_keys = []

    for arr0, arr1, arr2, global_time1 in itertools.product(possible_flood_values, possible_flood_values, possible_flood_values, target_global_time):
        mirror_tag = 0
        if global_time1 == 1:
            mirror_tag += 0b1000000000000000
        if arr0 != 0:
            mirror_tag += 0b0100000000000000
            if arr0 & app1_flood_value:
                mirror_tag += 0b0010000000000000
            if arr0 & app2_flood_value:
                mirror_tag += 0b0001000000000000
            if arr0 & app3_flood_value:
                mirror_tag += 0b0000100000000000
            if arr0 & app4_flood_value:
                mirror_tag += 0b0000010000000000
        if arr1 != 0:
            mirror_tag += 0b0000001000000000
            if arr1 & app1_flood_value:
                mirror_tag += 0b0000000100000000
            if arr1 & app2_flood_value:
                mirror_tag += 0b0000000010000000
            if arr1 & app3_flood_value:
                mirror_tag += 0b0000000001000000
            if arr1 & app4_flood_value:
                mirror_tag += 0b0000000000100000
        if arr2 != 0:
            mirror_tag += 0b0000000000010000
            if arr2 & app1_flood_value:
                mirror_tag += 0b0000000000001000
            if arr2 & app2_flood_value:
                mirror_tag += 0b0000000000000100
            if arr2 & app3_flood_value:
                mirror_tag += 0b0000000000000010
            if arr2 & app4_flood_value: 
                mirror_tag += 0b0000000000000001
        if mirror_tag == 0 or mirror_tag == 0x8000:
            # No overflow: do nothing
            continue
        else:
            key = check_overflow.make_key([
                gc.KeyTuple('reg_c2_overflow_flag_arr0', arr0),
                gc.KeyTuple('reg_c2_overflow_flag_arr1', arr1),
                gc.KeyTuple('reg_c2_overflow_flag_arr2', arr2),
                gc.KeyTuple('global_time1', global_time1)
            ])
            new_keys.append(key)
            keys.append(key)
            data = check_overflow.make_data([gc.DataTuple('tag', mirror_tag)], 'SwitchIngress.set_mirror_flag_action')
            datas.append(data)
    try:
        if mode == "add":
            check_overflow.entry_add(target, keys, datas)
            old_keys = new_keys
        elif mode == "del":
            check_overflow.entry_del(target, old_keys)
            old_keys = [] 
    except Exception as e:
        print("[Resource Manager] ERROR: Failed to update table entry:", e)
        sys.exit()

def get_switch_global_time(bfrt_info, target):
    register = bfrt_info.table_get('SwitchIngress.global_time1_reg')
    register_idx = 0
    resp = register.entry_get(
        target, 
        [register.make_key([gc.KeyTuple('$REGISTER_INDEX', register_idx)])], 
        {'from_hw': True})
    data, _ = next(resp)
    # print(data.to_dict())
    current_global_time = data.to_dict()['SwitchIngress.global_time1_reg.f1'][0]
    return current_global_time

# Re calculate memory slice for new time window
def memory_slice_manager(bfrt_info, target, co_monitor, interval):
    current_slice = [8] * 4
    old_slice_dict = {0: [8] * 4, 1: [8] * 4}
    old_global_time = 0
    global old_cms_values

    while True:
        next_global_time = 0
        # Get timestam
        current_global_time = get_switch_global_time(bfrt_info, target)
        # print(f"[DEBUG][Resource Manager] Current global_time1_reg.f1: {current_global_time}")
        if current_global_time == old_global_time:
            time.sleep(interval)
            continue
        else:
            time.sleep(WINDOW_SIZE_1 - 2.5) # Sleep until 2.5 seconds before the end of the time window
            old_global_time = current_global_time

            print(f"[Resource Manager] Current timestamp: {current_global_time}")
            next_global_time = 1 if current_global_time == 0 else 0

            # Measure the time taken for slice update
            start_time = time.time()

            # Store cms value berfore reset
            print("[Resource Manager] Store CMS values before reset")
            t1 = time.time()
            for i in range(4):  
                old_cms_values[i] = co_monitor.get_current_counts(i, next_global_time)
            t2 = time.time()
            print(f"[Resource Manager] Store CMS values time: {t2 - t1:.6f} seconds")
            print("[Resource Manager] store finished")

            # # update current_max just in case of no traffic
            # co_monitor.current_max[next_global_time] = [  
            #     max(old_cms_values[i].values(), default=0) for i in range(4)
            # ]

            # Update slice
            print("[Resource Manager] Calculating New Memory Slice")
            t1 = time.time()
            old_slice = old_slice_dict[next_global_time]
            print(f"[Debug] co_monitor.current_max[{next_global_time}]: {co_monitor.get_current_max(next_global_time)}")
            current_slice = change_adaptive_memory(current_slice, 4, co_monitor.get_current_max(current_global_time))
            print(f"[Resource Manager] Old Slice: {old_slice}, New Slice: {current_slice}")
            # Update old slice
            old_slice_dict[next_global_time] = current_slice 
            t2 = time.time()
            print(f"[Resource Manager] Slice calculation time: {t2 - t1:.6f} seconds")

            print("[Resource Manager] Updated table entry")
            t1 = time.time()
            # TODO: change the table entry of dyn, slice,
            # reg_c2_dyn_table
            icmp_only, udp_only, syn_only, dnsq_only = calc_dyn_table(current_slice)
            resub_to_update = calc_dyn_resubmit(current_slice)
            update_dyn_table(bfrt_info, target, icmp_only, udp_only, syn_only, dnsq_only, resub_to_update, next_global_time)

            # reg_c2_slicing_table
            mask1, mask2, mask3, mask4, mask5 = calc_slicing_table(current_slice)
            update_slicing_table(bfrt_info, target, mask1, mask2, mask3, mask4, mask5, next_global_time)

            # reg_c2_overflow_table
            update_overflow_table(bfrt_info, target, old_slice, "del", [next_global_time]) # Delete previous entry
            update_overflow_table(bfrt_info, target, current_slice, "add", [next_global_time]) # Add new entry
            t2 = time.time()
            print(f"[Resource Manager] Table update time: {t2 - t1:.6f} seconds")
            # reg_c_timer2: Next flow will automatically delete the previous value when the next time window starts
            # # Clear next register
            # register = bfrt_info.table_get('SwitchIngress.reg_c2_w' + str(next_global_time + 1) + '_0')
            # register.entry_del(target, [])
            
            # reset the counter of co-monitor
            t1 = time.time()
            co_monitor.reset(next_global_time)
            t2 = time.time()
            print(f"[Resource Manager] Reset CMS time: {t2 - t1:.6f} seconds")

            # Measure end time
            end_time = time.time()
            elapsed_time = end_time - start_time

            print(f"[DEBUG][Resource Manager] Slice calculation and update time: {elapsed_time:.6f} seconds")

            # Sleep until next time window
            time.sleep(interval)

def monitor_packet_counts():
    """Monitor and log packet counts every 0.1 seconds."""
    global n_processed_pkts
    while True:
        time.sleep(0.1)  # Sleep for 0.1 seconds
        with lock:
            processed_packet_counts.append(n_processed_pkts)
            print(f"[DEBUG] Processed Packets: {processed_packet_counts}")
            n_processed_pkts = 0  # Reset counter

if __name__ == "__main__":
    try:
        interface = gc.ClientInterface(
            grpc_addr = 'localhost:50052',
            client_id = 0,
            device_id = 0,
            num_tries = True)
        print('Connected to BF Runtime Server as client id: ', str(0))
    except:
        print('Could not connect to BF Runtime server')
        sys.exit()

    target = gc.Target(device_id=0, pipe_id=0xFFFF)
    print('Connected to BfRt Server!')

    # Get the information about the running program
    bfrt_info = interface.bfrt_info_get()
    print('The target runs the program ', bfrt_info.p4_name_get())

    # Establish that you are working with this program
    interface.bind_pipeline_config(bfrt_info.p4_name_get())

    # # Print the list of tables in the "pipe" node
    # data = []
    # for name in bfrt_info.table_dict.keys():
    #     if name.split('.')[0] == 'pipe':
    #         # pdb.set_trace()
    #         t = bfrt_info.table_get(name)
    #         table_name = t.info.name_get()
    #         if table_name != name:
    #             continue
    #         table_type = t.info.type_get()
    #         try:
    #             result = t.usage_get(target)
    #             table_usage = next(result)
    #         except:
    #             table_usage = 'n/a'
    #         table_size = t.info.size_get()
    #         data.append([table_name, table_type, table_usage, table_size])
    # print(tabulate(data, headers=['Full Table Name','Type','Usage','Capacity']))

    ################### You can now use BFRT CLIENT ###########################
    print("Start Cerberus Control Plane")
    print("current window size: ", WINDOW_SIZE_1)

    ## Start cerberus control plane logic 
    # Initialize co-monitoring
    co_monitor = CoMonitor(n_task=4, counter_size_per_tasks=[32, 32, 32, 32], array_size_per_tasks=[16, 16, 16, 16], n_hash=3, n_window=2)

    # Start memory slicing manager thread
    memory_slicing_thread = threading.Thread(target=memory_slice_manager, args=(bfrt_info, target, co_monitor, (WINDOW_SIZE_1 / 100)))
    memory_slicing_thread.daemon = True  # Exit when the main thread exits
    memory_slicing_thread.start()

    threading.Thread(target=monitor_packet_counts, daemon=True).start()

    # Start sniffing
    sniff_tgt_iface = TARGET_INTERFACE
    print(f"Start sniffing: {sniff_tgt_iface}")
    sniff(iface=sniff_tgt_iface, prn=partial(packet_callback, target=target, bfrt_info=bfrt_info, co_monitor=co_monitor), store=False)
