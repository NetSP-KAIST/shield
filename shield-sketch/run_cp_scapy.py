#!/usr/bin/env python3

##
## Shield control plane
## 

import os
import sys
import pdb

# This is optional if you use proper PYTHONPATH
if __name__ == "__main__":
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
import threading
from scapy.all import sendp, sniff, Ether, IP, TCP, UDP, ICMP
from scapy.utils import rdpcap
from functools import partial
from co_monitor import CoMonitor
import setup

#####################################################################
#   Change these constants for different shapes and configuration   #
#####################################################################
# TARGET_INTERFACE = "veth250"    # Use Tofino-model for simulation: note that the model performance (pps) is low to make overflow
TARGET_INTERFACE = "ens1"       # Use bfrt_kpkt module for use user level interface with Tofino (CPU_PCIE)
# TARGET_INTERFACE = "enp4s0f1"   # Use bfrt_kpkt module for use user level interface with Tofino (CPU_ETHERNET, port:64)
#####################################################################
#   Change these constants for different shapes and configuration   #
#####################################################################

WINDOW_SIZE_1_NS = 1 << setup.GLOBAL_TIME1  # nanoseconds
WINDOW_SIZE_2_NS = 1 << setup.GLOBAL_TIME2  # nanoseconds
WINDOW_SIZE_3_NS = 1 << setup.GLOBAL_TIME3  # nanoseconds
WINDOW_SIZE_1 = WINDOW_SIZE_1_NS / 1e9      # seconds
WINDOW_SIZE_2 = WINDOW_SIZE_2_NS / 1e9      # seconds
WINDOW_SIZE_3 = WINDOW_SIZE_3_NS / 1e9      # seconds

class ControlPlane:
    def __init__(self, bfrt_info, target, do_setup: bool, do_manage: bool, do_sniff: bool):
        self.target = target

        # counter
        self.uploaded_packet_counts = []
        self.n_processed_pkts = 0
        self.processed_packet_counts = []
        self.lock = threading.Lock()

        self.tables = setup.tables(bfrt_info)
        if do_setup:
            setup.cleanUp(self.target, list(self.tables.values()))
            setup.setUp(bfrt_info, self.target, do_decay=True, do_block=True)

        ## Start Shield control plane logic
        # Start packet monitoring thread
        threading.Thread(target=self.monitor_uploaded_packet_counts, daemon=True).start()
        threading.Thread(target=self.monitor_processed_packet_counts, daemon=True).start()

        if do_manage:
            path = os.path.dirname(os.path.realpath(__file__))
            self.management_pkts = rdpcap(f"{path}/management_packets_{setup.LAYER1_ENTRY_SIZE_EXP}.pcap")

            # Start manager threads - clear entries in layer 1, decay entries in layer 2 and 3, and clear overflow counters
            threading.Thread(target=self.manager, daemon=True).start()

        if do_sniff:
            # Initialize co-monitoring
            co_monitor = CoMonitor(n_task=4, layer3_array_size_exp_per_tasks=[setup.LAYER3_ENTRY_SIZE_EXP]*4, decay_amount=2)

            # Start sniffing
            sniff_tgt_iface = TARGET_INTERFACE
            print(f"Start sniffing: {sniff_tgt_iface}")
            threading.Thread(target=sniff, kwargs={"iface": sniff_tgt_iface, "filter": "inbound", "prn": partial(self.packet_callback, co_monitor=co_monitor), "store": False}, daemon=True).start()
            # sniff(iface=sniff_tgt_iface, filter="inbound", prn=partial(self.packet_callback, co_monitor=co_monitor), store=False)
        print("Control plane is now fully running.")

    # Callback of sniff(), parse the packet and send to co-monitoring
    def packet_callback(self, packet, co_monitor):
        raw = bytes(packet)
        upload_type = int.from_bytes(raw[:2], byteorder='big')
        packet = Ether(raw[2:])

        # Parse the packet and print the information: IP
        src_ip = None
        dst_ip = None
        proto = None
        src_port = None
        dst_port = None

        with self.lock:
            self.n_processed_pkts += 1

        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
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

        # Extract data from upload_type
        layer3_overflowed = (upload_type >> 8) & 0x1
        if layer3_overflowed:
            arr0_app0_overflowed = (upload_type >> 7) & 0x1
            arr0_app1_overflowed = (upload_type >> 6) & 0x1
            arr0_app2_overflowed = (upload_type >> 5) & 0x1
            arr0_app3_overflowed = (upload_type >> 4) & 0x1

            arr1_app0_overflowed = (upload_type >> 3) & 0x1
            arr1_app1_overflowed = (upload_type >> 2) & 0x1
            arr1_app2_overflowed = (upload_type >> 1) & 0x1
            arr1_app3_overflowed = (upload_type >> 0) & 0x1

            app0_overflow_data = [arr0_app0_overflowed, arr1_app0_overflowed]
            app1_overflow_data = [arr0_app1_overflowed, arr1_app1_overflowed]
            app2_overflow_data = [arr0_app2_overflowed, arr1_app2_overflowed]
            app3_overflow_data = [arr0_app3_overflowed, arr1_app3_overflowed]
            overflowed_data = [app0_overflow_data, app1_overflow_data, app2_overflow_data, app3_overflow_data]

            # crc_result = TofinoCRC32.hash0(src_ip, dst_ip)
            # print(f"Computed reg_c2_key_a: 0x{crc_result:08X}")
            # crc_result = TofinoCRC32.hash1(src_ip, dst_ip)
            # print(f"Computed reg_c2_key_b: 0x{crc_result:08X}")

            # print(f"[DEBUG][Co-monitor] Update CMS: src={src_ip}, dst={dst_ip}")
            for i, overflowed in enumerate(overflowed_data):
                # For task id i, update CMS
                read_value = co_monitor.plus(i, [src_ip, dst_ip, src_port, dst_port, proto], overflowed)

                # Check if the read value exceeds the threshold
                # TODO: Add the blocklist management: e.g.,release blocklist after a certain time
                if (read_value << (setup.LAYER1_BIT_SIZE + setup.LAYER2_BIT_SIZE + setup.LAYER3_BIT_SIZE - 3)) > setup.THRESHOLDS[i]:
                    print(f"[Co-monitor] Task {i} - Read value: {read_value}")
                    try:
                        print(f"[Co-monitor] Task {i} - Add to Blocklist: has filtered: IP_PAIR({src_ip}, {dst_ip})")
                        blocklist = self.tables['check_blocklist']
                        blocklist.info.key_field_annotation_add('hdr.ipv4.src_addr', 'ipv4')
                        blocklist.info.key_field_annotation_add('hdr.ipv4.dst_addr', 'ipv4')

                        key = blocklist.make_key([
                            gc.KeyTuple('hdr.ipv4.src_addr', src_ip),
                            gc.KeyTuple('hdr.ipv4.dst_addr', dst_ip)
                        ])
                        data = blocklist.make_data([], 'Ingress.drop')

                        try:
                            blocklist.entry_add(self.target, [key], [data])  
                        except gc.BfruntimeRpcException as e:
                            if "ALREADY_EXISTS" in str(e):
                                print("[Co-monitor] Entry already exists, modifying instead.")
                                blocklist.entry_mod(self.target, [key], [data])  
                            else:
                                raise e  
                    except Exception as e:
                        print("[Co-monitor] ERROR: Failed to update blocklist table entry:", e)
                        sys.exit()
        else:   # blocklist request from data plane
            pass

    def get_switch_global_time(self, gt_index: int):
        if not 1 <= gt_index <= 3:
            raise ValueError(f"Invalid gt_index: {gt_index}")

        global_time_str = f'reg_global_time{gt_index}'
        global_time_reg = self.tables[global_time_str]
        for (data, key) in global_time_reg.entry_get(self.target, [global_time_reg.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])], flags={'from_hw': True}):
            global_time = data.to_dict()[f'Ingress.{global_time_str}.f1'][0]
        return global_time

    # Manage each layer by sending packets
    def manager(self, interval=WINDOW_SIZE_1 / 100):
        prev_global_time1 = 0
        elapsed_time = WINDOW_SIZE_1

        while True:
            curr_global_time1 = self.get_switch_global_time(1)
            # print(f"[DEBUG][Manager] Current global_time1_reg.f1: {curr_global_time1}")

            if curr_global_time1 != prev_global_time1:
                time.sleep(max(WINDOW_SIZE_1 - elapsed_time*1.3, 0))    # Sleep until (elapsed_time*1.3) seconds before the end of the time window
                prev_global_time1 = curr_global_time1
                print(f"[Manager] Current global_time1: {curr_global_time1}")

                # Measure the time taken for slice update
                start_time = time.time()

                sendp(self.management_pkts, iface=TARGET_INTERFACE, verbose=False)

                # Measure end time
                end_time = time.time()
                elapsed_time = end_time - start_time
                print(f"[DEBUG][Manager] Sent management packets: {elapsed_time:.6f} seconds")

            time.sleep(interval)

    def monitor_uploaded_packet_counts(self):
        """Monitor and log uploaded packet counts every 0.2 seconds."""
        to_cpu_counter = bfrt_info.table_get('Ingress.to_cpu_counter')
        key = to_cpu_counter.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])
        interval = 0.2  # s
        next_time = time.time()
        while True:
            current_time = time.time()
            while current_time < next_time:
                time.sleep(next_time - current_time)
                current_time = time.time()

            for (data, _) in to_cpu_counter.entry_get(target, [key], {'from_hw': True}):
                uploaded_pkts = data.to_dict()['Ingress.to_cpu_counter.f1'][0]
            self.uploaded_packet_counts.append((uploaded_pkts, time.time()))
            # print(f"[DEBUG] Uploaded Packets: {self.uploaded_packet_counts}")

            next_time = current_time + interval

    def monitor_processed_packet_counts(self):
        """Monitor and log processed packet counts every 0.2 seconds."""
        interval = 0.2  # s
        next_time = time.time()
        while True:
            current_time = time.time()
            while current_time < next_time:
                time.sleep(next_time - current_time)
                current_time = time.time()

            with self.lock:
                self.processed_packet_counts.append((self.n_processed_pkts, time.time()))
                # print(f"[DEBUG] Processed Packets: {self.processed_packet_counts}")

            next_time = current_time + interval

if __name__ == "__main__":
    try:
        interface = gc.ClientInterface(
            grpc_addr = 'localhost:50052',
            client_id = 0,
            device_id = 0,
            num_tries = 1)
        print('Connected to BF Runtime Server as client', str(0))
    except:
        print('Could not connect to BF Runtime server')
        quit

    # Get the information about the running program
    bfrt_info = interface.bfrt_info_get()
    print('The target runs the program ', bfrt_info.p4_name_get())

    # Establish that you are working with this program
    interface.bind_pipeline_config(bfrt_info.p4_name_get())

    # We are going to read information from device 0
    target = gc.Target(device_id=0, pipe_id=0xFFFF)

    ################### You can now use BFRT CLIENT ###########################
    print("Start Shield Control Plane")
    cp = ControlPlane(bfrt_info, target, do_setup=True, do_manage=True, do_sniff=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print(f"Uploaded Packets: {cp.uploaded_packet_counts}")
        print(f"Processed Packets: {cp.processed_packet_counts}")
