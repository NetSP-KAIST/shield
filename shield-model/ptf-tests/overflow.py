#!/usr/bin/env python3

"""
Testing overflow functionality across specific table setup
"""
import sys
import os
from layered_cms import *
from utils import *

parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
import setup

########################################################################
########    Running Multiple Tests with the same setup   ###############
########################################################################

# This new Base Class extends the setup method of BaseProgramTest by adding the
# desired network setup
class TestGroupOverflow(BaseProgramTest):
    def setUp(self):
        BaseProgramTest.setUp(self)
        setup.setUp(self.bfrt_info, self.dev_tgt, do_decay=False, do_block=True)    # decay and block functionality disabled
        self.periodic_sender = PeriodicSender(self, 0.5)    # Send periodic packets for global_timeN_reg update

class SendToLayer1(TestGroupOverflow):
    """
    Send packets affecting layer 1
    Send [1, 2**(setup.LAYER1_BIT_SIZE-1)-1] packets randomly on each task
    """
    def runTest(self):
        ip = "12.34.56.78"
        packet_numbers = pick_numbers(1, 2**(setup.LAYER1_BIT_SIZE-1)-1)

        send_packets([ip], [packet_numbers], setup.SOFTWARE)
        time.sleep(5)

        result = read_dataplane(self, ip, True)
        packet_numbers[1] += packet_numbers[2]  # DNS flood also count as UDP flood
        self.assertEqual(result, [packet_numbers for _ in range(2)])

class SendToLayer2(TestGroupOverflow):
    """
    Send packets affecting layer 1 and 2
    Send 2**(setup.LAYER1_BIT_SIZE-1) packets on each task
    """
    def runTest(self):
        ip = "12.34.56.78"
        packet_numbers = [2**(setup.LAYER1_BIT_SIZE-1)] * 4

        self.periodic_sender.start()
        wait_until_global_time_changes(self, 2, 0.5)
        self.periodic_sender.stop()

        send_packets([ip], [packet_numbers], setup.SOFTWARE)
        time.sleep(5)

        result = read_dataplane(self, ip, True)
        packet_numbers[1] += packet_numbers[2]  # DNS flood also count as UDP flood
        self.assertEqual(result, [packet_numbers for _ in range(2)])

class SendToLayer3(TestGroupOverflow):
    """
    Send packets affecting layer 1, 2, and 3
    Send 2**(setup.LAYER1_BIT_SIZE+setup.LAYER2_BIT_SIZE-2) packets on a single task
    """
    def runTest(self):
        ip = "12.34.56.78"
        packet_numbers = [0] * 4
        packet_numbers[random.randint(0, 3)] = 2**(setup.LAYER1_BIT_SIZE+setup.LAYER2_BIT_SIZE-2)

        self.periodic_sender.start()
        wait_until_global_time_changes(self, 3, 0.5)
        self.periodic_sender.stop()

        send_packets([ip], [packet_numbers], setup.SOFTWARE)
        time.sleep(5)

        result = read_dataplane(self, ip, True)
        packet_numbers[1] += packet_numbers[2]  # DNS flood also count as UDP flood
        self.assertEqual(result, [packet_numbers for _ in range(2)])

# Software is too slow to get this test passed
# class SendToControlPlane(TestGroupOverflow):
#     """
#     Send packets affecting layer 1, 2, 3, and control plane
#     Send 2**(setup.LAYER1_BIT_SIZE+setup.LAYER2_BIT_SIZE+setup.LAYER3_BIT_SIZE-3) packets on a single task
#     """
#     def runTest(self):
#         ip = "12.34.56.78"
#         packet_numbers = [0] * 4
#         packet_numbers[random.randint(0, 3)] = 2**(setup.LAYER1_BIT_SIZE+setup.LAYER2_BIT_SIZE+setup.LAYER3_BIT_SIZE-3)

#         self.periodic_sender.start()
#         wait_until_global_time_changes(self, 3, 0.5)
#         self.periodic_sender.stop()

#         send_packets([ip], [packet_numbers], setup.SOFTWARE)
#         time.sleep(5)

#         result = read_dataplane(self, ip, True)
#         self.assertEqual(result, [[0] * 4 for _ in range(2)])
#         upload_h = {
#             0: Raw(bytes([0b1, 0b10001000])),
#             1: Raw(bytes([0b1, 0b01000100])),
#             2: Raw(bytes([0b1, 0b01100110])),
#             3: Raw(bytes([0b1, 0b00010001]))
#         }
#         pkts = {
#             0 : Ether(dst="00:98:76:54:32:10",src="00:55:55:55:55:55")/IP(dst=victim_ip, src=ip)/ICMP(type=8),
#             1 : Ether(dst="00:98:76:54:32:10",src="00:55:55:55:55:55")/IP(dst=victim_ip, src=ip)/UDP(dport=80, chksum=0),
#             2 : Ether(dst="00:98:76:54:32:10",src="00:55:55:55:55:55")/IP(dst=victim_ip, src=ip)/UDP(dport=53, chksum=0),
#             3 : Ether(dst="00:98:76:54:32:10",src="00:55:55:55:55:55")/IP(dst=victim_ip, src=ip)/TCP(flags="S")
#         }
#         pkt_index = packet_numbers.index(2**(setup.LAYER1_BIT_SIZE+setup.LAYER2_BIT_SIZE+setup.LAYER3_BIT_SIZE-3))
#         verify_packet(self, upload_h[pkt_index]/pkts[pkt_index], self.swports[2])
