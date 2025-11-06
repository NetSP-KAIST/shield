#!/usr/bin/env python3

"""
Testing decay functionality across specific table setup
"""
import sys
import os
from scapy.all import *
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
class TestGroupDecay(BaseProgramTest):
    def setUp(self):
        if not setup.GLOBAL_TIME1 <= setup.GLOBAL_TIME2 <= setup.GLOBAL_TIME3:
            print(f"GLOBAL_TIME1 <= GLOBAL_TIME2 <= GLOBAL_TIME3 needed: {setup.GLOBAL_TIME1}, {setup.GLOBAL_TIME2}, {setup.GLOBAL_TIME3}")
        BaseProgramTest.setUp(self)
        setup.setUp(self.bfrt_info, self.dev_tgt, do_decay=True, do_block=True) # block functionality disabled
        self.periodic_sender = PeriodicSender(self, 0.5)    # Send periodic packets for global_timeN_reg update

class DecayLayer2(TestGroupDecay):
    """
    Send packets affecting layer 1 and 2, and see whether the value on layer 2 is well decayed
    Send 2**setup.LAYER1_BIT_SIZE packets on a single task
    Then wait for global_time2 change, send 1 packet on each task, and see the decayed result
    """
    def runTest(self):
        ip = "12.34.56.78"
        packet_numbers = [0] * 4
        packet_numbers[random.randint(0, 3)] = 2**setup.LAYER1_BIT_SIZE

        self.periodic_sender.start()
        global_time = wait_until_global_time_changes(self, 2, 0.5)
        self.periodic_sender.stop()

        send_packets([ip], [packet_numbers], setup.SOFTWARE)
        time.sleep(5)

        result = read_dataplane(self, ip, True)
        packet_numbers[1] += packet_numbers[2]  # DNS flood also count as UDP flood
        self.assertEqual(result, [packet_numbers for _ in range(2)])

        send_ip_packet([ip])
        while True:
            self.periodic_sender.start()
            wait_until_global_time_changes(self, 1, 0.5)
            self.periodic_sender.stop()
            send_ip_packet([ip])
            if global_time != check_global_time(self, 2):
                break
        time.sleep(5)

        result = read_dataplane(self, ip, False)
        for j in range(4):
            layer1 = packet_numbers[j] % 2**(setup.LAYER1_BIT_SIZE-1)
            layer2 = packet_numbers[j] // 2**(setup.LAYER1_BIT_SIZE-1)

            layer1 = 0 if setup.GLOBAL_TIME2 > setup.GLOBAL_TIME1 else layer1
            layer2 //= 2**setup.LAYER2_DECAY_BIT

            packet_numbers[j] = layer1 + (layer2 << (setup.LAYER1_BIT_SIZE-1))
        self.assertEqual(result, [packet_numbers for _ in range(2)])

# Software is too slow to get this test passed
# class DecayLayer3(TestGroupDecay):
#     """
#     Send packets affecting layer 1, 2, and 3, and see whether the value on layer 3 is well decayed
#     Send 2**(setup.LAYER1_BIT_SIZE+setup.LAYER2_BIT_SIZE-1) packets randomly on a single task
#     Then wait for global_time3 change, send 1 packet on each task, and see the decayed result
#     """
#     def runTest(self):
#         ip = "12.34.56.78"
#         packet_numbers = [0] * 4
#         packet_numbers[random.randint(0, 3)] = 2**(setup.LAYER1_BIT_SIZE+setup.LAYER2_BIT_SIZE-1)

#         self.periodic_sender.start()
#         global_time = wait_until_global_time_changes(self, 3, 0.5)
#         self.periodic_sender.stop()

#         send_packets([ip], [packet_numbers], setup.SOFTWARE)
#         time.sleep(5)

#         result = read_dataplane(self, ip, True)
#         packet_numbers[1] += packet_numbers[2]  # DNS flood also count as UDP flood
#         self.assertEqual(result, [packet_numbers for _ in range(2)])

#         send_ip_packet([ip])
#         while True:
#             self.periodic_sender.start()
#             wait_until_global_time_changes(self, 1, 0.5)
#             self.periodic_sender.stop()
#             send_ip_packet([ip])
#             if global_time != check_global_time(self, 3):
#                 break
#         time.sleep(5)

#         result = read_dataplane(self, ip, False)
#         for j in range(4):
#             layer1 = packet_numbers[j] % 2**(setup.LAYER1_BIT_SIZE-1)
#             layer2 = packet_numbers[j] // 2**(setup.LAYER1_BIT_SIZE-1) % 2**(setup.LAYER2_BIT_SIZE-1)
#             layer3 = packet_numbers[j] // 2**(setup.LAYER1_BIT_SIZE-1) // 2**(setup.LAYER2_BIT_SIZE-1)

#             layer1 = 0 if setup.GLOBAL_TIME3 > setup.GLOBAL_TIME1 else layer1
#             layer2 //= 2**setup.LAYER2_DECAY_BIT * 2**(setup.GLOBAL_TIME3-setup.GLOBAL_TIME2)
#             layer3 //= 2**setup.LAYER3_DECAY_BIT

#             packet_numbers[j] = layer1 + (layer2 << (setup.LAYER1_BIT_SIZE-1)) + (layer3 << (setup.LAYER1_BIT_SIZE+setup.LAYER2_BIT_SIZE-2))
#         self.assertEqual(result, [packet_numbers for _ in range(2)])
