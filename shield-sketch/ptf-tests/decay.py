#!/usr/bin/env python3

"""
Testing decay functionality across specific table setup
"""
import sys
import os
from scapy.all import *
from shield import *
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
        setup.setUp(self.bfrt_info, self.dev_tgt, do_decay=True, do_block=True)    # block functionality disabled
        self.periodic_sender = PeriodicSender(self, 0.1)    # Send periodic packets for global_timeN_reg update

class DecayLayer2(TestGroupDecay):
    """
    Send packets affecting layer 1 and 2, and see whether the value on layer 2 is well decayed
    Send [2**(setup.LAYER1_BIT_SIZE-1), 2**(setup.LAYER1_BIT_SIZE+setup.LAYER2_BIT_SIZE-2)-1] packets randomly on each task for 3 IPs
    Then wait for global_time2 change, send 1 packet on each task, and see the decayed result
    """
    def runTest(self):
        num_ips = 3
        ips = generate_distinct_ips(num_ips)
        random_numbers = [pick_numbers(2**(setup.LAYER1_BIT_SIZE-1), 2**(setup.LAYER1_BIT_SIZE+setup.LAYER2_BIT_SIZE-2)-1) for _ in range(num_ips)]

        self.periodic_sender.start()
        wait_until_global_time_changes(self, 2, 0.1)
        self.periodic_sender.stop()

        send_packets(ips, random_numbers)

        for i, ip in enumerate(ips):
            result = read_dataplane(self, ip, True)
            random_numbers[i][1] += random_numbers[i][2]    # DNS flood also count as UDP flood
            self.assertEqual(result, [random_numbers[i] for _ in range(2)])

        for _ in range(2**(setup.GLOBAL_TIME2-setup.GLOBAL_TIME1)):
            self.periodic_sender.start()
            wait_until_global_time_changes(self, 1, 0.1)
            self.periodic_sender.stop()

            send_ip_packet(ips)

        for i, ip in enumerate(ips):
            result = read_dataplane(self, ip, False)
            for j in range(4):
                layer1 = random_numbers[i][j] % 2**(setup.LAYER1_BIT_SIZE-1)
                layer2 = random_numbers[i][j] // 2**(setup.LAYER1_BIT_SIZE-1)

                layer1 = 0 if setup.GLOBAL_TIME2 > setup.GLOBAL_TIME1 else layer1
                layer2 //= 2**setup.LAYER2_DECAY_BIT

                random_numbers[i][j] = layer1 + (layer2 << (setup.LAYER1_BIT_SIZE-1))
            self.assertEqual(result, [random_numbers[i] for _ in range(2)])

class DecayLayer3(TestGroupDecay):
    """
    Send packets affecting layer 1, 2, and 3, and see whether the value on layer 3 is well decayed
    Send [2**(setup.LAYER1_BIT_SIZE+setup.LAYER2_BIT_SIZE-2), 2**(setup.LAYER1_BIT_SIZE+setup.LAYER2_BIT_SIZE+setup.LAYER3_BIT_SIZE-3)-1] packets randomly on each task for 1 IP
    Then wait for global_time3 change, send 1 packet on each task, and see the decayed result
    """
    def runTest(self):
        num_ips = 1
        ips = generate_distinct_ips(num_ips)
        random_numbers = [pick_numbers(2**(setup.LAYER1_BIT_SIZE+setup.LAYER2_BIT_SIZE-2), 2**(setup.LAYER1_BIT_SIZE+setup.LAYER2_BIT_SIZE+setup.LAYER3_BIT_SIZE-3)-1) for _ in range(num_ips)]

        self.periodic_sender.start()
        wait_until_global_time_changes(self, 3, 0.1)
        self.periodic_sender.stop()

        send_packets(ips, random_numbers)

        for i, ip in enumerate(ips):
            result = read_dataplane(self, ip, True)
            random_numbers[i][1] += random_numbers[i][2]    # DNS flood also count as UDP flood
            self.assertEqual(result, [random_numbers[i] for _ in range(2)])

        for _ in range(2**(setup.GLOBAL_TIME3-setup.GLOBAL_TIME1)):
            self.periodic_sender.start()
            wait_until_global_time_changes(self, 1, 0.1)
            self.periodic_sender.stop()

            send_ip_packet(ips)

        for i, ip in enumerate(ips):
            result = read_dataplane(self, ip, False)
            for j in range(4):
                layer1 = random_numbers[i][j] % 2**(setup.LAYER1_BIT_SIZE-1)
                layer2 = random_numbers[i][j] // 2**(setup.LAYER1_BIT_SIZE-1) % 2**(setup.LAYER2_BIT_SIZE-1)
                layer3 = random_numbers[i][j] // 2**(setup.LAYER1_BIT_SIZE-1) // 2**(setup.LAYER2_BIT_SIZE-1)

                layer1 = 0 if setup.GLOBAL_TIME3 > setup.GLOBAL_TIME1 else layer1
                layer2 //= 2**setup.LAYER2_DECAY_BIT * 2**(setup.GLOBAL_TIME3-setup.GLOBAL_TIME2)
                layer3 //= 2**setup.LAYER3_DECAY_BIT

                random_numbers[i][j] = layer1 + (layer2 << (setup.LAYER1_BIT_SIZE-1)) + (layer3 << (setup.LAYER1_BIT_SIZE+setup.LAYER2_BIT_SIZE-2))
            self.assertEqual(result, [random_numbers[i] for _ in range(2)])
