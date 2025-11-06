#!/usr/bin/env python3

"""
Foundational class for SHIELD PTF tests

This module contains the BaseProgramTest class specifically taylored for the
given program. The tayloring is done by defining two methods:
   1) tableSetUp() which creates the lists of tables tests are supposed to
      access along with defining proper field attributes
   2) setUp() that calls the parent's setUp method, while passing tableSetUp
      as an additional argument

All individual tests are subclassed from the this base (BaseProgramTest) or
its subclasses if necessary

The easiest way to write a test for the program is to start with a line

from layered_cms import *

NOTE: please run PTF with LAYER1_BIT_SIZE=4, LAYER2_BIT_SIZ=4, LAYER3_BIT_SIZE=4
(Otherwise, too many packets would be sent, possibly causing packets to be transmitted across different time windows.)
"""

######### STANDARD MODULE IMPORTS ########
import unittest
import logging
import grpc
import pdb
import copy

######### PTF modules for BFRuntime Client Library APIs #######
import ptf
from ptf.testutils import *
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as gc

# Explicit Scapy import is required, since BF_PKTPY is not adequate for this
# test
if ptf.config['packet_manipulation_module'].endswith('scapy'):
    try:
        from scapy.all import *
    except:
        print("This test requires Scapy. Please, install it")
        quit()
else:
    print("This test requires Scapy. Please run it with PKTPY=false")
    quit()

# Add ~/tools to the search path
import os
import sys
TOOLS = os.path.expanduser(os.path.join('~'+os.environ['SUDO_USER'], 'tools'))
sys.path.insert(0, TOOLS)

# testbase is located in ~/tools
from testbase import P4ProgramTest

########## Basic Initialization ############
class BaseProgramTest(P4ProgramTest):
    def setUp(self):
        P4ProgramTest.setUp(self, self.tableSetUp)

    def tableSetUp(self):
        # Registers
        self.reg_global_time1 = self.bfrt_info.table_get('Ingress.reg_global_time1')
        self.reg_global_time2 = self.bfrt_info.table_get('Ingress.reg_global_time2')
        self.reg_global_time3 = self.bfrt_info.table_get('Ingress.reg_global_time3')

        self.reg_c_timer1_arr0 = self.bfrt_info.table_get('Ingress.reg_c_timer1_arr0')
        self.reg_c_timer1_arr1 = self.bfrt_info.table_get('Ingress.reg_c_timer1_arr1')
        self.reg_c_timer2_arr0 = self.bfrt_info.table_get('Ingress.reg_c_timer2_arr0')
        self.reg_c_timer2_arr1 = self.bfrt_info.table_get('Ingress.reg_c_timer2_arr1')
        self.reg_c_timer3_arr0 = self.bfrt_info.table_get('Ingress.reg_c_timer3_arr0')
        self.reg_c_timer3_arr1 = self.bfrt_info.table_get('Ingress.reg_c_timer3_arr1')

        self.reg_c2_layer1_arr0_w1 = self.bfrt_info.table_get('Ingress.reg_c2_layer1_arr0_w1')
        self.reg_c2_layer1_arr0_w2 = self.bfrt_info.table_get('Ingress.reg_c2_layer1_arr0_w2')
        self.reg_c2_layer1_arr1_w1 = self.bfrt_info.table_get('Ingress.reg_c2_layer1_arr1_w1')
        self.reg_c2_layer1_arr1_w2 = self.bfrt_info.table_get('Ingress.reg_c2_layer1_arr1_w2')
        self.reg_c2_layer2_arr0_tg0 = self.bfrt_info.table_get('Ingress.reg_c2_layer2_arr0_tg0')
        self.reg_c2_layer2_arr0_tg1 = self.bfrt_info.table_get('Ingress.reg_c2_layer2_arr0_tg1')
        self.reg_c2_layer2_arr1_tg0 = self.bfrt_info.table_get('Ingress.reg_c2_layer2_arr1_tg0')
        self.reg_c2_layer2_arr1_tg1 = self.bfrt_info.table_get('Ingress.reg_c2_layer2_arr1_tg1')
        self.reg_c2_layer3_arr0_tg0 = self.bfrt_info.table_get('Ingress.reg_c2_layer3_arr0_tg0')
        self.reg_c2_layer3_arr0_tg1 = self.bfrt_info.table_get('Ingress.reg_c2_layer3_arr0_tg1')
        self.reg_c2_layer3_arr1_tg0 = self.bfrt_info.table_get('Ingress.reg_c2_layer3_arr1_tg0')
        self.reg_c2_layer3_arr1_tg1 = self.bfrt_info.table_get('Ingress.reg_c2_layer3_arr1_tg1')

        self.reg_c2_layer1_arr0_overflow_counter = self.bfrt_info.table_get('Ingress.reg_c2_layer1_arr0_overflow_counter')
        self.reg_c2_layer1_arr1_overflow_counter = self.bfrt_info.table_get('Ingress.reg_c2_layer1_arr1_overflow_counter')
        self.reg_c2_layer2_arr0_overflow_counter = self.bfrt_info.table_get('Ingress.reg_c2_layer2_arr0_overflow_counter')
        self.reg_c2_layer2_arr1_overflow_counter = self.bfrt_info.table_get('Ingress.reg_c2_layer2_arr1_overflow_counter')

        # Tables
        self.check_blocklist = self.bfrt_info.table_get('Ingress.check_blocklist')
        self.check_blocklist.info.key_field_annotation_add(
            "hdr.ipv4.src_addr", "ipv4")
        self.check_blocklist.info.key_field_annotation_add(
            "hdr.ipv4.dst_addr", "ipv4")

        self.check_icmpq_table = self.bfrt_info.table_get('Ingress.check_icmpq_table')
        self.check_udp_table = self.bfrt_info.table_get('Ingress.check_udp_table')
        self.check_dnsq_table = self.bfrt_info.table_get('Ingress.check_dnsq_table')
        self.check_syn_table = self.bfrt_info.table_get('Ingress.check_syn_table')

        self.reg_global_time1_set_table = self.bfrt_info.table_get('Ingress.reg_global_time1_set_table')
        self.reg_global_time2_set_table = self.bfrt_info.table_get('Ingress.reg_global_time2_set_table')
        self.reg_global_time3_set_table = self.bfrt_info.table_get('Ingress.reg_global_time3_set_table')

        self.reg_c_timer1_arr0_table = self.bfrt_info.table_get('Ingress.reg_c_timer1_arr0_table')
        self.reg_c_timer1_arr1_table = self.bfrt_info.table_get('Ingress.reg_c_timer1_arr1_table')
        self.reg_c_timer2_arr0_table = self.bfrt_info.table_get('Ingress.reg_c_timer2_arr0_table')
        self.reg_c_timer2_arr1_table = self.bfrt_info.table_get('Ingress.reg_c_timer2_arr1_table')
        self.reg_c_timer3_arr0_table = self.bfrt_info.table_get('Ingress.reg_c_timer3_arr0_table')
        self.reg_c_timer3_arr1_table = self.bfrt_info.table_get('Ingress.reg_c_timer3_arr1_table')

        self.reg_c2_layer1_dyn_table = self.bfrt_info.table_get('Ingress.reg_c2_layer1_dyn_table')
        self.reg_c2_layer2_arr0_dyn_table = self.bfrt_info.table_get('Ingress.reg_c2_layer2_arr0_dyn_table')
        self.reg_c2_layer2_arr1_dyn_table = self.bfrt_info.table_get('Ingress.reg_c2_layer2_arr1_dyn_table')
        self.reg_c2_layer3_arr0_dyn_table = self.bfrt_info.table_get('Ingress.reg_c2_layer3_arr0_dyn_table')
        self.reg_c2_layer3_arr1_dyn_table = self.bfrt_info.table_get('Ingress.reg_c2_layer3_arr1_dyn_table')

        self.reg_c2_layer1_arr0_w1_table = self.bfrt_info.table_get('Ingress.reg_c2_layer1_arr0_w1_table')
        self.reg_c2_layer1_arr0_w2_table = self.bfrt_info.table_get('Ingress.reg_c2_layer1_arr0_w2_table')
        self.reg_c2_layer1_arr1_w1_table = self.bfrt_info.table_get('Ingress.reg_c2_layer1_arr1_w1_table')
        self.reg_c2_layer1_arr1_w2_table = self.bfrt_info.table_get('Ingress.reg_c2_layer1_arr1_w2_table')
        self.reg_c2_layer2_arr0_tg0_table = self.bfrt_info.table_get('Ingress.reg_c2_layer2_arr0_tg0_table')
        self.reg_c2_layer2_arr0_tg1_table = self.bfrt_info.table_get('Ingress.reg_c2_layer2_arr0_tg1_table')
        self.reg_c2_layer2_arr1_tg0_table = self.bfrt_info.table_get('Ingress.reg_c2_layer2_arr1_tg0_table')
        self.reg_c2_layer2_arr1_tg1_table = self.bfrt_info.table_get('Ingress.reg_c2_layer2_arr1_tg1_table')
        self.reg_c2_layer3_arr0_tg0_table = self.bfrt_info.table_get('Ingress.reg_c2_layer3_arr0_tg0_table')
        self.reg_c2_layer3_arr0_tg1_table = self.bfrt_info.table_get('Ingress.reg_c2_layer3_arr0_tg1_table')
        self.reg_c2_layer3_arr1_tg0_table = self.bfrt_info.table_get('Ingress.reg_c2_layer3_arr1_tg0_table')
        self.reg_c2_layer3_arr1_tg1_table = self.bfrt_info.table_get('Ingress.reg_c2_layer3_arr1_tg1_table')

        self.extract_reg_c2_layer2_arr0 = self.bfrt_info.table_get('Ingress.extract_reg_c2_layer2_arr0')
        self.extract_reg_c2_layer2_arr1 = self.bfrt_info.table_get('Ingress.extract_reg_c2_layer2_arr1')
        self.extract_reg_c2_layer3_arr0 = self.bfrt_info.table_get('Ingress.extract_reg_c2_layer3_arr0')
        self.extract_reg_c2_layer3_arr1 = self.bfrt_info.table_get('Ingress.extract_reg_c2_layer3_arr1')

        self.reg_c2_layer1_overflow_table = self.bfrt_info.table_get('Ingress.reg_c2_layer1_overflow_table')
        self.reg_c2_layer2_overflow_table = self.bfrt_info.table_get('Ingress.reg_c2_layer2_overflow_table')
        self.reg_c2_layer3_overflow_table = self.bfrt_info.table_get('Ingress.reg_c2_layer3_overflow_table')

        self.reg_c2_layer1_arr0_overflow_counter_table = self.bfrt_info.table_get('Ingress.reg_c2_layer1_arr0_overflow_counter_table')
        self.reg_c2_layer1_arr1_overflow_counter_table = self.bfrt_info.table_get('Ingress.reg_c2_layer1_arr1_overflow_counter_table')
        self.reg_c2_layer2_arr0_overflow_counter_table = self.bfrt_info.table_get('Ingress.reg_c2_layer2_arr0_overflow_counter_table')
        self.reg_c2_layer2_arr1_overflow_counter_table = self.bfrt_info.table_get('Ingress.reg_c2_layer2_arr1_overflow_counter_table')

        self.ipv4_port_and_recirculate_mirror_table = self.bfrt_info.table_get('Ingress.ipv4_port_and_recirculate_mirror_table')

        self.block_threshold_arr0_slice0_table = self.bfrt_info.table_get('Ingress.block_threshold_arr0_slice0_table')
        self.block_threshold_arr0_slice1_table = self.bfrt_info.table_get('Ingress.block_threshold_arr0_slice1_table')
        self.block_threshold_arr0_slice2_table = self.bfrt_info.table_get('Ingress.block_threshold_arr0_slice2_table')
        self.block_threshold_arr0_slice3_table = self.bfrt_info.table_get('Ingress.block_threshold_arr0_slice3_table')
        self.block_threshold_arr1_slice0_table = self.bfrt_info.table_get('Ingress.block_threshold_arr1_slice0_table')
        self.block_threshold_arr1_slice1_table = self.bfrt_info.table_get('Ingress.block_threshold_arr1_slice1_table')
        self.block_threshold_arr1_slice2_table = self.bfrt_info.table_get('Ingress.block_threshold_arr1_slice2_table')
        self.block_threshold_arr1_slice3_table = self.bfrt_info.table_get('Ingress.block_threshold_arr1_slice3_table')
        self.block_threshold_table = self.bfrt_info.table_get('Ingress.block_threshold_table')

        self.mirror_cfg = self.bfrt_info.table_get("$mirror.cfg")

        # Create a list of tables to clean up
        self.tables = [ # Registers
                        self.reg_global_time1, self.reg_global_time2, self.reg_global_time3,

                        self.reg_c_timer1_arr0, self.reg_c_timer1_arr1,
                        self.reg_c_timer2_arr0, self.reg_c_timer2_arr1,
                        self.reg_c_timer3_arr0, self.reg_c_timer3_arr1,

                        self.reg_c2_layer1_arr0_w1, self.reg_c2_layer1_arr0_w2,
                        self.reg_c2_layer1_arr1_w1, self.reg_c2_layer1_arr1_w2,
                        self.reg_c2_layer2_arr0_tg0, self.reg_c2_layer2_arr0_tg1,
                        self.reg_c2_layer2_arr1_tg0, self.reg_c2_layer2_arr1_tg1,
                        self.reg_c2_layer3_arr0_tg0, self.reg_c2_layer3_arr0_tg1,
                        self.reg_c2_layer3_arr1_tg0, self.reg_c2_layer3_arr1_tg1,

                        self.reg_c2_layer1_arr0_overflow_counter, self.reg_c2_layer1_arr1_overflow_counter,
                        self.reg_c2_layer2_arr0_overflow_counter, self.reg_c2_layer2_arr1_overflow_counter,

                        # Tables
                        self.check_blocklist,

                        self.check_icmpq_table, self.check_udp_table, self.check_dnsq_table, self.check_syn_table,

                        self.reg_global_time1_set_table, self.reg_global_time2_set_table, self.reg_global_time3_set_table,

                        self.reg_c_timer1_arr0_table, self.reg_c_timer1_arr1_table,
                        self.reg_c_timer2_arr0_table, self.reg_c_timer2_arr1_table,
                        self.reg_c_timer3_arr0_table, self.reg_c_timer3_arr1_table,

                        self.reg_c2_layer1_dyn_table,
                        self.reg_c2_layer2_arr0_dyn_table, self.reg_c2_layer2_arr1_dyn_table,
                        self.reg_c2_layer3_arr0_dyn_table, self.reg_c2_layer3_arr1_dyn_table,

                        self.reg_c2_layer1_arr0_w1_table, self.reg_c2_layer1_arr0_w2_table,
                        self.reg_c2_layer1_arr1_w1_table, self.reg_c2_layer1_arr1_w2_table,
                        self.reg_c2_layer2_arr0_tg0_table, self.reg_c2_layer2_arr0_tg1_table,
                        self.reg_c2_layer2_arr1_tg0_table, self.reg_c2_layer2_arr1_tg1_table,
                        self.reg_c2_layer3_arr0_tg0_table, self.reg_c2_layer3_arr0_tg1_table,
                        self.reg_c2_layer3_arr1_tg0_table, self.reg_c2_layer3_arr1_tg1_table,

                        self.extract_reg_c2_layer2_arr0, self.extract_reg_c2_layer2_arr1,
                        self.extract_reg_c2_layer3_arr0, self.extract_reg_c2_layer3_arr1,

                        self.reg_c2_layer1_overflow_table, self.reg_c2_layer2_overflow_table, self.reg_c2_layer3_overflow_table,

                        self.reg_c2_layer1_arr0_overflow_counter_table, self.reg_c2_layer1_arr1_overflow_counter_table,
                        self.reg_c2_layer2_arr0_overflow_counter_table, self.reg_c2_layer2_arr1_overflow_counter_table,

                        self.ipv4_port_and_recirculate_mirror_table,

                        self.block_threshold_arr0_slice0_table, self.block_threshold_arr0_slice1_table,
                        self.block_threshold_arr0_slice2_table, self.block_threshold_arr0_slice3_table,
                        self.block_threshold_arr1_slice0_table, self.block_threshold_arr1_slice1_table,
                        self.block_threshold_arr1_slice2_table, self.block_threshold_arr1_slice3_table,
                        self.block_threshold_table,

                        self.mirror_cfg
                       ]

        ########## END OF CUSTOMIZATION ###########

#
# Individual tests can now be subclassed from BaseProgramTest
#
