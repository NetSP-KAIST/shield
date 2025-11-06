#!/usr/bin/python3

##
## Initial Table setup for Cerberus
## 

import os
import sys
import pdb

# import sys
print("[DEBUG] sys.executable:", sys.executable)
print("[DEBUG] sys.path:", sys.path)

#
# This is optional if you use proper PYTHONPATH
#
SDE_INSTALL = os.environ.get("SDE_INSTALL")
if not SDE_INSTALL:
    # fallback (optional)
    SDE_INSTALL = "/home/edgecore/bf-sde-9.13.4/install"
    print("[WARN] SDE_INSTALL not found in environment, using fallback.")

PYTHON3_VER = f"{sys.version_info.major}.{sys.version_info.minor}"
SDE_PYTHON3 = os.path.join(SDE_INSTALL, "lib", f"python{PYTHON3_VER}", "site-packages")
sys.path.append(SDE_PYTHON3)
sys.path.append(os.path.join(SDE_PYTHON3, "tofino"))
sys.path.append(os.path.join(SDE_PYTHON3, "tofino", "bfrt_grpc"))

# bfrt grpc
import grpc
import bfrt_grpc.client as gc
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2

# test utils
from ptf import config
import ptf.testutils as testutils
# from bfruntime_client_base_tests import BfRuntimeTest

# Others
import time
import itertools

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

################### You can now use BFRT CLIENT ###########################

# This is just an example. Put in your own code
from tabulate import tabulate

# Print the list of tables in the "pipe" node
data = []
for name in bfrt_info.table_dict.keys():
    if name.split('.')[0] == 'pipe':
        # pdb.set_trace()
        t = bfrt_info.table_get(name)
        table_name = t.info.name_get()
        if table_name != name:
            continue
        table_type = t.info.type_get()
        try:
            result = t.usage_get(target)
            table_usage = next(result)
        except:
            table_usage = 'n/a'
        table_size = t.info.size_get()
        data.append([table_name, table_type, table_usage, table_size])
print(tabulate(data, headers=['Full Table Name','Type','Usage','Capacity']))

#####################
# Insert Basic rules
#####################


# Set timestamp
set_global_timer = bfrt_info.table_get('SwitchIngress.set_global_time1_table')
keys = []
datas = []
for i in [0, 1]:
    key = set_global_timer.make_key([gc.KeyTuple('ig_prsr_md.global_tstamp[33:33]', i)])
    data = set_global_timer.make_data([gc.DataTuple('flag', i)], 'SwitchIngress.set_global_time1_action')
    keys.append(key)
    datas.append(data)
set_global_timer.entry_add(target, keys, datas)

#####################
# Check flow type
#####################
# ICMP
check_icmp = bfrt_info.table_get('SwitchIngress.check_icmp_table')
key_icmp_request = check_icmp.make_key([
        gc.KeyTuple('hdr.icmp.$valid', True),  # isValid = True
        gc.KeyTuple('hdr.icmp.type_', 8)      # type = 8 (Echo Request)
    ])
data_icmp_request = check_icmp.make_data([],'SwitchIngress.check_icmpq_setflag')
check_icmp.entry_add(target, [key_icmp_request], [data_icmp_request])

key_icmp_reply = check_icmp.make_key([
        gc.KeyTuple('hdr.icmp.$valid', True),  # valid = True
        gc.KeyTuple('hdr.icmp.type_', 0)      # type = 0 (Echo Reply)
    ])
data_icmp_reply = check_icmp.make_data([],'SwitchIngress.check_icmpr_setflag')

# UDP
check_udp = bfrt_info.table_get('SwitchIngress.check_udp_table')
key_udp = check_udp.make_key([
        gc.KeyTuple('hdr.udp.$valid', True),  # isValid = True
])
data_udp = check_udp.make_data([],'SwitchIngress.check_udp_setflag')
check_udp.entry_add(target, [key_udp], [data_udp])

# DNS query
check_dns_q  = bfrt_info.table_get('SwitchIngress.check_dns_q_table')

key = check_dns_q.make_key([
    gc.KeyTuple('hdr.ipv4.protocol', 17), # UDP
    gc.KeyTuple('hdr.udp.dst_port', 53) 
])
data = check_dns_q.make_data([], 'SwitchIngress.check_dnsq_setflag')  # Action for DNS
check_dns_q.entry_add(target, [key], [data])

check_syn = bfrt_info.table_get('SwitchIngress.check_syn_table')
key = check_syn.make_key([
    gc.KeyTuple('hdr.ipv4.protocol', 6), # TCP
    gc.KeyTuple('hdr.tcp.$valid', True),
    gc.KeyTuple('hdr.tcp.flags', 2) 
])
data = check_syn.make_data([], 'SwitchIngress.check_syn_setflag')  # Action for DNS
check_syn.entry_add(target, [key], [data])

#####################
# Set update value for CMS
#####################
# Initial setup for CMS: equally distribute memory bits to each slice
# 2-tuple: icmp (8) / udp (8) / syn (8) / dnsq (8), and increment only 1 bit
# [0]0000001 [0]0000001 [0]0000001 [0]0000001
# NO Isolation Bit, first bit of each task is carry bit
icmp_only = 0x1000000
udp_only = 0x10000
syn_only = 0x100
dnsq_only = 0x1
# NOTE: coremelt add packet length to the CMS value in the data plane 
#       with 'reg_c2_merge1' action in 'reg_c2_dyn_table'

keys = []
datas = []
c2_flags = ["icmpq_flag", "udp_flag", "syn_flag", "dnsq_flag", "resubmit_flag", "global_time1"]
combinations = itertools.product([0, 1], repeat=len(c2_flags))

reg_c2_dyn = bfrt_info.table_get('SwitchIngress.reg_c2_dyn_table')

for combo in combinations:
    flag_values = dict(zip(c2_flags, combo))
    if flag_values["resubmit_flag"] == 1:
        to_update_value = 0x7F7F7F7F
        key = reg_c2_dyn.make_key([
            gc.KeyTuple('icmpq_flag', flag_values["icmpq_flag"]),
            gc.KeyTuple('udp_flag', flag_values["udp_flag"]),
            gc.KeyTuple('syn_flag', flag_values["syn_flag"]),
            gc.KeyTuple('dnsq_flag', flag_values["dnsq_flag"]),
            gc.KeyTuple('ig_intr_md.resubmit_flag', 1),
            gc.KeyTuple('global_time1', flag_values["global_time1"]) 
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
            gc.KeyTuple('global_time1', flag_values["global_time1"]) 
        ])
        keys.append(key)
        datas.append(reg_c2_dyn.make_data([gc.DataTuple('slices', to_update_value)], 'SwitchIngress.reg_c2_merge'))
        continue
reg_c2_dyn.entry_add(target, keys, datas)

# #####################
# # empty blacklist on initialization
# #####################
# blocklist = bfrt_info.table_get('SwitchIngress.check_blocklist')
# blocklist.info.key_field_annotation_add('hdr.ipv4.src_addr', 'ipv4')
# blocklist.info.key_field_annotation_add('hdr.ipv4.dst_addr', 'ipv4')

#####################
# Check timestamp
#####################
reg_c_timer1 = bfrt_info.table_get('SwitchIngress.reg_c_timer1_table')
keys = []
datas = []
for i in [0,1]:
    key = reg_c_timer1.make_key([gc.KeyTuple('global_time1', i)])
    keys.append(key)
    if i == 0:
        datas.append(reg_c_timer1.make_data([],'SwitchIngress.reg_c_timer1_update0_action'))
    else:
        datas.append(reg_c_timer1.make_data([],'SwitchIngress.reg_c_timer1_update1_action'))
    # datas.append(reg_c_timer1.make_data([],'SwitchIngress.reg_c_timer1_update0_action'))
reg_c_timer1.entry_add(target, keys, datas)

gt = bfrt_info.table_get('SwitchIngress.global_time1_reg_set_table')
keys = []
datas = []
for i in [0,1]:
    key = gt.make_key([gc.KeyTuple('global_time1', i)])
    keys.append(key)
    if i == 0:
        datas.append(gt.make_data([],'SwitchIngress.global_time1_set0_action'))
    else:
        datas.append(gt.make_data([],'SwitchIngress.global_time1_set1_action'))
gt.entry_add(target, keys, datas)

#####################
# Update CMS register
#####################

# icmp / udp / coremelt
#  4 [1]  12 [1]  14  (total) 32bits
# dnsa / ssdpa / ntpa
#  10 [1] 10  [1] 10  (total) 32bits

# Update CMS for 2-tuple
# If global_time1 == 0 then use w1, otherwise use w2
reg_c2_w1_0 = bfrt_info.table_get('SwitchIngress.reg_c2_w1_0_table')
reg_c2_w1_1 = bfrt_info.table_get('SwitchIngress.reg_c2_w1_1_table')
reg_c2_w1_2 = bfrt_info.table_get('SwitchIngress.reg_c2_w1_2_table')
reg_c2_w1 = [reg_c2_w1_0, reg_c2_w1_1, reg_c2_w1_2]

for j, i in enumerate(reg_c2_w1):
    keys = []
    datas = []
    reg_c2_flags = ["global_time1", "reg_c_timer1_res", "resubmit_flag"]
    combinations = itertools.product([0, 1], repeat=len(reg_c2_flags))
    for combo in combinations:
        flag_values = dict(zip(reg_c2_flags, combo))
        # print(flag_values)
        # print('reg_c2_w1_' + str(j) + '_setbit_action')
        if flag_values["global_time1"] == 1:
            # If global_time1 == 1, then use w2
            # Do nothing in reg_c2_w1
            continue
        else:
            if flag_values["resubmit_flag"] == 1:
                key = i.make_key([
                    gc.KeyTuple('global_time1', 0),
                    gc.KeyTuple('reg_c_timer1_res', flag_values["reg_c_timer1_res"]),
                    gc.KeyTuple('ig_intr_md.resubmit_flag', 1)
                ])
                keys.append(key)
                datas.append(i.make_data([],'SwitchIngress.reg_c2_w1_' + str(j) + '_setbit_action'))
                continue
            else:
                if flag_values["reg_c_timer1_res"] == 0:
                    key = i.make_key([
                        gc.KeyTuple('global_time1', 0),
                        gc.KeyTuple('reg_c_timer1_res', 0),
                        gc.KeyTuple('ig_intr_md.resubmit_flag', 0)
                    ])
                    keys.append(key)
                    datas.append(i.make_data([],'SwitchIngress.reg_c2_w1_' + str(j) + '_plus_action'))
                else: # Just window changed: Clear and plus = setbit to toupdate_value
                    key = i.make_key([
                        gc.KeyTuple('global_time1', 0),
                        gc.KeyTuple('reg_c_timer1_res', 1),
                        gc.KeyTuple('ig_intr_md.resubmit_flag', 0)
                    ])
                    keys.append(key)
                    datas.append(i.make_data([],'SwitchIngress.reg_c2_w1_' + str(j) + '_setbit_action'))
    # print(i, 'reg_c2_w1_' + str(j))
    i.entry_add(target, keys, datas)


reg_c2_w2_0 = bfrt_info.table_get('SwitchIngress.reg_c2_w2_0_table')
reg_c2_w2_1 = bfrt_info.table_get('SwitchIngress.reg_c2_w2_1_table')
reg_c2_w2_2 = bfrt_info.table_get('SwitchIngress.reg_c2_w2_2_table')
reg_c2_w2 = [reg_c2_w2_0, reg_c2_w2_1, reg_c2_w2_2]
for j, i in enumerate(reg_c2_w2):
    keys = []
    datas = []
    reg_c2_flags = ["global_time1", "reg_c_timer1_res", "resubmit_flag"]
    combinations = itertools.product([0, 1], repeat=len(reg_c2_flags))
    for combo in combinations:
        flag_values = dict(zip(reg_c2_flags, combo))

        if flag_values["global_time1"] == 0:
            # If global_time1 == 0, then use w1
            # Do nothing in reg_c2_w2
            continue
        else:
            if flag_values["resubmit_flag"] == 1:
                key = i.make_key([
                    gc.KeyTuple('global_time1', 1),
                    gc.KeyTuple('reg_c_timer1_res', flag_values["reg_c_timer1_res"]),
                    gc.KeyTuple('ig_intr_md.resubmit_flag', 1)
                ])
                keys.append(key)
                datas.append(i.make_data([],'SwitchIngress.reg_c2_w2_' + str(j) + '_setbit_action'))
                continue
            else:
                if flag_values["reg_c_timer1_res"] == 1:
                    key = i.make_key([
                        gc.KeyTuple('global_time1', 1),
                        gc.KeyTuple('reg_c_timer1_res', 1),
                        gc.KeyTuple('ig_intr_md.resubmit_flag', 0)
                    ])
                    keys.append(key)
                    datas.append(i.make_data([],'SwitchIngress.reg_c2_w2_' + str(j) + '_plus_action'))
                else: # Just window changed: Clear and plus = setbit to toupdate_value
                    key = i.make_key([
                        gc.KeyTuple('global_time1', 1),
                        gc.KeyTuple('reg_c_timer1_res', 0),
                        gc.KeyTuple('ig_intr_md.resubmit_flag', 0)
                    ])
                    keys.append(key)
                    datas.append(i.make_data([],'SwitchIngress.reg_c2_w2_' + str(j) + '_setbit_action'))
    i.entry_add(target, keys, datas)

slicing = bfrt_info.table_get('SwitchIngress.reg_c2_slicing_table')
slicing_flags = ["icmpq_flag", "udp_flag", "syn_flag", "dnsq_flag", "global_time1"]
combinations = itertools.product([0, 1], repeat=len(slicing_flags))
keys = []
datas = []
for combo in combinations:
    flag_values = dict(zip(slicing_flags, combo))
    if flag_values["icmpq_flag"] == 1 \
        or flag_values["udp_flag"] == 1 \
        or flag_values["syn_flag"] == 1 \
        or flag_values["dnsq_flag"] == 1:
        mask1 = 0b10000000100000001000000010000000 # extract carry bit
        mask2 = 0b01111111000000000000000000000000 # extract task1 
        mask3 = 0b00000000011111110000000000000000 # extract task2
        mask4 = 0b00000000000000000111111100000000 # extract task3
        mask5 = 0b00000000000000000000000001111111 # extract task4
        key = slicing.make_key([
            gc.KeyTuple('icmpq_flag', flag_values["icmpq_flag"]),
            gc.KeyTuple('udp_flag', flag_values["udp_flag"]),
            gc.KeyTuple('syn_flag', flag_values["syn_flag"]),
            gc.KeyTuple('dnsq_flag', flag_values["dnsq_flag"]),
            gc.KeyTuple('global_time1', flag_values["global_time1"])
        ])
        keys.append(key)
        datas.append(slicing.make_data([gc.DataTuple('mask1', mask1),
                                        gc.DataTuple('mask2', mask2),
                                        gc.DataTuple('mask3', mask3),
                                        gc.DataTuple('mask4', mask4),
                                        gc.DataTuple('mask5', mask5)], 
                                        'SwitchIngress.extract_reg_c2_slicing_action'))
slicing.entry_add(target, keys, datas)

check_overflow = bfrt_info.table_get('SwitchIngress.reg_c2_overflow_table')
of_keys = ['reg_c2_overflow_flag_arr0', 'reg_c2_overflow_flag_arr1', 'reg_c2_overflow_flag_arr2', 'global_time1']
app1_flood_value = 0x80000000
app2_flood_value = 0x00800000
app3_flood_value = 0x00008000
app4_flood_value = 0x00000080
flood_values = [
    app1_flood_value,  # app1_flood
    app2_flood_value,  # app2_flood
    app3_flood_value,  # app3_flood
    app4_flood_value   # app4_flood
]
possible_flood_values = [0] + [sum(combo) for i in range(1, len(flood_values) + 1) 
                         for combo in itertools.combinations(flood_values, i)]
keys = []
datas = []
for arr0, arr1, arr2, global_time1 in itertools.product(possible_flood_values, possible_flood_values, possible_flood_values, [0, 1]):
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
        keys.append(key)
        data = check_overflow.make_data([gc.DataTuple('tag', mirror_tag)], 'SwitchIngress.set_mirror_flag_action')
        datas.append(data)
check_overflow.entry_add(target, keys, datas)


# upload and resubmit
# If flag is set, then upload the packet to the CPU
upload = bfrt_info.table_get('SwitchIngress.resubmit_mirror_table')
keys = []
datas = []
upload_flags = ["overflow_flag", "resubmit_flag"]
combinations = itertools.product([0, 1], repeat=len(upload_flags))
for combo in combinations:
    flag_values = dict(zip(upload_flags, combo))
    # If already resubmitted, then now mirror to CPU,
    if flag_values["resubmit_flag"] == 1:
        key = upload.make_key([gc.KeyTuple('ig_intr_md.resubmit_flag',1),
                               gc.KeyTuple('overflow_flag', flag_values['overflow_flag'])])
        keys.append(key)
        data = upload.make_data([], 'SwitchIngress.mirror_to_CPU')
        datas.append(data)
        continue
    else:
        # Not rusubmitted and not overflowed, then do nothing
        if flag_values['overflow_flag'] == 0:
            key = upload.make_key([gc.KeyTuple('ig_intr_md.resubmit_flag', 0),
                                   gc.KeyTuple('overflow_flag', 0)])
            keys.append(key)
            data = upload.make_data([], 'SwitchIngress.skip_egress')
            datas.append(data)
            continue
        # If not resubmitted yet, resubmit first
        else:
            key = upload.make_key([gc.KeyTuple('ig_intr_md.resubmit_flag', 0),
                                   gc.KeyTuple('overflow_flag', 1)])
            keys.append(key)
            data = upload.make_data([], 'SwitchIngress.resubmit_set')
            datas.append(data)
            continue
upload.entry_add(target, keys, datas)

mirror_cfg_table = bfrt_info.table_get("$mirror.cfg")
mirror_cfg_table.entry_add(
                    target,
                    [mirror_cfg_table.make_key([gc.KeyTuple('$sid', 10)])],
                    [mirror_cfg_table.make_data([gc.DataTuple('$direction', str_val="INGRESS"),
                                                 gc.DataTuple('$ucast_egress_port', 64), # CPU Etherenet: enp4s0f1 : 04:00.1
                                                #  gc.DataTuple('$ucast_egress_port', 66), # CPU Etherenet: enp4s0f0 : 04:00.0 
                                                #  gc.DataTuple('$ucast_egress_port', 192), # CPU PCIe: ens1
                                                 gc.DataTuple('$ucast_egress_port_valid', bool_val=True),
                                                 gc.DataTuple('$session_enable', bool_val=True),
                                                 gc.DataTuple('$max_pkt_len', 1024)],
                                                '$normal')]
                )

set_index_table = bfrt_info.table_get('SwitchEgress.set_index_table')
key = set_index_table.make_key([gc.KeyTuple('hdr.ethernet.$valid', True)])
data = set_index_table.make_data([],'SwitchEgress.set_index')
set_index_table.entry_add(target, [key], [data])

# register = bfrt_info.table_get('SwitchIngress.reg_c2_w2_0')
# register.entry_del(target, [])


# def table_add(target, table, keys, action, action_data=[]):
#     keys = [table.make_key([gc.KeyTuple(*f)   for f in keys])]
#     datas = [table.make_data([gc.DataTuple(*p) for p in action_data],
#                                   action)]
#     table.entry_add(target, keys, datas)

# def table_clear(target, table):
#     keys = []
#     for data,key in table.entry_get(target):
#         if key is not None:
#             keys.append(key)
#     table.entry_del(target, keys)

############################## FINALLY ####################################

# print("The End")
