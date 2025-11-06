#!/usr/bin/env python3

import os
import sys
import pdb
import itertools

#
# This is optional if you use proper PYTHONPATH
#
if __name__ == "__main__":
    SDE_INSTALL   = os.environ['SDE_INSTALL']
    SDE_PYTHON2   = os.path.join(SDE_INSTALL, 'lib', 'python2.7', 'site-packages')
    sys.path.append(SDE_PYTHON2)
    sys.path.append(os.path.join(SDE_PYTHON2, 'tofino'))
    sys.path.append(os.path.join(SDE_PYTHON2, 'tofino', 'bfrt_grpc'))

    PYTHON3_VER   = '{}.{}'.format(
        sys.version_info.major,
        sys.version_info.minor)
    SDE_PYTHON3   = os.path.join(SDE_INSTALL, 'lib', 'python' + PYTHON3_VER,
                                'site-packages')
    sys.path.append(SDE_PYTHON3)
    sys.path.append(os.path.join(SDE_PYTHON3, 'tofino'))
    sys.path.append(os.path.join(SDE_PYTHON3, 'tofino', 'bfrt_grpc'))

# Here is the most important module
import bfrt_grpc.client as gc


#####################################################################
#   Change these constants for different shapes and configuration   #
#####################################################################
LAYER1_ENTRY_SIZE_EXP   = 16        # 2**16
LAYER2_ENTRY_SIZE_EXP   = 15        # 2**15
LAYER3_ENTRY_SIZE_EXP   = 14        # 2**14
LAYER1_BIT_SIZE         = 8         # 8 bits per task at layer 1
LAYER2_BIT_SIZE         = 16        # 16 bits per task at layer 2
LAYER3_BIT_SIZE         = 16        # 16 bits per task at layer 3
LAYER2_DECAY_BIT        = 1
LAYER3_DECAY_BIT        = 2
BLOCKLIST_SIZE          = 131072    # 2**17
THRESHOLD_ICMPQ         = 2000
THRESHOLD_UDP           = 2000
THRESHOLD_DNSQ          = 750
THRESHOLD_SYN           = 2000

GLOBAL_TIME1            = 33        # about 8 seconds
GLOBAL_TIME2            = 34        # about 16 seconds
GLOBAL_TIME3            = 35        # about 32 seconds

RECIRC_PORT             = 68
# PORT_A                  = 0
# PORT_B                  = 1
PORT_A                  = 44        # port 11 (enp216s0np0)
PORT_B                  = 36        # port 12 (enp59s0np0)
PORT_M                  = 192

PTF_TEST                = 0         # 1 is for PTF test, otherwise 0
if PTF_TEST:
    LAYER1_BIT_SIZE     = 4         # 4 bits per task at layer 1
    LAYER2_BIT_SIZE     = 4         # 4 bits per task at layer 2
    LAYER3_BIT_SIZE     = 4         # 4 bits per task at layer 3
    # PORT_A              = 0
    # PORT_B              = 1
    PORT_A              = 64        # CPU Ethernet port
    PORT_B              = 66        # CPU Ethernet port
#####################################################################
#   Change these constants for different shapes and configuration   #
#####################################################################

LAYER1_ENTRY_SIZE       = (1 << (LAYER1_ENTRY_SIZE_EXP))
LAYER2_ENTRY_SIZE       = (1 << (LAYER2_ENTRY_SIZE_EXP))
LAYER3_ENTRY_SIZE       = (1 << (LAYER3_ENTRY_SIZE_EXP))
LAYER1_TOTAL_BIT_SIZE   = ((LAYER1_BIT_SIZE)*4)
LAYER2_TOTAL_BIT_SIZE   = ((LAYER2_BIT_SIZE)*2)
LAYER3_TOTAL_BIT_SIZE   = ((LAYER3_BIT_SIZE)*2)

LAYER1_ICMPQ   = 1 << ((LAYER1_BIT_SIZE)*3)
LAYER1_UDP     = 1 << ((LAYER1_BIT_SIZE)*2)
LAYER1_DNSQ    = 1 << ((LAYER1_BIT_SIZE)*1)
LAYER1_SYN     = 1
LAYER2_ICMPQ   = 1 << (LAYER2_BIT_SIZE)
LAYER2_UDP     = 1
LAYER2_DNSQ    = 1 << (LAYER2_BIT_SIZE)
LAYER2_SYN     = 1
LAYER3_ICMPQ   = 1 << (LAYER3_BIT_SIZE)
LAYER3_UDP     = 1
LAYER3_DNSQ    = 1 << (LAYER3_BIT_SIZE)
LAYER3_SYN     = 1

LAYER1_DATA_3  = (1<<((LAYER1_BIT_SIZE)-1)) - 1
LAYER1_DATA_2  = LAYER1_DATA_3 << ((LAYER1_BIT_SIZE)*1)
LAYER1_DATA_1  = LAYER1_DATA_3 << ((LAYER1_BIT_SIZE)*2)
LAYER1_DATA_0  = LAYER1_DATA_3 << ((LAYER1_BIT_SIZE)*3)
LAYER1_DATA    = LAYER1_DATA_3 + LAYER1_DATA_2 + LAYER1_DATA_1 + LAYER1_DATA_0
LAYER2_DATA_LO = (1<<((LAYER2_BIT_SIZE)-1)) - 1
LAYER2_DATA_HI = LAYER2_DATA_LO << (LAYER2_BIT_SIZE)
LAYER2_DATA    = LAYER2_DATA_LO + LAYER2_DATA_HI
LAYER3_DATA_LO = (1<<((LAYER3_BIT_SIZE)-1)) - 1
LAYER3_DATA_HI = LAYER3_DATA_LO << (LAYER3_BIT_SIZE)
LAYER3_DATA    = LAYER3_DATA_LO + LAYER3_DATA_HI

LAYER2_DECAY_DATA_LO    = (1<<((LAYER2_BIT_SIZE)-(LAYER2_DECAY_BIT))) - 1
LAYER2_DECAY_DATA_HI    = LAYER2_DECAY_DATA_LO << (LAYER2_BIT_SIZE)
LAYER2_DECAY_DATA       = LAYER2_DECAY_DATA_LO + LAYER2_DECAY_DATA_HI
LAYER3_DECAY_DATA_LO    = (1<<((LAYER3_BIT_SIZE)-(LAYER3_DECAY_BIT))) - 1
LAYER3_DECAY_DATA_HI    = LAYER3_DECAY_DATA_LO << (LAYER3_BIT_SIZE)
LAYER3_DECAY_DATA       = LAYER3_DECAY_DATA_LO + LAYER3_DECAY_DATA_HI

THRESHOLDS = [THRESHOLD_ICMPQ, THRESHOLD_UDP, THRESHOLD_DNSQ, THRESHOLD_SYN]

def setUp(bfrt_info, target, do_decay: bool, do_block: bool):
    ### Adding an entry to a table ###

    #####################
    # Check flow type
    #####################

    # ICMP request
    check_icmpq_table = bfrt_info.table_get('Ingress.check_icmpq_table')
    key_icmpq = check_icmpq_table.make_key([
            gc.KeyTuple('hdr.icmp.$valid', 1),  # isValid = True
            gc.KeyTuple('hdr.icmp.type_', 8)    # type = 8 (Echo Request)
        ])
    data_icmpq = check_icmpq_table.make_data([],'Ingress.check_icmpq_setflag')
    check_icmpq_table.entry_add(target, [key_icmpq], [data_icmpq])

    # UDP
    check_udp_table = bfrt_info.table_get('Ingress.check_udp_table')
    key_udp = check_udp_table.make_key([
            gc.KeyTuple('hdr.udp.$valid', 1),   # isValid = True
    ])
    data_udp = check_udp_table.make_data([],'Ingress.check_udp_setflag')
    check_udp_table.entry_add(target, [key_udp], [data_udp])

    # DNS query
    check_dnsq_table = bfrt_info.table_get('Ingress.check_dnsq_table')
    key_dnsq = check_dnsq_table.make_key([
        gc.KeyTuple('hdr.udp.$valid', 1),
        gc.KeyTuple('hdr.udp.dst_port', 53) 
    ])
    data_dnsq = check_dnsq_table.make_data([], 'Ingress.check_dnsq_setflag')    # Action for DNS
    check_dnsq_table.entry_add(target, [key_dnsq], [data_dnsq])

    # SYN
    check_syn_table = bfrt_info.table_get('Ingress.check_syn_table')
    key_syn = check_syn_table.make_key([
        gc.KeyTuple('hdr.tcp.$valid', 1),
        gc.KeyTuple('hdr.tcp.flags', 2) 
    ])
    data_syn = check_syn_table.make_data([], 'Ingress.check_syn_setflag')       # Action for SYN
    check_syn_table.entry_add(target, [key_syn], [data_syn])


    #####################
    # Check timestamp
    #####################

    reg_global_time1_set_table = bfrt_info.table_get('Ingress.reg_global_time1_set_table')
    reg_global_time2_set_table = bfrt_info.table_get('Ingress.reg_global_time2_set_table')
    reg_global_time3_set_table = bfrt_info.table_get('Ingress.reg_global_time3_set_table')
    reg_global_time_set_table = [reg_global_time1_set_table, reg_global_time2_set_table, reg_global_time3_set_table]
    for i, table in enumerate(reg_global_time_set_table, start=1):
        keys = []
        datas = []
        for time in [0,1]:
            key = table.make_key([gc.KeyTuple(f'global_time{i}', time)])
            keys.append(key)
            datas.append(table.make_data([], f'Ingress.global_time{i}_set{time}_action'))
        table.entry_add(target, keys, datas)

    reg_c_timer1_arr0_table = bfrt_info.table_get('Ingress.reg_c_timer1_arr0_table')
    reg_c_timer1_arr1_table = bfrt_info.table_get('Ingress.reg_c_timer1_arr1_table')
    reg_c_timer2_arr0_table = bfrt_info.table_get('Ingress.reg_c_timer2_arr0_table')
    reg_c_timer2_arr1_table = bfrt_info.table_get('Ingress.reg_c_timer2_arr1_table')
    reg_c_timer3_arr0_table = bfrt_info.table_get('Ingress.reg_c_timer3_arr0_table')
    reg_c_timer3_arr1_table = bfrt_info.table_get('Ingress.reg_c_timer3_arr1_table')
    reg_c_timer1_table = [reg_c_timer1_arr0_table, reg_c_timer1_arr1_table]
    reg_c_timer2_table = [reg_c_timer2_arr0_table, reg_c_timer2_arr1_table]
    reg_c_timer3_table = [reg_c_timer3_arr0_table, reg_c_timer3_arr1_table]
    reg_c_timer_table = [reg_c_timer1_table, reg_c_timer2_table, reg_c_timer3_table]
    for i, table_list in enumerate(reg_c_timer_table, start=1):
        for j, table in enumerate(table_list):
            keys = []
            datas = []
            for time in [0,1]:
                key = table.make_key([gc.KeyTuple(f'global_time{i}', time)])
                keys.append(key)
                datas.append(table.make_data([], f'Ingress.reg_c_timer{i}_arr{j}_update{time}_action'))
            table.entry_add(target, keys, datas)


    #####################
    # Set update value for CMS
    #####################

    reg_c2_layer1_dyn_table = bfrt_info.table_get('Ingress.reg_c2_layer1_dyn_table')
    keys = []
    datas = []
    for icmpq_flag, udp_flag, dnsq_flag, syn_flag in itertools.product([0, 1], repeat=4):
        key = reg_c2_layer1_dyn_table.make_key([
            gc.KeyTuple('icmpq_flag', icmpq_flag),
            gc.KeyTuple('udp_flag', udp_flag),
            gc.KeyTuple('dnsq_flag', dnsq_flag),
            gc.KeyTuple('syn_flag', syn_flag)
        ])
        keys.append(key)
        to_update_value = 0
        if icmpq_flag:
            to_update_value |= LAYER1_ICMPQ
        if udp_flag:
            to_update_value |= LAYER1_UDP
        if dnsq_flag:
            to_update_value |= LAYER1_DNSQ
        if syn_flag:
            to_update_value |= LAYER1_SYN
        datas.append(reg_c2_layer1_dyn_table.make_data([gc.DataTuple('slices', to_update_value)], 'Ingress.reg_c2_layer1_merge'))
    reg_c2_layer1_dyn_table.entry_add(target, keys, datas)

    reg_c2_layer2_arr0_dyn_table = bfrt_info.table_get('Ingress.reg_c2_layer2_arr0_dyn_table')
    reg_c2_layer2_arr1_dyn_table = bfrt_info.table_get('Ingress.reg_c2_layer2_arr1_dyn_table')
    reg_c2_layer2_dyn_table = [reg_c2_layer2_arr0_dyn_table, reg_c2_layer2_arr1_dyn_table]
    for i, table in enumerate(reg_c2_layer2_dyn_table):
        keys = []
        datas = []
        for reg_c_timer2_diff, app0, app1, app2, app3, decay_update_isvalid in itertools.product([0, 1], repeat=6):
            key = table.make_key([
                gc.KeyTuple(f'reg_c_timer2_arr{i}_diff', reg_c_timer2_diff),
                gc.KeyTuple(f'reg_c2_layer1_arr{i}_cur_res[{(LAYER1_BIT_SIZE*4)-1}:{(LAYER1_BIT_SIZE*4)-1}]', app0),
                gc.KeyTuple(f'reg_c2_layer1_arr{i}_cur_res[{(LAYER1_BIT_SIZE*3)-1}:{(LAYER1_BIT_SIZE*3)-1}]', app1),
                gc.KeyTuple(f'reg_c2_layer1_arr{i}_cur_res[{(LAYER1_BIT_SIZE*2)-1}:{(LAYER1_BIT_SIZE*2)-1}]', app2),
                gc.KeyTuple(f'reg_c2_layer1_arr{i}_cur_res[{(LAYER1_BIT_SIZE*1)-1}:{(LAYER1_BIT_SIZE*1)-1}]', app3),
                gc.KeyTuple('hdr.decay_update.$valid', decay_update_isvalid)
            ])
            keys.append(key)
            if decay_update_isvalid:
                datas.append(table.make_data([], f'Ingress.reg_c2_layer2_arr{i}_decay'))
            else:
                tg0_to_update_value = 0
                tg1_to_update_value = 0
                if app0:
                    tg0_to_update_value |= LAYER2_ICMPQ
                if app1:
                    tg0_to_update_value |= LAYER2_UDP
                if app2:
                    tg1_to_update_value |= LAYER2_DNSQ
                if app3:
                    tg1_to_update_value |= LAYER2_SYN
                if do_decay and reg_c_timer2_diff:  # Need to recirculate for decay
                    tg0_to_update_value *= 2**LAYER2_DECAY_BIT
                    tg1_to_update_value *= 2**LAYER2_DECAY_BIT
                datas.append(table.make_data([gc.DataTuple('slices0', tg0_to_update_value), gc.DataTuple('slices1', tg1_to_update_value)], f'Ingress.reg_c2_layer2_arr{i}_merge'))
        table.entry_add(target, keys, datas)

    reg_c2_layer3_arr0_dyn_table = bfrt_info.table_get('Ingress.reg_c2_layer3_arr0_dyn_table')
    reg_c2_layer3_arr1_dyn_table = bfrt_info.table_get('Ingress.reg_c2_layer3_arr1_dyn_table')
    reg_c2_layer3_dyn_table = [reg_c2_layer3_arr0_dyn_table, reg_c2_layer3_arr1_dyn_table]
    for i, table in enumerate(reg_c2_layer3_dyn_table):
        keys = []
        datas = []
        for reg_c_timer3_diff, app0, app1, app2, app3, decay_update_isvalid in itertools.product([0, 1], repeat=6):
            key = table.make_key([
                gc.KeyTuple(f'reg_c_timer3_arr{i}_diff', reg_c_timer3_diff),
                gc.KeyTuple(f'reg_c2_layer2_arr{i}_tg0_res[{(LAYER2_BIT_SIZE*2)-1}:{(LAYER2_BIT_SIZE*2)-1}]', app0),
                gc.KeyTuple(f'reg_c2_layer2_arr{i}_tg0_res[{(LAYER2_BIT_SIZE*1)-1}:{(LAYER2_BIT_SIZE*1)-1}]', app1),
                gc.KeyTuple(f'reg_c2_layer2_arr{i}_tg1_res[{(LAYER2_BIT_SIZE*2)-1}:{(LAYER2_BIT_SIZE*2)-1}]', app2),
                gc.KeyTuple(f'reg_c2_layer2_arr{i}_tg1_res[{(LAYER2_BIT_SIZE*1)-1}:{(LAYER2_BIT_SIZE*1)-1}]', app3),
                gc.KeyTuple('hdr.decay_update.$valid', decay_update_isvalid)
            ])
            keys.append(key)
            if decay_update_isvalid:
                datas.append(table.make_data([], f'Ingress.reg_c2_layer3_arr{i}_decay'))
            else:
                tg0_to_update_value = 0
                tg1_to_update_value = 0
                if app0:
                    tg0_to_update_value |= LAYER3_ICMPQ
                if app1:
                    tg0_to_update_value |= LAYER3_UDP
                if app2:
                    tg1_to_update_value |= LAYER3_DNSQ
                if app3:
                    tg1_to_update_value |= LAYER3_SYN
                if do_decay and reg_c_timer3_diff:  # Need to recirculate for decay
                    tg0_to_update_value *= 2**LAYER3_DECAY_BIT
                    tg1_to_update_value *= 2**LAYER3_DECAY_BIT
                datas.append(table.make_data([gc.DataTuple('slices0', tg0_to_update_value), gc.DataTuple('slices1', tg1_to_update_value)], f'Ingress.reg_c2_layer3_arr{i}_merge'))
        table.entry_add(target, keys, datas)


    #####################
    # Update CMS register
    #####################

    # Update CMS for 2-tuple
    # If global_time1 == 0 then use w1, otherwise use w2
    reg_c2_layer1_arr0_w1_table = bfrt_info.table_get('Ingress.reg_c2_layer1_arr0_w1_table')
    reg_c2_layer1_arr0_w2_table = bfrt_info.table_get('Ingress.reg_c2_layer1_arr0_w2_table')
    reg_c2_layer1_arr1_w1_table = bfrt_info.table_get('Ingress.reg_c2_layer1_arr1_w1_table')
    reg_c2_layer1_arr1_w2_table = bfrt_info.table_get('Ingress.reg_c2_layer1_arr1_w2_table')
    reg_c2_layer1_arr0_table = [reg_c2_layer1_arr0_w1_table, reg_c2_layer1_arr0_w2_table]
    reg_c2_layer1_arr1_table = [reg_c2_layer1_arr1_w1_table, reg_c2_layer1_arr1_w2_table]
    reg_c2_layer1_table = [reg_c2_layer1_arr0_table, reg_c2_layer1_arr1_table]
    for i, table_list in enumerate(reg_c2_layer1_table):    # arr0-1
        for j, table in enumerate(table_list, start=1):     # w1-2
            keys = []
            datas = []
            for global_time1, reg_c_timer1, overflow_isvalid, decay_update_isvalid in itertools.product([0, 1], repeat=4):
                key = table.make_key([
                    gc.KeyTuple('global_time1', global_time1),
                    gc.KeyTuple(f'reg_c_timer1_arr{i}_res', reg_c_timer1),
                    gc.KeyTuple('hdr.overflow.$valid', overflow_isvalid),
                    gc.KeyTuple('hdr.decay_update.$valid', decay_update_isvalid)
                ])
                keys.append(key)
                if decay_update_isvalid or overflow_isvalid:
                    datas.append(table.make_data([], f'Ingress.reg_c2_layer1_arr{i}_w{j}_setbit_action'))
                elif global_time1 == reg_c_timer1:
                    datas.append(table.make_data([], f'Ingress.reg_c2_layer1_arr{i}_w{j}_plus_action'))
                else:
                    datas.append(table.make_data([], f'Ingress.reg_c2_layer1_arr{i}_w{j}_update_action'))
            table.entry_add(target, keys, datas)

    reg_c2_layer2_arr0_tg0_table = bfrt_info.table_get('Ingress.reg_c2_layer2_arr0_tg0_table')
    reg_c2_layer2_arr0_tg1_table = bfrt_info.table_get('Ingress.reg_c2_layer2_arr0_tg1_table')
    reg_c2_layer2_arr1_tg0_table = bfrt_info.table_get('Ingress.reg_c2_layer2_arr1_tg0_table')
    reg_c2_layer2_arr1_tg1_table = bfrt_info.table_get('Ingress.reg_c2_layer2_arr1_tg1_table')
    reg_c2_layer3_arr0_tg0_table = bfrt_info.table_get('Ingress.reg_c2_layer3_arr0_tg0_table')
    reg_c2_layer3_arr0_tg1_table = bfrt_info.table_get('Ingress.reg_c2_layer3_arr0_tg1_table')
    reg_c2_layer3_arr1_tg0_table = bfrt_info.table_get('Ingress.reg_c2_layer3_arr1_tg0_table')
    reg_c2_layer3_arr1_tg1_table = bfrt_info.table_get('Ingress.reg_c2_layer3_arr1_tg1_table')
    reg_c2_layer2_arr0_table = [reg_c2_layer2_arr0_tg0_table, reg_c2_layer2_arr0_tg1_table]
    reg_c2_layer2_arr1_table = [reg_c2_layer2_arr1_tg0_table, reg_c2_layer2_arr1_tg1_table]
    reg_c2_layer3_arr0_table = [reg_c2_layer3_arr0_tg0_table, reg_c2_layer3_arr0_tg1_table]
    reg_c2_layer3_arr1_table = [reg_c2_layer3_arr1_tg0_table, reg_c2_layer3_arr1_tg1_table]
    reg_c2_layer2_table = [reg_c2_layer2_arr0_table, reg_c2_layer2_arr1_table]
    reg_c2_layer3_table = [reg_c2_layer3_arr0_table, reg_c2_layer3_arr1_table]
    reg_c2_layer2_layer3_table = [reg_c2_layer2_table, reg_c2_layer3_table]
    for i, table_list_list in enumerate(reg_c2_layer2_layer3_table, start=2):   # layer2, layer3
        for j, table_list in enumerate(table_list_list):                        # arr0, arr1
            for k, table in enumerate(table_list):                              # tg0, tg1
                keys = []
                datas = []
                for overflow_isvalid, decay_update_isvalid, is_decay in itertools.product([0, 1], repeat=3):
                    key = table.make_key([
                        gc.KeyTuple('hdr.overflow.$valid', overflow_isvalid),
                        gc.KeyTuple('hdr.decay_update.$valid', decay_update_isvalid),
                        gc.KeyTuple(f'hdr.decay_update.layer{i}_arr{j}_is_decay', is_decay)
                    ])
                    keys.append(key)
                    if decay_update_isvalid:
                        if is_decay:
                            datas.append(table.make_data([], f'Ingress.reg_c2_layer{i}_arr{j}_tg{k}_decay_action'))
                        else:
                            datas.append(table.make_data([], f'Ingress.reg_c2_layer{i}_arr{j}_tg{k}_read_action'))
                    elif overflow_isvalid:
                        datas.append(table.make_data([], f'Ingress.reg_c2_layer{i}_arr{j}_tg{k}_setbit_action'))
                    else:
                        datas.append(table.make_data([], f'Ingress.reg_c2_layer{i}_arr{j}_tg{k}_plus_action'))
                table.entry_add(target, keys, datas)

    extract_reg_c2_layer2_arr0 = bfrt_info.table_get('Ingress.extract_reg_c2_layer2_arr0')
    extract_reg_c2_layer2_arr1 = bfrt_info.table_get('Ingress.extract_reg_c2_layer2_arr1')
    extract_reg_c2_layer3_arr0 = bfrt_info.table_get('Ingress.extract_reg_c2_layer3_arr0')
    extract_reg_c2_layer3_arr1 = bfrt_info.table_get('Ingress.extract_reg_c2_layer3_arr1')
    extract_reg_c2_layer2 = [extract_reg_c2_layer2_arr0, extract_reg_c2_layer2_arr1]
    extract_reg_c2_layer3 = [extract_reg_c2_layer3_arr0, extract_reg_c2_layer3_arr1]
    extract_reg_c2 = [extract_reg_c2_layer2, extract_reg_c2_layer3]
    for i, table_list in enumerate(extract_reg_c2, start=2):    # w2-3
        for j, table in enumerate(table_list):                  # arr0-1
            keys = []
            datas = []
            for w1_slice0, w1_slice1, w1_slice2, w1_slice3, w2_slice0, w2_slice1, w2_slice2, w2_slice3 in itertools.product([0, 1], repeat=8):
                ovf_ctr = (w1_slice0 << 7) + (w1_slice1 << 6) + (w1_slice2 << 5) + (w1_slice3 << 4) \
                        + (w2_slice0 << 3) + (w2_slice1 << 2) + (w2_slice2 << 1) + (w2_slice3 << 0)
                slice0 = w1_slice0 | w2_slice0
                slice1 = w1_slice1 | w2_slice1
                slice2 = w1_slice2 | w2_slice2
                slice3 = w1_slice3 | w2_slice3
                key = table.make_key([gc.KeyTuple(f'reg_c2_layer{i-1}_arr{j}_overflow_counter_res', ovf_ctr)])
                keys.append(key)
                datas.append(table.make_data([], f'Ingress.extract_reg_c2_layer{i}_arr{j}_{slice0}{slice1}{slice2}{slice3}'))
            table.entry_add(target, keys, datas)

    reg_c2_layer1_overflow_table = bfrt_info.table_get('Ingress.reg_c2_layer1_overflow_table')
    keys = []
    datas = []
    for arr0_app0, arr0_app1, arr0_app2, arr0_app3, arr1_app0, arr1_app1, arr1_app2, arr1_app3 in itertools.product([0, 1], repeat=8):
        if arr0_app0 or arr0_app1 or arr0_app2 or arr0_app3 or arr1_app0 or arr1_app1 or arr1_app2 or arr1_app3:    # Only if overflow exists
            key = reg_c2_layer1_overflow_table.make_key([
                gc.KeyTuple(f'reg_c2_layer1_arr0_cur_res[{(LAYER1_BIT_SIZE*4)-1}:{(LAYER1_BIT_SIZE*4)-1}]', arr0_app0),
                gc.KeyTuple(f'reg_c2_layer1_arr0_cur_res[{(LAYER1_BIT_SIZE*3)-1}:{(LAYER1_BIT_SIZE*3)-1}]', arr0_app1),
                gc.KeyTuple(f'reg_c2_layer1_arr0_cur_res[{(LAYER1_BIT_SIZE*2)-1}:{(LAYER1_BIT_SIZE*2)-1}]', arr0_app2),
                gc.KeyTuple(f'reg_c2_layer1_arr0_cur_res[{(LAYER1_BIT_SIZE*1)-1}:{(LAYER1_BIT_SIZE*1)-1}]', arr0_app3),
                gc.KeyTuple(f'reg_c2_layer1_arr1_cur_res[{(LAYER1_BIT_SIZE*4)-1}:{(LAYER1_BIT_SIZE*4)-1}]', arr1_app0),
                gc.KeyTuple(f'reg_c2_layer1_arr1_cur_res[{(LAYER1_BIT_SIZE*3)-1}:{(LAYER1_BIT_SIZE*3)-1}]', arr1_app1),
                gc.KeyTuple(f'reg_c2_layer1_arr1_cur_res[{(LAYER1_BIT_SIZE*2)-1}:{(LAYER1_BIT_SIZE*2)-1}]', arr1_app2),
                gc.KeyTuple(f'reg_c2_layer1_arr1_cur_res[{(LAYER1_BIT_SIZE*1)-1}:{(LAYER1_BIT_SIZE*1)-1}]', arr1_app3)
            ])
            keys.append(key)
            data = reg_c2_layer1_overflow_table.make_data([], 'Ingress.set_layer1_overflow_flag_action')
            datas.append(data)
    reg_c2_layer1_overflow_table.entry_add(target, keys, datas)

    reg_c2_layer2_overflow_table = bfrt_info.table_get('Ingress.reg_c2_layer2_overflow_table')
    keys = []
    datas = []
    for arr0_tg0_hi, arr0_tg0_lo, arr0_tg1_hi, arr0_tg1_lo, arr1_tg0_hi, arr1_tg0_lo, arr1_tg1_hi, arr1_tg1_lo in itertools.product([0, 1], repeat=8):
        if arr0_tg0_hi or arr0_tg0_lo or arr0_tg1_hi or arr0_tg1_lo or arr1_tg0_hi or arr1_tg0_lo or arr1_tg1_hi or arr1_tg1_lo:    # Only if overflow exists
            key = reg_c2_layer2_overflow_table.make_key([
                gc.KeyTuple(f'reg_c2_layer2_arr0_tg0_res[{(LAYER2_BIT_SIZE*2)-1}:{(LAYER2_BIT_SIZE*2)-1}]', arr0_tg0_hi),
                gc.KeyTuple(f'reg_c2_layer2_arr0_tg0_res[{(LAYER2_BIT_SIZE*1)-1}:{(LAYER2_BIT_SIZE*1)-1}]', arr0_tg0_lo),
                gc.KeyTuple(f'reg_c2_layer2_arr0_tg1_res[{(LAYER2_BIT_SIZE*2)-1}:{(LAYER2_BIT_SIZE*2)-1}]', arr0_tg1_hi),
                gc.KeyTuple(f'reg_c2_layer2_arr0_tg1_res[{(LAYER2_BIT_SIZE*1)-1}:{(LAYER2_BIT_SIZE*1)-1}]', arr0_tg1_lo),
                gc.KeyTuple(f'reg_c2_layer2_arr1_tg0_res[{(LAYER2_BIT_SIZE*2)-1}:{(LAYER2_BIT_SIZE*2)-1}]', arr1_tg0_hi),
                gc.KeyTuple(f'reg_c2_layer2_arr1_tg0_res[{(LAYER2_BIT_SIZE*1)-1}:{(LAYER2_BIT_SIZE*1)-1}]', arr1_tg0_lo),
                gc.KeyTuple(f'reg_c2_layer2_arr1_tg1_res[{(LAYER2_BIT_SIZE*2)-1}:{(LAYER2_BIT_SIZE*2)-1}]', arr1_tg1_hi),
                gc.KeyTuple(f'reg_c2_layer2_arr1_tg1_res[{(LAYER2_BIT_SIZE*1)-1}:{(LAYER2_BIT_SIZE*1)-1}]', arr1_tg1_lo)
            ])
            keys.append(key)
            data = reg_c2_layer2_overflow_table.make_data([], 'Ingress.set_layer2_overflow_flag_action')
            datas.append(data)
    reg_c2_layer2_overflow_table.entry_add(target, keys, datas)

    reg_c2_layer3_overflow = bfrt_info.table_get('Ingress.reg_c2_layer3_overflow_table')
    keys = []
    datas = []
    for arr0_tg0_hi, arr0_tg0_lo, arr0_tg1_hi, arr0_tg1_lo, arr1_tg0_hi, arr1_tg0_lo, arr1_tg1_hi, arr1_tg1_lo in itertools.product([0, 1], repeat=8):
        layer3_overflow_tag = 0
        if arr0_tg0_hi:
            layer3_overflow_tag |= 0b010000000
        if arr0_tg0_lo:
            layer3_overflow_tag |= 0b001000000
        if arr0_tg1_hi:
            layer3_overflow_tag |= 0b000100000
        if arr0_tg1_lo:
            layer3_overflow_tag |= 0b000010000
        if arr1_tg0_hi:
            layer3_overflow_tag |= 0b000001000
        if arr1_tg0_lo:
            layer3_overflow_tag |= 0b000000100
        if arr1_tg1_hi:
            layer3_overflow_tag |= 0b000000010
        if arr1_tg1_lo:
            layer3_overflow_tag |= 0b000000001
        if layer3_overflow_tag: # Only if overflow exists
            layer3_overflow_tag |= 0b100000000
        key = reg_c2_layer3_overflow.make_key([
            gc.KeyTuple(f'reg_c2_layer3_arr0_tg0_res[{(LAYER3_BIT_SIZE*2)-1}:{(LAYER3_BIT_SIZE*2)-1}]', arr0_tg0_hi),
            gc.KeyTuple(f'reg_c2_layer3_arr0_tg0_res[{(LAYER3_BIT_SIZE*1)-1}:{(LAYER3_BIT_SIZE*1)-1}]', arr0_tg0_lo),
            gc.KeyTuple(f'reg_c2_layer3_arr0_tg1_res[{(LAYER3_BIT_SIZE*2)-1}:{(LAYER3_BIT_SIZE*2)-1}]', arr0_tg1_hi),
            gc.KeyTuple(f'reg_c2_layer3_arr0_tg1_res[{(LAYER3_BIT_SIZE*1)-1}:{(LAYER3_BIT_SIZE*1)-1}]', arr0_tg1_lo),
            gc.KeyTuple(f'reg_c2_layer3_arr1_tg0_res[{(LAYER3_BIT_SIZE*2)-1}:{(LAYER3_BIT_SIZE*2)-1}]', arr1_tg0_hi),
            gc.KeyTuple(f'reg_c2_layer3_arr1_tg0_res[{(LAYER3_BIT_SIZE*1)-1}:{(LAYER3_BIT_SIZE*1)-1}]', arr1_tg0_lo),
            gc.KeyTuple(f'reg_c2_layer3_arr1_tg1_res[{(LAYER3_BIT_SIZE*2)-1}:{(LAYER3_BIT_SIZE*2)-1}]', arr1_tg1_hi),
            gc.KeyTuple(f'reg_c2_layer3_arr1_tg1_res[{(LAYER3_BIT_SIZE*1)-1}:{(LAYER3_BIT_SIZE*1)-1}]', arr1_tg1_lo)
        ])
        keys.append(key)
        data = reg_c2_layer3_overflow.make_data([gc.DataTuple('tag', layer3_overflow_tag)], 'Ingress.set_layer3_overflow_tag_action')
        datas.append(data)
    reg_c2_layer3_overflow.entry_add(target, keys, datas)

    reg_c2_layer1_arr0_overflow_counter_table = bfrt_info.table_get('Ingress.reg_c2_layer1_arr0_overflow_counter_table')
    reg_c2_layer1_arr1_overflow_counter_table = bfrt_info.table_get('Ingress.reg_c2_layer1_arr1_overflow_counter_table')
    reg_c2_layer2_arr0_overflow_counter_table = bfrt_info.table_get('Ingress.reg_c2_layer2_arr0_overflow_counter_table')
    reg_c2_layer2_arr1_overflow_counter_table = bfrt_info.table_get('Ingress.reg_c2_layer2_arr1_overflow_counter_table')
    reg_c2_layer1_overflow_counter_table = [reg_c2_layer1_arr0_overflow_counter_table, reg_c2_layer1_arr1_overflow_counter_table]
    reg_c2_layer2_overflow_counter_table = [reg_c2_layer2_arr0_overflow_counter_table, reg_c2_layer2_arr1_overflow_counter_table]
    reg_c2_layer1_layer2_overflow_counter_table = [reg_c2_layer1_overflow_counter_table, reg_c2_layer2_overflow_counter_table]
    for i, table_list in enumerate(reg_c2_layer1_layer2_overflow_counter_table, start=1):   # layer1-2
        for j, table in enumerate(table_list):                                              # arr0-1
            keys = []
            datas = []
            for global_time, reg_c_timer_diff in itertools.product([0, 1], repeat=2):
                key = table.make_key([
                    gc.KeyTuple(f'global_time{i+1}', global_time),
                    gc.KeyTuple(f'reg_c_timer{i+1}_arr{j}_diff', reg_c_timer_diff)
                ])
                keys.append(key)
                if reg_c_timer_diff:
                    datas.append(table.make_data([], f'Ingress.reg_c2_layer{i}_arr{j}_w{global_time+1}_overflow_counter_reset_action'))
                else:
                    datas.append(table.make_data([], f'Ingress.reg_c2_layer{i}_arr{j}_w{global_time+1}_overflow_counter_update_action'))
            table.entry_add(target, keys, datas)


    #####################
    # Send packets to port
    #####################

    ipv4_port_and_recirculate_mirror_table = bfrt_info.table_get('Ingress.ipv4_port_and_recirculate_mirror_table')
    keys = []
    datas = []
    for port in [PORT_A, PORT_B]:
        for reg_c_timer2_arr0_diff, reg_c_timer2_arr1_diff, reg_c_timer3_arr0_diff, reg_c_timer3_arr1_diff, decay_ingress_port_is_port_a, decay_ingress_port_is_management, l1_ovf, l2_ovf, l3_ovf, overflow_ingress_port_is_port_a in itertools.product([0, 1], repeat=10):
            key = ipv4_port_and_recirculate_mirror_table.make_key([
                gc.KeyTuple('ig_intr_md.ingress_port', port),
                gc.KeyTuple('reg_c_timer2_arr0_diff', reg_c_timer2_arr0_diff),
                gc.KeyTuple('reg_c_timer2_arr1_diff', reg_c_timer2_arr1_diff),
                gc.KeyTuple('reg_c_timer3_arr0_diff', reg_c_timer3_arr0_diff),
                gc.KeyTuple('reg_c_timer3_arr1_diff', reg_c_timer3_arr1_diff),
                gc.KeyTuple('hdr.decay_update.$valid', 0),
                gc.KeyTuple('hdr.decay_update.ingress_port_is_port_a', decay_ingress_port_is_port_a),
                gc.KeyTuple('hdr.decay_update.ingress_port_is_management', decay_ingress_port_is_management),
                gc.KeyTuple('layer1_overflow_flag', l1_ovf),
                gc.KeyTuple('layer2_overflow_flag', l2_ovf),
                gc.KeyTuple('layer3_overflow_tag[8:8]', l3_ovf),
                gc.KeyTuple('hdr.overflow.$valid', 0),
                gc.KeyTuple('hdr.overflow.ingress_port_is_port_a', overflow_ingress_port_is_port_a)
            ])
            keys.append(key)
            decay_tag = 0
            if reg_c_timer2_arr0_diff:
                decay_tag |= 0b1000
            if reg_c_timer2_arr1_diff:
                decay_tag |= 0b0100
            if reg_c_timer3_arr0_diff:
                decay_tag |= 0b0010
            if reg_c_timer3_arr1_diff:
                decay_tag |= 0b0001
            if do_decay and decay_tag:
                data = ipv4_port_and_recirculate_mirror_table.make_data([gc.DataTuple('decay_tag', decay_tag), gc.DataTuple('ingress_port_is_port_a', int(port == PORT_A)), gc.DataTuple('ingress_port_is_management', 0)], 'Ingress.decay_recirculate')
                datas.append(data)
            elif l3_ovf:
                data = ipv4_port_and_recirculate_mirror_table.make_data([gc.DataTuple('ingress_port_is_port_a', int(port == PORT_A))], 'Ingress.overflow_recirculate_and_mirror_to_CPU')
                datas.append(data)
            elif l1_ovf or l2_ovf:
                data = ipv4_port_and_recirculate_mirror_table.make_data([gc.DataTuple('ingress_port_is_port_a', int(port == PORT_A))], 'Ingress.overflow_recirculate')
                datas.append(data)
            else:
                data = ipv4_port_and_recirculate_mirror_table.make_data([gc.DataTuple('port', PORT_B if port == PORT_A else PORT_A)], 'Ingress.send')
                datas.append(data)
    if do_decay:
        for reg_c_timer2_arr0_diff, reg_c_timer2_arr1_diff, reg_c_timer3_arr0_diff, reg_c_timer3_arr1_diff, decay_ingress_port_is_port_a, decay_ingress_port_is_management, l1_ovf, l2_ovf, l3_ovf, overflow_ingress_port_is_port_a in itertools.product([0, 1], repeat=10):
            key = ipv4_port_and_recirculate_mirror_table.make_key([
                gc.KeyTuple('ig_intr_md.ingress_port', PORT_M),
                gc.KeyTuple('reg_c_timer2_arr0_diff', reg_c_timer2_arr0_diff),
                gc.KeyTuple('reg_c_timer2_arr1_diff', reg_c_timer2_arr1_diff),
                gc.KeyTuple('reg_c_timer3_arr0_diff', reg_c_timer3_arr0_diff),
                gc.KeyTuple('reg_c_timer3_arr1_diff', reg_c_timer3_arr1_diff),
                gc.KeyTuple('hdr.decay_update.$valid', 0),
                gc.KeyTuple('hdr.decay_update.ingress_port_is_port_a', decay_ingress_port_is_port_a),
                gc.KeyTuple('hdr.decay_update.ingress_port_is_management', decay_ingress_port_is_management),
                gc.KeyTuple('layer1_overflow_flag', l1_ovf),
                gc.KeyTuple('layer2_overflow_flag', l2_ovf),
                gc.KeyTuple('layer3_overflow_tag[8:8]', l3_ovf),
                gc.KeyTuple('hdr.overflow.$valid', 0),
                gc.KeyTuple('hdr.overflow.ingress_port_is_port_a', overflow_ingress_port_is_port_a)
            ])
            decay_tag = 0
            if reg_c_timer2_arr0_diff:
                decay_tag |= 0b1000
            if reg_c_timer2_arr1_diff:
                decay_tag |= 0b0100
            if reg_c_timer3_arr0_diff:
                decay_tag |= 0b0010
            if reg_c_timer3_arr1_diff:
                decay_tag |= 0b0001
            if do_decay and decay_tag:
                keys.append(key)
                data = ipv4_port_and_recirculate_mirror_table.make_data([gc.DataTuple('decay_tag', decay_tag), gc.DataTuple('ingress_port_is_port_a', 0), gc.DataTuple('ingress_port_is_management', 1)], 'Ingress.decay_recirculate')
                datas.append(data)
        for decay_ingress_port_is_port_a, l1_ovf, l2_ovf, l3_ovf, overflow_ingress_port_is_port_a in itertools.product([0, 1], repeat=5):
            key = ipv4_port_and_recirculate_mirror_table.make_key([
                gc.KeyTuple('ig_intr_md.ingress_port', RECIRC_PORT),
                gc.KeyTuple('reg_c_timer2_arr0_diff', 0),
                gc.KeyTuple('reg_c_timer2_arr1_diff', 0),
                gc.KeyTuple('reg_c_timer3_arr0_diff', 0),
                gc.KeyTuple('reg_c_timer3_arr1_diff', 0),
                gc.KeyTuple('hdr.decay_update.$valid', 1),
                gc.KeyTuple('hdr.decay_update.ingress_port_is_port_a', decay_ingress_port_is_port_a),
                gc.KeyTuple('hdr.decay_update.ingress_port_is_management', 0),
                gc.KeyTuple('layer1_overflow_flag', l1_ovf),
                gc.KeyTuple('layer2_overflow_flag', l2_ovf),
                gc.KeyTuple('layer3_overflow_tag[8:8]', l3_ovf),
                gc.KeyTuple('hdr.overflow.$valid', 0),
                gc.KeyTuple('hdr.overflow.ingress_port_is_port_a', overflow_ingress_port_is_port_a)
            ])
            keys.append(key)
            data = ipv4_port_and_recirculate_mirror_table.make_data([gc.DataTuple('port', PORT_B if decay_ingress_port_is_port_a else PORT_A)], 'Ingress.send')
            datas.append(data)
    for decay_ingress_port_is_port_a, decay_ingress_port_is_management, l1_ovf, l2_ovf, l3_ovf, overflow_ingress_port_is_port_a in itertools.product([0, 1], repeat=6):
        key = ipv4_port_and_recirculate_mirror_table.make_key([
            gc.KeyTuple('ig_intr_md.ingress_port', RECIRC_PORT),
            gc.KeyTuple('reg_c_timer2_arr0_diff', 0),
            gc.KeyTuple('reg_c_timer2_arr1_diff', 0),
            gc.KeyTuple('reg_c_timer3_arr0_diff', 0),
            gc.KeyTuple('reg_c_timer3_arr1_diff', 0),
            gc.KeyTuple('hdr.decay_update.$valid', 0),
            gc.KeyTuple('hdr.decay_update.ingress_port_is_port_a', decay_ingress_port_is_port_a),
            gc.KeyTuple('hdr.decay_update.ingress_port_is_management', decay_ingress_port_is_management),
            gc.KeyTuple('layer1_overflow_flag', l1_ovf),
            gc.KeyTuple('layer2_overflow_flag', l2_ovf),
            gc.KeyTuple('layer3_overflow_tag[8:8]', l3_ovf),
            gc.KeyTuple('hdr.overflow.$valid', 1),
            gc.KeyTuple('hdr.overflow.ingress_port_is_port_a', overflow_ingress_port_is_port_a)
        ])
        keys.append(key)
        data = ipv4_port_and_recirculate_mirror_table.make_data([gc.DataTuple('port', PORT_B if overflow_ingress_port_is_port_a else PORT_A)], 'Ingress.send')
        datas.append(data)
    ipv4_port_and_recirculate_mirror_table.entry_add(target, keys, datas)
    data = ipv4_port_and_recirculate_mirror_table.make_data([], 'Ingress.drop')
    ipv4_port_and_recirculate_mirror_table.default_entry_set(target, data)


    #####################
    # Block packets with value >= threshold
    #####################

    if do_block:
        block_threshold_arr0_slice0_table = bfrt_info.table_get('Ingress.block_threshold_arr0_slice0_table')
        block_threshold_arr0_slice1_table = bfrt_info.table_get('Ingress.block_threshold_arr0_slice1_table')
        block_threshold_arr0_slice2_table = bfrt_info.table_get('Ingress.block_threshold_arr0_slice2_table')
        block_threshold_arr0_slice3_table = bfrt_info.table_get('Ingress.block_threshold_arr0_slice3_table')
        block_threshold_arr1_slice0_table = bfrt_info.table_get('Ingress.block_threshold_arr1_slice0_table')
        block_threshold_arr1_slice1_table = bfrt_info.table_get('Ingress.block_threshold_arr1_slice1_table')
        block_threshold_arr1_slice2_table = bfrt_info.table_get('Ingress.block_threshold_arr1_slice2_table')
        block_threshold_arr1_slice3_table = bfrt_info.table_get('Ingress.block_threshold_arr1_slice3_table')
        block_threshold_arr0_table = [block_threshold_arr0_slice0_table, block_threshold_arr0_slice1_table, block_threshold_arr0_slice2_table, block_threshold_arr0_slice3_table]
        block_threshold_arr1_table = [block_threshold_arr1_slice0_table, block_threshold_arr1_slice1_table, block_threshold_arr1_slice2_table, block_threshold_arr1_slice3_table]
        block_thresholds_table = [block_threshold_arr0_table, block_threshold_arr1_table]
        for i, table_list in enumerate(block_thresholds_table): # arr0-1
            for j, table in enumerate(table_list):              # slice0-3
                keys = []
                datas = []
                for k in range(THRESHOLDS[j]):
                    key = table.make_key([gc.KeyTuple(f'md.extracted_reg_c2_arr{i}_slice{j}', k)])
                    keys.append(key)
                    datas.append(table.make_data([], 'NoAction'))
                table.entry_add(target, keys, datas)
                data = table.make_data([], f'Ingress.block_threshold_arr{i}_slice{j}_set')
                table.default_entry_set(target, data)

        block_threshold_table = bfrt_info.table_get('Ingress.block_threshold_table')
        keys = []
        datas = []
        for arr0_slice0, arr0_slice1, arr0_slice2, arr0_slice3, arr1_slice0, arr1_slice1, arr1_slice2, arr1_slice3 in itertools.product([0, 1], repeat=8):
            if (arr0_slice0 and arr1_slice0) or (arr0_slice1 and arr1_slice1) or (arr0_slice2 and arr1_slice2) or (arr0_slice3 and arr1_slice3):
                key = block_threshold_table.make_key([
                    gc.KeyTuple('block_request_arr0_slice0', arr0_slice0),
                    gc.KeyTuple('block_request_arr0_slice1', arr0_slice1),
                    gc.KeyTuple('block_request_arr0_slice2', arr0_slice2),
                    gc.KeyTuple('block_request_arr0_slice3', arr0_slice3),
                    gc.KeyTuple('block_request_arr1_slice0', arr1_slice0),
                    gc.KeyTuple('block_request_arr1_slice1', arr1_slice1),
                    gc.KeyTuple('block_request_arr1_slice2', arr1_slice2),
                    gc.KeyTuple('block_request_arr1_slice3', arr1_slice3)
                ])
                keys.append(key)
                datas.append(block_threshold_table.make_data([], 'Ingress.drop'))
        block_threshold_table.entry_add(target, keys, datas)

    mirror_cfg_table = bfrt_info.table_get("$mirror.cfg")
    mirror_cfg_table.entry_add(
        target,
        [mirror_cfg_table.make_key([gc.KeyTuple('$sid', 10)])],
        [mirror_cfg_table.make_data([gc.DataTuple('$direction', str_val="INGRESS"),
                                    #  gc.DataTuple('$ucast_egress_port', 64),    # CPU Ethernet: enp4s0f1
                                        gc.DataTuple('$ucast_egress_port', 192),   # CPU PCIe: ens1
                                        gc.DataTuple('$ucast_egress_port_valid', bool_val=True),
                                        gc.DataTuple('$session_enable', bool_val=True),
                                        gc.DataTuple('$max_pkt_len', 1024)],
                                        '$normal')]
    )

def tables(bfrt_info):  # Used by control plane
    # Registers
    reg_global_time1 = bfrt_info.table_get('Ingress.reg_global_time1')
    reg_global_time2 = bfrt_info.table_get('Ingress.reg_global_time2')
    reg_global_time3 = bfrt_info.table_get('Ingress.reg_global_time3')

    reg_c_timer1_arr0 = bfrt_info.table_get('Ingress.reg_c_timer1_arr0')
    reg_c_timer1_arr1 = bfrt_info.table_get('Ingress.reg_c_timer1_arr1')
    reg_c_timer2_arr0 = bfrt_info.table_get('Ingress.reg_c_timer2_arr0')
    reg_c_timer2_arr1 = bfrt_info.table_get('Ingress.reg_c_timer2_arr1')
    reg_c_timer3_arr0 = bfrt_info.table_get('Ingress.reg_c_timer3_arr0')
    reg_c_timer3_arr1 = bfrt_info.table_get('Ingress.reg_c_timer3_arr1')

    reg_c2_layer1_arr0_w1 = bfrt_info.table_get('Ingress.reg_c2_layer1_arr0_w1')
    reg_c2_layer1_arr0_w2 = bfrt_info.table_get('Ingress.reg_c2_layer1_arr0_w2')
    reg_c2_layer1_arr1_w1 = bfrt_info.table_get('Ingress.reg_c2_layer1_arr1_w1')
    reg_c2_layer1_arr1_w2 = bfrt_info.table_get('Ingress.reg_c2_layer1_arr1_w2')
    reg_c2_layer2_arr0_tg0 = bfrt_info.table_get('Ingress.reg_c2_layer2_arr0_tg0')
    reg_c2_layer2_arr0_tg1 = bfrt_info.table_get('Ingress.reg_c2_layer2_arr0_tg1')
    reg_c2_layer2_arr1_tg0 = bfrt_info.table_get('Ingress.reg_c2_layer2_arr1_tg0')
    reg_c2_layer2_arr1_tg1 = bfrt_info.table_get('Ingress.reg_c2_layer2_arr1_tg1')
    reg_c2_layer3_arr0_tg0 = bfrt_info.table_get('Ingress.reg_c2_layer3_arr0_tg0')
    reg_c2_layer3_arr0_tg1 = bfrt_info.table_get('Ingress.reg_c2_layer3_arr0_tg1')
    reg_c2_layer3_arr1_tg0 = bfrt_info.table_get('Ingress.reg_c2_layer3_arr1_tg0')
    reg_c2_layer3_arr1_tg1 = bfrt_info.table_get('Ingress.reg_c2_layer3_arr1_tg1')

    reg_c2_layer1_arr0_overflow_counter = bfrt_info.table_get('Ingress.reg_c2_layer1_arr0_overflow_counter')
    reg_c2_layer1_arr1_overflow_counter = bfrt_info.table_get('Ingress.reg_c2_layer1_arr1_overflow_counter')
    reg_c2_layer2_arr0_overflow_counter = bfrt_info.table_get('Ingress.reg_c2_layer2_arr0_overflow_counter')
    reg_c2_layer2_arr1_overflow_counter = bfrt_info.table_get('Ingress.reg_c2_layer2_arr1_overflow_counter')

    # Tables
    check_blocklist = bfrt_info.table_get('Ingress.check_blocklist')
    check_blocklist.info.key_field_annotation_add("hdr.ipv4.src_addr", "ipv4")
    check_blocklist.info.key_field_annotation_add("hdr.ipv4.dst_addr", "ipv4")

    check_icmpq_table = bfrt_info.table_get('Ingress.check_icmpq_table')
    check_udp_table = bfrt_info.table_get('Ingress.check_udp_table')
    check_dnsq_table = bfrt_info.table_get('Ingress.check_dnsq_table')
    check_syn_table = bfrt_info.table_get('Ingress.check_syn_table')

    reg_global_time1_set_table = bfrt_info.table_get('Ingress.reg_global_time1_set_table')
    reg_global_time2_set_table = bfrt_info.table_get('Ingress.reg_global_time2_set_table')
    reg_global_time3_set_table = bfrt_info.table_get('Ingress.reg_global_time3_set_table')

    reg_c_timer1_arr0_table = bfrt_info.table_get('Ingress.reg_c_timer1_arr0_table')
    reg_c_timer1_arr1_table = bfrt_info.table_get('Ingress.reg_c_timer1_arr1_table')
    reg_c_timer2_arr0_table = bfrt_info.table_get('Ingress.reg_c_timer2_arr0_table')
    reg_c_timer2_arr1_table = bfrt_info.table_get('Ingress.reg_c_timer2_arr1_table')
    reg_c_timer3_arr0_table = bfrt_info.table_get('Ingress.reg_c_timer3_arr0_table')
    reg_c_timer3_arr1_table = bfrt_info.table_get('Ingress.reg_c_timer3_arr1_table')

    reg_c2_layer1_dyn_table = bfrt_info.table_get('Ingress.reg_c2_layer1_dyn_table')
    reg_c2_layer2_arr0_dyn_table = bfrt_info.table_get('Ingress.reg_c2_layer2_arr0_dyn_table')
    reg_c2_layer2_arr1_dyn_table = bfrt_info.table_get('Ingress.reg_c2_layer2_arr1_dyn_table')
    reg_c2_layer3_arr0_dyn_table = bfrt_info.table_get('Ingress.reg_c2_layer3_arr0_dyn_table')
    reg_c2_layer3_arr1_dyn_table = bfrt_info.table_get('Ingress.reg_c2_layer3_arr1_dyn_table')

    reg_c2_layer1_arr0_w1_table = bfrt_info.table_get('Ingress.reg_c2_layer1_arr0_w1_table')
    reg_c2_layer1_arr0_w2_table = bfrt_info.table_get('Ingress.reg_c2_layer1_arr0_w2_table')
    reg_c2_layer1_arr1_w1_table = bfrt_info.table_get('Ingress.reg_c2_layer1_arr1_w1_table')
    reg_c2_layer1_arr1_w2_table = bfrt_info.table_get('Ingress.reg_c2_layer1_arr1_w2_table')
    reg_c2_layer2_arr0_tg0_table = bfrt_info.table_get('Ingress.reg_c2_layer2_arr0_tg0_table')
    reg_c2_layer2_arr0_tg1_table = bfrt_info.table_get('Ingress.reg_c2_layer2_arr0_tg1_table')
    reg_c2_layer2_arr1_tg0_table = bfrt_info.table_get('Ingress.reg_c2_layer2_arr1_tg0_table')
    reg_c2_layer2_arr1_tg1_table = bfrt_info.table_get('Ingress.reg_c2_layer2_arr1_tg1_table')
    reg_c2_layer3_arr0_tg0_table = bfrt_info.table_get('Ingress.reg_c2_layer3_arr0_tg0_table')
    reg_c2_layer3_arr0_tg1_table = bfrt_info.table_get('Ingress.reg_c2_layer3_arr0_tg1_table')
    reg_c2_layer3_arr1_tg0_table = bfrt_info.table_get('Ingress.reg_c2_layer3_arr1_tg0_table')
    reg_c2_layer3_arr1_tg1_table = bfrt_info.table_get('Ingress.reg_c2_layer3_arr1_tg1_table')

    extract_reg_c2_layer2_arr0 = bfrt_info.table_get('Ingress.extract_reg_c2_layer2_arr0')
    extract_reg_c2_layer2_arr1 = bfrt_info.table_get('Ingress.extract_reg_c2_layer2_arr1')
    extract_reg_c2_layer3_arr0 = bfrt_info.table_get('Ingress.extract_reg_c2_layer3_arr0')
    extract_reg_c2_layer3_arr1 = bfrt_info.table_get('Ingress.extract_reg_c2_layer3_arr1')

    reg_c2_layer1_overflow_table = bfrt_info.table_get('Ingress.reg_c2_layer1_overflow_table')
    reg_c2_layer2_overflow_table = bfrt_info.table_get('Ingress.reg_c2_layer2_overflow_table')
    reg_c2_layer3_overflow_table = bfrt_info.table_get('Ingress.reg_c2_layer3_overflow_table')

    reg_c2_layer1_arr0_overflow_counter_table = bfrt_info.table_get('Ingress.reg_c2_layer1_arr0_overflow_counter_table')
    reg_c2_layer1_arr1_overflow_counter_table = bfrt_info.table_get('Ingress.reg_c2_layer1_arr1_overflow_counter_table')
    reg_c2_layer2_arr0_overflow_counter_table = bfrt_info.table_get('Ingress.reg_c2_layer2_arr0_overflow_counter_table')
    reg_c2_layer2_arr1_overflow_counter_table = bfrt_info.table_get('Ingress.reg_c2_layer2_arr1_overflow_counter_table')

    ipv4_port_and_recirculate_mirror_table = bfrt_info.table_get('Ingress.ipv4_port_and_recirculate_mirror_table')

    block_threshold_arr0_slice0_table = bfrt_info.table_get('Ingress.block_threshold_arr0_slice0_table')
    block_threshold_arr0_slice1_table = bfrt_info.table_get('Ingress.block_threshold_arr0_slice1_table')
    block_threshold_arr0_slice2_table = bfrt_info.table_get('Ingress.block_threshold_arr0_slice2_table')
    block_threshold_arr0_slice3_table = bfrt_info.table_get('Ingress.block_threshold_arr0_slice3_table')
    block_threshold_arr1_slice0_table = bfrt_info.table_get('Ingress.block_threshold_arr1_slice0_table')
    block_threshold_arr1_slice1_table = bfrt_info.table_get('Ingress.block_threshold_arr1_slice1_table')
    block_threshold_arr1_slice2_table = bfrt_info.table_get('Ingress.block_threshold_arr1_slice2_table')
    block_threshold_arr1_slice3_table = bfrt_info.table_get('Ingress.block_threshold_arr1_slice3_table')
    block_threshold_table = bfrt_info.table_get('Ingress.block_threshold_table')

    mirror_cfg = bfrt_info.table_get("$mirror.cfg")

    tables = { # Registers
               "reg_global_time1" : reg_global_time1,
               "reg_global_time2" : reg_global_time2,
               "reg_global_time3" : reg_global_time3,

               "reg_c_timer1_arr0" : reg_c_timer1_arr0,
               "reg_c_timer1_arr1" : reg_c_timer1_arr1,
               "reg_c_timer2_arr0" : reg_c_timer2_arr0,
               "reg_c_timer2_arr1" : reg_c_timer2_arr1,
               "reg_c_timer3_arr0" : reg_c_timer3_arr0,
               "reg_c_timer3_arr1" : reg_c_timer3_arr1,

               "reg_c2_layer1_arr0_w1" : reg_c2_layer1_arr0_w1,
               "reg_c2_layer1_arr0_w2" : reg_c2_layer1_arr0_w2,
               "reg_c2_layer1_arr1_w1" : reg_c2_layer1_arr1_w1,
               "reg_c2_layer1_arr1_w2" : reg_c2_layer1_arr1_w2,
               "reg_c2_layer2_arr0_tg0" : reg_c2_layer2_arr0_tg0,
               "reg_c2_layer2_arr0_tg1" : reg_c2_layer2_arr0_tg1,
               "reg_c2_layer2_arr1_tg0" : reg_c2_layer2_arr1_tg0,
               "reg_c2_layer2_arr1_tg1" : reg_c2_layer2_arr1_tg1,
               "reg_c2_layer3_arr0_tg0" : reg_c2_layer3_arr0_tg0,
               "reg_c2_layer3_arr0_tg1" : reg_c2_layer3_arr0_tg1,
               "reg_c2_layer3_arr1_tg0" : reg_c2_layer3_arr1_tg0,
               "reg_c2_layer3_arr1_tg1" : reg_c2_layer3_arr1_tg1,

               "reg_c2_layer1_arr0_overflow_counter" : reg_c2_layer1_arr0_overflow_counter,
               "reg_c2_layer1_arr1_overflow_counter" : reg_c2_layer1_arr1_overflow_counter,
               "reg_c2_layer2_arr0_overflow_counter" : reg_c2_layer2_arr0_overflow_counter,
               "reg_c2_layer2_arr1_overflow_counter" : reg_c2_layer2_arr1_overflow_counter,

               # Tables 
               "check_blocklist" : check_blocklist,

               "check_icmpq_table" : check_icmpq_table,
               "check_udp_table" : check_udp_table,
               "check_dnsq_table" : check_dnsq_table,
               "check_syn_table" : check_syn_table,

               "reg_global_time1_set_table" : reg_global_time1_set_table,
               "reg_global_time2_set_table" : reg_global_time2_set_table,
               "reg_global_time3_set_table" : reg_global_time3_set_table,

               "reg_c_timer1_arr0_table" : reg_c_timer1_arr0_table,
               "reg_c_timer1_arr1_table" : reg_c_timer1_arr1_table,
               "reg_c_timer2_arr0_table" : reg_c_timer2_arr0_table,
               "reg_c_timer2_arr1_table" : reg_c_timer2_arr1_table,
               "reg_c_timer3_arr0_table" : reg_c_timer3_arr0_table,
               "reg_c_timer3_arr1_table" : reg_c_timer3_arr1_table,

               "reg_c2_layer1_dyn_table" : reg_c2_layer1_dyn_table,
               "reg_c2_layer2_arr0_dyn_table" : reg_c2_layer2_arr0_dyn_table,
               "reg_c2_layer2_arr1_dyn_table" : reg_c2_layer2_arr1_dyn_table,
               "reg_c2_layer3_arr0_dyn_table" : reg_c2_layer3_arr0_dyn_table,
               "reg_c2_layer3_arr1_dyn_table" : reg_c2_layer3_arr1_dyn_table,

               "reg_c2_layer1_arr0_w1_table" : reg_c2_layer1_arr0_w1_table,
               "reg_c2_layer1_arr0_w2_table" : reg_c2_layer1_arr0_w2_table,
               "reg_c2_layer1_arr1_w1_table" : reg_c2_layer1_arr1_w1_table,
               "reg_c2_layer1_arr1_w2_table" : reg_c2_layer1_arr1_w2_table,
               "reg_c2_layer2_arr0_tg0_table" : reg_c2_layer2_arr0_tg0_table,
               "reg_c2_layer2_arr0_tg1_table" : reg_c2_layer2_arr0_tg1_table,
               "reg_c2_layer2_arr1_tg0_table" : reg_c2_layer2_arr1_tg0_table,
               "reg_c2_layer2_arr1_tg1_table" : reg_c2_layer2_arr1_tg1_table,
               "reg_c2_layer3_arr0_tg0_table" : reg_c2_layer3_arr0_tg0_table,
               "reg_c2_layer3_arr0_tg1_table" : reg_c2_layer3_arr0_tg1_table,
               "reg_c2_layer3_arr1_tg0_table" : reg_c2_layer3_arr1_tg0_table,
               "reg_c2_layer3_arr1_tg1_table" : reg_c2_layer3_arr1_tg1_table,

               "extract_reg_c2_layer2_arr0" : extract_reg_c2_layer2_arr0,
               "extract_reg_c2_layer2_arr1" : extract_reg_c2_layer2_arr1,
               "extract_reg_c2_layer3_arr0" : extract_reg_c2_layer3_arr0,
               "extract_reg_c2_layer3_arr1" : extract_reg_c2_layer3_arr1,

               "reg_c2_layer1_overflow_table" : reg_c2_layer1_overflow_table,
               "reg_c2_layer2_overflow_table" : reg_c2_layer2_overflow_table,
               "reg_c2_layer3_overflow_table" : reg_c2_layer3_overflow_table,

               "reg_c2_layer1_arr0_overflow_counter_table" : reg_c2_layer1_arr0_overflow_counter_table,
               "reg_c2_layer1_arr1_overflow_counter_table" : reg_c2_layer1_arr1_overflow_counter_table,
               "reg_c2_layer2_arr0_overflow_counter_table" : reg_c2_layer2_arr0_overflow_counter_table,
               "reg_c2_layer2_arr1_overflow_counter_table" : reg_c2_layer2_arr1_overflow_counter_table,

               "ipv4_port_and_recirculate_mirror_table" : ipv4_port_and_recirculate_mirror_table,

               "block_threshold_arr0_slice0_table" : block_threshold_arr0_slice0_table,
               "block_threshold_arr0_slice1_table" : block_threshold_arr0_slice1_table,
               "block_threshold_arr0_slice2_table" : block_threshold_arr0_slice2_table,
               "block_threshold_arr0_slice3_table" : block_threshold_arr0_slice3_table,
               "block_threshold_arr1_slice0_table" : block_threshold_arr1_slice0_table,
               "block_threshold_arr1_slice1_table" : block_threshold_arr1_slice1_table,
               "block_threshold_arr1_slice2_table" : block_threshold_arr1_slice2_table,
               "block_threshold_arr1_slice3_table" : block_threshold_arr1_slice3_table,
               "block_threshold_table" : block_threshold_table,

               "mirror.cfg" : mirror_cfg
              }

    return tables

def cleanUp(target, tables):    # Used by control plane
    try:
        for t in tables:
            # Empty list of keys means 'all entries'
            t.entry_del(target, [])

            # Not all tables support default entry
            try:
                t.default_entry_reset(target)
            except:
                pass
    except Exception as e:
        print('Error cleaning up: {}'.format(e))

if __name__ == "__main__":
    #
    # Connect to the BF Runtime Server
    #
    for bfrt_client_id in range(10):
        try:
            interface = gc.ClientInterface(
                grpc_addr = 'localhost:50052',
                client_id = bfrt_client_id,
                device_id = 0,
                num_tries = 1)
            print('Connected to BF Runtime Server as client', bfrt_client_id)
            break;
        except:
            print('Could not connect to BF Runtime server')
            quit

    #
    # Get the information about the running program
    #
    bfrt_info = interface.bfrt_info_get()
    print('The target runs the program ', bfrt_info.p4_name_get())

    #
    # Establish that you are using this program on the given connection
    #
    if bfrt_client_id == 0:
        interface.bind_pipeline_config(bfrt_info.p4_name_get())

    ################### You can now use BFRT CLIENT ###########################

    # We are going to read information from device 0
    target = gc.Target(0)

    cleanUp(target, list(tables(bfrt_info).values()))
    setUp(bfrt_info, target, do_decay=True, do_block=True)
