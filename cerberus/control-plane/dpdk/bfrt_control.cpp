// bfrt_control.cpp
#include "bfrt_control.hpp"
#include <bitset>
#include <algorithm>
#include <iostream>
#include <memory>
#include <numeric>

namespace cerberus {

const bfrt::BfRtInfo *bfrtInfo = nullptr;
const bfrt::BfRtTable *blocklistTable = nullptr;
const bfrt::BfRtTable *dynTable = nullptr;
const bfrt::BfRtTable *slicingTable = nullptr;
const bfrt::BfRtTable *overflowTable = nullptr;
std::shared_ptr<bfrt::BfRtSession> session;
std::shared_ptr<bfrt::BfRtSession> session2;
bf_rt_target_t dev_tgt;

static std::array<std::vector<std::vector<uint32_t>>, 2> old_overflow_keys_by_time;

void initBFRT(bf_rt_target_t target, const std::string &p4_name) {
    dev_tgt = target;

    // Get devMgr singleton instance
    auto &devMgr = bfrt::BfRtDevMgr::getInstance();
    auto status = devMgr.bfRtInfoGet(dev_tgt.dev_id, p4_name, &bfrtInfo);
    if (status != BF_SUCCESS) {
        std::cerr << "[ERROR] Failed to get BFRT info" << std::endl;
        bf_sys_assert(status == BF_SUCCESS);
    }
    // Create a session object
    session = bfrt::BfRtSession::sessionCreate();
    session2 = bfrt::BfRtSession::sessionCreate();
}

uint64_t read_register(const bfrt::BfRtTable *reg_var, bf_rt_id_t reg_index_key_id, bf_rt_id_t reg_data_id){
    std::unique_ptr<bfrt::BfRtTableKey> reg_key;
	std::unique_ptr<bfrt::BfRtTableData> reg_data;

	auto status = reg_var->keyAllocate(&reg_key);
	assert(status == BF_SUCCESS);

	status = reg_var->dataAllocate(&reg_data);
	assert(status == BF_SUCCESS);

	uint64_t key = 0;
	status = reg_key->setValue(reg_index_key_id, key);
	assert(status == BF_SUCCESS);

    uint64_t flags = 0;
    BF_RT_FLAG_SET(flags, BF_RT_FROM_HW);
	status = reg_var->tableEntryGet(*session, dev_tgt, flags, *(reg_key.get()), reg_data.get());
    if (status != BF_SUCCESS) {
        std::cerr << "Failed to read register" << std::endl;
        return 0;
    }

	std::vector<uint64_t> values;
	status = reg_data->getValue(reg_data_id, &values);
	assert(status == BF_SUCCESS);
    session->sessionCompleteOperations();

    // for (auto value : values) {
    //     std::cout << "[DEBUG] Register Value: " << value << std::endl;
    // }

	return values[0];
}

uint32_t readGlobalTime() {
    bfrt::BfRtTable::TableType table_type;
    bf_rt_id_t key_field_id;
    bf_rt_id_t data_field_id;

    if (!bfrtInfo) {
        std::cerr << "BFRT not initialized" << std::endl;
        return 0;
    }

    const bfrt::BfRtTable *regTable = nullptr;
    auto status = bfrtInfo->bfrtTableFromNameGet("SwitchIngress.global_time1_reg", &regTable);
    if (status != BF_SUCCESS || !regTable) {
        std::cerr << "Failed to get register table" << std::endl;
        return 0;
    }
    status = regTable->tableTypeGet(&table_type);
    bf_sys_assert(status == BF_SUCCESS);
    bf_sys_assert(table_type == bfrt::BfRtTable::TableType::REGISTER);

    status = regTable->keyFieldIdGet("$REGISTER_INDEX", &key_field_id);
    bf_sys_assert(status == BF_SUCCESS);
    status = regTable->dataFieldIdGet("SwitchIngress.global_time1_reg.f1", &data_field_id);
    bf_sys_assert(status == BF_SUCCESS);

    uint64_t value = read_register(regTable, key_field_id, data_field_id);
    return static_cast<uint32_t>(value);
}


void addBlocklistEntry(uint32_t src_ip, uint32_t dst_ip) {
    std::unique_ptr<bfrt::BfRtTableKey> key;
    std::unique_ptr<bfrt::BfRtTableData> data;

    bf_rt_id_t src_addr_id = 0;
    bf_rt_id_t dst_addr_id = 0;
    bf_rt_id_t drop_action_id = 0;

    bf_status_t status;
    status = bfrtInfo->bfrtTableFromNameGet("SwitchIngress.check_blocklist", &blocklistTable);
    bf_sys_assert(status == BF_SUCCESS);
    status = blocklistTable->actionIdGet("SwitchIngress.drop_packet", &drop_action_id);
    bf_sys_assert(status == BF_SUCCESS);
    status = blocklistTable->keyFieldIdGet("hdr.ipv4.src_addr", &src_addr_id);
    bf_sys_assert(status == BF_SUCCESS);
    status = blocklistTable->keyFieldIdGet("hdr.ipv4.dst_addr", &dst_addr_id);
    bf_sys_assert(status == BF_SUCCESS);

    status = blocklistTable->keyAllocate(&key);
    bf_sys_assert(status == BF_SUCCESS);
    status = blocklistTable->dataAllocate(drop_action_id, &data);
    bf_sys_assert(status == BF_SUCCESS);
    status = key->setValue(src_addr_id, static_cast<uint64_t>(src_ip));
    bf_sys_assert(status == BF_SUCCESS);
    status = key->setValue(dst_addr_id, static_cast<uint64_t>(dst_ip));
    bf_sys_assert(status == BF_SUCCESS);

    session2->beginTransaction(false);
    uint64_t flags = 0;
    // BF_RT_FLAG_SET(flags, BF_RT_FROM_HW);
    status = blocklistTable->tableEntryAdd(*session2, dev_tgt, flags, *key, *data);
    // if (status == BF_ALREADY_EXISTS) {
        // Do nothing if the entry already exists
    // }
    // bf_sys_assert(status == BF_SUCCESS);
    session2->verifyTransaction();
    session2->sessionCompleteOperations();
    session2->commitTransaction(true);
}

void updateDynTable(const std::vector<int>& slice, uint64_t global_time) {
    bf_status_t status;

    status = bfrtInfo->bfrtTableFromNameGet("SwitchIngress.reg_c2_dyn_table", &dynTable);
    bf_sys_assert(status == BF_SUCCESS);

    bf_rt_id_t dyn_time_id = 0;
    bf_rt_id_t reg_c2_merge_id = 0;
    bf_rt_id_t dyn_merge_slice_id = 0;
    bf_rt_id_t reg_c2_reset_id = 0;
    bf_rt_id_t dyn_reset_slice_id = 0;
    bf_rt_id_t icmpq_flag_id = 0;
    bf_rt_id_t udp_flag_id = 0;
    bf_rt_id_t syn_flag_id = 0;
    bf_rt_id_t dnsq_flag_id = 0;
    bf_rt_id_t resubmit_flag_id = 0;

    status = dynTable->actionIdGet("SwitchIngress.reg_c2_merge", &reg_c2_merge_id);
    bf_sys_assert(status == BF_SUCCESS);
    status = dynTable->actionIdGet("SwitchIngress.reg_c2_reset", &reg_c2_reset_id);
    bf_sys_assert(status == BF_SUCCESS);

    status = dynTable->keyFieldIdGet("global_time1", &dyn_time_id);
    bf_sys_assert(status == BF_SUCCESS);
    status = dynTable->keyFieldIdGet("icmpq_flag", &icmpq_flag_id);
    bf_sys_assert(status == BF_SUCCESS);
    status = dynTable->keyFieldIdGet("udp_flag", &udp_flag_id);
    bf_sys_assert(status == BF_SUCCESS);
    status = dynTable->keyFieldIdGet("syn_flag", &syn_flag_id);
    bf_sys_assert(status == BF_SUCCESS);
    status = dynTable->keyFieldIdGet("dnsq_flag", &dnsq_flag_id);
    bf_sys_assert(status == BF_SUCCESS);
    status = dynTable->keyFieldIdGet("ig_intr_md.resubmit_flag", &resubmit_flag_id);
    bf_sys_assert(status == BF_SUCCESS);

    status = dynTable->dataFieldIdGet("slices", reg_c2_merge_id, &dyn_merge_slice_id);
    bf_sys_assert(status == BF_SUCCESS);
    status = dynTable->dataFieldIdGet("slices", reg_c2_reset_id, &dyn_reset_slice_id);
    bf_sys_assert(status == BF_SUCCESS);

    // calc_dyn_table
    std::vector<uint32_t> increments;
    int total_bits = 32;

    for (int bits : slice) {
        if (bits <= 0 || bits > total_bits) {
            std::cerr << "Invalid slice size: " << bits << "\n";
            return;
        }
        total_bits -= bits;
        increments.push_back(1u << total_bits);
    }

    // calc_dyn_resubmit
    uint32_t resub_mask = 0;
    total_bits = 32;
    for (int bits : slice) {
        if (bits <= 0 || bits > total_bits) {
            std::cerr << "Invalid slice size in resub_mask: " << bits << "\n";
            return;
        }
        total_bits -= bits;
        resub_mask |= ((1u << (bits - 1)) - 1u) << total_bits;
    }

    session->beginTransaction(false);
    // update dyn_table
    for (int combo = 0; combo < 32; ++combo) {
        bool resubmit = combo & 1;

        std::unique_ptr<bfrt::BfRtTableKey> key;
        std::unique_ptr<bfrt::BfRtTableData> data;
        bf_status_t status;

        // Use action ID instead of setActionName
        bf_rt_id_t action_id = resubmit ? reg_c2_reset_id : reg_c2_merge_id;
        bf_rt_id_t dyn_slice_id = resubmit ? dyn_reset_slice_id : dyn_merge_slice_id;

        status = dynTable->keyAllocate(&key);
        bf_sys_assert(status == BF_SUCCESS);
        status = dynTable->dataAllocate(action_id, &data);
        bf_sys_assert(status == BF_SUCCESS);

        status = key->setValue(icmpq_flag_id, (combo >> 4) & 1);
        bf_sys_assert(status == BF_SUCCESS);
        status = key->setValue(udp_flag_id,   (combo >> 3) & 1);
        bf_sys_assert(status == BF_SUCCESS);
        status = key->setValue(syn_flag_id,   (combo >> 2) & 1);
        bf_sys_assert(status == BF_SUCCESS);
        status = key->setValue(dnsq_flag_id,  (combo >> 1) & 1);
        bf_sys_assert(status == BF_SUCCESS);
        status = key->setValue(resubmit_flag_id, resubmit);
        bf_sys_assert(status == BF_SUCCESS);
        status = key->setValue(dyn_time_id, global_time);
        bf_sys_assert(status == BF_SUCCESS);

        uint32_t val = 0;
        if (resubmit) {
            val = resub_mask;
        } else {
            if (combo & 0x10) val += increments[0]; // icmpq
            if (combo & 0x08) val += increments[1]; // udp
            if (combo & 0x04) val += increments[2]; // syn
            if (combo & 0x02) val += increments[3]; // dnsq
        }

        status = data->setValue(dyn_slice_id, static_cast<uint64_t>(val));
        bf_sys_assert(status == BF_SUCCESS);

        uint64_t flags = 0;
        BF_RT_FLAG_SET(flags, BF_RT_FROM_HW);
        status = dynTable->tableEntryMod(*session, dev_tgt, flags, *key, *data);
        if (status != BF_SUCCESS) {
            printf("Failed to tableEntryMod (%s)\n", bf_err_str(status));
            // free(switchd_ctx);
            bf_sys_assert(status == BF_SUCCESS);
        }
    }
    session->verifyTransaction();
    session->sessionCompleteOperations();
    session->commitTransaction(true);
}

void updateSlicingTable(const std::vector<int>& slice, uint64_t global_time) {
    bf_status_t status;

    bf_rt_id_t slicing_time_id = 0;
    bf_rt_id_t extract_reg_c2_slicing_action_id = 0;
    bf_rt_id_t icmpq_flag_id = 0;
    bf_rt_id_t udp_flag_id = 0;
    bf_rt_id_t syn_flag_id = 0;
    bf_rt_id_t dnsq_flag_id = 0;
    std::vector<bf_rt_id_t> slicing_mask_ids;

    status = bfrtInfo->bfrtTableFromNameGet("SwitchIngress.reg_c2_slicing_table", &slicingTable);
    bf_sys_assert(status == BF_SUCCESS);

    status = slicingTable->actionIdGet("SwitchIngress.extract_reg_c2_slicing_action", &extract_reg_c2_slicing_action_id);
    bf_sys_assert(status == BF_SUCCESS);

    status = slicingTable->keyFieldIdGet("icmpq_flag", &icmpq_flag_id);
    bf_sys_assert(status == BF_SUCCESS);
    status = slicingTable->keyFieldIdGet("udp_flag", &udp_flag_id);
    bf_sys_assert(status == BF_SUCCESS);
    status = slicingTable->keyFieldIdGet("syn_flag", &syn_flag_id);
    bf_sys_assert(status == BF_SUCCESS);
    status = slicingTable->keyFieldIdGet("dnsq_flag", &dnsq_flag_id);
    bf_sys_assert(status == BF_SUCCESS);
    status = slicingTable->keyFieldIdGet("global_time1", &slicing_time_id);
    bf_sys_assert(status == BF_SUCCESS);

    static const std::vector<std::string> field_names = {"mask1", "mask2", "mask3", "mask4", "mask5"};
    for (const auto &name : field_names) {
        bf_rt_id_t id;
        status = slicingTable->dataFieldIdGet(name, extract_reg_c2_slicing_action_id, &id);
        bf_sys_assert(status == BF_SUCCESS);
        slicing_mask_ids.push_back(id);
    }
    
    
    // calc_slicing_table
    std::vector<uint32_t> masks;
    int total_bits = std::accumulate(slice.begin(), slice.end(), 0);
    uint32_t carry_mask = 0;
    int current_bit = total_bits;
    for (auto bits : slice) {
        current_bit -= bits;
        carry_mask |= (1 << (current_bit + bits - 1)); 
    }
    masks.push_back(carry_mask); // mask1

    current_bit = total_bits;
    for (auto bits : slice) {   // mask2 - mask5
        current_bit -= bits;
        masks.push_back(((1 << bits) - 1) << current_bit);
    }

    session->beginTransaction(false);
    // update_slicing_table
    for (int combo = 1; combo < 16; ++combo) {
        std::unique_ptr<bfrt::BfRtTableKey> key;
        std::unique_ptr<bfrt::BfRtTableData> data;
        status = slicingTable->keyAllocate(&key);
        bf_sys_assert(status == BF_SUCCESS);
        slicingTable->dataAllocate(extract_reg_c2_slicing_action_id, &data);
        bf_sys_assert(status == BF_SUCCESS);
        
        key->setValue(icmpq_flag_id, (combo >> 3) & 1);
        key->setValue(udp_flag_id, (combo >> 2) & 1);
        key->setValue(syn_flag_id, (combo >> 1) & 1);
        key->setValue(dnsq_flag_id, combo & 1);
        key->setValue(slicing_time_id, global_time);

        for (int i = 0; i < 5; ++i) {
            data->setValue(slicing_mask_ids[i], static_cast<uint64_t>(masks[i]));
        }

        uint64_t flags = 0;
        BF_RT_FLAG_SET(flags, BF_RT_FROM_HW);
        status = slicingTable->tableEntryMod(*session, dev_tgt, flags, *key, *data);
        if (status != BF_SUCCESS) {
            printf("Failed to tableEntryMod (%s)\n", bf_err_str(status));
            // free(switchd_ctx);
            bf_sys_assert(status == BF_SUCCESS);
        }
    }
    session->verifyTransaction();
    session->sessionCompleteOperations();
    session->commitTransaction(true);
;}

void initializeOldOverflowKeys(const std::vector<int>& initial_slice) {
    for (uint64_t t = 0; t <= 1; ++t) {
        int current_bit = 32;
        std::vector<uint32_t> flood_flags;
        for (auto bits : initial_slice) {
            current_bit -= bits;
            flood_flags.push_back(1 << (current_bit + bits - 1));
        }

        std::vector<uint32_t> combos = {0};
        for (int i = 1; i < 16; ++i) {
            uint32_t val = 0;
            if (i & 1) val += flood_flags[0];
            if (i & 2) val += flood_flags[1];
            if (i & 4) val += flood_flags[2];
            if (i & 8) val += flood_flags[3];
            combos.push_back(val);
        }

        std::vector<std::vector<uint32_t>> result;

        for (auto a0 : combos) {
            for (auto a1 : combos) {
                for (auto a2 : combos) {
                    uint32_t tag = 0;
                    if (t == 1) tag += 0b1000000000000000;
                    if (a0) {
                        tag += 0b0100000000000000;
                        if (a0 & flood_flags[0]) tag += 0b0010000000000000;
                        if (a0 & flood_flags[1]) tag += 0b0001000000000000;
                        if (a0 & flood_flags[2]) tag += 0b0000100000000000;
                        if (a0 & flood_flags[3]) tag += 0b0000010000000000;
                    }
                    if (a1) {
                        tag += 0b0000001000000000;
                        if (a1 & flood_flags[0]) tag += 0b0000000100000000;
                        if (a1 & flood_flags[1]) tag += 0b0000000010000000;
                        if (a1 & flood_flags[2]) tag += 0b0000000001000000;
                        if (a1 & flood_flags[3]) tag += 0b0000000000100000;
                    }
                    if (a2) {
                        tag += 0b0000000000010000;
                        if (a2 & flood_flags[0]) tag += 0b0000000000001000;
                        if (a2 & flood_flags[1]) tag += 0b0000000000000100;
                        if (a2 & flood_flags[2]) tag += 0b0000000000000010;
                        if (a2 & flood_flags[3]) tag += 0b0000000000000001;
                    }

                    if (tag == 0 || tag == 0x8000) continue;
                    result.push_back({a0, a1, a2});
                }
            }
        }
        old_overflow_keys_by_time[t] = std::move(result);
    }
}

void updateOverflowTable(const std::vector<int>& slice, const std::string& mode, uint64_t next_time) {
    bf_status_t status;

    bf_rt_id_t overflow_time_id = 0;
    bf_rt_id_t overflow_tag_id = 0;
    bf_rt_id_t set_mirror_flag_action_id = 0;
    std::vector<bf_rt_id_t> overflow_flag_ids;

    status = bfrtInfo->bfrtTableFromNameGet("SwitchIngress.reg_c2_overflow_table", &overflowTable);
    bf_sys_assert(status == BF_SUCCESS);
    status = overflowTable->actionIdGet("SwitchIngress.set_mirror_flag_action", &set_mirror_flag_action_id);
    bf_sys_assert(status == BF_SUCCESS);

    status = overflowTable->keyFieldIdGet("global_time1", &overflow_time_id);
    bf_sys_assert(status == BF_SUCCESS);

    static const std::vector<std::string> field_names = {
        "reg_c2_overflow_flag_arr0", 
        "reg_c2_overflow_flag_arr1", 
        "reg_c2_overflow_flag_arr2"
    };
    for (const auto &name : field_names) {
        bf_rt_id_t id;
        status = overflowTable->keyFieldIdGet(name, &id);
        bf_sys_assert(status == BF_SUCCESS);
        overflow_flag_ids.push_back(id);
    }

    status = overflowTable->dataFieldIdGet("tag", set_mirror_flag_action_id, &overflow_tag_id);
    bf_sys_assert(status == BF_SUCCESS);

    // calc_overflow_table
    int current_bit = 32;
    std::vector<uint32_t> flood_flags;
    for (auto bits : slice) {
        current_bit -= bits;
        flood_flags.push_back(1 << (current_bit + bits - 1));
    }

    // del mode
    if (mode == "del") {
        auto keys = old_overflow_keys_by_time[next_time]; //copy
        if (keys.empty()) {
            std::cout << "[DEBUG] Skipping deletion: no old keys for global_time " << next_time << std::endl;
            return;
        }
        for (const auto& key : keys) {
            std::unique_ptr<bfrt::BfRtTableKey> del_key;
            status = overflowTable->keyAllocate(&del_key);
            bf_sys_assert(status == BF_SUCCESS);
            del_key->setValue(overflow_flag_ids[0], key[0]);
            del_key->setValue(overflow_flag_ids[1], key[1]);
            del_key->setValue(overflow_flag_ids[2], key[2]);
            del_key->setValue(overflow_time_id, next_time);

            status = overflowTable->tableEntryDel(*session, dev_tgt, 0, *del_key);
            if (status != BF_SUCCESS) {
                printf("Failed to tableEntryDel (%s)\n", bf_err_str(status));
                std::cout << "Fail to del: " << key[0] << "," << key[1] << "," << key[2]
                          << "," << next_time << std::endl;
            }
        }
        return;
    }

    // update_overflow_table: "add" mode
    std::vector<uint32_t> combos = {0};
    for (int i = 1; i < 16; ++i) {
        uint32_t val = 0;
        if (i & 1) val += flood_flags[0];
        if (i & 2) val += flood_flags[1];
        if (i & 4) val += flood_flags[2];
        if (i & 8) val += flood_flags[3];
        combos.push_back(val);
    }

    std::cout << "[DEBUG] Combo("<< next_time << "): " << std::bitset<32>(combos[15]) << " mode: " << mode << std::endl;

    std::vector<std::vector<uint32_t>> new_keys;

    session->beginTransaction(false);
    for (auto a0 : combos) {
        for (auto a1 : combos) {
            for (auto a2 : combos) {
                uint32_t tag = 0;
                if (next_time == 1) tag += 0b1000000000000000;
                if (a0) {
                    tag += 0b0100000000000000;
                    if (a0 & flood_flags[0]) tag += 0b0010000000000000;
                    if (a0 & flood_flags[1]) tag += 0b0001000000000000;
                    if (a0 & flood_flags[2]) tag += 0b0000100000000000;
                    if (a0 & flood_flags[3]) tag += 0b0000010000000000;
                }
                if (a1) {
                    tag += 0b0000001000000000;
                    if (a1 & flood_flags[0]) tag += 0b0000000100000000;
                    if (a1 & flood_flags[1]) tag += 0b0000000010000000;
                    if (a1 & flood_flags[2]) tag += 0b0000000001000000;
                    if (a1 & flood_flags[3]) tag += 0b0000000000100000;
                }
                if (a2) {
                    tag += 0b0000000000010000;
                    if (a2 & flood_flags[0]) tag += 0b0000000000001000;
                    if (a2 & flood_flags[1]) tag += 0b0000000000000100;
                    if (a2 & flood_flags[2]) tag += 0b0000000000000010;
                    if (a2 & flood_flags[3]) tag += 0b0000000000000001;
                }

                if (tag == 0 || tag == 0x8000) continue;

                std::unique_ptr<bfrt::BfRtTableKey> key;
                std::unique_ptr<bfrt::BfRtTableData> data;
                status = overflowTable->keyAllocate(&key);
                bf_sys_assert(status == BF_SUCCESS);
                status = overflowTable->dataAllocate(set_mirror_flag_action_id, &data);
                bf_sys_assert(status == BF_SUCCESS);

                key->setValue(overflow_flag_ids[0], a0);
                key->setValue(overflow_flag_ids[1], a1);
                key->setValue(overflow_flag_ids[2], a2);
                key->setValue(overflow_time_id, next_time);
                data->setValue(overflow_tag_id, static_cast<uint64_t>(tag));

                new_keys.push_back({a0, a1, a2});

                status = overflowTable->tableEntryAddOrMod(*session, dev_tgt, 0, *key, *data, nullptr);
                if (status != BF_SUCCESS) {
                    printf("Failed to tableEntryAddOrMod (%s)\n", bf_err_str(status));
                    std::cout << "Fail to add/mod: " << a0 << "," << a1 << "," << a2
                              << "," << next_time << "," << tag << std::endl;
                }
            }
        }
    }
    // Store the new keys for potential deletion later
    old_overflow_keys_by_time[next_time] = std::move(new_keys);
    session->verifyTransaction();
    session->sessionCompleteOperations();
    session->commitTransaction(true);
}

} // namespace cerberus
