// bfrt_control.hpp
#pragma once

#include <cstdint>
#include <string>
#include <vector>
extern "C"
{
#include <bf_switchd/bf_switchd.h>
#include <bf_rt/bf_rt_common.h>
#include <lld/bf_ts_if.h>
#include <pkt_mgr/pkt_mgr_intf.h>
#include <pipe_mgr/pipe_mgr_intf.h>
#include <port_mgr/bf_port_if.h>
}
#include <bf_rt/bf_rt.hpp>

namespace cerberus {

    void initBFRT(bf_rt_target_t target, const std::string &p4_name);
    void addBlocklistEntry(uint32_t src_ip, uint32_t dst_ip);
    void reg_cb(const bf_rt_target_t &, void *);
    uint64_t read_register(const bfrt::BfRtTable *reg_var, bf_rt_id_t reg_index_key_id, bf_rt_id_t reg_data_id);
    uint32_t readGlobalTime();
    void updateDynTable(const std::vector<int>& slice, uint64_t next_global_time);
    void updateSlicingTable(const std::vector<int>& slice, uint64_t next_global_time);
    void initializeOldOverflowKeys(const std::vector<int>& initial_slice);
    void updateOverflowTable(const std::vector<int>& slice, const std::string& mode, uint64_t next_time);
 
} // namespace cerberus