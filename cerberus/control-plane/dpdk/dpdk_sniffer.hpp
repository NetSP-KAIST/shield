// packet_sniffer.hpp
#pragma once

#include "co_monitor.hpp"

#include <memory>
#include <string>
#include <thread>

namespace cerberus {
    extern std::shared_ptr<CoMonitor> co_monitor;
    void packetSnifferLoop(std::shared_ptr<CoMonitor> monitor, std::vector<std::vector<int>>& slice_dict);
    struct WorkerArgs {
        std::shared_ptr<CoMonitor> monitor;
        std::vector<std::vector<int>>* slice_dict;
    };
}// namespace cerberus