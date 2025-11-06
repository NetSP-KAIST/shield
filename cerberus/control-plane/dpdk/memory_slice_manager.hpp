// memory_slice_manager.hpp
#pragma once

#include <cstdint>
#include <memory>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include "bfrt_control.hpp"
#include "co_monitor.hpp"

namespace cerberus {

class MemorySliceManager {
public:
    MemorySliceManager(CoMonitor& monitor, double interval = 5.0);
    void start();
    void stop();
    std::vector<std::vector<int>> slice_dict_ = {{8, 8, 8, 8}, {8, 8, 8, 8}}; // Initial slice

private:
    void run();
    uint64_t getGlobalTime();
    void updateTables();

    CoMonitor& monitor_;
    std::atomic<bool> running_;
    std::thread worker_;
    double interval_;
    std::vector<int> current_slice_;
    uint64_t last_global_time_;
};

} // namespace cerberus
