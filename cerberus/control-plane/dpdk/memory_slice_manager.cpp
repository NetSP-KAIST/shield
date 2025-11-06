// memory_slice_manager.cpp
#include "memory_slice_manager.hpp"
#include "bfrt_control.hpp"
#include <chrono>
#include <thread>
#include <iostream>
#include <cmath>
#include <unordered_map>
#include <boost/functional/hash.hpp>
#include <fstream>

namespace cerberus {

std::array<std::unordered_map<std::pair<int, int>, uint32_t, boost::hash<std::pair<int, int>>>, 4> old_cms_values;

MemorySliceManager::MemorySliceManager(CoMonitor& monitor, double interval)
    : monitor_(monitor), interval_(interval), running_(false),
      slice_dict_({{8, 8, 8, 8}, {8, 8, 8, 8}}), current_slice_({8, 8, 8, 8}),
      last_global_time_(0) {}

void MemorySliceManager::start() {
    running_ = true;
    worker_ = std::thread(&MemorySliceManager::run, this);
}

void MemorySliceManager::stop() {
    running_ = false;
    if (worker_.joinable()) worker_.join();
}

std::vector<int> change_adaptive_memory(const std::vector<int>& current_slice, const std::vector<int>& max_tasks) {
    const int total_bits = 32;
    const bool ENABLE_MIN_SHARE = true;
    const int n_tasks = current_slice.size();
    std::vector<int> ideal_shares(n_tasks);

    auto bits_used = [](uint32_t value) -> int {
        int bits = 0;
        while (value > 0) {
            ++bits;
            value >>= 1;
        }
        return bits;
    };

    for (int i = 0; i < n_tasks; ++i) {
        ideal_shares[i] = std::max(1, current_slice[i] - 1 + bits_used(max_tasks[i]));
    }

    auto calculate_shares = [&](int total, const std::vector<int>& ideals, bool enable_min_share) -> std::vector<int> {
        std::vector<int> result(ideals.size());
        double sum_ideal = 0.0;
        for (int val : ideals) sum_ideal += static_cast<double>(val);

        for (size_t i = 0; i < ideals.size(); ++i) {
            result[i] = static_cast<int>(std::round((ideals[i] / sum_ideal) * total));
        }

        int sum_result = 0;
        for (int val : result) sum_result += val;
        int diff = total - sum_result;

        while (diff != 0) {
            for (size_t i = 0; i < result.size(); ++i) {
                if (diff > 0 && (!enable_min_share || result[i] > 0)) {
                    ++result[i];
                    --diff;
                } else if (diff < 0 && result[i] > 1) {
                    --result[i];
                    ++diff;
                }
                if (diff == 0) break;
            }
        }

        return result;
    };

    return calculate_shares(total_bits, ideal_shares, ENABLE_MIN_SHARE);
}

void MemorySliceManager::run() {
    std::cout << "[DEBUG][MemorySliceManager] Starting MemorySliceManager thread." << std::endl;
    initializeOldOverflowKeys(slice_dict_[0]);
    std::cout << "[DEBUG][MemorySliceManager] Old overflow keys initialized." << std::endl;
    while (running_) {
        // Check if the global time has changed
        uint64_t global_time = readGlobalTime();
        if (global_time == last_global_time_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }
        std::cout << "[DEBUG][MemorySliceManager] Global time changed." << std::endl;

        // std::this_thread::sleep_for(std::chrono::duration<double>(interval_ - 0.1));
        uint64_t next_time = (global_time == 0) ? 1 : 0;
        last_global_time_ = global_time;

        std::cout << "[DEBUG][MemorySliceManager] Global time: " << global_time << ", Next time: " << next_time << std::endl;

        if (next_time < 0 || next_time >= 2) {
            std::cerr << "[ERROR][MemorySliceManager] Invalid next_time: " << next_time << std::endl;
            continue;
        }

        // Store old CMS values
        monitor_.saveToOldCMS(next_time);

        // Calculate new slice
        auto max_tasks = monitor_.get_current_max(global_time);
        current_slice_ = change_adaptive_memory(current_slice_, max_tasks);
        auto old_slice = slice_dict_[next_time];
        std::cout << "[MemorySliceManager] Old slice: ";
        for (const auto& val : old_slice) {
            std::cout << val << " ";
        }
        std::cout << std::endl;
        slice_dict_[next_time] = current_slice_;
        std::cout << "[MemorySliceManager] New slice: ";
        for (const auto& val : current_slice_) {
            std::cout << val << " ";
        }
        std::cout << std::endl;

        if (old_slice == current_slice_) {
            continue;
        }

        // Update tables
        updateDynTable(current_slice_, next_time);
        updateSlicingTable(current_slice_, next_time);

        // Delete old overflow table entries and add new ones
        updateOverflowTable(old_slice, "del", next_time);
        updateOverflowTable(current_slice_, "add", next_time);

        // Reset the cms
        monitor_.advanceWindow(next_time);
    }
}

} // namespace cerberus
