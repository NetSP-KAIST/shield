// co_monitor.hpp
#pragma once

#include <vector>
#include <mutex>
#include <string>
#include <unordered_map>
#include "count_min_sketch.hpp"
#include <boost/functional/hash.hpp>
namespace cerberus {
class CoMonitor {
public:
    CoMonitor(int n_task,
        const std::vector<int>& counter_sizes,
        const std::vector<int>& array_sizes,
        int n_hash, int n_window);

    std::vector<uint32_t> read(int task_id, const std::string& ip_src, const std::string& ip_dst, int current_window);
    std::vector<int> get_current_max(int current_window);

    uint32_t update(int task_id, const std::string& ip_src, const std::string& ip_dst,
                    uint16_t src_port, uint16_t dst_port, uint8_t proto,
                    const std::vector<int>& overflowed_data,
                    int current_window);

    void reset(int current_window);

    std::unordered_map<std::pair<int, int>, uint32_t, boost::hash<std::pair<int, int>>> get_current_counts(int task_id, int current_window);

    // Public for direct access from main if needed
    std::vector<std::vector<int>> current_max;

    uint32_t getPreviousValue(int task_id, const std::vector<int>& keys);
    void advanceWindow(int next_window);

    void saveToOldCMS(int target_window);

private:
    std::vector<std::vector<CountMinSketch>> cms;  // [window][task]
    std::vector<CountMinSketch> old_cms;  // [task]
    std::mutex mtx;
    int depth;
    int n_window_;
    int current_window_ = 0;
    int n_task_;
};
}// namespace cerberus