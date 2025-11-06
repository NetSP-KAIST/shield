// co_monitor.cpp
#include "co_monitor.hpp"
#include <algorithm>
#include <iostream>
#include <boost/functional/hash.hpp>
namespace cerberus {
CoMonitor::CoMonitor(int n_task, const std::vector<int>& counter_sizes,
                     const std::vector<int>& array_sizes, int n_hash, int n_window)
    : depth(n_hash), n_window_(n_window), n_task_(n_task)
{
    cms.resize(n_window);
    for (int w = 0; w < n_window; ++w) {
        for (int i = 0; i < n_task; ++i) {
            cms[w].emplace_back(counter_sizes[i], 1<<array_sizes[i], n_hash);
        }
    }
    for (int w = 0; w < n_window; ++w) {
        for (int i = 0; i < n_task; ++i) {
            cms[w][i].reset();
        }
    }
    
    for (int i = 0; i < n_task; ++i) {
        old_cms.emplace_back(counter_sizes[i], 1<<array_sizes[i], n_hash);
    }
    for (int i = 0; i < n_task; ++i) {
        old_cms[i].reset();
    }

    current_max.resize(n_window, std::vector<int>(n_task, 0));
    for (int w = 0; w < n_window; ++w) {
        for (int i = 0; i < n_task; ++i) {
            current_max[w][i] = 0;
        }
    }
}

std::vector<uint32_t> CoMonitor::read(int task_id, const std::string& ip_src, const std::string& ip_dst, int current_window) {
    std::lock_guard<std::mutex> lock(mtx);
    return cms[current_window][task_id].read(ip_src, ip_dst);
}

std::vector<int> CoMonitor::get_current_max(int current_window) {
    std::lock_guard<std::mutex> lock(mtx);
    return current_max[current_window];
}

uint32_t CoMonitor::update(int task_id, const std::string& ip_src, const std::string& ip_dst,
                           uint16_t src_port, uint16_t dst_port, uint8_t proto,
                           const std::vector<int>& overflowed_data, int current_window)
{
    std::lock_guard<std::mutex> lock(mtx);
    auto& sketch = cms[current_window][task_id];
    auto keys = TofinoCRC32::hash_keys(ip_src, ip_dst);

    uint32_t result = 0;
    uint32_t max_val = 0;
    uint32_t min_val = sketch.max;

    std::vector<uint32_t> cms_result = sketch.plus(ip_src, ip_dst, overflowed_data);
    for (int i = 0; i < keys.size(); ++i) {
        uint32_t current = cms_result[i];
        // std::cout << "[Debug] Task " << task_id << ": sketch.cms[" << i << "][" << keys[i] << "] = " << current << std::endl;
        max_val = std::max(max_val, current);
        min_val = std::min(min_val, current);
    }

    if (max_val > current_max[current_window][task_id]) {
        // std::cout << "[Debug] Task " << task_id << ": Updated current_max[" << current_window << "] = " << max_val << std::endl;
        current_max[current_window][task_id] = max_val;
    }

    result = min_val;
    return result;
}

std::unordered_map<std::pair<int, int>, uint32_t, boost::hash<std::pair<int, int>>>
CoMonitor::get_current_counts(int task_id, int current_window) {
    std::lock_guard<std::mutex> lock(mtx);
    std::unordered_map<std::pair<int, int>, uint32_t, boost::hash<std::pair<int, int>>> counts;
    auto& sketch = cms[current_window][task_id];
    for (int i = 0; i < depth; ++i) {
        for (int j = 0; j < sketch.cms[i].size(); ++j) {
            counts[{i, j}] = sketch.cms[i][j];
        }
    }
    return counts;
}

uint32_t CoMonitor::getPreviousValue(int task_id, const std::vector<int>& keys) {
    uint32_t min_val = UINT32_MAX;
    auto& sketch = old_cms[task_id];
    for (int i = 0; i < keys.size(); ++i) {
        auto it = sketch.cms[i][keys[i]];
        min_val = std::min(min_val, it);
    }
    return min_val;
}

void CoMonitor::advanceWindow(int next_window) {
    std::lock_guard<std::mutex> lock(mtx);
    current_window_ = (current_window_ + 1) % n_window_;

    for (int task = 0; task < n_task_; ++task) {
        cms[next_window][task].reset();
        current_max[next_window][task] = 0;
    }
    std::cout << "[Co-monitor] Clear sketches for Window " << next_window << std::endl;

    std::cout << "[advanceWindow] Advanced to window: " << current_window_ << std::endl;
}

void CoMonitor::saveToOldCMS(int target_window) {
    std::lock_guard<std::mutex> lock(mtx);

    if (target_window < 0 || target_window >= n_window_) {
        std::cerr << "[Error] Invalid target_window: " << target_window << std::endl;
        return;
    }

    for (int task = 0; task < n_task_; ++task) {
        old_cms[task] = cms[target_window][task]; // Copy the CountMinSketch for each task
    }

}
} // namespace cerberus