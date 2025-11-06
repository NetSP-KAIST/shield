// count_min_sketch.hpp
#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include "crc.hpp"

class CountMinSketch {
public:
    CountMinSketch(uint8_t counter_size_bits, size_t array_size, int n_hash);

    std::vector<int> keys(const std::string& ip_src, const std::string& ip_dst) const;
    std::vector<uint32_t> plus(const std::string& ip_src, const std::string& ip_dst, const std::vector<int>& value);
    std::vector<uint32_t> minus(const std::string& ip_src, const std::string& ip_dst, uint32_t value);
    std::vector<uint32_t> setbit(const std::string& ip_src, const std::string& ip_dst, uint32_t value);
    std::vector<uint32_t> read(const std::string& ip_src, const std::string& ip_dst) const;
    void reset();

    uint32_t max; // maximum counter value

    // Public access for co-monitor (can be made private with friend class)
    std::vector<std::vector<uint32_t>> cms;

private:
    uint8_t counter_size;
    size_t cms_array_size;
    int depth;
};
