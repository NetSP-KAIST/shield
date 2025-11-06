// count_min_sketch.cpp
#include "count_min_sketch.hpp"
#include <algorithm>
#include <iostream>

CountMinSketch::CountMinSketch(uint8_t counter_size_bits, size_t array_size, int n_hash)
    : counter_size(counter_size_bits),
      cms_array_size(array_size),
      depth(n_hash),
      max((1u << (counter_size_bits - 1)) - 1)
{
    cms.resize(depth, std::vector<uint32_t>(cms_array_size, 0));
    reset();
}

std::vector<int> CountMinSketch::keys(const std::string& ip_src, const std::string& ip_dst) const {
    std::vector<int> key_list;

    uint32_t reg_c2_key_a = TofinoCRC32::hash0(ip_src, ip_dst);
    uint32_t reg_c2_key_b = TofinoCRC32::hash1(ip_src, ip_dst);

    int key0 = reg_c2_key_a & 0x0000FFFF;
    int key1 = (reg_c2_key_a & 0xFFFF0000) >> 16;
    int key2 = reg_c2_key_b & 0x0000FFFF;

    key0 %= cms_array_size;
    key1 %= cms_array_size;
    key2 %= cms_array_size;

    return {key0, key1, key2};
}

std::vector<uint32_t> CountMinSketch::plus(const std::string& ip_src, const std::string& ip_dst, const std::vector<int>& value) {
    std::vector<uint32_t> result;
    auto indices = keys(ip_src, ip_dst);
    for (int i = 0; i < depth; ++i) {
        if (cms[i][indices[i]] > max - value[i]) {
            cms[i][indices[i]] = max;
        } else {
            cms[i][indices[i]] += value[i];
        }
        result.push_back(cms[i][indices[i]]);
        // std::cout << "[Debug] CountMinSketch::plus: cms[" << i << "][" << indices[i] << "] = " << cms[i][indices[i]] << std::endl;
    }
    return result;
}

std::vector<uint32_t> CountMinSketch::minus(const std::string& ip_src, const std::string& ip_dst, uint32_t value) {
    std::vector<uint32_t> result;
    auto indices = keys(ip_src, ip_dst);
    for (int i = 0; i < depth; ++i) {
        if (cms[i][indices[i]] < value) {
            cms[i][indices[i]] = 0;
        } else {
            cms[i][indices[i]] -= value;
        }
        result.push_back(cms[i][indices[i]]);
    }
    return result;
}

std::vector<uint32_t> CountMinSketch::setbit(const std::string& ip_src, const std::string& ip_dst, uint32_t value) {
    std::vector<uint32_t> result;
    auto indices = keys(ip_src, ip_dst);
    for (int i = 0; i < depth; ++i) {
        cms[i][indices[i]] = value;
        result.push_back(cms[i][indices[i]]);
    }
    return result;
}

std::vector<uint32_t> CountMinSketch::read(const std::string& ip_src, const std::string& ip_dst) const {
    std::vector<uint32_t> result;
    auto indices = keys(ip_src, ip_dst);
    for (int i = 0; i < depth; ++i) {
        result.push_back(cms[i][indices[i]]);
    }
    return result;
}

void CountMinSketch::reset() {
    for (int i = 0; i < depth; ++i) {
        std::fill(cms[i].begin(), cms[i].end(), 0);
    }
    std::cout << "[CountMinSketch] Reset all counters." << std::endl;
}
