// crc.hpp
#pragma once

#include <string>
#include <vector>
#include <cstdint>

class TofinoCRC32 {
public:
    static uint32_t hash0(const std::string& ip_src, const std::string& ip_dst);
    static uint32_t hash1(const std::string& ip_src, const std::string& ip_dst);
    static uint32_t hash2(const std::string& ip_src, const std::string& ip_dst, uint16_t src_port, uint16_t dst_port, uint8_t proto);
    static uint32_t hash3(const std::string& ip_src, const std::string& ip_dst, uint16_t src_port, uint16_t dst_port, uint8_t proto);
    static std::vector<int> hash_keys(const std::string& ip_src, const std::string& ip_dst);


private:
    static uint32_t crc32_custom(const std::vector<uint8_t>& data, uint32_t poly, uint32_t init, uint32_t xor_out, bool reverse);
    static std::vector<uint8_t> ip_to_bytes(const std::string& ip);
    static std::vector<uint8_t> port_to_bytes(uint16_t port);
    static uint8_t reverse_byte(uint8_t byte);
    static uint32_t reverse_bits_32(uint32_t n);
};