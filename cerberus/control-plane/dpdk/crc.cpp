// crc.cpp
#include "crc.hpp"
#include <sstream>
#include <stdexcept>
#include <bitset>
#include <algorithm>
#include <arpa/inet.h>  // For inet_pton

uint8_t TofinoCRC32::reverse_byte(uint8_t byte) {
    byte = (byte & 0xF0) >> 4 | (byte & 0x0F) << 4;
    byte = (byte & 0xCC) >> 2 | (byte & 0x33) << 2;
    byte = (byte & 0xAA) >> 1 | (byte & 0x55) << 1;
    return byte;
}

uint32_t TofinoCRC32::reverse_bits_32(uint32_t n) {
    n = ((n >> 1) & 0x55555555) | ((n & 0x55555555) << 1);
    n = ((n >> 2) & 0x33333333) | ((n & 0x33333333) << 2);
    n = ((n >> 4) & 0x0F0F0F0F) | ((n & 0x0F0F0F0F) << 4);
    n = ((n >> 8) & 0x00FF00FF) | ((n & 0x00FF00FF) << 8);
    n = (n >> 16) | (n << 16);
    return n;
}

uint32_t TofinoCRC32::crc32_custom(const std::vector<uint8_t>& data, uint32_t poly, uint32_t init, uint32_t xor_out, bool reverse) {
    uint32_t crc = init;
    for (auto byte : data) {
        if (reverse)
            byte = reverse_byte(byte);
        crc ^= (static_cast<uint32_t>(byte) << 24);
        for (int i = 0; i < 8; ++i) {
            if (crc & 0x80000000)
                crc = (crc << 1) ^ poly;
            else
                crc <<= 1;
        }
        crc &= 0xFFFFFFFF;
    }
    if (reverse)
        crc = reverse_bits_32(crc);
    return crc ^ xor_out;
}

std::vector<uint8_t> TofinoCRC32::ip_to_bytes(const std::string& ip) {
    std::vector<uint8_t> result(4);
    if (inet_pton(AF_INET, ip.c_str(), result.data()) != 1)
        throw std::invalid_argument("Invalid IP address format: " + ip);
    return result;
}

std::vector<uint8_t> TofinoCRC32::port_to_bytes(uint16_t port) {
    return { static_cast<uint8_t>((port >> 8) & 0xFF), static_cast<uint8_t>(port & 0xFF) };
}

uint32_t TofinoCRC32::hash0(const std::string& ip_src, const std::string& ip_dst) {
    auto data = ip_to_bytes(ip_src);
    auto dst = ip_to_bytes(ip_dst);
    data.insert(data.end(), dst.begin(), dst.end());
    return crc32_custom(data, 0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, true);
}

uint32_t TofinoCRC32::hash1(const std::string& ip_src, const std::string& ip_dst) {
    auto data = ip_to_bytes(ip_src);
    auto dst = ip_to_bytes(ip_dst);
    data.insert(data.end(), dst.begin(), dst.end());
    return crc32_custom(data, 0x1EDC6F41, 0xFFFFFFFF, 0xFFFFFFFF, true);
}

uint32_t TofinoCRC32::hash2(const std::string& ip_src, const std::string& ip_dst, uint16_t src_port, uint16_t dst_port, uint8_t proto) {
    auto data = ip_to_bytes(ip_src);
    auto dst = ip_to_bytes(ip_dst);
    auto sp = port_to_bytes(src_port);
    auto dp = port_to_bytes(dst_port);
    data.insert(data.end(), dst.begin(), dst.end());
    data.insert(data.end(), sp.begin(), sp.end());
    data.insert(data.end(), dp.begin(), dp.end());
    data.push_back(proto);
    return crc32_custom(data, 0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, true);
}

uint32_t TofinoCRC32::hash3(const std::string& ip_src, const std::string& ip_dst, uint16_t src_port, uint16_t dst_port, uint8_t proto) {
    auto data = ip_to_bytes(ip_src);
    auto dst = ip_to_bytes(ip_dst);
    auto sp = port_to_bytes(src_port);
    auto dp = port_to_bytes(dst_port);
    data.insert(data.end(), dst.begin(), dst.end());
    data.insert(data.end(), sp.begin(), sp.end());
    data.insert(data.end(), dp.begin(), dp.end());
    data.push_back(proto);
    return crc32_custom(data, 0x1EDC6F41, 0xFFFFFFFF, 0xFFFFFFFF, true);
}

std::vector<int> TofinoCRC32::hash_keys(const std::string& ip_src, const std::string& ip_dst) {
    uint32_t h0 = hash0(ip_src, ip_dst);
    uint32_t h1 = hash1(ip_src, ip_dst);

    int key0 = h0 & 0x0000FFFF;
    int key1 = (h0 & 0xFFFF0000) >> 16;
    int key2 = h1 & 0x0000FFFF;

    return { key0, key1, key2 };
}
