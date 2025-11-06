#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from functools import lru_cache
import unittest

@lru_cache(maxsize=60000)
def crc32_custom(data, poly, init, xor_out, reverse):
    crc = init
    for byte in data:
        if reverse:
            byte = int('{:08b}'.format(byte)[::-1], 2)  # Reverse bits per byte
        crc ^= (byte << 24)
        for _ in range(8):
            if crc & 0x80000000:
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1
            crc &= 0xFFFFFFFF  # Keep it within 32-bit
    if reverse:
        crc = int('{:032b}'.format(crc)[::-1], 2)  # Reverse the final CRC
    return crc ^ xor_out

def ip_to_bytes(ip):
    return bytes(map(int, ip.split('.')))

def port_to_bytes(port):
    return port.to_bytes(2, byteorder='big')  # Convert 16-bit port to bytes


# CRC Hash functions that match with data plane 
# NOTE: The following functions are used to generate CRC hash values that match with the data plane.
# The data plane uses CRC hash values is an index to lookups the register.
# Get IP with string format (e.g., "1.2.3.4"), but port and protocol with integer format 
class TofinoCRC32:
    # CRC function for reg_c2_key_a
    def hash0(ip_src, ip_dst):
        data = ip_to_bytes(ip_src) + ip_to_bytes(ip_dst)
        poly = 0x04C11DB7
        init = 0xFFFFFFFF
        xor_out = 0xFFFFFFFF
        reverse = True
        return crc32_custom(data, poly, init, xor_out, reverse)

    # CRC function for reg_c2_key_b
    def hash1(ip_src, ip_dst):
        data = ip_to_bytes(ip_src) + ip_to_bytes(ip_dst)
        poly = 0x1EDC6F41
        init = 0xFFFFFFFF
        xor_out = 0xFFFFFFFF
        reverse = True
        return crc32_custom(data, poly, init, xor_out, reverse)

    # CRC for reg_c5_key_a
    def hash2(ip_src, ip_dst, src_port, dst_port, protocol):
        data = (
            ip_to_bytes(ip_src) + 
            ip_to_bytes(ip_dst) + 
            port_to_bytes(src_port) + 
            port_to_bytes(dst_port) + 
            protocol.to_bytes(1, byteorder='big')  # Protocol is 1 byte
        )

        poly = 0x04C11DB7  
        init = 0xFFFFFFFF  
        xor_out = 0xFFFFFFFF  
        reverse = True  

        return crc32_custom(data, poly, init, xor_out, reverse)

    # CRC for reg_c5_key_b
    def hash3(ip_src, ip_dst, src_port, dst_port, protocol):
        data = (
            ip_to_bytes(ip_src) + 
            ip_to_bytes(ip_dst) + 
            port_to_bytes(src_port) + 
            port_to_bytes(dst_port) + 
            protocol.to_bytes(1, byteorder='big')  # Protocol is 1 byte
        )

        poly = 0x1EDC6F41  
        init = 0xFFFFFFFF  
        xor_out = 0xFFFFFFFF  
        reverse = True  

        return crc32_custom(data, poly, init, xor_out, reverse)


############################################
# Unit Test
############################################
class TestTofinoCRC32(unittest.TestCase):
    def test_hash0(self):
        ip_src = "1.2.3.4"
        ip_dst = "10.11.12.13"
        reg_c2_key_a = 0xFCEF2684
        self.assertEqual(TofinoCRC32.hash0(ip_src, ip_dst), reg_c2_key_a)

    def test_hash1(self):
        ip_src = "1.2.3.4"
        ip_dst = "10.11.12.13"
        reg_c2_key_b = 0x3601B331
        self.assertEqual(TofinoCRC32.hash1(ip_src, ip_dst), reg_c2_key_b)

    def test_hash2(self):
        ip_src = "1.2.3.4"
        ip_dst = "10.11.12.13"
        src_port = 1234
        dst_port = 5678
        protocol = 17  # UDP protocol number
        reg_c5_key_a = 0x1D6B094F
        self.assertEqual(TofinoCRC32.hash2(ip_src, ip_dst, src_port, dst_port, protocol), reg_c5_key_a)
    
    def test_hash3(self):
        ip_src = "1.2.3.4"
        ip_dst = "10.11.12.13"
        src_port = 1234
        dst_port = 5678
        protocol = 17  # UDP protocol number
        reg_c5_key_b = 0xECDCFDCF
        self.assertEqual(TofinoCRC32.hash3(ip_src, ip_dst, src_port, dst_port, protocol), reg_c5_key_b)

if __name__ == '__main__':
    unittest.main()
