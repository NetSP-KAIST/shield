#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from crc import TofinoCRC32

class CountMinSketch:
    def __init__(self, layer3_array_size_exp: int):
        self.cms_array_size_exp = layer3_array_size_exp
        self.cms_array_size = 2**layer3_array_size_exp
        self.depth = 2
        # self.carry_bits = [[False] * self.cms_array_size for _ in range(self.depth)]    # not used
        self.cms = [[0] * self.cms_array_size for _ in range(self.depth)]

    def get_key(self, ip_pair) -> list[int]:
        reg_c2_key_a = TofinoCRC32.hash0(ip_pair[0], ip_pair[1])
        reg_c2_key_b = TofinoCRC32.hash1(ip_pair[0], ip_pair[1])
        key0 = reg_c2_key_a & (self.cms_array_size-1)
        key1 = reg_c2_key_b & (self.cms_array_size-1)
        # print(key0, key1)
        return [key0, key1]

    def plus(self, element, value: list[int]) -> list[int]:
        read_value = []
        for i, hash_value in enumerate(self.get_key(element)):
            # Not consider overflow in CP
            self.cms[i][hash_value] += value[i]
            read_value.append(self.cms[i][hash_value])
        return read_value

    def decay(self, decay_amount: int):
        for i in range(self.depth):
            for j in range(self.cms_array_size):
                self.cms[i][j] >>= decay_amount

    def read(self, element) -> list[int]:
        read_value = []
        for i, hash_value in enumerate(self.get_key(element)):
            read_value.append(self.cms[i][hash_value])
        return read_value
