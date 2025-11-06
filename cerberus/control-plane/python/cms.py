#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from crc import TofinoCRC32

class CountMinSketch:
    def __init__(self, counter_size: int, array_size: int, n_hash: int):
        self.counter_size = counter_size
        self.cms_array_size = array_size
        self.depth = n_hash
        self.max = 2**(self.counter_size-1) - 1
        # self.carry_bits = [[False] * self.cms_array_size for _ in range(self.depth)] # not used
        self.cms = [[0] * self.cms_array_size for _ in range(self.depth)]
    
    def keys(self, ip_pair) -> list[int]:
        reg_c2_key_a = TofinoCRC32.hash0(ip_pair[0], ip_pair[1])
        reg_c2_key_b = TofinoCRC32.hash1(ip_pair[0], ip_pair[1])
        key0 = (reg_c2_key_a & 0x0000FFFF)
        key1 = (reg_c2_key_a & 0xFFFF0000) >> 16
        key2 = (reg_c2_key_b & 0x0000FFFF)
        # print(key0, key1, key2)
        return [key0, key1, key2]

    def plus(self, element, value: int = 1) -> tuple[list[int], list[int]]:
        read_value = []
        for i, hash_value in enumerate(self.keys(element)):
            # Not consider overflow in CP
            self.cms[i][hash_value] += value
            read_value.append(self.cms[i][hash_value])
        return read_value

    def minus(self, element, value: int) -> tuple[list[int], list[int]]:
        read_value = []
        for i, hash_value in enumerate(self.keys(element)):
            if self.cms[i][hash_value] < value:
                self.cms[i][hash_value] = 0
            else:
                self.cms[i][hash_value] -= value
            read_value.append(self.cms[i][hash_value])
        return read_value

    def setbit(self, element, value: int) -> tuple[list[int], list[int]]:
        read_value = []
        for i, hash_value in enumerate(self.keys(element)):
            self.cms[i][hash_value] = value
            read_value.append(self.cms[i][hash_value])
        return read_value

    def reset(self) -> None:
        for i in range(self.depth):
            for j in range(self.cms_array_size):
                self.cms[i][j] = 0
        # self.cms = [[0] * self.cms_array_size for _ in range(self.depth)]

    def read(self, element) -> list[int]:
        read_value = []
        for i, hash_value in enumerate(self.keys(element)):
            read_value.append(self.cms[i][hash_value])
        return read_value
