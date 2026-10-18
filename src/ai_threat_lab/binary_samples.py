"""Tiny synthetic format descriptors for offline demonstrations, not runnable programs."""

import struct


def synthetic_binary_samples():
    pe = bytearray(528)
    pe[:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 128)
    pe[128:132] = b"PE\0\0"
    struct.pack_into("<HH", pe, 132, 0x8664, 1)
    struct.pack_into("<HH", pe, 148, 240, 3)
    struct.pack_into("<H", pe, 152, 0x20B)
    struct.pack_into("<I", pe, 260, 16)
    struct.pack_into("<II", pe, 408, 16, 512)
    struct.pack_into("<I", pe, 428, 0xE0000020)
    elf = bytearray(180)
    elf[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into("<HHIQQQIHHHHHH", elf, 16, 3, 62, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", elf, 64, 1, 7, 176, 176, 0, 4, 4, 1)
    struct.pack_into("<IIQQQQQQ", elf, 120, 0x6474E551, 7, 0, 0, 0, 0, 0, 1)
    return {"synthetic-pe.bin": bytes(pe), "synthetic-elf.bin": bytes(elf)}
