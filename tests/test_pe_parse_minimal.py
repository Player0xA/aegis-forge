from __future__ import annotations

import struct

from aegis.pe import parse_pe_bytes


def _build_minimal_pe() -> bytes:
    # Minimal DOS header (64 bytes) with e_lfanew at 0x3C pointing to 0x80
    dos = bytearray(b"MZ" + b"\x00" * 58)
    dos += struct.pack("<I", 0x80)  # e_lfanew
    if len(dos) < 0x80:
        dos += b"\x00" * (0x80 - len(dos))

    # NT signature
    nt = bytearray(b"PE\x00\x00")

    # COFF header (20 bytes)
    machine = 0x14C  # i386
    num_sections = 1
    time_stamp = 0x5F3759DF
    ptr_sym = 0
    num_sym = 0
    size_opt = 0xE0  # typical PE32 optional header size
    characteristics = 0x0002  # executable image
    coff = struct.pack("<HHIIIHH", machine, num_sections, time_stamp, ptr_sym, num_sym, size_opt, characteristics)

    # Optional header (PE32, enough bytes)
    opt = bytearray(b"\x00" * size_opt)
    struct.pack_into("<H", opt, 0x00, 0x10B)      # Magic PE32
    struct.pack_into("<I", opt, 0x10, 0x1000)     # AddressOfEntryPoint
    struct.pack_into("<I", opt, 0x1C, 0x400000)   # ImageBase (PE32)
    struct.pack_into("<I", opt, 0x38, 0x2000)     # SizeOfImage
    struct.pack_into("<H", opt, 0x44, 2)          # Subsystem (Windows GUI)
    struct.pack_into("<H", opt, 0x46, 0x8140)     # DllCharacteristics (random-ish)

    # Section header (40 bytes)
    name = b".text\x00\x00\x00"
    virtual_size = 0x100
    virtual_address = 0x1000
    raw_size = 0x200
    raw_ptr = 0x200
    characteristics_sec = 0x60000020  # code + execute + read
    sh = bytearray(40)
    sh[0:8] = name
    struct.pack_into("<I", sh, 8, virtual_size)
    struct.pack_into("<I", sh, 12, virtual_address)
    struct.pack_into("<I", sh, 16, raw_size)
    struct.pack_into("<I", sh, 20, raw_ptr)
    struct.pack_into("<I", sh, 36, characteristics_sec)

    blob = bytes(dos) + bytes(nt) + coff + bytes(opt) + bytes(sh)

    # Pad to raw_ptr then add section raw data
    if len(blob) < raw_ptr:
        blob += b"\x00" * (raw_ptr - len(blob))
    blob += b"\x90" * raw_size  # NOP sled as raw data

    return blob


def test_parse_minimal_pe_success():
    data = _build_minimal_pe()
    res = parse_pe_bytes(data)

    assert res.present is True
    assert res.pe is not None
    assert res.pe["coff"]["machine"] == 0x14C
    assert res.pe["coff"]["number_of_sections"] == 1
    assert res.pe["optional"]["is_pe32_plus"] is False
    assert res.pe["optional"]["address_of_entry_point"] == 0x1000
    assert res.pe["sections"][0]["name"] == ".text"
    assert res.pe["section_count_parsed"] == 1
    # entropy should be defined (raw bytes exist)
    assert res.pe["sections"][0]["entropy"] is not None


def test_parse_non_pe_bytes_not_present():
    res = parse_pe_bytes(b"hello world")
    assert res.present is False
    assert res.pe is None
    assert res.errors == []
