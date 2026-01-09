from __future__ import annotations

import struct
from aegis.pe import parse_pe_bytes

def _build_arm64_pe32plus() -> bytes:
    # DOS header with e_lfanew -> 0x80
    dos = bytearray(b"MZ" + b"\x00" * 58)
    dos += struct.pack("<I", 0x80)
    if len(dos) < 0x80:
        dos += b"\x00" * (0x80 - len(dos))

    nt = bytearray(b"PE\x00\x00")

    # COFF: machine=ARM64 (0xAA64), 1 section, opt header size 0xF0 (common PE32+)
    coff = struct.pack("<HHIIIHH", 0xAA64, 1, 0x12345678, 0, 0, 0xF0, 0x0022)

    opt = bytearray(b"\x00" * 0xF0)
    struct.pack_into("<H", opt, 0x00, 0x20B)         # PE32+
    struct.pack_into("<I", opt, 0x10, 0x1000)        # EntryPoint
    struct.pack_into("<Q", opt, 0x18, 0x140000000)   # ImageBase
    struct.pack_into("<I", opt, 0x38, 0x2000)        # SizeOfImage
    struct.pack_into("<H", opt, 0x44, 2)             # Subsystem

    # One section header (.text)
    sh = bytearray(40)
    sh[0:8] = b".text\x00\x00\x00"
    struct.pack_into("<I", sh, 8, 0x100)
    struct.pack_into("<I", sh, 12, 0x1000)
    struct.pack_into("<I", sh, 16, 0x200)
    struct.pack_into("<I", sh, 20, 0x200)
    struct.pack_into("<I", sh, 36, 0x60000020)

    blob = bytes(dos) + bytes(nt) + coff + bytes(opt) + bytes(sh)
    if len(blob) < 0x200:
        blob += b"\x00" * (0x200 - len(blob))
    blob += b"\x90" * 0x200
    return blob

def test_arm64_pe32plus_detected():
    res = parse_pe_bytes(_build_arm64_pe32plus())
    assert res.present is True
    assert res.pe is not None
    assert res.pe["coff"]["machine"] == 0xAA64
    assert res.pe["optional"]["is_pe32_plus"] is True
    assert res.pe["optional"]["magic"] == 0x20B
    assert res.pe["section_count_parsed"] == 1
