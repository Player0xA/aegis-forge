from __future__ import annotations

import struct
from aegis.pe import parse_pe_bytes

def _build_pe32_with_one_export() -> bytes:
    # One .rdata section at RVA 0x2000, raw_ptr 0x200
    e_lfanew = 0x80
    dos = bytearray(b"MZ" + b"\x00" * 58)
    dos += struct.pack("<I", e_lfanew)
    if len(dos) < e_lfanew:
        dos += b"\x00" * (e_lfanew - len(dos))

    nt = bytearray(b"PE\x00\x00")
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0x22222222, 0, 0, 0xE0, 0x0002)

    opt = bytearray(b"\x00" * 0xE0)
    struct.pack_into("<H", opt, 0x00, 0x10B)   # PE32
    struct.pack_into("<I", opt, 0x5C, 16)      # NumberOfRvaAndSizes

    export_rva = 0x2000
    export_size = 0x100
    struct.pack_into("<I", opt, 0x60 + 0*8, export_rva)      # Export RVA
    struct.pack_into("<I", opt, 0x60 + 0*8 + 4, export_size) # Export size

    sh = bytearray(40)
    sh[0:8] = b".rdata\x00\x00"
    struct.pack_into("<I", sh, 8, 0x400)
    struct.pack_into("<I", sh, 12, 0x2000)
    struct.pack_into("<I", sh, 16, 0x400)
    struct.pack_into("<I", sh, 20, 0x200)
    struct.pack_into("<I", sh, 36, 0x40000040)

    blob = bytes(dos) + bytes(nt) + coff + bytes(opt) + bytes(sh)
    if len(blob) < 0x200:
        blob += b"\x00" * (0x200 - len(blob))

    rdata = bytearray(b"\x00" * 0x400)

    # Export Directory at RVA 0x2000 (offset 0)
    # Name RVA = 0x2060
    # Base = 1
    # NumberOfFunctions = 1
    # NumberOfNames = 1
    # AddressOfNames = 0x2070
    # AddressOfNameOrdinals = 0x2080
    struct.pack_into("<I", rdata, 12, 0x2060)  # Name RVA
    struct.pack_into("<I", rdata, 16, 1)       # Base
    struct.pack_into("<I", rdata, 20, 1)       # NumberOfFunctions
    struct.pack_into("<I", rdata, 24, 1)       # NumberOfNames
    struct.pack_into("<I", rdata, 32, 0x2070)  # AddressOfNames
    struct.pack_into("<I", rdata, 36, 0x2080)  # AddressOfNameOrdinals

    # DLL name at RVA 0x2060 (offset 0x60)
    rdata[0x60 : 0x60 + len(b"TESTDLL.dll\x00")] = b"TESTDLL.dll\x00"

    # AddressOfNames table (1 entry) points to RVA 0x2090
    struct.pack_into("<I", rdata, 0x70, 0x2090)

    # AddressOfNameOrdinals table (1 entry) ordinal index 0
    struct.pack_into("<H", rdata, 0x80, 0)

    # Exported name at RVA 0x2090 (offset 0x90)
    rdata[0x90 : 0x90 + len(b"MyExport\x00")] = b"MyExport\x00"

    blob += bytes(rdata)
    return blob

def test_pe_exports_parsed():
    res = parse_pe_bytes(_build_pe32_with_one_export())
    assert res.present is True
    assert res.pe is not None
    ex = res.pe["exports"]
    assert ex["present"] is True
    assert ex["dll_name"].lower() == "testdll.dll"
    assert "MyExport" in ex["names"]
    assert ex["ordinal_base"] == 1
    assert 1 in ex["ordinals"]
