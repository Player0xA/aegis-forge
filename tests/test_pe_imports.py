from __future__ import annotations

import struct
from aegis.pe import parse_pe_bytes

def _build_pe32_with_one_import() -> bytes:
    # Layout plan:
    # - e_lfanew = 0x80
    # - one section .rdata at RVA 0x2000, raw_ptr 0x200, raw_size 0x400
    # - import directory at RVA 0x2000
    # - thunk table at RVA 0x2040
    # - dll name at RVA 0x2060 -> "KERNEL32.dll\0"
    # - import-by-name at RVA 0x2080 -> hint(2) + "ExitProcess\0"

    e_lfanew = 0x80
    dos = bytearray(b"MZ" + b"\x00" * 58)
    dos += struct.pack("<I", e_lfanew)
    if len(dos) < e_lfanew:
        dos += b"\x00" * (e_lfanew - len(dos))

    nt = bytearray(b"PE\x00\x00")

    machine = 0x14C
    num_sections = 1
    time_stamp = 0x11111111
    size_opt = 0xE0
    characteristics = 0x0002
    coff = struct.pack("<HHIIIHH", machine, num_sections, time_stamp, 0, 0, size_opt, characteristics)

    opt = bytearray(b"\x00" * size_opt)
    struct.pack_into("<H", opt, 0x00, 0x10B)      # PE32
    struct.pack_into("<I", opt, 0x10, 0x1000)     # EntryPoint
    struct.pack_into("<I", opt, 0x1C, 0x400000)   # ImageBase
    struct.pack_into("<I", opt, 0x38, 0x3000)     # SizeOfImage
    struct.pack_into("<H", opt, 0x44, 2)          # Subsystem

    # Data directories: NumberOfRvaAndSizes @ 0x5C, DataDirectory starts @ 0x60
    struct.pack_into("<I", opt, 0x5C, 16)         # NumberOfRvaAndSizes
    import_rva = 0x2000
    import_size = 0x100
    struct.pack_into("<I", opt, 0x60 + 1 * 8, import_rva)       # Import RVA
    struct.pack_into("<I", opt, 0x60 + 1 * 8 + 4, import_size)  # Import size

    # Section header: .rdata
    sh = bytearray(40)
    sh[0:8] = b".rdata\x00\x00"
    struct.pack_into("<I", sh, 8, 0x400)        # VirtualSize
    struct.pack_into("<I", sh, 12, 0x2000)      # VirtualAddress
    struct.pack_into("<I", sh, 16, 0x400)       # SizeOfRawData
    struct.pack_into("<I", sh, 20, 0x200)       # PointerToRawData
    struct.pack_into("<I", sh, 36, 0x40000040)  # Readable data

    blob = bytes(dos) + bytes(nt) + coff + bytes(opt) + bytes(sh)
    # pad to raw_ptr 0x200
    if len(blob) < 0x200:
        blob += b"\x00" * (0x200 - len(blob))

    rdata = bytearray(b"\x00" * 0x400)

    # Import Descriptor at RVA 0x2000 (offset 0x200)
    # OriginalFirstThunk = 0 (use FirstThunk), Name = 0x2060, FirstThunk = 0x2040
    desc_off = 0x000
    struct.pack_into("<I", rdata, desc_off + 0, 0)        # OriginalFirstThunk
    struct.pack_into("<I", rdata, desc_off + 12, 0x2060)  # Name RVA
    struct.pack_into("<I", rdata, desc_off + 16, 0x2040)  # FirstThunk RVA

    # Terminator descriptor (all zeros) at +20 already zeroed

    # Thunk table at RVA 0x2040 (offset 0x40 in section)
    # First entry: RVA to IMAGE_IMPORT_BY_NAME (0x2080), then 0 terminator
    struct.pack_into("<I", rdata, 0x40, 0x2080)
    struct.pack_into("<I", rdata, 0x44, 0)

    # DLL name at RVA 0x2060 (offset 0x60)
    rdata[0x60 : 0x60 + len(b"KERNEL32.dll\x00")] = b"KERNEL32.dll\x00"

    # IMAGE_IMPORT_BY_NAME at RVA 0x2080 (offset 0x80): hint(2 bytes) + "ExitProcess\0"
    struct.pack_into("<H", rdata, 0x80, 0)
    rdata[0x82 : 0x82 + len(b"ExitProcess\x00")] = b"ExitProcess\x00"

    blob += bytes(rdata)
    return blob

def test_pe_imports_parsed():
    data = _build_pe32_with_one_import()
    res = parse_pe_bytes(data)
    assert res.present is True
    assert res.pe is not None
    imps = res.pe.get("imports", [])
    assert len(imps) == 1
    assert imps[0]["dll"].lower() == "kernel32.dll"
    assert "ExitProcess" in imps[0]["functions"]
