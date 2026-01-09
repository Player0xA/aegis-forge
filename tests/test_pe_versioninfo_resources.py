from __future__ import annotations

import struct
from aegis.pe import parse_pe_bytes

def _u16(s: str) -> bytes:
    return s.encode("utf-16le") + b"\x00\x00"

def _align4(b: bytes) -> bytes:
    pad = (-len(b)) & 3
    return b + (b"\x00" * pad)

def _block(key: str, value_utf16: bytes, children: bytes, *, wtype: int) -> bytes:
    # wValueLength for type=1 is in WCHARs
    if wtype == 1:
        wvlen = len(value_utf16) // 2
    else:
        wvlen = len(value_utf16)
    header = struct.pack("<HHH", 0, wvlen, wtype)
    body = header + _u16(key)
    body = _align4(body)
    body += value_utf16
    body = _align4(body)
    body += children
    body = _align4(body)
    # patch wLength
    body = struct.pack("<H", len(body)) + body[2:]
    return body

def _build_vs_versioninfo() -> bytes:
    # String: CompanyName="ACME"
    company_val = "ACME".encode("utf-16le") + b"\x00\x00"
    string = _block("CompanyName", company_val, b"", wtype=1)

    # StringTable key typically looks like "040904B0"
    string_table = _block("040904B0", b"", string, wtype=1)

    # StringFileInfo
    sfi = _block("StringFileInfo", b"", string_table, wtype=1)

    # VS_VERSION_INFO root (no fixed file info to keep minimal)
    root = _block("VS_VERSION_INFO", b"", sfi, wtype=1)
    return root

def _build_pe32_with_rsrc_versioninfo() -> bytes:
    e_lfanew = 0x80
    dos = bytearray(b"MZ" + b"\x00" * 58)
    dos += struct.pack("<I", e_lfanew)
    if len(dos) < e_lfanew:
        dos += b"\x00" * (e_lfanew - len(dos))

    nt = bytearray(b"PE\x00\x00")
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0x11111111, 0, 0, 0xE0, 0x0002)

    opt = bytearray(b"\x00" * 0xE0)
    struct.pack_into("<H", opt, 0x00, 0x10B)   # PE32
    struct.pack_into("<I", opt, 0x5C, 16)      # NumberOfRvaAndSizes

    # Resource directory: index 2 -> RVA 0x2000 size 0x600
    struct.pack_into("<I", opt, 0x60 + 2*8, 0x2000)
    struct.pack_into("<I", opt, 0x60 + 2*8 + 4, 0x600)

    sh = bytearray(40)
    sh[0:8] = b".rsrc\x00\x00\x00"
    struct.pack_into("<I", sh, 8, 0x600)     # virtual size
    struct.pack_into("<I", sh, 12, 0x2000)   # virtual address
    struct.pack_into("<I", sh, 16, 0x600)    # raw size
    struct.pack_into("<I", sh, 20, 0x200)    # raw ptr
    struct.pack_into("<I", sh, 36, 0x40000040)

    blob = bytes(dos) + bytes(nt) + coff + bytes(opt) + bytes(sh)
    if len(blob) < 0x200:
        blob += b"\x00" * (0x200 - len(blob))

    rsrc = bytearray(b"\x00" * 0x600)

    # Resource tree (base RVA 0x2000, base offset 0x200)
    # Root dir @ 0x00: 0 named, 1 id
    struct.pack_into("<HH", rsrc, 12, 0, 1)

    # Root entry[0] @ 0x10: ID=16, points to dir @ 0x40 (high bit)
    struct.pack_into("<I", rsrc, 0x10, 16)
    struct.pack_into("<I", rsrc, 0x14, 0x80000040)

    # Type dir @ 0x40: 0 named, 1 id
    struct.pack_into("<HH", rsrc, 0x40 + 12, 0, 1)
    # entry: ID=1 -> dir @ 0x80
    struct.pack_into("<I", rsrc, 0x40 + 0x10, 1)
    struct.pack_into("<I", rsrc, 0x40 + 0x14, 0x80000080)

    # Name dir @ 0x80: 0 named, 1 id
    struct.pack_into("<HH", rsrc, 0x80 + 12, 0, 1)
    # entry: lang 1033 -> data entry @ 0xC0
    struct.pack_into("<I", rsrc, 0x80 + 0x10, 1033)
    struct.pack_into("<I", rsrc, 0x80 + 0x14, 0x000000C0)

    vs = _build_vs_versioninfo()

    # Data entry @ 0xC0 (IMAGE_RESOURCE_DATA_ENTRY)
    # OffsetToData = RVA 0x2100 (rsrc base 0x2000 + 0x100)
    struct.pack_into("<I", rsrc, 0xC0 + 0, 0x2100)
    struct.pack_into("<I", rsrc, 0xC0 + 4, len(vs))
    struct.pack_into("<I", rsrc, 0xC0 + 8, 0)  # CodePage
    struct.pack_into("<I", rsrc, 0xC0 + 12, 0) # Reserved

    # Put VS blob at offset 0x100 in rsrc section
    rsrc[0x100 : 0x100 + len(vs)] = vs

    blob += bytes(rsrc)
    return blob

def test_pe_resources_versioninfo_companyname():
    data = _build_pe32_with_rsrc_versioninfo()
    res = parse_pe_bytes(data)
    assert res.present is True
    assert res.pe is not None
    r = res.pe["resources"]
    assert r["present"] is True
    assert r["version_info"].get("CompanyName") == "ACME"
