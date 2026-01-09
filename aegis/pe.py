from __future__ import annotations

import math
import struct
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

IMAGE_DOS_SIGNATURE = b"MZ"
IMAGE_NT_SIGNATURE = b"PE\x00\x00"

IMAGE_FILE_DLL = 0x2000

PE32_MAGIC = 0x10B
PE32P_MAGIC = 0x20B

# Data directory indices
DIR_EXPORT = 0
DIR_IMPORT = 1
DIR_RESOURCE = 2
DIR_SECURITY = 4

# Resource constants
RT_VERSION = 16


@dataclass(frozen=True)
class PeParseResult:
    present: bool
    pe: Optional[Dict[str, Any]]
    errors: List[Dict[str, Any]]


def _err(code: str, message: str, **extra: Any) -> Dict[str, Any]:
    d = {"code": code, "message": message}
    d.update(extra)
    return d


def _u16(data: bytes, off: int) -> Optional[int]:
    if off < 0 or off + 2 > len(data):
        return None
    return struct.unpack_from("<H", data, off)[0]


def _u32(data: bytes, off: int) -> Optional[int]:
    if off < 0 or off + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, off)[0]


def _u64(data: bytes, off: int) -> Optional[int]:
    if off < 0 or off + 8 > len(data):
        return None
    return struct.unpack_from("<Q", data, off)[0]


def _read_bytes(data: bytes, off: int, size: int) -> Optional[bytes]:
    if off < 0 or size < 0 or off + size > len(data):
        return None
    return data[off : off + size]


def _safe_ascii(b: bytes) -> str:
    return b.split(b"\x00", 1)[0].decode("ascii", errors="replace")


def _read_c_string(data: bytes, off: int, *, max_len: int = 512) -> Optional[str]:
    if off < 0 or off >= len(data):
        return None
    end = min(len(data), off + max_len)
    chunk = data[off:end]
    nul = chunk.find(b"\x00")
    if nul == -1:
        return None
    return chunk[:nul].decode("ascii", errors="replace")


def _align4(x: int) -> int:
    return (x + 3) & ~3


def _read_utf16le_zstring(data: bytes, off: int, *, max_chars: int = 512) -> Tuple[Optional[str], int]:
    """
    Read UTF-16LE null-terminated string starting at off.
    Returns (string_without_null, bytes_consumed_including_null).
    """
    if off < 0 or off >= len(data):
        return None, 0
    end = min(len(data), off + max_chars * 2)
    i = off
    while i + 1 < end:
        if data[i] == 0 and data[i + 1] == 0:
            raw = data[off:i]
            try:
                s = raw.decode("utf-16le", errors="replace")
            except Exception:
                s = raw.decode("utf-16le", errors="replace")
            return s, (i + 2) - off
        i += 2
    return None, 0


def _shannon_entropy(blob: bytes) -> float:
    if not blob:
        return 0.0
    counts = [0] * 256
    for x in blob:
        counts[x] += 1
    n = len(blob)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return float(ent)


def _rva_to_offset(rva: int, *, sections: List[Dict[str, Any]], file_len: int) -> Optional[int]:
    if rva <= 0:
        return None
    for s in sections:
        va = int(s.get("virtual_address", 0) or 0)
        vs = int(s.get("virtual_size", 0) or 0)
        raw_ptr = int(s.get("raw_ptr", 0) or 0)
        raw_size = int(s.get("raw_size", 0) or 0)
        span = max(vs, raw_size)
        if span <= 0:
            continue
        if va <= rva < va + span:
            delta = rva - va
            off = raw_ptr + delta
            if 0 <= off < file_len:
                return off
    return None


def _parse_imports(
    data: bytes,
    *,
    is_pe32_plus: bool,
    sections: List[Dict[str, Any]],
    import_rva: int,
    import_size: int,
    max_dlls: int = 256,
    max_funcs_per_dll: int = 2048,
    max_name_len: int = 512,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    errors: List[Dict[str, Any]] = []
    imports: List[Dict[str, Any]] = []

    base_off = _rva_to_offset(import_rva, sections=sections, file_len=len(data))
    if base_off is None:
        return [], [
            _err(
                "E_PE_IMPORT_RVA_UNMAPPABLE",
                "Import directory RVA could not be mapped to file offset.",
                import_rva=import_rva,
            )
        ]

    desc_off = base_off
    dll_count = 0

    while True:
        if dll_count >= max_dlls:
            errors.append(
                _err(
                    "E_PE_IMPORT_TOO_MANY_DLLS",
                    f"Import DLL count exceeded max_dlls={max_dlls}.",
                    max_dlls=max_dlls,
                )
            )
            break

        if desc_off + 20 > len(data):
            errors.append(_err("E_PE_IMPORT_DESC_TRUNCATED", "Import descriptor table truncated.", desc_off=desc_off))
            break

        original_first_thunk = _u32(data, desc_off + 0) or 0
        time_date_stamp = _u32(data, desc_off + 4) or 0
        forwarder_chain = _u32(data, desc_off + 8) or 0
        name_rva = _u32(data, desc_off + 12) or 0
        first_thunk = _u32(data, desc_off + 16) or 0

        if (
            original_first_thunk == 0
            and time_date_stamp == 0
            and forwarder_chain == 0
            and name_rva == 0
            and first_thunk == 0
        ):
            break

        name_off = _rva_to_offset(name_rva, sections=sections, file_len=len(data))
        if name_off is None:
            errors.append(
                _err(
                    "E_PE_IMPORT_DLL_NAME_UNMAPPABLE",
                    "Import DLL name RVA could not be mapped.",
                    name_rva=name_rva,
                )
            )
            dll_name = None
        else:
            dll_name = _read_c_string(data, name_off, max_len=max_name_len)

        if not dll_name:
            dll_name = f"__unreadable_dll_{dll_count}__"
            errors.append(
                _err(
                    "E_PE_IMPORT_DLL_NAME_UNREADABLE",
                    "Import DLL name could not be read (missing NUL or decode issue).",
                    name_rva=name_rva,
                )
            )

        thunk_rva = original_first_thunk or first_thunk
        thunk_off = _rva_to_offset(thunk_rva, sections=sections, file_len=len(data))
        if thunk_off is None:
            errors.append(
                _err(
                    "E_PE_IMPORT_THUNK_UNMAPPABLE",
                    "Import thunk RVA could not be mapped.",
                    thunk_rva=thunk_rva,
                    dll=dll_name,
                )
            )
            funcs: List[str] = []
            ords: List[int] = []
        else:
            funcs = []
            ords = []
            entry_size = 8 if is_pe32_plus else 4
            ordinal_flag = 0x8000000000000000 if is_pe32_plus else 0x80000000

            func_seen = set()
            ord_seen = set()

            for idx in range(max_funcs_per_dll):
                ent_off = thunk_off + idx * entry_size
                if ent_off + entry_size > len(data):
                    errors.append(
                        _err(
                            "E_PE_IMPORT_THUNK_TRUNCATED",
                            "Import thunk table truncated.",
                            dll=dll_name,
                            thunk_off=thunk_off,
                        )
                    )
                    break

                val = _u64(data, ent_off) if is_pe32_plus else _u32(data, ent_off)
                if val is None:
                    break
                if val == 0:
                    break

                if val & ordinal_flag:
                    ordinal = int(val & 0xFFFF)
                    if ordinal not in ord_seen:
                        ord_seen.add(ordinal)
                        ords.append(ordinal)
                    continue

                ibn_rva = int(val)
                ibn_off = _rva_to_offset(ibn_rva, sections=sections, file_len=len(data))
                if ibn_off is None:
                    errors.append(
                        _err(
                            "E_PE_IMPORT_BY_NAME_UNMAPPABLE",
                            "IMAGE_IMPORT_BY_NAME RVA could not be mapped.",
                            dll=dll_name,
                            ibn_rva=ibn_rva,
                        )
                    )
                    continue

                name = _read_c_string(data, ibn_off + 2, max_len=max_name_len)
                if not name:
                    errors.append(
                        _err(
                            "E_PE_IMPORT_BY_NAME_UNREADABLE",
                            "Imported function name unreadable (missing NUL or decode).",
                            dll=dll_name,
                            ibn_rva=ibn_rva,
                        )
                    )
                    continue

                if name not in func_seen:
                    func_seen.add(name)
                    funcs.append(name)

            funcs.sort()

        imports.append({"dll": dll_name, "functions": funcs, "ordinals": sorted(ords)})
        dll_count += 1
        desc_off += 20

    imports.sort(key=lambda x: x.get("dll", ""))
    return imports, errors


def _parse_exports(
    data: bytes,
    *,
    sections: List[Dict[str, Any]],
    export_rva: int,
    export_size: int,
    max_names: int = 4096,
    max_name_len: int = 512,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    errors: List[Dict[str, Any]] = []

    base_off = _rva_to_offset(export_rva, sections=sections, file_len=len(data))
    if base_off is None:
        return (
            {
                "present": False,
                "dll_name": None,
                "ordinal_base": None,
                "function_count": 0,
                "name_count": 0,
                "names": [],
                "ordinals": [],
            },
            [
                _err(
                    "E_PE_EXPORT_RVA_UNMAPPABLE",
                    "Export directory RVA could not be mapped to file offset.",
                    export_rva=export_rva,
                )
            ],
        )

    if base_off + 40 > len(data):
        return (
            {
                "present": False,
                "dll_name": None,
                "ordinal_base": None,
                "function_count": 0,
                "name_count": 0,
                "names": [],
                "ordinals": [],
            },
            [_err("E_PE_EXPORT_DIR_TRUNCATED", "Export directory truncated.", export_off=base_off)],
        )

    name_rva = _u32(data, base_off + 12) or 0
    ordinal_base = _u32(data, base_off + 16) or 0
    num_funcs = _u32(data, base_off + 20) or 0
    num_names = _u32(data, base_off + 24) or 0
    addr_names_rva = _u32(data, base_off + 32) or 0
    addr_ord_rva = _u32(data, base_off + 36) or 0

    dll_name = None
    if name_rva:
        name_off = _rva_to_offset(name_rva, sections=sections, file_len=len(data))
        if name_off is None:
            errors.append(_err("E_PE_EXPORT_DLLNAME_UNMAPPABLE", "Export DLL name RVA unmappable.", name_rva=name_rva))
        else:
            dll_name = _read_c_string(data, name_off, max_len=max_name_len)
            if not dll_name:
                errors.append(_err("E_PE_EXPORT_DLLNAME_UNREADABLE", "Export DLL name unreadable.", name_rva=name_rva))

    names: List[str] = []
    ordinals: List[int] = []

    if num_names:
        if num_names > max_names:
            errors.append(_err("E_PE_EXPORT_TOO_MANY_NAMES", f"Export name count exceeded max_names={max_names}.", num_names=num_names))
            num_names = max_names

        names_off = _rva_to_offset(addr_names_rva, sections=sections, file_len=len(data)) if addr_names_rva else None
        ords_off = _rva_to_offset(addr_ord_rva, sections=sections, file_len=len(data)) if addr_ord_rva else None

        if names_off is None or ords_off is None:
            errors.append(_err("E_PE_EXPORT_TABLES_UNMAPPABLE", "Export names/ordinals tables unmappable.", addr_names_rva=addr_names_rva, addr_ord_rva=addr_ord_rva))
        else:
            seen = set()
            ord_seen = set()
            for i in range(int(num_names)):
                ptr_rva = _u32(data, names_off + i * 4)
                if ptr_rva is None:
                    break
                ptr_off = _rva_to_offset(int(ptr_rva), sections=sections, file_len=len(data))
                if ptr_off is None:
                    errors.append(_err("E_PE_EXPORT_NAME_UNMAPPABLE", "Export name RVA unmappable.", name_rva=int(ptr_rva)))
                    continue
                s = _read_c_string(data, ptr_off, max_len=max_name_len)
                if not s:
                    errors.append(_err("E_PE_EXPORT_NAME_UNREADABLE", "Export name unreadable.", name_rva=int(ptr_rva)))
                    continue
                if s not in seen:
                    seen.add(s)
                    names.append(s)

                ord_idx = _u16(data, ords_off + i * 2)
                if ord_idx is not None:
                    ord_val = int(ordinal_base + ord_idx)
                    if ord_val not in ord_seen:
                        ord_seen.add(ord_val)
                        ordinals.append(ord_val)

            names.sort()
            ordinals.sort()

    exports = {
        "present": True if (num_funcs or num_names or dll_name) else False,
        "dll_name": dll_name,
        "ordinal_base": int(ordinal_base) if ordinal_base else 0,
        "function_count": int(num_funcs),
        "name_count": int(num_names),
        "names": names,
        "ordinals": ordinals,
    }
    return exports, errors


def _parse_versioninfo_strings(vs: bytes, *, max_pairs: int = 200, max_key_chars: int = 200, max_val_chars: int = 2000) -> Tuple[Dict[str, str], List[Dict[str, Any]]]:
    """
    Parse VS_VERSIONINFO / StringFileInfo / StringTable / String blocks.
    Returns (kv_pairs, errors).
    Deterministic:
      - preserves first-seen key
      - final dict sorted by key
    """
    errors: List[Dict[str, Any]] = []
    pairs: Dict[str, str] = {}

    def read_block(off: int, limit: int) -> Optional[Tuple[int, int, int, str, int, int]]:
        # Returns (wLength, wValueLength, wType, key, header_end, block_end)
        if off < 0 or off + 6 > limit:
            return None
        wlen = _u16(vs, off)
        wvlen = _u16(vs, off + 2)
        wtype = _u16(vs, off + 4)
        if wlen is None or wvlen is None or wtype is None:
            return None
        if wlen < 6:
            return None
        end = off + int(wlen)
        if end > limit:
            return None

        key, consumed = _read_utf16le_zstring(vs, off + 6, max_chars=max_key_chars)
        if key is None or consumed <= 0:
            return None
        header_end = off + 6 + consumed
        return int(wlen), int(wvlen), int(wtype), key, int(header_end), int(end)

    def parse_children(children_off: int, block_end: int, depth: int) -> None:
        if depth > 8:
            errors.append(_err("E_PE_VI_TOO_DEEP", "VersionInfo nesting too deep.", depth=depth))
            return
        cur = _align4(children_off)
        while cur + 6 <= block_end:
            blk = read_block(cur, block_end)
            if blk is None:
                break
            wlen, wvlen, wtype, key, header_end, end = blk

            # Value starts aligned
            val_off = _align4(header_end)
            # For String blocks, value is UTF-16LE string of wvlen WCHARs (includes terminating null typically)
            if key and key != "VS_VERSION_INFO" and key != "StringFileInfo" and key != "VarFileInfo":
                # If this is a String node, it usually has wtype=1 and wvlen>0
                if wtype == 1 and wvlen > 0 and len(pairs) < max_pairs:
                    val_bytes_len = min((wvlen * 2), max_val_chars * 2)
                    if val_off + val_bytes_len <= end:
                        raw = vs[val_off : val_off + val_bytes_len]
                        # strip trailing nulls
                        try:
                            sval = raw.decode("utf-16le", errors="replace").rstrip("\x00")
                        except Exception:
                            sval = raw.decode("utf-16le", errors="replace").rstrip("\x00")
                        if key not in pairs:
                            pairs[key] = sval

            # Children begin after value region, aligned
            # We don't know exact value byte length for non-String nodes, but spec aligns after value.
            # We approximate:
            if wtype == 1:
                value_bytes = wvlen * 2
            else:
                value_bytes = wvlen  # not used much; safe fallback
            child_off = _align4(val_off + int(value_bytes))
            if child_off < end:
                parse_children(child_off, end, depth + 1)

            cur = _align4(end)

    root = read_block(0, len(vs))
    if root is None:
        return {}, [_err("E_PE_VI_PARSE_FAILED", "Failed to parse VS_VERSIONINFO root.")]
    wlen, wvlen, wtype, key, header_end, end = root
    if key != "VS_VERSION_INFO":
        return {}, [_err("E_PE_VI_BAD_ROOT", "Root key is not VS_VERSION_INFO.", root_key=key)]

    val_off = _align4(header_end)
    # Skip fixed file info (wvlen bytes for type 0, or wvlen words for type 1)
    if wtype == 0:
        value_bytes = wvlen
    else:
        value_bytes = wvlen * 2
    child_off = _align4(val_off + int(value_bytes))
    if child_off < end:
        parse_children(child_off, end, 0)

    # Deterministic ordering
    pairs_sorted = {k: pairs[k] for k in sorted(pairs.keys())}
    return pairs_sorted, errors


def _parse_resources_versioninfo(
    data: bytes,
    *,
    sections: List[Dict[str, Any]],
    resource_rva: int,
    resource_size: int,
    max_nodes: int = 2048,
    max_vs_size: int = 2_000_000,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Parse PE resource directory to locate RT_VERSION (16) and extract VersionInfo StringFileInfo pairs.
    Deterministic selection: choose the lowest-id path at each level.
    """
    errors: List[Dict[str, Any]] = []
    res = {"present": False, "version_info": {}}

    base_off = _rva_to_offset(resource_rva, sections=sections, file_len=len(data))
    if base_off is None:
        return res, [
            _err(
                "E_PE_RSRC_RVA_UNMAPPABLE",
                "Resource directory RVA could not be mapped to file offset.",
                resource_rva=resource_rva,
            )
        ]

    base_end = min(len(data), base_off + max(0, int(resource_size)))
    if base_end - base_off < 16:
        return res, [_err("E_PE_RSRC_TRUNCATED", "Resource directory truncated.", resource_off=base_off)]

    nodes_seen = 0

    def read_dir(dir_rel: int) -> Optional[Tuple[int, int, int]]:
        nonlocal nodes_seen
        nodes_seen += 1
        if nodes_seen > max_nodes:
            errors.append(_err("E_PE_RSRC_TOO_MANY_NODES", f"Resource nodes exceeded max_nodes={max_nodes}.", max_nodes=max_nodes))
            return None

        off = base_off + dir_rel
        if off < base_off or off + 16 > base_end:
            errors.append(_err("E_PE_RSRC_DIR_OOB", "Resource directory out of bounds.", dir_rel=dir_rel))
            return None
        n_named = _u16(data, off + 12) or 0
        n_id = _u16(data, off + 14) or 0
        entries_off = off + 16
        total = int(n_named) + int(n_id)
        return entries_off - base_off, total, int(n_named)

    def read_entry(entry_rel_off: int, idx: int) -> Optional[Tuple[Optional[int], bool, int]]:
        # Returns (id, is_dir, target_rel)
        eoff = base_off + entry_rel_off + idx * 8
        if eoff < base_off or eoff + 8 > base_end:
            return None
        name_or_id = _u32(data, eoff) or 0
        off_to = _u32(data, eoff + 4) or 0
        is_dir = bool(off_to & 0x80000000)
        target_rel = int(off_to & 0x7FFFFFFF)

        # We only deterministically use ID entries (named entries ignored for now)
        is_named = bool(name_or_id & 0x80000000)
        if is_named:
            return None
        rid = int(name_or_id & 0xFFFF_FFFF)
        return rid, is_dir, target_rel

    def pick_child(dir_rel: int, want_id: Optional[int] = None) -> Optional[Tuple[int, bool]]:
        rd = read_dir(dir_rel)
        if rd is None:
            return None
        entries_rel, total, n_named = rd
        # iterate only over ID entries (skip named region first)
        best: Optional[Tuple[int, bool]] = None  # (target_rel, is_dir)
        best_id: Optional[int] = None
        for i in range(total):
            ent = read_entry(entries_rel, i)
            if ent is None:
                continue
            rid, is_dir, target_rel = ent
            if want_id is not None and rid != want_id:
                continue
            if best is None or (rid is not None and best_id is not None and rid < best_id) or (best_id is None and rid is not None):
                best = (target_rel, is_dir)
                best_id = rid
        return best

    # Level 1: Type directory -> RT_VERSION (16)
    type_pick = pick_child(0, want_id=RT_VERSION)
    if not type_pick:
        return res, errors  # no version info
    type_rel, type_is_dir = type_pick
    if not type_is_dir:
        errors.append(_err("E_PE_RSRC_BAD_TREE", "RT_VERSION entry is not a directory.", type_rel=type_rel))
        return res, errors

    # Level 2: Name directory (pick lowest id)
    name_pick = pick_child(type_rel, want_id=None)
    if not name_pick:
        return res, errors
    name_rel, name_is_dir = name_pick
    if not name_is_dir:
        errors.append(_err("E_PE_RSRC_BAD_TREE", "Version name entry is not a directory.", name_rel=name_rel))
        return res, errors

    # Level 3: Language directory (pick lowest id)
    lang_pick = pick_child(name_rel, want_id=None)
    if not lang_pick:
        return res, errors
    lang_rel, lang_is_dir = lang_pick
    if lang_is_dir:
        errors.append(_err("E_PE_RSRC_BAD_TREE", "Language entry unexpectedly points to a directory.", lang_rel=lang_rel))
        return res, errors

    # Data entry: IMAGE_RESOURCE_DATA_ENTRY (16 bytes)
    data_entry_off = base_off + lang_rel
    if data_entry_off < base_off or data_entry_off + 16 > base_end:
        errors.append(_err("E_PE_RSRC_DATA_ENTRY_OOB", "Resource data entry out of bounds.", lang_rel=lang_rel))
        return res, errors

    data_rva = _u32(data, data_entry_off + 0) or 0
    data_size = _u32(data, data_entry_off + 4) or 0
    if data_size <= 0:
        return res, errors

    if data_size > max_vs_size:
        errors.append(_err("E_PE_RSRC_VS_TOO_LARGE", f"VersionInfo size exceeds max_vs_size={max_vs_size}.", data_size=data_size, max_vs_size=max_vs_size))
        data_size = max_vs_size

    data_off = _rva_to_offset(int(data_rva), sections=sections, file_len=len(data))
    if data_off is None:
        errors.append(_err("E_PE_RSRC_DATA_RVA_UNMAPPABLE", "Resource data RVA could not be mapped.", data_rva=int(data_rva)))
        return res, errors

    if data_off + int(data_size) > len(data):
        errors.append(_err("E_PE_RSRC_DATA_TRUNCATED", "Resource data extends beyond file.", data_off=int(data_off), data_size=int(data_size)))
        data_size = max(0, len(data) - data_off)

    vs_blob = data[data_off : data_off + int(data_size)]
    kv, vi_errs = _parse_versioninfo_strings(vs_blob)
    errors.extend(vi_errs)

    if kv:
        res["present"] = True
        res["version_info"] = kv
    else:
        # Still present if we found the resource, but had no strings
        res["present"] = True
        res["version_info"] = {}

    return res, errors


def parse_pe_bytes(
    data: bytes,
    *,
    max_sections: int = 96,
    max_section_entropy_bytes: int = 10_000_000,
) -> PeParseResult:
    errors: List[Dict[str, Any]] = []

    if len(data) < 64:
        return PeParseResult(present=False, pe=None, errors=[])

    if data[:2] != IMAGE_DOS_SIGNATURE:
        return PeParseResult(present=False, pe=None, errors=[])

    e_lfanew = _u32(data, 0x3C)
    if e_lfanew is None:
        return PeParseResult(present=True, pe=None, errors=[_err("E_PE_DOS_TRUNCATED", "DOS header truncated; missing e_lfanew.")])

    if e_lfanew >= len(data) or e_lfanew < 0:
        return PeParseResult(present=True, pe=None, errors=[_err("E_PE_E_LFANEW_OOB", "e_lfanew points outside file.", e_lfanew=e_lfanew)])

    sig = _read_bytes(data, e_lfanew, 4)
    if sig != IMAGE_NT_SIGNATURE:
        return PeParseResult(present=True, pe=None, errors=[_err("E_PE_BAD_NT_SIGNATURE", "Missing PE\\0\\0 signature.", e_lfanew=e_lfanew)])

    coff_off = e_lfanew + 4
    if coff_off + 20 > len(data):
        return PeParseResult(present=True, pe=None, errors=[_err("E_PE_COFF_TRUNCATED", "COFF header truncated.", coff_off=coff_off)])

    machine = _u16(data, coff_off + 0)
    number_of_sections = _u16(data, coff_off + 2)
    time_date_stamp = _u32(data, coff_off + 4)
    size_of_optional_header = _u16(data, coff_off + 16)
    characteristics = _u16(data, coff_off + 18)

    if machine is None or number_of_sections is None or time_date_stamp is None or size_of_optional_header is None or characteristics is None:
        return PeParseResult(present=True, pe=None, errors=[_err("E_PE_COFF_READ_FAILED", "Failed reading COFF header fields.")])

    is_dll = bool(characteristics & IMAGE_FILE_DLL)

    opt_off = coff_off + 20
    if opt_off + size_of_optional_header > len(data):
        errors.append(
            _err(
                "E_PE_OPT_TRUNCATED",
                "Optional header truncated or size exceeds file.",
                opt_off=opt_off,
                size_of_optional_header=size_of_optional_header,
            )
        )
        size_of_optional_header = max(0, min(size_of_optional_header, len(data) - opt_off))

    opt_magic = _u16(data, opt_off)
    if opt_magic not in (PE32_MAGIC, PE32P_MAGIC):
        errors.append(_err("E_PE_OPT_BAD_MAGIC", "Optional header magic not PE32/PE32+.", opt_magic=opt_magic))

    is_pe32_plus = opt_magic == PE32P_MAGIC

    address_of_entry_point = _u32(data, opt_off + 0x10)
    image_base = _u64(data, opt_off + 0x18) if is_pe32_plus else _u32(data, opt_off + 0x1C)
    subsystem = _u16(data, opt_off + 0x44)
    dll_characteristics = _u16(data, opt_off + 0x46)
    size_of_image = _u32(data, opt_off + 0x38)

    # Data directories
    num_rva_off = opt_off + (0x6C if is_pe32_plus else 0x5C)
    dd_off = opt_off + (0x70 if is_pe32_plus else 0x60)
    num_rva_and_sizes = _u32(data, num_rva_off) or 0

    export_rva = export_size = 0
    import_rva = import_size = 0
    resource_rva = resource_size = 0
    dd_end = opt_off + size_of_optional_header

    def _dd(idx: int) -> Tuple[int, int]:
        if num_rva_and_sizes >= (idx + 1) and dd_off + (idx + 1) * 8 <= dd_end:
            r = _u32(data, dd_off + idx * 8) or 0
            s = _u32(data, dd_off + idx * 8 + 4) or 0
            return int(r), int(s)
        return 0, 0

    export_rva, export_size = _dd(DIR_EXPORT)
    import_rva, import_size = _dd(DIR_IMPORT)
    resource_rva, resource_size = _dd(DIR_RESOURCE)
    security_rva, security_size = _dd(DIR_SECURITY)

    sect_off = opt_off + size_of_optional_header
    if sect_off > len(data):
        errors.append(_err("E_PE_SECTION_TABLE_OOB", "Section table offset outside file.", sect_off=sect_off))
        sect_off = len(data)

    if number_of_sections > max_sections:
        errors.append(
            _err(
                "E_PE_SECTION_COUNT_CLAMPED",
                f"Section count too large; clamped to max_sections={max_sections}.",
                number_of_sections=number_of_sections,
                max_sections=max_sections,
            )
        )
        num_sections = max_sections
    else:
        num_sections = number_of_sections

    sections: List[Dict[str, Any]] = []
    for i in range(num_sections):
        sh_off = sect_off + i * 40
        if sh_off + 40 > len(data):
            errors.append(_err("E_PE_SECTION_HEADER_TRUNCATED", "Section header truncated.", section_index=i, sh_off=sh_off))
            break

        name_b = _read_bytes(data, sh_off + 0, 8) or b""
        name = _safe_ascii(name_b)
        virtual_size = _u32(data, sh_off + 8) or 0
        virtual_address = _u32(data, sh_off + 12) or 0
        size_of_raw_data = _u32(data, sh_off + 16) or 0
        ptr_raw = _u32(data, sh_off + 20) or 0
        sect_chars = _u32(data, sh_off + 36) or 0

        entropy = None
        if size_of_raw_data and ptr_raw:
            raw_max = min(size_of_raw_data, max_section_entropy_bytes)
            raw_blob = _read_bytes(data, ptr_raw, raw_max) or b""
            entropy = round(_shannon_entropy(raw_blob), 6)

        sections.append(
            {
                "name": name,
                "virtual_size": int(virtual_size),
                "virtual_address": int(virtual_address),
                "raw_size": int(size_of_raw_data),
                "raw_ptr": int(ptr_raw),
                "characteristics": int(sect_chars),
                "entropy": entropy,
                "entropy_bytes_used": int(min(size_of_raw_data, max_section_entropy_bytes)) if (size_of_raw_data and ptr_raw) else 0,
            }
        )

    pe: Dict[str, Any] = {
        "present": True,
        "dos": {"e_lfanew": int(e_lfanew)},
        "nt": {"signature": "PE\\0\\0"},
        "coff": {
            "machine": int(machine),
            "number_of_sections": int(number_of_sections),
            "time_date_stamp": int(time_date_stamp),
            "characteristics": int(characteristics),
            "is_dll": bool(is_dll),
        },
        "optional": {
            "magic": int(opt_magic) if opt_magic is not None else None,
            "is_pe32_plus": bool(is_pe32_plus),
            "address_of_entry_point": int(address_of_entry_point) if address_of_entry_point is not None else None,
            "image_base": int(image_base) if image_base is not None else None,
            "subsystem": int(subsystem) if subsystem is not None else None,
            "dll_characteristics": int(dll_characteristics) if dll_characteristics is not None else None,
            "size_of_image": int(size_of_image) if size_of_image is not None else None,
            "data_directories": {
                "number_of_rva_and_sizes": int(num_rva_and_sizes),
                "export_table_rva": int(export_rva),
                "export_table_size": int(export_size),
                "import_table_rva": int(import_rva),
                "import_table_size": int(import_size),
                "resource_table_rva": int(resource_rva),
                "resource_table_size": int(resource_size),
                "security_table_offset": int(security_rva),
                "security_table_size": int(security_size),
            },

        },
        "sections": sections,
        "section_count_parsed": len(sections),
        "imports": [],
        "exports": {"present": False, "dll_name": None, "ordinal_base": 0, "function_count": 0, "name_count": 0, "names": [], "ordinals": []},
        "resources": {"present": False, "version_info": {}},
    }

    if import_rva and import_size:
        imps, imp_errs = _parse_imports(
            data,
            is_pe32_plus=is_pe32_plus,
            sections=sections,
            import_rva=int(import_rva),
            import_size=int(import_size),
        )
        pe["imports"] = imps
        errors.extend(imp_errs)

    if export_rva and export_size:
        exps, exp_errs = _parse_exports(
            data,
            sections=sections,
            export_rva=int(export_rva),
            export_size=int(export_size),
        )
        pe["exports"] = exps
        errors.extend(exp_errs)
    if resource_rva and resource_size:
        rsrc, rsrc_errs = _parse_resources_versioninfo(
            data,
            sections=sections,
            resource_rva=int(resource_rva),
            resource_size=int(resource_size),
        )
        pe["resources"] = rsrc
        errors.extend(rsrc_errs)

        # --- Phase 1: derived heuristics (must never crash parsing) ---
    try:
        from aegis.pe_heuristics import compute_pe_heuristics
        pe["heuristics"] = compute_pe_heuristics(pe, data)
    except Exception as e:
        errors.append(_err("E_PE_HEURISTICS_FAILED", f"Failed to compute PE heuristics: {type(e).__name__}"))

    return PeParseResult(present=True, pe=pe, errors=errors)
