from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional

# Conservative list: common packer-ish / abnormal section names.
# (Heuristic indicator only; not a verdict.)
_SUSPICIOUS_SECTION_NAMES = {
    "UPX0",
    "UPX1",
    "UPX2",
    ".UPX",
    ".ASPACK",
    ".PACK",
    ".MPRESS",
    ".PETITE",
    ".BOOM",
    "FSG!",
    "MEW",
}


def _normalize_section_name(name: str) -> str:
    return (name or "").strip()


def entrypoint_section_name(address_of_entry_point_rva: Optional[int], sections: List[Dict[str, Any]]) -> Optional[str]:
    """
    Return the section name that contains AddressOfEntryPoint RVA.
    Deterministic: first match in section order.
    """
    if address_of_entry_point_rva is None:
        return None
    rva = int(address_of_entry_point_rva)
    if rva <= 0:
        return None

    for s in sections:
        va = int(s.get("virtual_address", 0) or 0)
        vs = int(s.get("virtual_size", 0) or 0)
        raw_size = int(s.get("raw_size", 0) or 0)
        span = max(vs, raw_size)
        if span <= 0:
            continue
        if va <= rva < va + span:
            return _normalize_section_name(str(s.get("name", "")))
    return None


def high_entropy_sections(sections: List[Dict[str, Any]], *, threshold: float = 7.2) -> List[str]:
    """
    Return list of section names with entropy > threshold.
    Deterministic: preserve original section order.
    """
    out: List[str] = []
    for s in sections:
        ent = s.get("entropy", None)
        if ent is None:
            continue
        try:
            if float(ent) > float(threshold):
                out.append(_normalize_section_name(str(s.get("name", ""))))
        except Exception:
            continue
    return out


def suspicious_section_names(sections: List[Dict[str, Any]]) -> List[str]:
    """
    Return section names that match a conservative suspicious-name set.
    Deterministic: preserve original section order and unique.
    """
    out: List[str] = []
    seen = set()

    for s in sections:
        name = _normalize_section_name(str(s.get("name", "")))
        if not name:
            continue
        key = name.upper()
        if key in _SUSPICIOUS_SECTION_NAMES and key not in seen:
            seen.add(key)
            out.append(name)
    return out


def security_directory_listed(optional_data_dirs: Dict[str, Any]) -> bool:
    """
    Presence-only check for Security Directory (Authenticode).
    NOTE: This directory uses FILE OFFSET + SIZE (not RVA).
    """
    size = int(optional_data_dirs.get("security_table_size", 0) or 0)
    off = int(optional_data_dirs.get("security_table_offset", 0) or 0)
    return size > 0 and off > 0


def security_blob_readable(optional_data_dirs: Dict[str, Any], data: Optional[bytes]) -> Optional[bool]:
    """
    Checks if the Security Directory blob is readable within file bounds.
    Returns:
      - True: listed and looks readable
      - False: listed but invalid/out-of-bounds/truncated
      - None: not listed or no bytes provided
    """
    if data is None:
        return None

    size = int(optional_data_dirs.get("security_table_size", 0) or 0)
    off = int(optional_data_dirs.get("security_table_offset", 0) or 0)

    if size <= 0 or off <= 0:
        return None

    if off + size > len(data):
        return False

    # Minimal WIN_CERTIFICATE header is 8 bytes
    if size < 8:
        return False

    dw_len = int.from_bytes(data[off : off + 4], "little", signed=False)
    if dw_len < 8 or dw_len > size:
        return False

    return True


def imports_fingerprint_sha256(imports_list: List[Dict[str, Any]]) -> str:
    """
    Deterministic import fingerprint (NOT classic imphash).
    Canonical form:
      - dll names lowercased
      - function names lowercased
      - ordinals included as "ord:<n>"
      - per-dll lines sorted by dll (your parser already sorts, but we enforce)
    Returns sha256(hex) of the canonical text.
    """
    lines: List[str] = []

    # sort defensively
    imports_sorted = sorted(imports_list or [], key=lambda x: str((x or {}).get("dll", "")).lower())

    for imp in imports_sorted:
        if not isinstance(imp, dict):
            continue
        dll = str(imp.get("dll", "") or "").strip().lower()
        funcs_raw = imp.get("functions", []) or []
        ords_raw = imp.get("ordinals", []) or []

        funcs = sorted({str(f).strip().lower() for f in funcs_raw if f is not None and str(f).strip()})
        ords = sorted({int(o) for o in ords_raw if isinstance(o, int) or (isinstance(o, str) and o.isdigit())})

        items: List[str] = []
        items.extend(funcs)
        items.extend([f"ord:{o}" for o in ords])

        line = f"{dll}:{','.join(items)}"
        lines.append(line)

    canonical = "\n".join(lines)
    return hashlib.sha256(canonical.encode("utf-8", errors="strict")).hexdigest()


def compute_pe_heuristics(pe: Dict[str, Any], data: Optional[bytes] = None) -> Dict[str, Any]:
    """
    Compute derived-only heuristic fields from parsed PE dict.
    Safe-by-default: no execution, no disk I/O.
    """
    sections = pe.get("sections", []) or []
    imports_list = pe.get("imports", []) or []
    optional = pe.get("optional", {}) or {}
    dd = (optional.get("data_directories", {}) or {}) if isinstance(optional, dict) else {}

    aep = optional.get("address_of_entry_point", None) if isinstance(optional, dict) else None

    ep_sec = entrypoint_section_name(aep, sections)
    high_ent = high_entropy_sections(sections, threshold=7.2)
    susp_names = suspicious_section_names(sections)

    sec_listed = security_directory_listed(dd)
    sec_readable = security_blob_readable(dd, data)

    imp_fp = imports_fingerprint_sha256(imports_list)

    flags: List[str] = []
    if ep_sec:
        flags.append("entrypoint_section_resolved")
    if high_ent:
        flags.append("high_entropy_sections_present")
    if susp_names:
        flags.append("suspicious_section_names_present")
    if sec_listed:
        flags.append("security_directory_listed")
        if sec_readable is True:
            flags.append("security_blob_readable")
        elif sec_readable is False:
            flags.append("security_blob_unreadable")

    # IMPORTANT: Keep legacy + phase-1 keys both present.
    return {
        "entrypoint_section": ep_sec,
        "high_entropy_sections": high_ent,
        "high_entropy_threshold": 7.2,
        "suspicious_section_names": susp_names,

        # Legacy key expected by tests
        "security_directory_present": bool(sec_listed),

        # Phase 1 keys expected by tests
        "security_directory_listed": bool(sec_listed),
        "security_blob_readable": sec_readable,
        "imports_fingerprint_sha256": imp_fp,

        "flags": flags,
    }
