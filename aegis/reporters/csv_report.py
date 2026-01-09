from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Dict


def _get(d: Dict[str, Any], path: str, default):
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def write_summary_csv(path: Path, bundle: Dict[str, Any]) -> None:
    input_obj = bundle.get("input", {}) if isinstance(bundle, dict) else {}

    urls = _get(bundle, "findings.iocs.urls", []) or []
    ipv4 = _get(bundle, "findings.iocs.ipv4", []) or []
    domains = _get(bundle, "findings.iocs.domains", []) or []

    ascii_strings = _get(bundle, "findings.strings.ascii", []) or []
    utf16_strings = _get(bundle, "findings.strings.utf16le", []) or []
    strings_truncated = bool(_get(bundle, "findings.strings.truncated", False))

    arch_type = _get(bundle, "findings.archive.type", "")
    arch_member_count = _get(bundle, "findings.archive.member_count", "")
    arch_scanned_count = _get(bundle, "findings.archive.scanned_member_count", "")

    pe_present = bool(_get(bundle, "findings.pe.present", False))
    pe_machine = _get(bundle, "findings.pe.coff.machine", "")
    pe_sections = _get(bundle, "findings.pe.coff.number_of_sections", "")
    pe_is_dll = bool(_get(bundle, "findings.pe.coff.is_dll", False))
    pe_is_64 = bool(_get(bundle, "findings.pe.optional.is_pe32_plus", False))
    pe_entry = _get(bundle, "findings.pe.optional.address_of_entry_point", "")

    row = {
        "schema_version": bundle.get("schema_version", ""),
        "scan_id": bundle.get("scan_id", ""),
        "timestamp_utc": bundle.get("timestamp_utc", ""),

        "input_path": input_obj.get("input_path", ""),
        "file_type": input_obj.get("file_type", ""),
        "file_size": input_obj.get("file_size", ""),
        "sha256": input_obj.get("sha256", ""),
        "md5": input_obj.get("md5", ""),

        "archive_type": arch_type,
        "archive_member_count": arch_member_count,
        "archive_scanned_member_count": arch_scanned_count,

        "pe_present": "true" if pe_present else "false",
        "pe_machine": pe_machine,
        "pe_sections": pe_sections,
        "pe_is_dll": "true" if pe_is_dll else "false",
        "pe_is_64": "true" if pe_is_64 else "false",
        "pe_entrypoint_rva": pe_entry,

        "ioc_url_count": len(urls),
        "ioc_ipv4_count": len(ipv4),
        "ioc_domain_count": len(domains),

        "strings_ascii_count": len(ascii_strings),
        "strings_utf16le_count": len(utf16_strings),
        "strings_truncated": "true" if strings_truncated else "false",
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(row.keys()))
        writer.writeheader()
        writer.writerow(row)
