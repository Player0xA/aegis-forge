from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from aegis.archive import (
    list_rar_members_via_7z,
    list_zip_members,
    read_rar_member_bytes_via_7z,
    read_zip_member_bytes,
    read_zip_member_bytes_via_7z,
)
from aegis.extract_iocs import extract_iocs_from_texts
from aegis.extract_strings import extract_strings
from aegis.model import AnalyzedItem, Provenance
from aegis.pe import parse_pe_bytes


def file_hashes(path: Path) -> tuple[str, str]:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            sha256.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), md5.hexdigest()


def classify_basic(path: Path) -> str:
    n = path.name.lower()
    if n.endswith((".rar",)):
        return "rar"
    if n.endswith((".zip",)):
        return "zip"
    if n.endswith((".exe", ".dll", ".sys")):
        return "pe"
    return "unknown"


@dataclass(frozen=True)
class ScanLimits:
    max_input_bytes: int = 20_000_000

    archive_max_members_list: int = 5000
    archive_max_members_scan: int = 25
    archive_max_member_bytes: int = 20_000_000
    archive_max_decompressed_ratio: float = 100.0  # e.g. 1MB -> 100MB is ok
    archive_max_cumulative_bytes: int = 100_000_000

    subprocess_timeout: float = 30.0  # seconds for 7z extraction
    strings_min_len: int = 4
    strings_max_strings: int = 2000
    strings_max_total_bytes: int = 200_000
    iocs_max_each: int = 500

    # PE parsing bounds
    pe_max_sections: int = 96
    pe_max_section_entropy_bytes: int = 10_000_000


def read_file_bytes(path: Path, *, max_bytes: int) -> tuple[bytes, bool]:
    with path.open("rb") as f:
        data = f.read(max_bytes + 1)
    if len(data) > max_bytes:
        return data[:max_bytes], True
    return data, False


def scan_bytes_basic(data: bytes, *, limits: ScanLimits = ScanLimits()) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Returns (findings, errors).
    - findings are deterministic extracted facts
    - errors are structured error objects
    """
    errors: List[Dict[str, Any]] = []

    strings_res = extract_strings(
        data,
        min_len=limits.strings_min_len,
        max_strings=limits.strings_max_strings,
        max_total_bytes=limits.strings_max_total_bytes,
        enable_ascii=True,
        enable_utf16le=True,
    )

    all_texts: List[str] = strings_res.ascii + strings_res.utf16le
    iocs = extract_iocs_from_texts(all_texts, max_each=limits.iocs_max_each)

    findings: Dict[str, Any] = {
        "strings": {
            "ascii": strings_res.ascii,
            "utf16le": strings_res.utf16le,
            "truncated": bool(strings_res.truncated),
        },
        "iocs": {
            "urls": iocs.urls,
            "ipv4": iocs.ipv4,
            "domains": iocs.domains,
        },
    }

    # PE parse (bytes-based)
    pe_res = parse_pe_bytes(
        data,
        max_sections=limits.pe_max_sections,
        max_section_entropy_bytes=limits.pe_max_section_entropy_bytes,
    )
    if pe_res.present and pe_res.pe is not None:
        findings["pe"] = pe_res.pe
    if pe_res.errors:
        errors.extend(pe_res.errors)

    return findings, errors


def _hash_bytes(data: bytes) -> Dict[str, str]:
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
    }


def _try_zip_member_with_passwords(
    archive_path: Path,
    member_path: str,
    *,
    max_bytes: int,
    passwords: List[str],
    timeout: float = 30.0,
) -> Tuple[bytes, bool, List[Dict[str, Any]], Dict[str, Any]]:
    """
    Returns (data, truncated, errors, provenance)
    provenance is factual: backend used, AES detected, encryption handling.
    """
    provenance: Dict[str, Any] = {
        "extraction_backend": None,
        "zip_aes_detected": False,
        "encryption_handled": False,
    }

    # First attempt without password (works for unencrypted members)
    data, truncated, errs = read_zip_member_bytes(archive_path, member_path, max_bytes=max_bytes, password=None)
    if not errs:
        provenance["extraction_backend"] = "zipfile"
        provenance["encryption_handled"] = False
        return data, truncated, [], provenance

    # If AES encrypted, zipfile cannot decrypt; use 7z backend
    aes_needed = any(e.get("code") == "E_ZIP_AES_UNSUPPORTED_BY_PYZIPFILE" for e in errs)
    if aes_needed:
        provenance["zip_aes_detected"] = True
        provenance["extraction_backend"] = "7z"

        if not passwords:
            return b"", False, [
                {
                    "code": "E_ARCHIVE_ENCRYPTED_PASSWORD_REQUIRED",
                    "message": "AES-encrypted ZIP member detected; password required to proceed.",
                    "archive_path": str(archive_path),
                    "member_path": member_path,
                }
            ], provenance

        for pw in passwords:
            data2, trunc2, errs2 = read_zip_member_bytes_via_7z(
                archive_path, member_path, max_bytes=max_bytes, password=pw, timeout=timeout
            )
            if not errs2:
                provenance["encryption_handled"] = True
                return data2, trunc2, [], provenance

        return b"", False, [
            {
                "code": "E_ARCHIVE_ENCRYPTED_NEEDS_PASSWORD",
                "message": "AES-encrypted ZIP member requires a password; none of the provided passwords worked (7z backend).",
                "archive_path": str(archive_path),
                "member_path": member_path,
            }
        ], provenance

    # Otherwise, treat as normal encrypted ZipCrypto flow
    pw_needed = any(e.get("code") in ("E_ZIP_PASSWORD_REQUIRED", "E_ZIP_BAD_PASSWORD") for e in errs)
    if not pw_needed:
        # Could be corruption / unreadable for other reasons
        provenance["extraction_backend"] = "zipfile"
        return b"", False, errs, provenance

    for pw in passwords:
        data, truncated, errs2 = read_zip_member_bytes(archive_path, member_path, max_bytes=max_bytes, password=pw)
        if not errs2:
            provenance["extraction_backend"] = "zipfile"
            provenance["encryption_handled"] = True
            return data, truncated, [], provenance

    provenance["extraction_backend"] = "zipfile"
    return b"", False, [
        {
            "code": "E_ARCHIVE_ENCRYPTED_NEEDS_PASSWORD",
            "message": "Encrypted ZIP member requires a password; none of the provided passwords worked.",
            "archive_path": str(archive_path),
            "member_path": member_path,
        }
    ], provenance


def _try_rar_member_with_passwords(
    archive_path: Path,
    member_path: str,
    *,
    max_bytes: int,
    passwords: List[str],
    timeout: float = 30.0,
) -> Tuple[bytes, bool, List[Dict[str, Any]]]:
    data, truncated, errs = read_rar_member_bytes_via_7z(
        archive_path, member_path, max_bytes=max_bytes, password=None, timeout=timeout
    )
    if not errs:
        return data, truncated, []

    pw_needed = any(e.get("code") == "E_RAR_ENCRYPTED_OR_PASSWORD_REQUIRED" for e in errs)
    if not pw_needed:
        return b"", False, errs

    for pw in passwords:
        data, truncated, errs2 = read_rar_member_bytes_via_7z(
            archive_path, member_path, max_bytes=max_bytes, password=pw, timeout=timeout
        )
        if not errs2:
            return data, truncated, []
    return b"", False, [
        {
            "code": "E_ARCHIVE_ENCRYPTED_NEEDS_PASSWORD",
            "message": "Encrypted RAR member requires a password; none of the provided passwords worked.",
            "archive_path": str(archive_path),
            "member_path": member_path,
        }
    ]


def scan_archive_zip(
    path: Path,
    *,
    limits: ScanLimits,
    passwords: Optional[List[str]] = None,
    non_interactive: bool = False,
    prompt_confirm: Optional[callable] = None,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
    passwords = passwords or []
    errors: List[Dict[str, Any]] = []

    members, list_errors = list_zip_members(path)
    errors.extend(list_errors)

    members = sorted(members, key=lambda m: m.path)[: limits.archive_max_members_list]
    any_encrypted = any(m.encrypted for m in members if not m.is_dir)

    if any_encrypted and not passwords:
        if non_interactive:
            errors.append(
                {
                    "code": "E_ARCHIVE_ENCRYPTED_MEMBERS_SKIPPED",
                    "message": "Archive contains encrypted members; skipping them in non-interactive mode (no passwords provided).",
                    "archive_path": str(path),
                }
            )
        else:
            if prompt_confirm is None:
                allow = True
            else:
                allow = bool(
                    prompt_confirm(
                        f"Archive '{path.name}' contains encrypted members. Scan only unencrypted ones?",
                        default=True,
                    )
                )
            if not allow:
                errors.append(
                    {
                        "code": "E_INTERACTIVE_DECLINED",
                        "message": "User declined to continue after encrypted members were detected.",
                        "archive_path": str(path),
                    }
                )
                return (
                    {
                        "archive": {
                            "type": "zip",
                            "member_count": len(members),
                            "scanned_member_count": 0,
                            "members_scanned": [],
                        },
                        "iocs": {"urls": [], "ipv4": [], "domains": []},
                    },
                    [],
                    errors,
                )

    scanned: List[Dict[str, Any]] = []
    analyzed_items: List[AnalyzedItem] = []
    agg_urls, agg_ipv4, agg_domains = set(), set(), set()
    cumulative_bytes = 0

    count_scanned = 0
    for m in members:
        if m.is_dir:
            continue
        if count_scanned >= limits.archive_max_members_scan:
            break
        if cumulative_bytes >= limits.archive_max_cumulative_bytes:
            errors.append(
                {
                    "code": "E_ARCHIVE_CUMULATIVE_LIMIT_REACHED",
                    "message": f"Cumulative output bytes limit reached ({limits.archive_max_cumulative_bytes}). Skipping remaining members.",
                    "archive_path": str(path),
                }
            )
            break

        # Check compression ratio if psize is known
        if m.compressed_size and m.compressed_size > 0:
            ratio = m.size / m.compressed_size
            if ratio > limits.archive_max_decompressed_ratio:
                errors.append(
                    {
                        "code": "E_ARCHIVE_MEMBER_SKIPPED_RATIO",
                        "message": f"Member skipped due to high compression ratio ({ratio:.2f} > {limits.archive_max_decompressed_ratio}). Potential zip bomb.",
                        "archive_path": str(path),
                        "member_path": m.path,
                    }
                )
                continue

        if m.encrypted and not passwords and non_interactive:
            errors.append(
                {
                    "code": "E_ARCHIVE_MEMBER_SKIPPED_ENCRYPTED",
                    "message": "Encrypted member skipped (no password provided in non-interactive mode).",
                    "archive_path": str(path),
                    "member_path": m.path,
                }
            )
            continue

        data, truncated, read_errors, prov = _try_zip_member_with_passwords(
            path,
            m.path,
            max_bytes=limits.archive_max_member_bytes,
            passwords=passwords,
            timeout=limits.subprocess_timeout,
        )
        if read_errors:
            errors.extend(read_errors)
            continue

        cumulative_bytes += len(data)

        member_hashes = _hash_bytes(data)
        member_findings, member_errs = scan_bytes_basic(data, limits=limits)

        errors.extend(member_errs)

        agg_urls.update(member_findings["iocs"]["urls"])
        agg_ipv4.update(member_findings["iocs"]["ipv4"])
        agg_domains.update(member_findings["iocs"]["domains"])

        scanned.append(
            {
                "member_path": m.path,
                "size": m.size,
                "compressed_size": m.compressed_size,
                "encrypted": m.encrypted,
                "bytes_read": len(data),
                "truncated": bool(truncated),
                "hashes": member_hashes,
                "provenance": {
                    "extraction_backend": prov.get("extraction_backend"),
                    "zip_aes_detected": bool(prov.get("zip_aes_detected", False)),
                    "encryption_expected": bool(m.encrypted),
                    "encryption_handled": bool(prov.get("encryption_handled", False)),
                },
                # keep member findings lightweight but include PE presence summary
                "findings": {
                    "ioc_counts": {
                        "urls": len(member_findings["iocs"]["urls"]),
                        "ipv4": len(member_findings["iocs"]["ipv4"]),
                        "domains": len(member_findings["iocs"]["domains"]),
                    },
                    "pe_present": bool(member_findings.get("pe", {}).get("present", False)),
                    "pe_section_count": int(member_findings.get("pe", {}).get("section_count_parsed", 0) or 0),
                },
            }
        )

        analyzed_items.append(
            AnalyzedItem(
                path=m.path,
                bytes_read=len(data),
                hashes=member_hashes,
                truncated=bool(truncated),
                format="pe" if member_findings.get("pe", {}).get("present") else "unknown",
                provenance=Provenance(
                    data_source=prov.get("extraction_backend") or "zipfile",
                    encrypted_detected=bool(prov.get("zip_aes_detected", False)) or m.encrypted,
                    encryption_handled=bool(prov.get("encryption_handled", False)),
                ),
            )
        )

        count_scanned += 1
        if truncated:
            errors.append(
                {
                    "code": "E_ARCHIVE_MEMBER_TRUNCATED",
                    "message": f"Member bytes truncated to max_member_bytes={limits.archive_max_member_bytes}.",
                    "archive_path": str(path),
                    "member_path": m.path,
                }
            )

    if not scanned and members:
        errors.append(
            {
                "code": "E_ARCHIVE_NO_MEMBERS_SCANNED",
                "message": "No archive members were successfully scanned (all skipped or failed).",
                "archive_path": str(path),
            }
        )

    findings = {
        "archive": {
            "type": "zip",
            "member_count": len(members),
            "scanned_member_count": len(scanned),
            "members_scanned": scanned,
        },
        "iocs": {
            "urls": sorted(agg_urls),
            "ipv4": sorted(agg_ipv4),
            "domains": sorted(agg_domains),
        },
    }
    return findings, analyzed_items, errors


def scan_archive_rar(
    path: Path,
    *,
    limits: ScanLimits,
    passwords: Optional[List[str]] = None,
    non_interactive: bool = False,
    prompt_confirm: Optional[callable] = None,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
    passwords = passwords or []
    errors: List[Dict[str, Any]] = []

    members, list_errors = list_rar_members_via_7z(path)
    errors.extend(list_errors)

    members = sorted(members, key=lambda m: m.path)[: limits.archive_max_members_list]
    any_encrypted = any(m.encrypted for m in members if not m.is_dir)

    if any_encrypted and not passwords:
        if non_interactive:
            errors.append(
                {
                    "code": "E_ARCHIVE_ENCRYPTED_MEMBERS_SKIPPED",
                    "message": "Archive contains encrypted members; skipping them in non-interactive mode (no passwords provided).",
                    "archive_path": str(path),
                }
            )
        else:
            if prompt_confirm is None:
                allow = True
            else:
                allow = bool(
                    prompt_confirm(
                        f"Archive '{path.name}' contains encrypted members. Scan only unencrypted ones?",
                        default=True,
                    )
                )
            if not allow:
                errors.append(
                    {
                        "code": "E_INTERACTIVE_DECLINED",
                        "message": "User declined to continue after encrypted members were detected.",
                        "archive_path": str(path),
                    }
                )
                return (
                    {
                        "archive": {
                            "type": "rar",
                            "member_count": len(members),
                            "scanned_member_count": 0,
                            "members_scanned": [],
                        },
                        "iocs": {"urls": [], "ipv4": [], "domains": []},
                    },
                    [],
                    errors,
                )

    scanned: List[Dict[str, Any]] = []
    analyzed_items: List[AnalyzedItem] = []
    agg_urls, agg_ipv4, agg_domains = set(), set(), set()
    cumulative_bytes = 0

    count_scanned = 0
    for m in members:
        if m.is_dir:
            continue
        if count_scanned >= limits.archive_max_members_scan:
            break
        if cumulative_bytes >= limits.archive_max_cumulative_bytes:
            errors.append(
                {
                    "code": "E_ARCHIVE_CUMULATIVE_LIMIT_REACHED",
                    "message": f"Cumulative output bytes limit reached ({limits.archive_max_cumulative_bytes}). Skipping remaining members.",
                    "archive_path": str(path),
                }
            )
            break

        if m.compressed_size and m.compressed_size > 0:
            ratio = m.size / m.compressed_size
            if ratio > limits.archive_max_decompressed_ratio:
                errors.append(
                    {
                        "code": "E_ARCHIVE_MEMBER_SKIPPED_RATIO",
                        "message": f"Member skipped due to high compression ratio ({ratio:.2f} > {limits.archive_max_decompressed_ratio}). Potential zip bomb.",
                        "archive_path": str(path),
                        "member_path": m.path,
                    }
                )
                continue

        if m.encrypted and not passwords and non_interactive:
            errors.append(
                {
                    "code": "E_ARCHIVE_MEMBER_SKIPPED_ENCRYPTED",
                    "message": "Encrypted member skipped (no password provided in non-interactive mode).",
                    "archive_path": str(path),
                    "member_path": m.path,
                }
            )
            continue

        data, truncated, read_errors = _try_rar_member_with_passwords(
            path,
            m.path,
            max_bytes=limits.archive_max_member_bytes,
            passwords=passwords,
            timeout=limits.subprocess_timeout,
        )
        if read_errors:
            errors.extend(read_errors)
            continue

        cumulative_bytes += len(data)

        member_hashes = _hash_bytes(data)
        member_findings, member_errs = scan_bytes_basic(data, limits=limits)
        errors.extend(member_errs)

        agg_urls.update(member_findings["iocs"]["urls"])
        agg_ipv4.update(member_findings["iocs"]["ipv4"])
        agg_domains.update(member_findings["iocs"]["domains"])

        scanned.append(
            {
                "member_path": m.path,
                "size": m.size,
                "compressed_size": m.compressed_size,
                "encrypted": m.encrypted,
                "bytes_read": len(data),
                "truncated": bool(truncated),
                "hashes": member_hashes,
                "findings": {
                    "ioc_counts": {
                        "urls": len(member_findings["iocs"]["urls"]),
                        "ipv4": len(member_findings["iocs"]["ipv4"]),
                        "domains": len(member_findings["iocs"]["domains"]),
                    },
                    "pe_present": bool(member_findings.get("pe", {}).get("present", False)),
                    "pe_section_count": int(member_findings.get("pe", {}).get("section_count_parsed", 0) or 0),
                },
            }
        )

        analyzed_items.append(
            AnalyzedItem(
                path=m.path,
                bytes_read=len(data),
                hashes=member_hashes,
                truncated=bool(truncated),
                format="pe" if member_findings.get("pe", {}).get("present") else "unknown",
                provenance=Provenance(
                    data_source="7z",
                    encrypted_detected=m.encrypted,
                    encryption_handled=bool(len(data) > 0),
                ),
            )
        )

        count_scanned += 1
        if truncated:
            errors.append(
                {
                    "code": "E_ARCHIVE_MEMBER_TRUNCATED",
                    "message": f"Member bytes truncated to max_member_bytes={limits.archive_max_member_bytes}.",
                    "archive_path": str(path),
                    "member_path": m.path,
                }
            )

    if not scanned and members:
        errors.append(
            {
                "code": "E_ARCHIVE_NO_MEMBERS_SCANNED",
                "message": "No archive members were successfully scanned (all skipped or failed).",
                "archive_path": str(path),
            }
        )

    findings = {
        "archive": {
            "type": "rar",
            "member_count": len(members),
            "scanned_member_count": len(scanned),
            "members_scanned": scanned,
        },
        "iocs": {
            "urls": sorted(agg_urls),
            "ipv4": sorted(agg_ipv4),
            "domains": sorted(agg_domains),
        },
    }
    return findings, analyzed_items, errors


def scan_path_basic(
    path: Path,
    *,
    limits: ScanLimits = ScanLimits(),
    passwords: Optional[List[str]] = None,
    non_interactive: bool = False,
    prompt_confirm: Optional[callable] = None,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
    ftype = classify_basic(path)

    if ftype == "zip":
        return scan_archive_zip(
            path,
            limits=limits,
            passwords=passwords,
            non_interactive=non_interactive,
            prompt_confirm=prompt_confirm,
        )
    if ftype == "rar":
        return scan_archive_rar(
            path,
            limits=limits,
            passwords=passwords,
            non_interactive=non_interactive,
            prompt_confirm=prompt_confirm,
        )

    errors: List[Dict[str, Any]] = []
    data, truncated = read_file_bytes(path, max_bytes=limits.max_input_bytes)
    if truncated:
        errors.append(
            {
                "code": "E_INPUT_TRUNCATED",
                "message": f"Input exceeded max_input_bytes={limits.max_input_bytes}; read truncated.",
                "path": str(path),
            }
        )

    findings, byte_errs = scan_bytes_basic(data, limits=limits)
    errors.extend(byte_errs)

    findings["input_read"] = {
        "max_input_bytes": limits.max_input_bytes,
        "truncated": bool(truncated),
        "bytes_read": len(data),
    }

    analyzed_items = [
        AnalyzedItem(
            path=path.name,
            bytes_read=len(data),
            hashes=_hash_bytes(data),
            truncated=bool(truncated),
            format="pe" if findings.get("pe", {}).get("present") else "unknown",
            provenance=Provenance(
                data_source="direct",
                encrypted_detected=False,
                encryption_handled=False,
            ),
        )
    ]

    return findings, analyzed_items, errors
