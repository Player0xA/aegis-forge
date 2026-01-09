from __future__ import annotations

import shutil
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class ArchiveMember:
    path: str
    is_dir: bool
    size: int
    compressed_size: Optional[int] = None
    encrypted: Optional[bool] = None


def _is_safe_member_path(member_path: str) -> bool:
    p = Path(member_path)
    if p.is_absolute():
        return False
    if any(part == ".." for part in p.parts):
        return False
    return True


def _which_7z() -> Optional[str]:
    return shutil.which("7z") or shutil.which("7zz")


def list_zip_members(path: Path) -> Tuple[List[ArchiveMember], List[Dict[str, Any]]]:
    errors: List[Dict[str, Any]] = []
    members: List[ArchiveMember] = []
    try:
        with zipfile.ZipFile(path, "r") as zf:
            for info in zf.infolist():
                mpath = info.filename
                if not _is_safe_member_path(mpath):
                    errors.append(
                        {
                            "code": "E_ARCHIVE_MEMBER_UNSAFE_PATH",
                            "message": "Archive member path is unsafe (absolute or traversal).",
                            "archive_path": str(path),
                            "member_path": mpath,
                        }
                    )
                    continue

                members.append(
                    ArchiveMember(
                        path=mpath,
                        is_dir=info.is_dir(),
                        size=int(getattr(info, "file_size", 0) or 0),
                        compressed_size=int(getattr(info, "compress_size", 0) or 0),
                        encrypted=bool(getattr(info, "flag_bits", 0) & 0x1),
                    )
                )
    except zipfile.BadZipFile:
        errors.append(
            {
                "code": "E_ZIP_BAD_FILE",
                "message": "Not a valid ZIP file or ZIP is corrupted.",
                "archive_path": str(path),
            }
        )
    except Exception as e:
        errors.append(
            {
                "code": "E_ZIP_LIST_FAILED",
                "message": f"Failed to list ZIP members: {type(e).__name__}",
                "archive_path": str(path),
            }
        )
    return members, errors


def read_zip_member_bytes(
    path: Path,
    member_path: str,
    *,
    max_bytes: int,
    password: Optional[str] = None,
) -> Tuple[bytes, bool, List[Dict[str, Any]]]:
    errors: List[Dict[str, Any]] = []
    if not _is_safe_member_path(member_path):
        return b"", False, [
            {
                "code": "E_ARCHIVE_MEMBER_UNSAFE_PATH",
                "message": "Archive member path is unsafe (absolute or traversal).",
                "archive_path": str(path),
                "member_path": member_path,
            }
        ]

    pwd_bytes = password.encode("utf-8") if password is not None else None

    try:
        with zipfile.ZipFile(path, "r") as zf:
            # Detect AES encryption early (zipfile can't decrypt it)
            try:
                info = zf.getinfo(member_path)
                if _zipinfo_has_aes_extra(info) and (getattr(info, "flag_bits", 0) & 0x1):
                    return b"", False, [
                        {
                            "code": "E_ZIP_AES_UNSUPPORTED_BY_PYZIPFILE",
                            "message": "ZIP member appears AES-encrypted (0x9901). Python zipfile cannot decrypt; use 7z backend.",
                            "archive_path": str(path),
                            "member_path": member_path,
                        }
                    ]
            except KeyError:
                return b"", False, [
                    {
                        "code": "E_ZIP_MEMBER_NOT_FOUND",
                        "message": "ZIP member not found.",
                        "archive_path": str(path),
                        "member_path": member_path,
                    }
                ]

            with zf.open(member_path, "r", pwd=pwd_bytes) as f:
                data = f.read(max_bytes + 1)
                if len(data) > max_bytes:
                    return data[:max_bytes], True, []
                return data, False, []

    except RuntimeError as e:
        msg = str(e)
        code = "E_ZIP_ENCRYPTED_OR_UNREADABLE"
        if "password required" in msg.lower() or "encrypted" in msg.lower():
            code = "E_ZIP_PASSWORD_REQUIRED"
        if "bad password" in msg.lower():
            code = "E_ZIP_BAD_PASSWORD"
        errors.append(
            {
                "code": code,
                "message": f"ZIP member could not be read: {msg}",
                "archive_path": str(path),
                "member_path": member_path,
            }
        )
    except zipfile.BadZipFile:
        errors.append(
            {
                "code": "E_ZIP_BAD_FILE",
                "message": "Not a valid ZIP file or ZIP is corrupted.",
                "archive_path": str(path),
            }
        )
    except Exception as e:
        errors.append(
            {
                "code": "E_ZIP_EXTRACT_FAILED",
                "message": f"Failed to read ZIP member bytes: {type(e).__name__}",
                "archive_path": str(path),
                "member_path": member_path,
            }
        )

    return b"", False, errors

def list_rar_members_via_7z(path: Path) -> Tuple[List[ArchiveMember], List[Dict[str, Any]]]:
    errors: List[Dict[str, Any]] = []
    members: List[ArchiveMember] = []

    exe = _which_7z()
    if not exe:
        return [], [
            {
                "code": "E_7Z_MISSING",
                "message": "RAR support requires 7z/7zz installed (p7zip).",
                "archive_path": str(path),
            }
        ]

    cmd = [exe, "l", "-slt", str(path)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except Exception as e:
        return [], [
            {
                "code": "E_7Z_EXEC_FAILED",
                "message": f"Failed to execute 7z: {type(e).__name__}",
                "archive_path": str(path),
            }
        ]

    if proc.returncode != 0:
        errors.append(
            {
                "code": "E_RAR_LIST_FAILED",
                "message": "7z failed to list archive.",
                "archive_path": str(path),
                "stderr": (proc.stderr or "")[:1000],
            }
        )
        return [], errors

    cur: Dict[str, str] = {}
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            if "Path" in cur:
                mpath = cur.get("Path", "")
                size = int(cur.get("Size", "0") or "0")
                psize = cur.get("Packed Size")
                enc = cur.get("Encrypted")
                attrs = cur.get("Attributes", "")
                is_dir = "D" in attrs

                if _is_safe_member_path(mpath):
                    members.append(
                        ArchiveMember(
                            path=mpath,
                            is_dir=is_dir,
                            size=size,
                            compressed_size=int(psize) if psize and psize.isdigit() else None,
                            encrypted=True if enc == "+" else False if enc == "-" else None,
                        )
                    )
                else:
                    errors.append(
                        {
                            "code": "E_ARCHIVE_MEMBER_UNSAFE_PATH",
                            "message": "Archive member path is unsafe (absolute or traversal).",
                            "archive_path": str(path),
                            "member_path": mpath,
                        }
                    )
            cur = {}
            continue

        if " = " in line:
            k, v = line.split(" = ", 1)
            cur[k.strip()] = v.strip()

    if "Path" in cur:
        mpath = cur.get("Path", "")
        size = int(cur.get("Size", "0") or "0")
        psize = cur.get("Packed Size")
        enc = cur.get("Encrypted")
        attrs = cur.get("Attributes", "")
        is_dir = "D" in attrs

        if _is_safe_member_path(mpath):
            members.append(
                ArchiveMember(
                    path=mpath,
                    is_dir=is_dir,
                    size=size,
                    compressed_size=int(psize) if psize and psize.isdigit() else None,
                    encrypted=True if enc == "+" else False if enc == "-" else None,
                )
            )
        else:
            errors.append(
                {
                    "code": "E_ARCHIVE_MEMBER_UNSAFE_PATH",
                    "message": "Archive member path is unsafe (absolute or traversal).",
                    "archive_path": str(path),
                    "member_path": mpath,
                }
            )

    return members, errors


def read_rar_member_bytes_via_7z(
    path: Path,
    member_path: str,
    *,
    max_bytes: int,
    password: Optional[str] = None,
) -> Tuple[bytes, bool, List[Dict[str, Any]]]:
    if not _is_safe_member_path(member_path):
        return b"", False, [
            {
                "code": "E_ARCHIVE_MEMBER_UNSAFE_PATH",
                "message": "Archive member path is unsafe (absolute or traversal).",
                "archive_path": str(path),
                "member_path": member_path,
            }
        ]

    exe = _which_7z()
    if not exe:
        return b"", False, [
            {
                "code": "E_7Z_MISSING",
                "message": "RAR support requires 7z/7zz installed (p7zip).",
                "archive_path": str(path),
            }
        ]

    cmd = [exe, "x", "-so", "-y"]
    if password is not None:
        cmd.append(f"-p{password}")
    cmd.extend([str(path), member_path])

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert proc.stdout is not None
        data = proc.stdout.read(max_bytes + 1)
        truncated = len(data) > max_bytes
        if truncated:
            data = data[:max_bytes]

        stderr = (proc.stderr.read() if proc.stderr else b"").decode("utf-8", errors="ignore")
        rc = proc.wait()

        if rc != 0:
            msg = stderr.strip()
            code = "E_RAR_EXTRACT_FAILED"
            if "Wrong password" in msg or "Can not open encrypted archive" in msg or "Encrypted" in msg:
                code = "E_RAR_ENCRYPTED_OR_PASSWORD_REQUIRED"
            return b"", False, [
                {
                    "code": code,
                    "message": "7z failed to extract RAR member to memory.",
                    "archive_path": str(path),
                    "member_path": member_path,
                    "stderr": msg[:1000],
                }
            ]

        return data, truncated, []
    except Exception as e:
        return b"", False, [
            {
                "code": "E_7Z_EXTRACT_EXCEPTION",
                "message": f"Exception while extracting via 7z: {type(e).__name__}",
                "archive_path": str(path),
                "member_path": member_path,
            }
        ]

AES_EXTRA_FIELD_ID = 0x9901

def _zipinfo_has_aes_extra(info: zipfile.ZipInfo) -> bool:
    """
    Detect WinZip AES extra field (0x9901).
    Python zipfile cannot decrypt AES-encrypted ZIP members.
    """
    extra = getattr(info, "extra", b"") or b""
    i = 0
    # extra fields are: [header_id(2)][data_size(2)][data...]
    while i + 4 <= len(extra):
        header_id = int.from_bytes(extra[i : i + 2], "little")
        data_size = int.from_bytes(extra[i + 2 : i + 4], "little")
        i += 4
        if header_id == AES_EXTRA_FIELD_ID:
            return True
        i += data_size
    return False

def read_zip_member_bytes_via_7z(
    path: Path,
    member_path: str,
    *,
    max_bytes: int,
    password: Optional[str] = None,
) -> Tuple[bytes, bool, List[Dict[str, Any]]]:
    if not _is_safe_member_path(member_path):
        return b"", False, [
            {
                "code": "E_ARCHIVE_MEMBER_UNSAFE_PATH",
                "message": "Archive member path is unsafe (absolute or traversal).",
                "archive_path": str(path),
                "member_path": member_path,
            }
        ]

    exe = _which_7z()
    if not exe:
        return b"", False, [
            {
                "code": "E_7Z_MISSING",
                "message": "Encrypted ZIP (AES) support requires 7z/7zz installed (p7zip).",
                "archive_path": str(path),
            }
        ]

    cmd = [exe, "x", "-so", "-y"]
    if password is not None:
        cmd.append(f"-p{password}")
    cmd.extend([str(path), member_path])

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert proc.stdout is not None
        data = proc.stdout.read(max_bytes + 1)
        truncated = len(data) > max_bytes
        if truncated:
            data = data[:max_bytes]

        stderr = (proc.stderr.read() if proc.stderr else b"").decode("utf-8", errors="ignore")
        rc = proc.wait()

        if rc != 0:
            msg = stderr.strip()
            code = "E_ZIP_EXTRACT_FAILED_7Z"
            # 7z tends to say "Wrong password" when encrypted and wrong pw
            if "Wrong password" in msg or "wrong password" in msg:
                code = "E_ZIP_BAD_PASSWORD"
            elif "Encrypted" in msg or "encrypted" in msg:
                code = "E_ZIP_PASSWORD_REQUIRED"
            return b"", False, [
                {
                    "code": code,
                    "message": "7z failed to extract ZIP member to memory.",
                    "archive_path": str(path),
                    "member_path": member_path,
                    "stderr": msg[:1000],
                }
            ]

        return data, truncated, []
    except Exception as e:
        return b"", False, [
            {
                "code": "E_7Z_EXTRACT_EXCEPTION",
                "message": f"Exception while extracting ZIP via 7z: {type(e).__name__}",
                "archive_path": str(path),
                "member_path": member_path,
            }
        ]
