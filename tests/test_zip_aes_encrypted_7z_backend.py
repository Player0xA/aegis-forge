from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from aegis.scanner import ScanLimits, scan_path_basic


def test_zip_aes_encrypted_member_can_be_read_via_7z(tmp_path: Path):
    exe = shutil.which("7z") or shutil.which("7zz")
    if not exe:
        # consistent with your RAR missing 7z test philosophy: skip if not present
        return

    # Use the existing benign notepad.exe fixture as payload
    fixture_payload = Path("tests/fixtures/notepad.exe").resolve()
    assert fixture_payload.exists()

    # Create AES-encrypted ZIP
    zpath = tmp_path / "aes.zip"
    subprocess.check_call([exe, "a", "-tzip", "-pinfected", "-mem=AES256", str(zpath), str(fixture_payload)])

    limits = ScanLimits(archive_max_members_scan=5, archive_max_member_bytes=5_000_000)

    findings, items, errors = scan_path_basic(
        zpath,
        limits=limits,
        passwords=["infected"],
        non_interactive=True,
        prompt_confirm=None,
    )

    # Should scan at least 1 member
    assert findings.get("archive", {}).get("scanned_member_count", 0) >= 1

    # Must NOT end with the misleading "needs password" error when password is correct
    codes = [e.get("code") for e in errors]
    assert "E_ARCHIVE_ENCRYPTED_NEEDS_PASSWORD" not in codes
