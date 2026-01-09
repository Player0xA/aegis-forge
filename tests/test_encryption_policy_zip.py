from __future__ import annotations

from pathlib import Path

from aegis.archive import ArchiveMember
from aegis.scanner import ScanLimits, scan_archive_zip


def test_zip_encrypted_non_interactive_requires_password(monkeypatch, tmp_path: Path):
    z = tmp_path / "x.zip"
    z.write_bytes(b"not used")

    def fake_list_zip_members(_):
        return ([ArchiveMember(path="secret.txt", is_dir=False, size=10, compressed_size=5, encrypted=True)], [])

    monkeypatch.setattr("aegis.scanner.list_zip_members", fake_list_zip_members)

    findings, errors = scan_archive_zip(
        z,
        limits=ScanLimits(),
        passwords=[],
        non_interactive=True,
        prompt_confirm=None,
    )

    assert findings["archive"]["type"] == "zip"
    assert any(e.get("code") == "E_ARCHIVE_ENCRYPTED_PASSWORD_REQUIRED" for e in errors)
    assert any(e.get("code") == "E_ARCHIVE_MEMBER_SKIPPED_ENCRYPTED" for e in errors)
