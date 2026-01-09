from __future__ import annotations

import shutil
from pathlib import Path

from aegis.scanner import scan_path_basic


def test_rar_missing_7z_is_graceful(monkeypatch, tmp_path: Path):
    # Force "7z" to appear missing even if installed on dev machine
    monkeypatch.setattr(shutil, "which", lambda _: None)

    rpath = tmp_path / "sample.rar"
    rpath.write_bytes(b"not a real rar")  # we only test the missing-backend error path

    findings, errors = scan_path_basic(rpath)

    # findings exists but will be sparse; we mainly care about the structured error
    assert isinstance(errors, list)
    assert any(e.get("code") == "E_7Z_MISSING" for e in errors)
