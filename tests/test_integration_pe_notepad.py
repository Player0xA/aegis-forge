from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typer.testing import CliRunner

from aegis.cli import app

runner = CliRunner()


def _latest_zip(outdir: Path) -> Path:
    zips = sorted(outdir.glob("*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
    assert zips, f"No zip bundles found in {outdir}"
    return zips[0]


def test_scan_notepad_pe_bundle_fields(tmp_path: Path):
    # Arrange
    fixture = Path("tests/fixtures/notepad.exe")
    assert fixture.exists(), "Missing fixture tests/fixtures/notepad.exe"

    # Act
    result = runner.invoke(app, ["scan", str(fixture), "--outdir", str(tmp_path)])
    assert result.exit_code == 0, result.output

    bundle_zip = _latest_zip(tmp_path)

    with zipfile.ZipFile(bundle_zip, "r") as zf:
        bundle = json.loads(zf.read("bundle.json").decode("utf-8"))

    pe = bundle["findings"]["pe"]

    # Assert (these match your jq output)
    assert pe["present"] is True
    assert isinstance(pe.get("imports", []), list)
    assert len(pe["imports"]) == 49

    resources = pe.get("resources", {})
    assert resources.get("present") is True
    vi = resources.get("version_info", {})
    assert vi.get("ProductVersion") == "10.0.26100.7309"
