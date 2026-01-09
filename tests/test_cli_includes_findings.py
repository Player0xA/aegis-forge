from __future__ import annotations

import json
import zipfile
from pathlib import Path

from typer.testing import CliRunner

from aegis.cli import app


def test_cli_scan_writes_bundle_with_iocs(tmp_path: Path):
    runner = CliRunner()

    outdir = tmp_path / "out"
    outdir.mkdir(parents=True, exist_ok=True)

    result = runner.invoke(app, ["scan", "tests/fixtures/benign.txt", "--outdir", str(outdir)])
    assert result.exit_code == 0, result.stdout + "\n" + result.stderr if hasattr(result, "stderr") else result.stdout

    # Find the produced zip
    zips = list(outdir.glob("aegis_*.zip"))
    assert len(zips) == 1

    with zipfile.ZipFile(zips[0], "r") as zf:
        assert "bundle.json" in zf.namelist()
        bundle = json.loads(zf.read("bundle.json").decode("utf-8"))

    assert "findings" in bundle
    assert "iocs" in bundle["findings"]
    assert "urls" in bundle["findings"]["iocs"]
    assert "ipv4" in bundle["findings"]["iocs"]
    assert "domains" in bundle["findings"]["iocs"]

    assert "http://example.com" in bundle["findings"]["iocs"]["urls"]
    assert "1.2.3.4" in bundle["findings"]["iocs"]["ipv4"]
    assert "example.com" in bundle["findings"]["iocs"]["domains"]

