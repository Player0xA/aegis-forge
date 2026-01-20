from __future__ import annotations

import zipfile
from pathlib import Path

from aegis.scanner import scan_path_basic


def test_scan_zip_aggregates_iocs(tmp_path: Path):
    zpath = tmp_path / "fixture.zip"
    with zipfile.ZipFile(zpath, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("benign.txt", "hello http://example.com 1.2.3.4")

    findings, items, errors = scan_path_basic(zpath)

    assert len(items) == 1
    assert items[0].path == "benign.txt"
    assert items[0].provenance.data_source == "zipfile"

    assert "archive" in findings
    assert findings["archive"]["type"] == "zip"
    assert findings["archive"]["member_count"] >= 1
    assert findings["archive"]["scanned_member_count"] == 1

    assert "iocs" in findings
    assert "http://example.com" in findings["iocs"]["urls"]
    assert "1.2.3.4" in findings["iocs"]["ipv4"]
    assert "example.com" in findings["iocs"]["domains"]

    # ZIP should not require external backend
    assert not any(e.get("code") == "E_7Z_MISSING" for e in errors)
