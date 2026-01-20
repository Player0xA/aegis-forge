import pytest
import zipfile
from pathlib import Path
from aegis.scanner import ScanLimits, scan_path_basic

def test_cumulative_bytes_limit(tmp_path):
    # Create a ZIP with two members, each 1KB
    zpath = tmp_path / "cumulative.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("file1.txt", "A" * 1024)
        zf.writestr("file2.txt", "B" * 1024)
    
    # Set cumulative limit to 500 bytes. 
    # File 1 (1024 bytes) will be scanned because cumulative_bytes start at 0.
    # Then cumulative_bytes becomes 1024, which is >= 500, so File 2 will be skipped.
    limits = ScanLimits(archive_max_cumulative_bytes=500)
    findings, items, errors = scan_path_basic(zpath, limits=limits)
    
    assert findings["archive"]["scanned_member_count"] == 1
    assert any(e["code"] == "E_ARCHIVE_CUMULATIVE_LIMIT_REACHED" for e in errors)

def test_decompressed_ratio_limit(tmp_path):
    # Create a ZIP member that is highly compressed.
    # We MUST use compression (ZIP_DEFLATED) for ratio to be non-1.0
    zpath = tmp_path / "bomb.zip"
    data = b"\x00" * 100_000
    with zipfile.ZipFile(zpath, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb.txt", data)
    
    # 100KB of zeros compresses to ~100 bytes. Ratio ~1000.
    # Set ratio limit to 10.0
    limits = ScanLimits(archive_max_decompressed_ratio=10.0)
    findings, items, errors = scan_path_basic(zpath, limits=limits)
    
    assert findings["archive"]["scanned_member_count"] == 0
    assert any(e["code"] == "E_ARCHIVE_MEMBER_SKIPPED_RATIO" for e in errors)

def test_7z_timeout(tmp_path):
    # Accepted parameters check
    limits = ScanLimits(subprocess_timeout=0.1)
    # No functional test for timeout yet as it requires a slow 7z call
    pass
