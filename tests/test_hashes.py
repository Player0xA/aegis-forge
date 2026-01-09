from pathlib import Path
from aegis.scanner import file_hashes

def test_file_hashes(tmp_path: Path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"abc123")
    sha256, md5 = file_hashes(p)
    assert len(sha256) == 64
    assert len(md5) == 32

