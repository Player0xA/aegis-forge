from pathlib import Path
import subprocess
import sys
import zipfile
import json

def test_cli_produces_bundle_zip(tmp_path: Path):
    # Create a benign fixture
    fx = tmp_path / "note.txt"
    fx.write_text("hello world", encoding="utf-8")

    outdir = tmp_path / "out"
    cmd = [sys.executable, "-m", "aegis.cli", "scan", str(fx), "--outdir", str(outdir)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr

    zips = list(outdir.glob("aegis_*.zip"))
    assert zips, "No bundle zip produced"

    z = zips[0]
    with zipfile.ZipFile(z, "r") as zf:
        assert "manifest.json" in zf.namelist()
        assert "bundle.json" in zf.namelist()
        assert "summary.csv" in zf.namelist()

        bundle = json.loads(zf.read("bundle.json").decode("utf-8"))
        assert bundle["input"]["sha256"]

