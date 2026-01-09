from __future__ import annotations
from pathlib import Path
import json
import zipfile
import subprocess
import sys

REQUIRED_ARCNAMES = {"manifest.json", "bundle.json", "summary.csv"}

def _latest_bundle_zip(outdir: Path) -> Path:
    zips = sorted(outdir.glob("aegis_*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not zips:
        raise AssertionError("No bundle zip produced.")
    return zips[0]

def run_qa(fixtures_dir: Path, config_path: str | None) -> None:
    fixtures_dir = fixtures_dir.resolve()
    if not fixtures_dir.exists():
        raise AssertionError(f"Fixtures directory missing: {fixtures_dir}")

    # Ensure we have at least one benign fixture
    fixture_files = [p for p in fixtures_dir.iterdir() if p.is_file()]
    if not fixture_files:
        raise AssertionError(f"No fixtures found in: {fixtures_dir}")

    outdir = fixtures_dir / "_qa_out"
    outdir.mkdir(parents=True, exist_ok=True)

    # Run scan for each fixture
    for fx in fixture_files:
        cmd = [sys.executable, "-m", "aegis.cli", "scan", str(fx), "--outdir", str(outdir)]
        if config_path:
            cmd += ["--config", config_path]

        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            raise AssertionError(f"Scan failed for {fx}:\nSTDOUT:\n{r.stdout}\nSTDERR:\n{r.stderr}")

        # Validate bundle zip structure
        z = _latest_bundle_zip(outdir)
        with zipfile.ZipFile(z, "r") as zf:
            names = set(zf.namelist())
            missing = REQUIRED_ARCNAMES - names
            if missing:
                raise AssertionError(f"Bundle missing files {missing} in {z}")

            bundle = json.loads(zf.read("bundle.json").decode("utf-8"))
            manifest = json.loads(zf.read("manifest.json").decode("utf-8"))

        # Q&A checks (functional assertions)
        assert "scan_id" in bundle and bundle["scan_id"], "bundle.scan_id missing"
        assert "input" in bundle and bundle["input"], "bundle.input missing"
        assert bundle["input"]["sha256"], "input.sha256 missing"
        assert bundle["input"]["md5"], "input.md5 missing"
        assert bundle["input"]["file_size"] > 0, "input.file_size invalid"
        assert manifest.get("tool", {}).get("name") == "aegis-forge", "manifest.tool.name mismatch"

    print(f"[QA] OK — {len(fixture_files)} fixture(s) passed. Output: {outdir}")

