from __future__ import annotations

import platform
import shutil
import sys
import uuid
from pathlib import Path
from typing import List, Optional

try:
    from importlib import metadata
except ImportError:
    import importlib_metadata as metadata  # type: ignore

import typer

from aegis.bundler import write_json, zip_bundle
from aegis.config import config_to_snapshot, load_config
from aegis.model import Bundle, InputEvidence, Manifest
from aegis.reporters.console import render_console
from aegis.reporters.csv_report import write_summary_csv
from aegis.scanner import ScanLimits, classify_basic, file_hashes, scan_path_basic

app = typer.Typer(add_completion=False)


def version_callback(value: bool):
    if value:
        try:
            v = metadata.version("aegis-forge")
        except metadata.PackageNotFoundError:
            v = "0.1.0-dev"
        typer.echo(f"aegis-forge version: {v}")
        raise typer.Exit()


def check_7z_dependency():
    if not (shutil.which("7z") or shutil.which("7zz")):
        typer.secho(
            "Warning: 7z/7zz (p7zip) not found in PATH. RAR and AES-ZIP support will be disabled.",
            fg=typer.colors.YELLOW,
            err=True,
        )


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None, "--version", callback=version_callback, is_eager=True, help="Show version and exit."
    ),
):
    """
    Safe-by-default static analysis forensic tool.
    """
    pass


def env_snapshot() -> dict:
    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "machine": platform.machine(),
        "python": sys.version,
    }


def _limits_from_cfg(cfg) -> ScanLimits:
    lim = getattr(cfg, "limits", None)

    def g(name: str, default):
        if lim is None:
            return default
        return getattr(lim, name, default)

    return ScanLimits(
        max_input_bytes=g("max_input_bytes", 20_000_000),
        strings_min_len=g("strings_min_len", 4),
        strings_max_strings=g("strings_max_strings", 2000),
        strings_max_total_bytes=g("strings_max_total_bytes", 200_000),
        iocs_max_each=g("iocs_max_each", 500),
        archive_max_members_list=g("archive_max_members_list", 5000),
        archive_max_members_scan=g("archive_max_members_scan", 25),
        archive_max_member_bytes=g("archive_max_member_bytes", 20_000_000),
        archive_max_decompressed_ratio=g("archive_max_decompressed_ratio", 100.0),
        archive_max_cumulative_bytes=g("archive_max_cumulative_bytes", 100_000_000),
        subprocess_timeout=g("subprocess_timeout", 30.0),
    )


def _output_zip_name(scan_id: str, input_path: Path) -> str:
    stem = input_path.name
    if stem.lower().endswith(".zip"):
        stem = stem[:-4]
    return f"aegis_{scan_id}_{stem}.zip"


def _load_passwords(password: Optional[List[str]], password_file: Optional[str]) -> List[str]:
    pw: List[str] = []
    if password:
        pw.extend([p for p in password if p])

    if password_file:
        p = Path(password_file).expanduser().resolve()
        if p.exists() and p.is_file():
            for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                s = line.strip()
                if s and not s.startswith("#"):
                    pw.append(s)
        else:
            raise typer.BadParameter(f"Password file not found: {p}")

    seen = set()
    out: List[str] = []
    for x in pw:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _run_single_scan(
    p: Path,
    cfg,
    limits: ScanLimits,
    passwords: List[str],
    non_interactive: bool,
    prompt_hook,
    out_base: Path,
) -> Optional[dict]:
    """Runs logic for a single file, returns bundle content for summary if needed."""
    try:
        size = p.stat().st_size
        if size > cfg.limits.max_file_size_bytes:
            typer.secho(f"Skipping {p.name}: File too large ({size} bytes).", fg=typer.colors.YELLOW, err=True)
            return None

        scan_id = str(uuid.uuid4())
        sha256, md5 = file_hashes(p)
        ftype = classify_basic(p)

        inp = InputEvidence(
            input_path=str(p),
            file_size=size,
            sha256=sha256,
            md5=md5,
            file_type=ftype,
            notes="Static-only. No execution. Input remains unchanged.",
        )

        findings, analyzed_items, scan_errors = scan_path_basic(
            p,
            limits=limits,
            passwords=passwords,
            non_interactive=non_interactive,
            prompt_confirm=prompt_hook,
        )

        bundle_obj = Bundle(
            schema_version=cfg.schema_version,
            scan_id=scan_id,
            input=inp,
            findings=findings,
            analyzed_items=analyzed_items,
            errors=scan_errors,
        )
        bundle = bundle_obj.model_dump()

        manifest_obj = Manifest(
            schema_version=cfg.schema_version,
            scan_id=scan_id,
            tool={"name": "aegis-forge", "version": "0.1.0"},
            environment=env_snapshot(),
            config_snapshot=config_to_snapshot(cfg),
        )
        manifest = manifest_obj.model_dump()

        scan_dir = out_base / f"aegis_{scan_id}"
        scan_dir.mkdir(parents=True, exist_ok=True)

        manifest_path = scan_dir / "manifest.json"
        bundle_path = scan_dir / "bundle.json"
        csv_path = scan_dir / "summary.csv"

        write_json(manifest_path, manifest)
        write_json(bundle_path, bundle)
        write_summary_csv(csv_path, bundle)

        bundle_zip = out_base / _output_zip_name(scan_id, p)
        zip_bundle(
            bundle_zip,
            {
                "manifest.json": manifest_path,
                "bundle.json": bundle_path,
                "summary.csv": csv_path,
            },
        )

        if not non_interactive:
            render_console(bundle, bundle_zip)
        else:
            typer.echo(f"Scanned {p.name} -> {bundle_zip.name}")

        return bundle

    except Exception as e:
        typer.secho(f"Error scanning {p.name}: {type(e).__name__}: {e}", fg=typer.colors.RED, err=True)
        return None


@app.command()
def scan(
    path: str = typer.Argument(..., help="Input file or directory path."),
    config: str = typer.Option(None, "--config", help="Path to YAML config."),
    outdir: str = typer.Option(None, "--outdir", help="Override output directory."),
    password: Optional[List[str]] = typer.Option(None, "--password", help="Archive password (repeatable)."),
    password_file: Optional[str] = typer.Option(None, "--password-file", help="File with passwords (one per line)."),
    non_interactive: bool = typer.Option(False, "--non-interactive", help="Disable prompts (batch mode)."),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="Recurse into subdirectories (batch mode)."),
):
    check_7z_dependency()
    cfg = load_config(config)
    if outdir:
        cfg.output_dir = outdir

    p_in = Path(path).expanduser().resolve()
    if not p_in.exists():
        raise typer.BadParameter(f"Path does not exist: {p_in}")

    passwords = _load_passwords(password, password_file)
    limits = _limits_from_cfg(cfg)
    prompt_hook = None if non_interactive else typer.confirm
    out_base = Path(cfg.output_dir).expanduser().resolve()
    out_base.mkdir(parents=True, exist_ok=True)

    if p_in.is_file():
        _run_single_scan(p_in, cfg, limits, passwords, non_interactive, prompt_hook, out_base)
    elif p_in.is_dir():
        typer.echo(f"Starting batch scan of directory: {p_in}")
        pattern = "**/*" if recursive else "*"
        files = [f for f in p_in.glob(pattern) if f.is_file() and not f.name.startswith(".")]
        
        if not files:
            typer.echo("No files found to scan.")
            return

        typer.echo(f"Found {len(files)} files.")
        all_bundles = []
        for f in files:
            res = _run_single_scan(f, cfg, limits, passwords, non_interactive, prompt_hook, out_base)
            if res:
                all_bundles.append(res)
        
        # In batch mode, we might want a global index.csv in out_base
        if all_bundles:
            # We can't use write_summary_csv directly for multiple bundles easily without refactoring it,
            # but we can at least notify the user.
            typer.echo(f"Batch scan complete. Scanned {len(all_bundles)}/{len(files)} files.")
    else:
        raise typer.BadParameter(f"Unsupported path type: {p_in}")


@app.command()
def qa(
    fixtures: str = typer.Option("./tests/fixtures", "--fixtures", help="Path to QA fixtures directory."),
    config: str = typer.Option(None, "--config", help="Config file to use for QA run."),
):
    """
    Functional Q&A harness: runs the tool on fixtures and asserts bundle correctness.
    """
    from aegis.qa.harness import run_qa

    run_qa(fixtures_dir=Path(fixtures), config_path=config)


if __name__ == "__main__":
    app()
