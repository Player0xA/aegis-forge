from __future__ import annotations
from rich.console import Console
from rich.table import Table
from pathlib import Path
from typing import Dict, Any

console = Console()

def render_console(bundle: Dict[str, Any], bundle_zip: Path) -> None:
    inp = bundle.get("input", {})
    t = Table(title="Aegis Forge — Evidence Bundle (Static, No Execution)")
    t.add_column("Field")
    t.add_column("Value", overflow="fold")
    t.add_row("scan_id", str(bundle.get("scan_id", "")))
    t.add_row("timestamp_utc", str(bundle.get("timestamp_utc", "")))
    t.add_row("input", str(inp.get("input_path", "")))
    t.add_row("file_type", str(inp.get("file_type", "")))
    t.add_row("size", str(inp.get("file_size", "")))
    t.add_row("sha256", str(inp.get("sha256", "")))
    t.add_row("md5", str(inp.get("md5", "")))
    console.print(t)
    console.print(f"[green]Bundle written:[/green] {bundle_zip}")

