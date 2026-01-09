from __future__ import annotations
from pathlib import Path
import json
import zipfile
from typing import Dict, Any

def write_json(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")

def zip_bundle(bundle_zip_path: Path, files: Dict[str, Path]) -> None:
    bundle_zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(bundle_zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for arcname, fpath in files.items():
            zf.write(fpath, arcname=arcname)

