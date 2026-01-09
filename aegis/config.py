from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

import yaml
from pydantic import BaseModel


class Limits(BaseModel):
    # Existing
    max_file_size_bytes: int = 200_000_000

    # Added (Milestone B/C/D safe defaults; CLI already reads these if present)
    max_input_bytes: int = 20_000_000

    archive_max_members_list: int = 5000
    archive_max_members_scan: int = 25
    archive_max_member_bytes: int = 20_000_000

    strings_min_len: int = 4
    strings_max_strings: int = 2000
    strings_max_total_bytes: int = 200_000

    iocs_max_each: int = 500


class RarCfg(BaseModel):
    prefer_7z: bool = True


class LlmCfg(BaseModel):
    enabled: bool = False


class AppConfig(BaseModel):
    schema_version: str = "1.0"
    output_dir: str = "./out"
    workspace_dir: str = "./work"
    limits: Limits = Limits()
    rar: RarCfg = RarCfg()
    llm: LlmCfg = LlmCfg()


def load_config(path: Optional[str]) -> AppConfig:
    if not path:
        return AppConfig()
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return AppConfig.model_validate(data)


def config_to_snapshot(cfg: AppConfig) -> Dict[str, Any]:
    return cfg.model_dump()
