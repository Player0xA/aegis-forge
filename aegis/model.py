from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from pydantic import BaseModel, Field


def utc_now_iso() -> str:
    """
    UTC timestamp in ISO-8601 with 'Z' suffix, seconds precision.
    Example: 2026-01-08T17:12:34Z
    """
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


class InputEvidence(BaseModel):
    input_path: str
    file_size: int
    sha256: str
    md5: str
    file_type: str = "unknown"
    notes: str = ""


class Manifest(BaseModel):
    schema_version: str = "1.0"
    scan_id: str
    timestamp_utc: str = Field(default_factory=utc_now_iso)

    tool: Dict[str, Any] = Field(default_factory=dict)
    environment: Dict[str, Any] = Field(default_factory=dict)
    config_snapshot: Dict[str, Any] = Field(default_factory=dict)


class Bundle(BaseModel):
    schema_version: str = "1.0"
    scan_id: str
    timestamp_utc: str = Field(default_factory=utc_now_iso)

    input: InputEvidence
    findings: Dict[str, Any] = Field(default_factory=dict)
    errors: List[Dict[str, Any]] = Field(default_factory=list)

