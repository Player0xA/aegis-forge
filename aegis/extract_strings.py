from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class StringsResult:
    ascii: List[str]
    utf16le: List[str]
    truncated: bool


def _extract_ascii(data: bytes, min_len: int, max_strings: int, max_total_bytes: int) -> tuple[list[str], bool]:
    out: list[str] = []
    buf = bytearray()
    total = 0
    truncated = False

    def flush():
        nonlocal total
        if len(buf) >= min_len:
            s = buf.decode("ascii", errors="ignore")
            if s:
                out.append(s)
                total += len(s)
        buf.clear()

    for b in data:
        if 32 <= b <= 126:
            buf.append(b)
            if len(out) >= max_strings or total >= max_total_bytes:
                truncated = True
                break
        else:
            flush()
            if len(out) >= max_strings or total >= max_total_bytes:
                truncated = True
                break

    if not truncated:
        flush()

    if len(out) > max_strings:
        out = out[:max_strings]
        truncated = True

    return out, truncated


def _extract_utf16le(data: bytes, min_len: int, max_strings: int, max_total_bytes: int) -> tuple[list[str], bool]:
    out: list[str] = []
    truncated = False
    total = 0

    i = 0
    n = len(data)

    while i + 1 < n:
        if 32 <= data[i] <= 126 and data[i + 1] == 0x00:
            start = i
            i += 2
            while i + 1 < n and (32 <= data[i] <= 126) and data[i + 1] == 0x00:
                i += 2

            chunk = data[start:i]
            try:
                s = chunk.decode("utf-16le", errors="ignore")
            except Exception:
                s = ""

            if len(s) >= min_len and s:
                out.append(s)
                total += len(s)
                if len(out) >= max_strings or total >= max_total_bytes:
                    truncated = True
                    break
        else:
            i += 1

    if len(out) > max_strings:
        out = out[:max_strings]
        truncated = True

    return out, truncated


def extract_strings(
    data: bytes,
    *,
    min_len: int = 4,
    max_strings: int = 2000,
    max_total_bytes: int = 200_000,
    enable_ascii: bool = True,
    enable_utf16le: bool = True,
) -> StringsResult:
    ascii_list: list[str] = []
    utf16_list: list[str] = []
    truncated = False

    if enable_ascii:
        ascii_list, t1 = _extract_ascii(data, min_len, max_strings, max_total_bytes)
        truncated = truncated or t1

    if enable_utf16le:
        utf16_list, t2 = _extract_utf16le(data, min_len, max_strings, max_total_bytes)
        truncated = truncated or t2

    return StringsResult(ascii=ascii_list, utf16le=utf16_list, truncated=truncated)
