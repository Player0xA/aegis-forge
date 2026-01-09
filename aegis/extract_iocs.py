from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Set


_URL_RE = re.compile(r"\bhttps?://[^\s<>\"]+\b", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,63}\b", re.IGNORECASE)


@dataclass(frozen=True)
class IOCsResult:
    urls: List[str]
    ipv4: List[str]
    domains: List[str]


def extract_iocs_from_texts(texts: Iterable[str], *, max_each: int = 500) -> IOCsResult:
    urls: Set[str] = set()
    ips: Set[str] = set()
    domains: Set[str] = set()

    for t in texts:
        for m in _URL_RE.findall(t):
            if len(urls) < max_each:
                urls.add(m)

        for m in _IPV4_RE.findall(t):
            if len(ips) < max_each:
                ips.add(m)

        for m in _DOMAIN_RE.findall(t):
            if len(domains) < max_each:
                domains.add(m)

    return IOCsResult(
        urls=sorted(urls),
        ipv4=sorted(ips),
        domains=sorted(domains),
    )
