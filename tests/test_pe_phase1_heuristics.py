import json
from pathlib import Path

from aegis.pe import parse_pe_bytes


def test_pe_phase1_heuristics_keys_present():
    p = Path("tests/fixtures/notepad.exe")
    data = p.read_bytes()

    res = parse_pe_bytes(data)
    assert res.present is True
    assert res.pe is not None
    pe = res.pe

    assert "heuristics" in pe
    h = pe["heuristics"]

    # Required Phase 1 keys
    assert "entrypoint_section" in h
    assert "high_entropy_sections" in h
    assert "high_entropy_threshold" in h
    assert "suspicious_section_names" in h
    assert "security_directory_listed" in h
    assert "security_blob_readable" in h
    assert "imports_fingerprint_sha256" in h
    assert "flags" in h

    # fingerprint should be sha256 hex
    assert isinstance(h["imports_fingerprint_sha256"], str)
    assert len(h["imports_fingerprint_sha256"]) == 64

    # determinism sanity (json dumps should work)
    json.dumps(h)
