from __future__ import annotations

from pathlib import Path

from aegis.pe import parse_pe_bytes  # adjust if your module name differs


def test_pe_heuristics_present_for_notepad():
    data = Path("tests/fixtures/notepad.exe").read_bytes()
    res = parse_pe_bytes(data)
    assert res.present is True
    assert res.pe is not None

    h = res.pe.get("heuristics", None)
    assert isinstance(h, dict)

    # entrypoint section should be resolvable for a normal PE
    assert isinstance(h.get("entrypoint_section"), (str, type(None)))

    # lists should exist
    assert isinstance(h.get("high_entropy_sections"), list)
    assert isinstance(h.get("suspicious_section_names"), list)

    # presence-only boolean
    assert isinstance(h.get("security_directory_present"), bool)

    # deterministic flags list
    assert isinstance(h.get("flags"), list)
