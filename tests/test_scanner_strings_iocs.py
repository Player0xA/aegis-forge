from pathlib import Path

from aegis.scanner import scan_path_basic


def test_scan_path_basic_extracts_iocs_from_fixture():
    p = Path("tests/fixtures/benign.txt")
    findings, errors = scan_path_basic(p)

    assert "strings" in findings
    assert "iocs" in findings

    assert "http://example.com" in findings["iocs"]["urls"]
    assert "1.2.3.4" in findings["iocs"]["ipv4"]
    assert "example.com" in findings["iocs"]["domains"]

    # benign fixture should not need truncation errors
    assert errors == []
