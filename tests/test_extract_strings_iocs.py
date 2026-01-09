from aegis.extract_iocs import extract_iocs_from_texts
from aegis.extract_strings import extract_strings


def test_strings_and_iocs_from_benign_txt():
    data = b"hello http://example.com 1.2.3.4"

    sr = extract_strings(data, min_len=4)

    # String extraction returns contiguous printable runs, not tokenized pieces.
    assert any("http://example.com" in s for s in sr.ascii)

    iocs = extract_iocs_from_texts(sr.ascii + sr.utf16le)
    assert "http://example.com" in iocs.urls
    assert "1.2.3.4" in iocs.ipv4
    assert "example.com" in iocs.domains
