from pathlib import Path

from aegis.cli import _output_zip_name


def test_output_zip_name_does_not_double_zip_extension():
    scan_id = "123"
    assert _output_zip_name(scan_id, Path("benign.zip")) == "aegis_123_benign.zip"
    assert _output_zip_name(scan_id, Path("benign.txt")) == "aegis_123_benign.txt.zip"
