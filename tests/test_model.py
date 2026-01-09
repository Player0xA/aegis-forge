from datetime import datetime

from aegis.model import Bundle, InputEvidence, Manifest


def test_manifest_timestamp_utc_format():
    m = Manifest(scan_id="test")
    assert m.timestamp_utc.endswith("Z")
    datetime.fromisoformat(m.timestamp_utc.replace("Z", "+00:00"))


def test_bundle_constructs():
    inp = InputEvidence(
        input_path="tests/fixtures/benign.txt",
        file_size=1,
        sha256="0" * 64,
        md5="0" * 32,
    )
    b = Bundle(scan_id="test", input=inp)
    assert b.scan_id == "test"
    assert b.timestamp_utc.endswith("Z")

