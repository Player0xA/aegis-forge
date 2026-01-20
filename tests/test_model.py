import json
from datetime import datetime
from aegis.model import Bundle, InputEvidence, Manifest, AnalyzedItem, Provenance

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

def test_bundle_round_trip_validation():
    """Verify that a dumped bundle can be re-validated by the model."""
    inp = InputEvidence(
        input_path="sample.exe",
        file_size=1024,
        sha256="f" * 64,
        md5="f" * 32,
        file_type="pe"
    )
    item = AnalyzedItem(
        path="sample.exe",
        bytes_read=1024,
        hashes={"sha256": "f" * 64},
        truncated=False,
        format="pe",
        provenance=Provenance(data_source="direct")
    )
    b = Bundle(
        scan_id="test-uuid",
        input=inp,
        findings={"test": "data"},
        analyzed_items=[item],
        errors=[]
    )
    
    # Dump to dict/JSON
    data = b.model_dump()
    json_data = b.model_dump_json()
    
    # Re-validate
    b2 = Bundle.model_validate(data)
    b3 = Bundle.model_validate_json(json_data)
    
    assert b2.scan_id == "test-uuid"
    assert b3.analyzed_items[0].path == "sample.exe"
    assert b3.analyzed_items[0].provenance.data_source == "direct"
