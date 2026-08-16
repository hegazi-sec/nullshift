from pathlib import Path

import pytest

from app.db.alert_store import AlertStore, extract_alert_fields, normalize_severity


@pytest.fixture
def store(tmp_path: Path) -> AlertStore:
    return AlertStore(db_path=tmp_path / "test_chat.db")


def test_normalize_severity():
    assert normalize_severity(3) == "low"
    assert normalize_severity("7") == "medium"
    assert normalize_severity(12) == "high"
    assert normalize_severity(15) == "critical"
    assert normalize_severity("High") == "high"
    assert normalize_severity("informational") == "low"
    assert normalize_severity(None) == "medium"
    assert normalize_severity("weird-value") == "medium"


def test_extract_wazuh_shape():
    fields = extract_alert_fields({
        "rule": {"description": "SSH brute force detected", "level": 12},
        "agent": {"name": "web-01"},
    })
    assert fields["title"] == "SSH brute force detected"
    assert fields["severity"] == "high"
    assert fields["source"] == "wazuh"


def test_extract_limacharlie_shape():
    fields = extract_alert_fields({"cat": "suspicious-process", "detect": {"event": {}}})
    assert fields["title"] == "suspicious-process"
    assert fields["source"] == "limacharlie"


def test_extract_splunk_shape():
    fields = extract_alert_fields({"search_name": "Kerberoasting detected", "result": {}})
    assert fields["title"] == "Kerberoasting detected"
    assert fields["source"] == "splunk"


def test_extract_generic_shape():
    fields = extract_alert_fields({"title": "Custom alert", "severity": "critical"})
    assert fields["title"] == "Custom alert"
    assert fields["severity"] == "critical"
    assert fields["source"] == "unknown"


def test_extract_empty_payload():
    fields = extract_alert_fields({})
    assert fields["title"] == "Untitled alert"
    assert fields["severity"] == "medium"


def test_ingest_and_list(store: AlertStore):
    rec = store.ingest({"title": "Test alert", "severity": "high"}, source_hint="wazuh")
    assert rec["source"] == "wazuh"
    assert store.count_new() == 1
    listed = store.list()
    assert len(listed) == 1
    assert listed[0]["title"] == "Test alert"
    assert "payload_json" not in listed[0]  # list omits payload
    full = store.get(rec["id"])
    assert "Test alert" in full["payload_json"]


def test_claim_lifecycle(store: AlertStore):
    rec = store.ingest({"title": "X"})
    assert store.mark_investigating(rec["id"], user_id=1, conversation_id="conv-1") is True
    # Second claim loses — status is no longer 'new'
    assert store.mark_investigating(rec["id"], user_id=2, conversation_id="conv-2") is False
    got = store.get(rec["id"])
    assert got["status"] == "investigating"
    assert got["claimed_by"] == 1
    assert got["conversation_id"] == "conv-1"
    assert store.count_new() == 0


def test_dismiss(store: AlertStore):
    rec = store.ingest({"title": "X"})
    assert store.dismiss(rec["id"], user_id=1) is True
    assert store.get(rec["id"])["status"] == "dismissed"
    # Dismissing again is a no-op
    assert store.dismiss(rec["id"], user_id=1) is False


def test_list_filter_by_status(store: AlertStore):
    a = store.ingest({"title": "A"})
    b = store.ingest({"title": "B"})
    store.dismiss(b["id"], user_id=1)
    assert [x["title"] for x in store.list(status="new")] == ["A"]
    assert [x["title"] for x in store.list(status="dismissed")] == ["B"]
