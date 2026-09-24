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
    assert fields["severity"] == "medium"  # no rule metadata -> default
    assert extract_alert_fields({"cat": "x", "detect_mtd": {"severity": "info"}})["severity"] == "low"
    assert extract_alert_fields({"cat": "x", "detect_mtd": {"severity": "critical"}})["severity"] == "critical"


def test_startup_backfills_limacharlie_severity(tmp_path: Path):
    db = tmp_path / "chat.db"
    old = AlertStore(db_path=db).ingest({"cat": "x", "detect_mtd": {"severity": "high"}})
    AlertStore(db_path=db).conn.execute("UPDATE ingested_alerts SET severity='medium'").connection.commit()
    assert AlertStore(db_path=db).get(old["id"])["severity"] == "high"  # re-opening runs the backfill


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


def test_ingest_dedupes_limacharlie_detect_id(store: AlertStore):
    first = store.ingest({"cat": "x", "detect_id": "d-1"})
    again = store.ingest({"cat": "x", "detect_id": "d-1"})
    assert again["duplicate"] and again["id"] == first["id"]
    assert not store.ingest({"cat": "x"}).get("duplicate")  # no detect_id: never deduped
    assert len(store.list()) == 2


def test_stats_aggregates_window(store: AlertStore):
    a = store.ingest({"cat": "rule-a", "routing": {"hostname": "web-01"}})
    store.ingest({"cat": "rule-a", "routing": {"hostname": "web-01"}})
    store.ingest({"rule": {"description": "rule-b", "level": 12}, "agent": {"name": "db-01"}})
    store.dismiss(a["id"], user_id=1)
    s = store.stats(24)
    assert s["total"] == 3 and sum(s["volume"]) == 3 and len(s["volume"]) == 24
    assert s["top_rules"][0] == {"name": "rule-a", "n": 2}
    assert s["top_hosts"] == [{"name": "web-01", "n": 2}, {"name": "db-01", "n": 1}]
    assert s["by_severity"] == {"medium": 2, "high": 1}
    assert s["backlog"] == {"new": 2}
    assert s["triage_s"] is not None and len(s["recent"]) == 3
