from pathlib import Path

import pytest

from app.db.verdict_store import VerdictStore, classify_ioc, parse_decision


@pytest.fixture
def store(tmp_path: Path) -> VerdictStore:
    return VerdictStore(db_path=tmp_path / "test_chat.db")


def test_classify_ioc():
    assert classify_ioc("10.0.0.5") == "ip"
    assert classify_ioc("d41d8cd98f00b204e9800998ecf8427e") == "hash"
    assert classify_ioc("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "hash"
    assert classify_ioc("evil.example.com") == "domain"


def test_parse_decision_section_format():
    reply = (
        "SECTION 1 — Automated Analysis\n... events ...\n\n"
        "SECTION 2 — Reasoning\n...\n\n"
        "SECTION 3 — Decision\nMalicious\n\nConfidence: High"
    )
    v, c = parse_decision(reply)
    assert v == "Malicious"
    assert c == "High"


def test_parse_decision_inline_format():
    reply = "**Decision:** Likely Benign\n**Confidence:** Medium"
    v, c = parse_decision(reply)
    assert v == "Likely Benign"
    assert c == "Medium"


def test_parse_decision_no_format_returns_none():
    v, c = parse_decision("I have no opinion on this matter.")
    assert v is None and c is None


def test_parse_decision_inconclusive_with_suffix():
    reply = "SECTION 3 — Decision\nInconclusive – Escalate to L2\n\nConfidence: Low"
    v, c = parse_decision(reply)
    assert v == "Inconclusive"
    assert c == "Low"


def test_record_and_lookup_roundtrip(store: VerdictStore):
    inserted = store.record(
        user_id=1,
        conversation_id="conv-a",
        iocs=["1.2.3.4", "evil.com"],
        verdict="Suspicious",
        confidence="Medium",
        message_excerpt="investigate 1.2.3.4 and evil.com",
        evidence_summary={"totals": {"wazuh": 5}, "sources_queried": ["wazuh"]},
    )
    assert inserted == 2
    rows = store.lookup_for_iocs(user_id=1, iocs=["1.2.3.4", "unknown.host"])
    assert len(rows) == 1
    assert rows[0]["ioc_value"] == "1.2.3.4"
    assert rows[0]["verdict"] == "Suspicious"
    assert rows[0]["ioc_type"] == "ip"
    assert rows[0]["conversation_id"] == "conv-a"


def test_lookup_excludes_current_conversation(store: VerdictStore):
    store.record(1, "conv-a", ["1.2.3.4"], "Malicious", "High", "msg", {})
    store.record(1, "conv-b", ["1.2.3.4"], "Likely Benign", "Low", "msg", {})
    rows = store.lookup_for_iocs(user_id=1, iocs=["1.2.3.4"], exclude_conversation_id="conv-b")
    assert len(rows) == 1
    assert rows[0]["conversation_id"] == "conv-a"


def test_lookup_is_user_scoped(store: VerdictStore):
    store.record(1, "conv-a", ["1.2.3.4"], "Malicious", "High", "msg", {})
    store.record(2, "conv-b", ["1.2.3.4"], "Likely Benign", "Low", "msg", {})
    rows_u1 = store.lookup_for_iocs(user_id=1, iocs=["1.2.3.4"])
    rows_u2 = store.lookup_for_iocs(user_id=2, iocs=["1.2.3.4"])
    assert len(rows_u1) == 1 and rows_u1[0]["verdict"] == "Malicious"
    assert len(rows_u2) == 1 and rows_u2[0]["verdict"] == "Likely Benign"


def test_lookup_returns_multiple_per_ioc_ordered_desc(store: VerdictStore):
    store.record(1, "conv-1", ["1.2.3.4"], "Likely Benign", "Low", "msg", {})
    store.record(1, "conv-2", ["1.2.3.4"], "Suspicious", "Medium", "msg", {})
    store.record(1, "conv-3", ["1.2.3.4"], "Malicious", "High", "msg", {})
    rows = store.lookup_for_iocs(user_id=1, iocs=["1.2.3.4"], limit_per_ioc=3)
    assert [r["verdict"] for r in rows] == ["Malicious", "Suspicious", "Likely Benign"]


def test_record_with_no_iocs_is_noop(store: VerdictStore):
    assert store.record(1, "conv-a", [], "Suspicious", "High", "msg", {}) == 0
    assert store.record(1, "conv-a", ["", "  "], "Suspicious", "High", "msg", {}) == 0


def test_record_with_null_verdict_still_persists(store: VerdictStore):
    inserted = store.record(1, "conv-a", ["1.2.3.4"], None, None, "msg", {})
    assert inserted == 1
    rows = store.lookup_for_iocs(user_id=1, iocs=["1.2.3.4"])
    assert rows[0]["verdict"] is None
    assert rows[0]["confidence"] is None
