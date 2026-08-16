from pathlib import Path

import pytest

from app.db.chat_store import ChatStore
from app.db.incident_store import IncidentStore, case_number
from app.reports import build_incident_report_html, build_incident_report_md


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "test_chat.db"


@pytest.fixture
def store(db_path: Path) -> IncidentStore:
    return IncidentStore(db_path=db_path)


@pytest.fixture
def chat(db_path: Path) -> ChatStore:
    # Shares the same DB file so the conversations JOIN in get_for_user works.
    return ChatStore(db_path=db_path)


def test_case_number_format():
    assert case_number(1) == "INC-0001"
    assert case_number(42) == "INC-0042"


def test_create_defaults(store: IncidentStore):
    inc = store.create(user_id=1, title="Beaconing on WS-042")
    assert inc["case_number"] == "INC-0001"
    assert inc["severity"] == "medium"
    assert inc["status"] == "open"
    assert inc["closed_at"] is None


def test_case_seq_is_per_user(store: IncidentStore):
    a = store.create(user_id=1, title="A")
    b = store.create(user_id=1, title="B")
    c = store.create(user_id=2, title="C")
    assert a["case_number"] == "INC-0001"
    assert b["case_number"] == "INC-0002"
    assert c["case_number"] == "INC-0001"  # user 2 starts fresh


def test_invalid_severity_rejected(store: IncidentStore):
    with pytest.raises(ValueError):
        store.create(user_id=1, title="X", severity="apocalyptic")
    inc = store.create(user_id=1, title="X")
    with pytest.raises(ValueError):
        store.update_for_user(1, inc["id"], {"status": "reopened"})


def test_user_scoping(store: IncidentStore):
    inc = store.create(user_id=1, title="Mine")
    assert store.get_for_user(2, inc["id"]) is None
    assert store.update_for_user(2, inc["id"], {"title": "Stolen"}) is None
    assert store.delete_for_user(2, inc["id"]) is False
    assert store.link_conversation(2, inc["id"], "conv-x") is False
    # Owner still sees the original
    assert store.get_for_user(1, inc["id"])["title"] == "Mine"


def test_status_transitions_set_closed_at(store: IncidentStore):
    inc = store.create(user_id=1, title="X")
    closed = store.update_for_user(1, inc["id"], {"status": "closed", "verdict": "False positive"})
    assert closed["status"] == "closed"
    assert closed["closed_at"] is not None
    assert closed["verdict"] == "False positive"
    reopened = store.update_for_user(1, inc["id"], {"status": "investigating"})
    assert reopened["closed_at"] is None


def test_empty_string_clears_verdict_and_notes(store: IncidentStore):
    inc = store.create(user_id=1, title="X", notes="temp note")
    upd = store.update_for_user(1, inc["id"], {"verdict": "True positive"})
    assert upd["verdict"] == "True positive"
    cleared = store.update_for_user(1, inc["id"], {"verdict": "", "notes": " "})
    assert cleared["verdict"] is None
    assert cleared["notes"] is None


def test_link_unlink_conversations(store: IncidentStore, chat: ChatStore):
    conv = chat.create_conversation_for_user(1, title="Suspicious login burst")
    inc = store.create(user_id=1, title="X")
    assert store.link_conversation(1, inc["id"], conv["id"]) is True
    # Idempotent
    assert store.link_conversation(1, inc["id"], conv["id"]) is True
    got = store.get_for_user(1, inc["id"])
    assert len(got["conversations"]) == 1
    assert got["conversations"][0]["title"] == "Suspicious login burst"
    assert store.unlink_conversation(1, inc["id"], conv["id"]) is True
    assert store.unlink_conversation(1, inc["id"], conv["id"]) is False
    assert store.get_for_user(1, inc["id"])["conversations"] == []


def test_incidents_for_conversation(store: IncidentStore, chat: ChatStore):
    conv = chat.create_conversation_for_user(1, title="chat")
    inc = store.create(user_id=1, title="Case A")
    store.link_conversation(1, inc["id"], conv["id"])
    found = store.incidents_for_conversation(1, conv["id"])
    assert [i["id"] for i in found] == [inc["id"]]
    # Other users see nothing
    assert store.incidents_for_conversation(2, conv["id"]) == []


def test_list_filters_by_status_and_counts(store: IncidentStore, chat: ChatStore):
    a = store.create(user_id=1, title="A")
    b = store.create(user_id=1, title="B")
    store.update_for_user(1, b["id"], {"status": "closed"})
    conv = chat.create_conversation_for_user(1, title="chat")
    store.link_conversation(1, a["id"], conv["id"])
    all_incs = store.list_for_user(1)
    assert len(all_incs) == 2
    open_incs = store.list_for_user(1, status="open")
    assert [i["id"] for i in open_incs] == [a["id"]]
    assert open_incs[0]["conversation_count"] == 1


def test_delete_removes_links(store: IncidentStore, chat: ChatStore):
    conv = chat.create_conversation_for_user(1, title="chat")
    inc = store.create(user_id=1, title="X")
    store.link_conversation(1, inc["id"], conv["id"])
    assert store.delete_for_user(1, inc["id"]) is True
    assert store.get_for_user(1, inc["id"]) is None
    # Link rows are gone too
    assert store.incidents_for_conversation(1, conv["id"]) == []


def _report_fixtures():
    incident = {
        "id": "abc", "case_number": "INC-0001", "case_seq": 1,
        "title": "C2 beaconing from WS-042 <script>",
        "severity": "high", "status": "closed",
        "verdict": "True positive — contained", "notes": "Isolated host & rotated creds",
        "created_at": "2026-07-07T06:00:00+00:00",
        "updated_at": "2026-07-07T08:00:00+00:00",
        "closed_at": "2026-07-07T08:00:00+00:00",
    }
    conversations = [{
        "id": "conv-1", "title": "Beacon hunt",
        "created_at": "2026-07-07T06:00:00+00:00",
        "updated_at": "2026-07-07T07:00:00+00:00",
        "messages": [
            {"role": "user", "content": "check 10.9.8.7 <img src=x onerror=alert(1)>", "created_at": "2026-07-07T06:01:00+00:00"},
            {"role": "assistant", "content": "SECTION 3 — Decision\nMalicious", "created_at": "2026-07-07T06:02:00+00:00"},
        ],
    }]
    verdicts = [{
        "ioc_value": "10.9.8.7", "ioc_type": "ip", "verdict": "Malicious",
        "confidence": "High", "conversation_id": "conv-1",
        "message_excerpt": "check 10.9.8.7", "created_at": "2026-07-07T06:02:00+00:00",
    }]
    return incident, conversations, verdicts


def test_report_markdown_contains_key_sections():
    incident, conversations, verdicts = _report_fixtures()
    md = build_incident_report_md(incident, conversations, verdicts)
    assert "INC-0001" in md
    assert "HIGH" in md
    assert "10.9.8.7" in md
    assert "Beacon hunt" in md
    assert "Isolated host" in md


def test_report_html_escapes_user_content():
    incident, conversations, verdicts = _report_fixtures()
    html_doc = build_incident_report_html(incident, conversations, verdicts)
    assert "<script>" not in html_doc.split("</head>")[1]  # body has no raw tags from content
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_doc
    assert "INC-0001" in html_doc
    assert "10.9.8.7" in html_doc
