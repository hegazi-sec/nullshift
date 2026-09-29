import json
import uuid

import pytest

import app.agents as agents
from app.db import user_store
from app.db.agent_store import AgentStore
from app.db.alert_store import AlertStore
from app.db.chat_store import ChatStore
from app.db.incident_store import IncidentStore
from app.db.verdict_store import VerdictStore

SID = "11111111-2222-3333-4444-555555555555"
ADMIN = {"id": 1, "username": "admin", "role": "admin"}


@pytest.fixture
def env(tmp_path, monkeypatch):
    db = tmp_path / "chat.db"
    VerdictStore(db_path=db)  # conversation listing joins verdicts, which share chat.db in the app
    s = {"alerts_inbox": AlertStore(db_path=db), "agent_store": AgentStore(db_path=db),
         "store": ChatStore(db_path=db), "incident_store": IncidentStore(db_path=db)}
    for name, obj in s.items():
        monkeypatch.setattr(agents, name, obj)
    monkeypatch.setattr(user_store, "DB_PATH", str(tmp_path / "users.db"))
    user_store.init_db()
    user_store.create_user("admin", "x", "admin")
    cfg = json.loads(json.dumps(agents.DEFAULTS))
    cfg["triage"]["enabled_at"] = "2000-01-01"
    return s, cfg


def ingest(s, title, host, n=1):
    for _ in range(n):
        s["alerts_inbox"].ingest({"cat": title, "detect_id": uuid.uuid4().hex,
                                  "routing": {"hostname": host, "sid": SID}})


def llm(monkeypatch, outcomes):
    """Stub the chat pipeline: the first outcome whose key appears in the message wins."""
    def fake(actor, conv, message, mode):
        for key, (reply, verdict, conf) in outcomes.items():
            if key in message:
                return reply, verdict, conf
        raise AssertionError(f"unexpected message: {message[:80]}")
    monkeypatch.setattr(agents, "_investigate", fake)


def test_triage_groups_dismisses_confident_fps_and_opens_cases(env, monkeypatch):
    s, cfg = env
    ingest(s, "rule-a", "web-01", n=2)
    ingest(s, "rule-b", "db-01")
    llm(monkeypatch, {"rule-a": ("", "Likely Benign", "High"), "rule-b": ("", "Suspicious", "Medium")})

    assert agents.run_triage(cfg) == "2 group(s) triaged"
    alerts = {a["title"]: a for a in s["alerts_inbox"].list()}
    assert alerts["rule-a"]["status"] == "dismissed" and alerts["rule-b"]["status"] == "investigating"
    [dismissed] = s["agent_store"].entries("triage", "dismissed")
    assert len(json.loads(dismissed["data_json"])["alert_ids"]) == 2
    [case] = s["incident_store"].list_for_user(1)
    assert case["title"] == "rule-b on db-01" and case["conversation_count"] == 1
    assert agents.run_triage(cfg) == "0 group(s) triaged"  # nothing is triaged twice


def test_investigator_closes_confirmed_fp_and_proposes_isolation(env, monkeypatch):
    s, cfg = env
    ingest(s, "rule-a", "web-01")
    ingest(s, "rule-b", "db-01")
    llm(monkeypatch, {"rule-": ("", "Suspicious", "Medium")})
    agents.run_triage(cfg)
    cases = {c["title"]: c for c in s["incident_store"].list_for_user(1)}
    llm(monkeypatch, {
        cases["rule-a on web-01"]["case_number"]: ("**Recommended Response:** close", "Likely Benign", "High"),
        cases["rule-b on db-01"]["case_number"]: ("**Recommended Response:** isolate", "Malicious", "High"),
    })

    assert agents.run_investigator(cfg) == "2 case(s) investigated"
    after = {c["title"]: c for c in s["incident_store"].list_for_user(1)}
    assert after["rule-a on web-01"]["status"] == "closed"
    assert after["rule-b on db-01"]["status"] == "investigating" and after["rule-b on db-01"]["severity"] == "critical"
    [p] = s["agent_store"].proposals()
    assert (p["sid"], p["hostname"], p["status"]) == (SID, "db-01", "proposed")
    assert agents.run_investigator(cfg) == "0 case(s) investigated"


def test_undo_and_approval_gated_containment(env, monkeypatch):
    s, cfg = env
    ingest(s, "rule-a", "web-01")
    llm(monkeypatch, {"rule-a": ("", "Likely Benign", "High")})
    agents.run_triage(cfg)
    [entry] = s["agent_store"].entries("triage", "dismissed")
    agents.undo(entry["id"], ADMIN)
    assert s["alerts_inbox"].list()[0]["status"] == "new"
    with pytest.raises(ValueError):
        agents.undo(entry["id"], ADMIN)  # only once

    p = s["agent_store"].propose("case-1", SID, "web-01", "test")
    monkeypatch.setattr(agents, "load_config", lambda: cfg)
    with pytest.raises(PermissionError):
        agents.decide(p["id"], "approve", ADMIN)  # containment is off by default
    cfg["responder"]["enabled"] = True
    calls = []
    monkeypatch.setattr(agents, "_lc_isolation", lambda sid, isolate: calls.append(isolate) or (True, "HTTP 200"))
    assert agents.decide(p["id"], "approve", ADMIN)["status"] == "executed"
    with pytest.raises(ValueError):
        agents.decide(p["id"], "approve", ADMIN)  # no double isolation
    assert agents.decide(p["id"], "release", ADMIN)["status"] == "released"
    assert calls == [True, False]
    q = s["agent_store"].propose("case-2", SID, "db-01", "test")
    assert agents.decide(q["id"], "reject", ADMIN)["status"] == "rejected"


def test_reporter_posts_shift_report(env, monkeypatch):
    s, cfg = env
    ingest(s, "rule-a", "web-01", n=3)
    llm(monkeypatch, {"rule-a": ("", "Likely Benign", "High")})
    agents.run_triage(cfg)
    agents.run_reporter(cfg)
    [conv] = [c for c in s["store"].list_conversations_for_user(1) if c["title"].startswith("Shift report")]
    report = s["store"].get_conversation_for_user(1, conv["id"])["messages"][0]["content"]
    assert "Alerts received: **3**" in report and "1 alert group(s) dismissed" in report


def test_model_outage_decides_nothing_and_pauses(env, monkeypatch):
    s, cfg = env
    ingest(s, "rule-a", "web-01")
    def down(*a, **k):
        raise agents.LLMUnavailable("Model unavailable: quota")
    monkeypatch.setattr(agents, "_investigate", down)
    monkeypatch.setattr(agents, "_paused_until", {})

    agents._run("triage", cfg)
    assert s["alerts_inbox"].list()[0]["status"] == "new"  # retried on a later run
    assert s["store"].list_conversations_for_user(1) == [] and s["incident_store"].list_for_user(1) == []
    assert agents._paused_until["triage"] > 0 and agents.status["triage"]["result"].startswith("paused")
    assert s["agent_store"].recent()[0]["action"] == "error"
