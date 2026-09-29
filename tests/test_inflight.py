"""In-flight investigation contract and the conversation/alert API around it.

Temp DBs and a stubbed pipeline: no SIEM, RAG, VirusTotal or LLM calls.
Endpoints go through FastAPI's TestClient with the logged-in user overridden.
"""
import asyncio
import contextlib
import json
import os
import threading
import time

os.environ.setdefault("JWT_SECRET", "x" * 40)

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import ClientDisconnect

import app.main as m
from app.auth import get_current_user
from app.db import user_store
from app.db.alert_store import AlertStore
from app.db.chat_store import ChatStore
from app.db.incident_store import IncidentStore
from app.db.investigation_state import InvestigationStateStore
from app.db.prefs_store import PrefsStore
from app.db.verdict_store import VerdictStore
from app.schemas import MessageCreate


class _Settings:
    def __init__(self, values):
        self.values = values

    def get(self, key):
        return self.values.get(key)


@pytest.fixture
def env(tmp_path, monkeypatch):
    db = tmp_path / "chat.db"
    for name, obj in {
        "store": ChatStore(db_path=db), "alerts_inbox": AlertStore(db_path=db),
        "incident_store": IncidentStore(db_path=db), "verdict_store": VerdictStore(db_path=db),
        "inv_state": InvestigationStateStore(db_path=db), "prefs_store": PrefsStore(db_path=db),
        "settings_store": _Settings({"webhook_token": "hook"}),
    }.items():
        monkeypatch.setattr(m, name, obj)
    monkeypatch.setattr(user_store, "DB_PATH", str(tmp_path / "users.db"))
    user_store.init_db()
    users = {n: {"id": user_store.create_user(n, "x", "l1"), "username": n, "role": "l1"}
             for n in ("alice", "bob")}

    monkeypatch.setattr(m, "any_provider_configured", lambda: True)
    monkeypatch.setattr(m, "_supported_mode", lambda mode: mode)
    monkeypatch.setattr(m, "run_investigation", lambda *a, **k: {})
    monkeypatch.setattr(m, "auto_enrich_iocs", lambda *a, **k: [])
    monkeypatch.setattr(m, "_prime_prior_session_summaries", lambda *a, **k: [])
    monkeypatch.setattr(m._rag_mod.rag, "retrieve", lambda q: [])
    monkeypatch.setattr(m, "orchestrated_llm_reply", lambda *a, **k: "the answer")

    who = {"user": users["alice"]}
    m.app.dependency_overrides[get_current_user] = lambda: who["user"]
    yield users, who
    m.app.dependency_overrides.pop(get_current_user, None)
    with m._INFLIGHT_LOCK:
        m._INFLIGHT.clear()


def _events(body: str):
    return [json.loads(line[6:]) for line in body.splitlines() if line.startswith("data: ")]


def _new_conv(client) -> str:
    return client.post("/api/conversations", json={}).json()["id"]


def test_message_work_registers_pending_and_clears_it_even_on_exception(env, monkeypatch):
    users, _ = env
    alice, bob = users["alice"], users["bob"]
    conv = m.store.create_conversation_for_user(alice["id"], title="[Triage] rule-a")["id"]
    seen = []

    def reply(aug, cid, *a, **k):
        seen.append((m._pending(cid, alice["id"]), m._pending(cid, bob["id"])))
        return "Verdict: Suspicious"
    monkeypatch.setattr(m, "orchestrated_llm_reply", reply)

    # The agents call _do_message_work directly, so it owns the registry entry.
    assert m._do_message_work(conv, MessageCreate(message="look"), alice, mode="investigation_report")["reply"]
    [(mine, other)] = seen
    assert mine["stage"] == "Waiting for the model" and mine["since"] and other is None
    assert m._pending(conv, alice["id"]) is None

    def boom(*a, **k):
        raise RuntimeError("SIEM exploded")
    monkeypatch.setattr(m, "orchestrated_llm_reply", boom)
    with pytest.raises(RuntimeError):
        m._do_message_work(conv, MessageCreate(message="again"), alice)
    assert m._pending(conv, alice["id"]) is None
    msgs = m.store.get_conversation_for_user(alice["id"], conv)["messages"]
    assert [(x["role"], x["content"]) for x in msgs[-2:]] == [
        ("user", "again"), ("assistant", "⚠ Investigation failed: SIEM exploded")]

    # A run already going in the conversation: refused, nothing saved.
    assert m._inflight_claim(conv, alice["id"])
    with pytest.raises(HTTPException) as exc:
        m._do_message_work(conv, MessageCreate(message="third"), alice)
    assert exc.value.status_code == 409
    assert len(m.store.get_conversation_for_user(alice["id"], conv)["messages"]) == len(msgs)


def test_stream_saves_question_and_title_first_and_rejects_a_second_send(env, monkeypatch):
    client = TestClient(m.app)
    conv = _new_conv(client)
    entered, release = threading.Event(), threading.Event()

    def slow(*a, **k):
        entered.set()
        assert release.wait(10)
        return "the answer"
    monkeypatch.setattr(m, "orchestrated_llm_reply", slow)

    first = {}
    url = f"/api/conversations/{conv}/messages/stream"
    sender = threading.Thread(target=lambda: first.update(
        r=TestClient(m.app).post(url, json={"message": "Why is web-01 beaconing\nat night?"})))
    sender.start()
    try:
        assert entered.wait(10)
        # Another client (or a reload) already sees the question, the title and the run.
        got = client.get(f"/api/conversations/{conv}/messages").json()
        assert got["title"] == "Why is web-01 beaconing"
        assert [x["content"] for x in got["messages"]] == ["Why is web-01 beaconing\nat night?"]
        assert got["pending"]["stage"] == "Waiting for the model"
        [row] = client.get("/api/conversations").json()["conversations"]
        assert row["pending"] == got["pending"] and row["title"] == got["title"]

        second = client.post(url, json={"message": "hello?"})
        assert second.status_code == 409
        assert second.json()["detail"] == "An investigation is already running in this conversation"
    finally:
        release.set()
        sender.join(10)

    events = _events(first["r"].text)
    assert events[0]["type"] == "status" and events[-1] == {"type": "done", "reply": "the answer"}
    stages = ["Analyzing query", "Querying SIEM", "Retrieving playbooks", "Waiting for the model"]
    assert all(e["text"] in stages for e in events[:-1])  # sampled each second, so fast stages may be skipped
    after = client.get(f"/api/conversations/{conv}/messages").json()
    assert after["pending"] is None
    assert [x["role"] for x in after["messages"]] == ["user", "assistant"]
    assert client.get("/api/conversations").json()["conversations"][0]["pending"] is None


def test_stream_failure_is_persisted_and_image_only_message_gets_a_marker(env, monkeypatch):
    users, _ = env
    client = TestClient(m.app)
    conv = _new_conv(client)

    def boom(*a, **k):
        raise RuntimeError("model crashed")
    monkeypatch.setattr(m, "orchestrated_llm_reply", boom)
    r = client.post(f"/api/conversations/{conv}/messages/stream",
                    json={"message": "", "images": ["data:image/png;base64,AAAA", "data:image/png;base64,BBBB"]})
    assert r.status_code == 200
    assert _events(r.text)[-1] == {"type": "error", "text": "model crashed"}
    got = client.get(f"/api/conversations/{conv}/messages").json()
    assert got["pending"] is None and got["title"] == "[2 screenshots attached]"
    assert [(x["role"], x["content"]) for x in got["messages"]] == [
        ("user", "[2 screenshots attached]"), ("assistant", "⚠ Investigation failed: model crashed")]
    assert m._pending(conv, users["alice"]["id"]) is None


def test_stream_timeout_leaves_the_investigation_running(env, monkeypatch):
    users, _ = env
    client = TestClient(m.app)
    conv = _new_conv(client)
    release = threading.Event()
    monkeypatch.setattr(m, "orchestrated_llm_reply", lambda *a, **k: release.wait(10) and "late answer")
    monkeypatch.setattr(m, "_STREAM_TIMEOUT_S", 1)

    last = _events(client.post(f"/api/conversations/{conv}/messages/stream", json={"message": "slow one"}).text)[-1]
    assert last["type"] == "error" and "keeps running" in last["text"] and "Try again" not in last["text"]
    assert client.get(f"/api/conversations/{conv}/messages").json()["pending"]["stage"] == "Waiting for the model"
    release.set()
    for _ in range(200):
        if m._pending(conv, users["alice"]["id"]) is None:
            break
        time.sleep(0.05)
    msgs = client.get(f"/api/conversations/{conv}/messages").json()["messages"]
    assert [x["content"] for x in msgs] == ["slow one", "late answer"]


def _wait_until_idle(conv: str, user_id: int) -> None:
    for _ in range(200):
        if m._pending(conv, user_id) is None:
            return
        time.sleep(0.05)
    raise AssertionError("the investigation never finished")


@pytest.mark.parametrize("spec_version", ["2.3", "2.4"])
def test_stream_client_disconnect_leaves_the_investigation_running(env, monkeypatch, spec_version):
    users, _ = env
    alice = users["alice"]
    conv = _new_conv(TestClient(m.app))
    release = threading.Event()
    monkeypatch.setattr(m, "orchestrated_llm_reply", lambda *a, **k: release.wait(10) and "late answer")
    path = f"/api/conversations/{conv}/messages/stream"
    scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": spec_version}, "http_version": "1.1",
             "method": "POST", "scheme": "http", "path": path, "raw_path": path.encode(), "root_path": "",
             "query_string": b"", "headers": [(b"host", b"testserver"), (b"content-type", b"application/json")],
             "client": ("testclient", 50000), "server": ("testserver", 80)}

    async def tab_closed():
        started = asyncio.Event()
        inbox = [{"type": "http.request", "body": json.dumps({"message": "slow one"}).encode(), "more_body": False}]

        async def receive():
            if inbox:
                return inbox.pop(0)
            await started.wait()
            return {"type": "http.disconnect"}  # how a pre-2.4 server reports it

        async def send(message):
            if message["type"] == "http.response.start":
                assert message["status"] == 200
                started.set()
            elif spec_version == "2.4":
                raise OSError("connection reset")  # a 2.4 server fails the send instead

        with contextlib.suppress(ClientDisconnect):
            await asyncio.wait_for(m.app(scope, receive, send), 10)

    asyncio.run(tab_closed())
    assert m._pending(conv, alice["id"]) is not None  # the stream is gone, the work is not
    release.set()
    _wait_until_idle(conv, alice["id"])
    msgs = m.store.get_conversation_for_user(alice["id"], conv)["messages"]
    assert [x["content"] for x in msgs] == ["slow one", "late answer"]


def test_post_message_saves_question_first_and_records_failures(env, monkeypatch):
    users, _ = env
    alice = users["alice"]
    client = TestClient(m.app)
    conv = _new_conv(client)
    url = f"/api/conversations/{conv}/messages"
    seen = {}

    def reply(system, history, **k):
        got = m.store.get_conversation_for_user(alice["id"], conv)
        seen.update(title=got["title"], saved=[x["content"] for x in got["messages"]],
                    stage=m._pending(conv, alice["id"])["stage"])
        return "the answer"
    monkeypatch.setattr(m, "chat_with_history", reply)

    r = client.post(url, json={"message": "Why is web-01 beaconing\nat night?"})
    assert r.status_code == 200 and r.json()["reply"] == "the answer"
    assert seen == {"title": "Why is web-01 beaconing", "saved": ["Why is web-01 beaconing\nat night?"],
                    "stage": "Waiting for the model"}
    got = client.get(url).json()
    assert got["pending"] is None and [x["role"] for x in got["messages"]] == ["user", "assistant"]

    # A run already going in the conversation: refused, nothing saved.
    assert m._inflight_claim(conv, alice["id"])
    busy = client.post(url, json={"message": "hello?"})
    assert busy.status_code == 409 and busy.json()["detail"] == "An investigation is already running in this conversation"
    m._inflight_release(conv)
    assert len(client.get(url).json()["messages"]) == 2

    def boom(*a, **k):
        raise RuntimeError("kaboom")
    monkeypatch.setattr(m, "chat_with_history", boom)
    r = TestClient(m.app, raise_server_exceptions=False).post(
        url, json={"message": "", "images": ["data:image/png;base64,AAAA"]})
    assert r.status_code == 500
    got = client.get(url).json()
    assert got["pending"] is None
    assert [(x["role"], x["content"]) for x in got["messages"][2:]] == [
        ("user", "[1 screenshot attached]"), ("assistant", "⚠ Investigation failed: kaboom")]


def test_alert_list_pages_with_total(env):
    client = TestClient(m.app)
    ids = [m.alerts_inbox.ingest({"title": f"alert {i}"})["id"] for i in range(5)]
    m.alerts_inbox.dismiss(ids[0], 1)

    page = client.get("/api/alerts?limit=2&offset=1").json()
    assert [a["id"] for a in page["alerts"]] == [a["id"] for a in m.alerts_inbox.list()[1:3]]
    assert (page["total"], page["new_count"]) == (5, 4)
    assert client.get("/api/alerts?status=new&limit=0").json() == {"alerts": [], "new_count": 4, "total": 4}
    assert len(client.get("/api/alerts?limit=100000&offset=-3").json()["alerts"]) == 5  # clamped, not rejected


def test_deleting_a_conversation_unlinks_alerts_and_cases(env):
    users, _ = env
    uid = users["alice"]["id"]
    client = TestClient(m.app)
    conv = _new_conv(client)
    claimed = m.alerts_inbox.ingest({"title": "claimed"})["id"]
    fp = m.alerts_inbox.ingest({"title": "agent fp"})["id"]
    assert m.alerts_inbox.mark_investigating(claimed, uid, conv)
    m.alerts_inbox.set_agent_outcome([fp], "dismissed", "Triage agent: false positive", conv)
    case = m.incident_store.create(user_id=uid, title="case")
    m.incident_store.link_conversation(uid, case["id"], conv)

    assert client.delete(f"/api/conversations/{conv}").json() == {"ok": True}
    a = m.alerts_inbox.get(claimed)
    assert (a["status"], a["conversation_id"], a["claimed_by"]) == ("new", None, None)
    b = m.alerts_inbox.get(fp)
    assert (b["status"], b["conversation_id"]) == ("dismissed", None)  # a dismissal is not undone
    assert m.incident_store.get_for_user(uid, case["id"])["conversations"] == []
    assert m.incident_store.list_for_user(uid)[0]["conversation_count"] == 0


def test_investigate_reissues_the_seed_and_reports_who_holds_the_alert(env):
    users, who = env
    alice, bob = users["alice"], users["bob"]
    client = TestClient(m.app)
    alert_id = m.alerts_inbox.ingest({"title": "Suspicious logon"}, source_hint="wazuh")["id"]
    url = f"/api/alerts/{alert_id}/investigate"

    first = client.post(url).json()
    assert first["already_claimed"] is False and first["conversation_is_mine"] is True
    assert "Suspicious logon" in first["seed_message"]
    conv = first["conversation_id"]
    # The seed never went out (UI busy, tab closed): asking again hands it out again.
    again = client.post(url).json()
    assert (again["conversation_id"], again["already_claimed"], again["seed_message"]) == (
        conv, True, first["seed_message"])
    m.store.add_message_for_user(alice["id"], conv, "user", first["seed_message"])
    assert client.post(url).json()["seed_message"] is None

    got = client.get(f"/api/alerts/{alert_id}").json()
    assert (got["claimed_by_username"], got["conversation_is_mine"]) == ("alice", True)
    who["user"] = bob
    got = client.get(f"/api/alerts/{alert_id}").json()
    assert (got["claimed_by_username"], got["conversation_is_mine"]) == ("alice", False)
    theirs = client.post(url).json()
    assert (theirs["already_claimed"], theirs["seed_message"], theirs["conversation_is_mine"]) == (True, None, False)

    # A link left dangling by an older delete: the alert can be claimed afresh.
    m.store.delete_conversation_for_user(alice["id"], conv)
    fresh = client.post(url).json()
    assert fresh["already_claimed"] is False and fresh["conversation_id"] != conv and fresh["seed_message"]
    assert m.store.owner_of(fresh["conversation_id"]) == bob["id"]
    assert m.alerts_inbox.get(alert_id)["claimed_by"] == bob["id"]


def test_investigating_alert_left_without_a_chat_can_be_claimed(env):
    users, _ = env
    client = TestClient(m.app)
    conv = _new_conv(client)
    alert_id = m.alerts_inbox.ingest({"title": "agent fp"})["id"]
    m.alerts_inbox.set_agent_outcome([alert_id], "dismissed", "Investigator agent: false positive", conv)
    assert client.delete(f"/api/conversations/{conv}").json() == {"ok": True}
    # agents.undo of that case_closed puts the alerts back to 'investigating', which has no chat now.
    m.alerts_inbox.set_agent_outcome([alert_id], "investigating", "Agent decision undone by admin")

    got = client.post(f"/api/alerts/{alert_id}/investigate").json()
    assert got["already_claimed"] is False and got["seed_message"] and got["conversation_id"]
    a = m.alerts_inbox.get(alert_id)
    assert (a["conversation_id"], a["claimed_by"]) == (got["conversation_id"], users["alice"]["id"])


def test_cross_origin_writes_are_rejected_except_the_siem_webhook(env):
    client = TestClient(m.app)
    evil = {"Origin": "https://tools.soc.example"}

    assert client.post("/api/conversations", json={}, headers=evil).status_code == 403
    assert client.get("/api/conversations", headers=evil).status_code == 200  # reads are not state-changing
    assert client.post("/api/conversations", json={}).status_code == 200  # no Origin: curl, scripts
    assert client.post("/api/conversations", json={}, headers={"Origin": "http://testserver"}).status_code == 200
    # Behind a proxy that rewrites Host, the forwarded host is what the browser saw.
    proxied = {"Origin": "https://nullshift.soc.example", "X-Forwarded-Host": "nullshift.soc.example"}
    assert client.post("/api/conversations", json={}, headers=proxied).status_code == 200
    rewritten = {"Origin": "https://nullshift.soc.example", "Sec-Fetch-Site": "same-origin"}
    assert client.post("/api/conversations", json={}, headers=rewritten).status_code == 200
    sibling = {**evil, "Sec-Fetch-Site": "same-site"}
    assert client.delete("/api/conversations/x", headers=sibling).status_code == 403

    r = client.post("/api/alerts/ingest", json={"title": "from the SIEM"},
                    headers={**evil, "X-Webhook-Token": "hook"})
    assert r.status_code == 200 and m.alerts_inbox.count() == 1


def test_validation_errors_return_structured_detail(env):
    client = TestClient(m.app)
    conv = _new_conv(client)
    r = client.post(f"/api/conversations/{conv}/messages/stream", json={"message": ["not", "text"]})
    assert r.status_code == 422
    body = r.json()
    assert set(body) == {"detail"} and body["detail"][0]["loc"] == ["body", "message"]
