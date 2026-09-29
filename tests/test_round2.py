"""The in-flight event stream, forking an alert someone else holds, the
Content-Security-Policy on every page, and the same-origin check on writes.

Temp DBs and an in-memory settings store: nothing here touches data/config.db,
the network or an LLM.
"""
import json
import os
import re
import secrets
import threading

os.environ.setdefault("JWT_SECRET", secrets.token_urlsafe(32))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import app.auth as auth  # noqa: E402
import app.main as m  # noqa: E402
from app.auth import get_current_user  # noqa: E402
from app.db import user_store  # noqa: E402
from app.db.alert_store import AlertStore  # noqa: E402
from app.db.chat_store import ChatStore  # noqa: E402
from app.db.incident_store import IncidentStore  # noqa: E402
from app.db.verdict_store import VerdictStore  # noqa: E402


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Temp stores, two analysts, and the API logged in as whoever who["user"] is."""
    db = tmp_path / "chat.db"
    monkeypatch.setattr(m, "store", ChatStore(db_path=db))
    monkeypatch.setattr(m, "alerts_inbox", AlertStore(db_path=db))
    monkeypatch.setattr(m, "incident_store", IncidentStore(db_path=db))
    monkeypatch.setattr(m, "verdict_store", VerdictStore(db_path=db))
    monkeypatch.setattr(user_store, "DB_PATH", str(tmp_path / "users.db"))
    user_store.init_db()
    users = {n: {"id": user_store.create_user(n, "x", "l1"), "username": n, "role": "l1"}
             for n in ("alice", "bob")}
    who = {"user": users["alice"]}
    m.app.dependency_overrides[get_current_user] = lambda: who["user"]
    yield users, who
    m.app.dependency_overrides.pop(get_current_user, None)
    with m._INFLIGHT_LOCK:
        m._INFLIGHT.clear()


@pytest.fixture
def pages(tmp_path, monkeypatch):
    """Temp users.db and a dict standing in for config.db, for the HTML pages
    that check the session cookie themselves."""
    monkeypatch.setattr(user_store, "DB_PATH", str(tmp_path / "users.db"))
    user_store.init_db()
    cfg = {}
    monkeypatch.setattr(m.settings_store, "get", lambda k: cfg.get(k))
    return cfg


def _events(body: str):
    return [json.loads(line[6:]) for line in body.splitlines() if line.startswith("data: ")]


def _client_as(username=None, role="admin"):
    cookies = {}
    if username:
        user_store.create_user(username, auth.get_password_hash("a-long-enough-password"), role)
        cookies[auth.COOKIE_NAME] = auth.create_access_token({"sub": username, "role": role})
    return TestClient(m.app, cookies=cookies, follow_redirects=False)


# ── GET /api/inflight ────────────────────────────────────────────────────────

def test_inflight_stream_sends_this_users_runs_and_drops_finished_ones(env, monkeypatch):
    users, who = env
    alice, bob = users["alice"], users["bob"]
    monkeypatch.setattr(m, "_INFLIGHT_STREAM_S", 2.0)
    monkeypatch.setattr(m, "_INFLIGHT_POLL_S", 0.05)
    assert m._inflight_claim("conv-a", alice["id"])
    assert m._inflight_claim("conv-b", bob["id"])
    since = m._INFLIGHT["conv-a"]["started_at"]
    stage = threading.Timer(0.5, m._inflight_update, args=("conv-a",), kwargs={"stage": "Querying SIEM"})
    done = threading.Timer(1.0, m._inflight_release, args=("conv-a",))
    stage.start()
    done.start()
    r = TestClient(m.app).get("/api/inflight")  # the test client returns once the stream ends
    stage.join()
    done.join()

    assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
    assert (r.headers["cache-control"], r.headers["x-accel-buffering"]) == ("no-cache", "no")
    # The full set on connect, again on each change, and nothing while it stays the same.
    assert _events(r.text) == [
        {"type": "pending", "pending": {"conv-a": {"stage": "Analyzing query", "since": since}}},
        {"type": "pending", "pending": {"conv-a": {"stage": "Querying SIEM", "since": since}}},
        {"type": "pending", "pending": {}},
    ]

    # Bob sees only his own run, and never alice's.
    who["user"] = bob
    first = _events(TestClient(m.app).get("/api/inflight").text)[0]
    assert list(first["pending"]) == ["conv-b"]
    m._inflight_release("conv-b")
    assert _events(TestClient(m.app).get("/api/inflight").text) == [{"type": "pending", "pending": {}}]


def test_inflight_stream_requires_a_session(env):
    m.app.dependency_overrides.pop(get_current_user, None)
    assert TestClient(m.app).get("/api/inflight").status_code == 401


# ── POST /api/alerts/{id}/investigate?fork=1 ─────────────────────────────────

def test_fork_on_a_claimable_or_own_alert_is_a_normal_investigate(env):
    users, _ = env
    client = TestClient(m.app)
    plain_id = m.alerts_inbox.ingest({"title": "plain"})["id"]
    fork_id = m.alerts_inbox.ingest({"title": "forked"})["id"]

    plain = client.post(f"/api/alerts/{plain_id}/investigate").json()
    first = client.post(f"/api/alerts/{fork_id}/investigate?fork=1").json()
    assert set(first) == set(plain) and "forked" not in first
    assert (first["already_claimed"], first["conversation_is_mine"], first["claimed_by_username"]) == (
        False, True, "alice")
    a = m.alerts_inbox.get(fork_id)
    assert (a["status"], a["claimed_by"], a["conversation_id"]) == (
        "investigating", users["alice"]["id"], first["conversation_id"])
    # Already mine: the same chat comes back, as without fork.
    again = client.post(f"/api/alerts/{fork_id}/investigate?fork=1").json()
    assert (again["conversation_id"], again["already_claimed"]) == (first["conversation_id"], True)
    assert "forked" not in again


def test_fork_gives_a_separate_chat_and_leaves_the_alert_alone(env):
    users, who = env
    alice, bob = users["alice"], users["bob"]
    client = TestClient(m.app)
    title = "Suspicious logon from a very long named host " + "x" * 40
    alert_id = m.alerts_inbox.ingest({"title": title}, source_hint="wazuh")["id"]
    url = f"/api/alerts/{alert_id}/investigate"
    claimed = client.post(url).json()["conversation_id"]
    before = m.alerts_inbox.get(alert_id)

    who["user"] = bob
    theirs = client.post(url).json()  # without fork: still only who holds it
    assert (theirs["conversation_id"], theirs["conversation_is_mine"], theirs["seed_message"]) == (
        claimed, False, None)
    forked = client.post(f"{url}?fork=1").json()
    assert (forked["forked"], forked["conversation_is_mine"], forked["claimed_by_username"]) == (
        True, True, "alice")
    cid = forked["conversation_id"]
    assert cid != claimed and m.store.owner_of(cid) == bob["id"]
    assert m.store.get_conversation_for_user(bob["id"], cid)["title"] == f"[Alert] {title}"[:60]
    assert "Suspicious logon" in forked["seed_message"]
    assert m.alerts_inbox.get(alert_id) == before
    assert m.store.get_conversation_for_user(alice["id"], claimed) is not None


def test_fork_works_on_a_dismissed_alert_and_keeps_it_dismissed(env):
    users, who = env
    client = TestClient(m.app)
    alert_id = m.alerts_inbox.ingest({"title": "noise"})["id"]
    assert client.post(f"/api/alerts/{alert_id}/dismiss").json() == {"ok": True}
    before = m.alerts_inbox.get(alert_id)

    who["user"] = users["bob"]
    assert client.post(f"/api/alerts/{alert_id}/investigate").status_code == 409
    forked = client.post(f"/api/alerts/{alert_id}/investigate?fork=1").json()
    assert forked["forked"] is True and m.store.owner_of(forked["conversation_id"]) == users["bob"]["id"]
    assert m.alerts_inbox.get(alert_id) == before


def test_fork_claims_a_new_alert_that_an_undone_agent_decision_left_linked(env):
    # The triage agent dismisses with alice's chat, an undo puts the alert back
    # to 'new' and keeps that link: it is claimable, so fork=1 claims it.
    users, who = env
    alice, bob = users["alice"], users["bob"]
    client = TestClient(m.app)
    alert_id = m.alerts_inbox.ingest({"title": "agent undo"})["id"]
    agent_chat = m.store.create_conversation_for_user(alice["id"], title="[Triage] agent undo")["id"]
    m.alerts_inbox.set_agent_outcome([alert_id], "dismissed", "Triage agent: false positive", agent_chat)
    m.alerts_inbox.set_agent_outcome([alert_id], "new", "Agent decision undone by alice")
    assert m.alerts_inbox.get(alert_id)["conversation_id"] == agent_chat

    who["user"] = bob
    res = client.post(f"/api/alerts/{alert_id}/investigate?fork=1").json()
    assert "forked" not in res
    assert (res["already_claimed"], res["conversation_is_mine"], res["claimed_by_username"]) == (False, True, "bob")
    a = m.alerts_inbox.get(alert_id)
    assert (a["status"], a["claimed_by"], a["conversation_id"]) == ("investigating", bob["id"], res["conversation_id"])
    assert m.store.owner_of(res["conversation_id"]) == bob["id"]


# ── Content-Security-Policy ──────────────────────────────────────────────────

def _assert_csp(r, scripts=True):
    csp = r.headers["content-security-policy"]
    assert "default-src 'self'" in csp and "object-src 'none'" in csp and "frame-ancestors 'none'" in csp
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["referrer-policy"] == "same-origin"
    if not scripts:
        assert "script-src 'none'" in csp and "<script" not in r.text.lower()
        return None
    nonce = re.search(r"script-src 'self' 'nonce-([A-Za-z0-9_-]{16,})'", csp).group(1)
    tags = re.findall(r"<script\b[^>]*>", r.text, flags=re.I)
    assert tags and all(f'nonce="{nonce}"' in t for t in tags)
    assert r.text.count(f'nonce="{nonce}"') == len(tags)
    return nonce


def test_setup_page_has_a_csp_nonce(pages):
    r = _client_as().get("/setup")
    assert r.status_code == 200
    _assert_csp(r)


def test_login_ui_and_admin_pages_have_a_fresh_csp_nonce(pages):
    pages["setup_complete"] = "true"
    anon = _client_as()
    r = anon.get("/login")
    assert r.status_code == 200
    assert _assert_csp(r) != _assert_csp(anon.get("/login"))  # new per response

    admin = _client_as("admin")
    r = admin.get("/")
    assert r.status_code == 200 and "<title>" in r.text
    _assert_csp(r)
    r = admin.get("/admin")
    assert r.status_code == 200
    _assert_csp(r)
    assert "no-store" in r.headers["cache-control"] and auth.CSRF_COOKIE in r.cookies


def test_incident_report_runs_only_its_print_script(env):
    users, _ = env
    client = TestClient(m.app)
    conv = client.post("/api/conversations", json={}).json()["id"]
    m.store.add_message_for_user(users["alice"]["id"], conv, "user", "<script>alert(1)</script>")
    case = client.post("/api/incidents", json={"title": "<script>x</script>", "conversation_id": conv}).json()
    r = client.get(f"/api/incidents/{case['id']}/report")
    assert r.status_code == 200
    assert "&lt;script&gt;alert(1)" in r.text and "&lt;script&gt;x" in r.text
    # One script, the print button's, with the nonce; chat content stays escaped text.
    _assert_csp(r)
    assert len(re.findall(r"<script\b", r.text, flags=re.I)) == 1
    assert "window.print()" in r.text and not re.search(r"\son[a-z]+=", r.text, flags=re.I)


def test_api_docs_and_schema_are_not_served(pages):
    pages["setup_complete"] = "true"
    for client in (_client_as(), _client_as("admin")):
        for path in ("/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"):
            r = client.get(path)
            assert r.status_code == 404 and '"paths"' not in r.text, path


# ── Same-origin check on every write ─────────────────────────────────────────

EVIL = {"Origin": "https://tools.soc.example"}


def test_login_and_other_non_api_writes_need_the_same_origin(pages):
    pages["setup_complete"] = "true"
    client = _client_as()
    form = {"username": "nobody", "password": "wrong-password-here"}
    assert client.post("/login", data=form, headers=EVIL).status_code == 403
    same = client.post("/login", data=form, headers={"Origin": "http://testserver"})
    assert same.status_code == 303 and same.headers["location"] == "/login?error=1"
    assert client.post("/login", data=form).status_code == 303  # no Origin: curl, scripts
    assert client.post("/logout", headers=EVIL).status_code == 403
    assert client.post("/logout").status_code == 303
    assert client.post("/chat", json={"message": "hi"}, headers=EVIL).status_code == 403
    assert client.post("/admin/users", json={}, headers=EVIL).status_code == 403
    assert client.patch("/admin/users/1/disable", headers=EVIL).status_code == 403


def test_siem_webhook_post_stays_exempt(env, monkeypatch):
    monkeypatch.setattr(m, "settings_store", type("S", (), {"get": staticmethod(
        lambda k: "hook" if k == "webhook_token" else None)})())
    client = TestClient(m.app)
    r = client.post("/api/alerts/ingest", json={"title": "from the SIEM"},
                    headers={**EVIL, "X-Webhook-Token": "hook"})
    assert r.status_code == 200 and m.alerts_inbox.count() == 1
    # Only the POST is exempt.
    assert client.delete("/api/alerts/ingest", headers=EVIL).status_code == 403
