"""Auth guards and the admin/setup routes.

Temp users.db, an in-memory settings store and stubbed `requests`: nothing here
touches data/config.db, the network or an LLM.
"""
import json
import os
import secrets
import sqlite3

import pytest

# app.auth refuses to import without a JWT secret, and a fresh checkout has none configured.
os.environ.setdefault("JWT_SECRET", secrets.token_urlsafe(32))

from fastapi.testclient import TestClient  # noqa: E402

import app.auth as auth  # noqa: E402
import app.main as m  # noqa: E402
from app.db import user_store  # noqa: E402

CSRF = "csrf-test-token"


@pytest.fixture
def store(tmp_path, monkeypatch):
    """Temp users.db plus a dict standing in for config.db (settings_store is a
    shared singleton, so patching its methods covers main, auth and llm)."""
    monkeypatch.setattr(user_store, "DB_PATH", str(tmp_path / "users.db"))
    user_store.init_db()
    cfg = {"setup_complete": "true"}

    def set_many(updates, updated_by=None):
        for k, v in updates.items():
            if v is None or (isinstance(v, str) and not v.strip()):
                cfg.pop(k, None)
            else:
                cfg[k] = str(v)
        return len(updates)

    monkeypatch.setattr(m.settings_store, "get", lambda k: cfg.get(k))
    monkeypatch.setattr(m.settings_store, "set_many", set_many)
    return cfg


def add_user(name, role="admin", active=True):
    uid = user_store.create_user(name, auth.get_password_hash("a-long-enough-password"), role)
    if not active:
        with user_store.get_conn() as conn:
            conn.execute("UPDATE users SET is_active = 0 WHERE id = ?", (uid,))
    return uid


def client_as(username=None, role="admin", csrf=True):
    cookies = {}
    if username:
        cookies[auth.COOKIE_NAME] = auth.create_access_token({"sub": username, "role": role})
    cookies[auth.CSRF_COOKIE] = CSRF
    c = TestClient(m.app, cookies=cookies, follow_redirects=False)
    if csrf:
        c.headers["X-CSRF-Token"] = CSRF
    return c


def is_active(uid):
    return bool(user_store.get_user_by_id(uid)["is_active"])


# ── Disabling users ──────────────────────────────────────────────────────────

def test_admin_cannot_disable_themselves(store):
    me = add_user("admin")
    r = client_as("admin").patch(f"/admin/users/{me}/disable")
    assert r.status_code == 409 and "own account" in r.json()["detail"]
    assert is_active(me)


def test_disable_refuses_to_leave_no_active_admin(store):
    only_admin = add_user("admin")
    analyst = add_user("analyst", role="l1")
    # The route's self-check covers the single-caller case; the helper is what
    # stops two admins disabling each other at once from leaving none.
    assert auth._set_user_active(only_admin, False) is False
    assert is_active(only_admin)
    assert auth._set_user_active(analyst, False) is True
    assert not is_active(analyst)


def test_admin_can_disable_and_reenable_another_user(store):
    add_user("admin")
    other = add_user("admin2")
    c = client_as("admin")
    assert c.patch(f"/admin/users/{other}/disable").status_code == 200
    assert not is_active(other)
    # A disabled account can no longer use its session
    assert client_as("admin2").get("/admin/users").status_code == 401
    assert c.patch(f"/admin/users/{other}/enable").status_code == 200
    assert is_active(other)
    assert c.patch("/admin/users/999/enable").status_code == 404


def test_user_actions_require_csrf(store):
    add_user("admin")
    other = add_user("analyst", role="l1")
    c = client_as("admin", csrf=False)
    assert c.patch(f"/admin/users/{other}/disable").status_code == 403
    assert c.patch(f"/admin/users/{other}/enable").status_code == 403
    r = c.post("/admin/users", json={"username": "x1", "password": "a-long-enough-password", "role": "l1"})
    assert r.status_code == 403
    assert is_active(other) and user_store.get_user_by_username("x1") is None


def test_list_users_reports_the_caller(store):
    me = add_user("admin")
    add_user("analyst", role="l1")
    j = client_as("admin").get("/admin/users").json()
    assert j["me"] == me and len(j["users"]) == 2


# ── Creating users ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("body, detail", [
    ({"username": "shorty", "password": "too-short", "role": "l1"}, "at least 16"),
    ({"username": "<img src=x>", "password": "a-long-enough-password", "role": "l1"}, "letters, digits"),
    # `$` matches before a trailing newline: this would be a lookalike admin
    ({"username": "admin\n", "password": "a-long-enough-password", "role": "admin"}, "letters, digits"),
    ({"username": "ok_name", "password": "a-long-enough-password", "role": "root"}, "role"),
])
def test_create_user_validation(store, body, detail):
    add_user("admin")
    r = client_as("admin").post("/admin/users", json=body)
    assert r.status_code == 400 and detail in r.json()["detail"]


def test_create_user_ok_then_conflict(store):
    add_user("admin")
    c = client_as("admin")
    body = {"username": "analyst.02@soc", "password": "a-long-enough-password", "role": "l2"}
    assert c.post("/admin/users", json=body).status_code == 200
    assert c.post("/admin/users", json=body).status_code == 409


# ── Login and the /admin page ────────────────────────────────────────────────

def test_failed_login_returns_to_the_form(store):
    add_user("admin")
    add_user("gone", active=False)
    c = client_as()
    for user, pw in (("admin", "wrong-password-here"), ("nobody", "x"), ("gone", "a-long-enough-password")):
        r = c.post("/login", data={"username": user, "password": pw})
        assert r.status_code == 303 and r.headers["location"] == "/login?error=1"
    r = c.post("/login", data={"username": "admin", "password": "a-long-enough-password"})
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert auth.COOKIE_NAME in r.cookies


def test_admin_page_redirects_instead_of_json(store):
    add_user("admin")
    add_user("analyst", role="l1")
    assert client_as().get("/admin").headers["location"] == "/login"
    assert client_as("analyst", role="l1").get("/admin").headers["location"] == "/"
    r = client_as("admin").get("/admin")
    assert r.status_code == 200 and auth.CSRF_COOKIE in r.cookies


# ── Setup predicate ──────────────────────────────────────────────────────────

def test_setup_counts_accounts_in_users_db(store):
    store.pop("setup_complete")
    assert auth.is_setup_complete() is False
    assert client_as().get("/login").headers["location"] == "/setup"
    add_user("admin")
    # Flag missing but an account exists: /login must serve the form, not
    # bounce to /setup (which sends it back to / -> /login forever).
    assert auth.is_setup_complete() is True and m._is_setup_complete() is True
    assert client_as().get("/login").status_code == 200
    assert client_as().get("/setup").headers["location"] == "/"
    r = client_as().post("/api/setup/complete", json={"admin_username": "admin", "admin_password": "x" * 20})
    assert r.status_code == 403


@pytest.mark.parametrize("broken", ["settings", "users"])
def test_setup_check_fails_closed_on_db_error(store, monkeypatch, broken):
    """The wizard is unauthenticated and creates an admin, so a DB error must
    count as "setup done" rather than open it to anyone."""
    def locked(*a, **kw):
        raise sqlite3.OperationalError("database is locked")

    store.pop("setup_complete")
    if broken == "settings":
        monkeypatch.setattr(m.settings_store, "get", locked)
    else:
        monkeypatch.setattr(user_store, "any_users_exist", locked)
    assert auth.is_setup_complete() is True
    assert client_as().get("/setup").headers["location"] == "/"
    r = client_as().post("/api/setup/complete", json={"admin_username": "mallory", "admin_password": "x" * 20})
    assert r.status_code == 403 and user_store.get_user_by_username("mallory") is None


def test_setup_rejects_bad_username(store):
    store.pop("setup_complete")
    r = client_as().post("/api/setup/complete", json={"admin_username": "a b<c>", "admin_password": "x" * 20})
    assert r.status_code == 400 and user_store.any_users_exist() is False


# ── Settings PUT: routing that goes nowhere is refused ───────────────────────

@pytest.fixture
def routing(store, monkeypatch):
    """Stub provider state resolved from the stored settings, like llm.py: a
    provider is usable when its `<name>_api_key` is stored, and the effective
    chain is the saved chain (or pin) narrowed to usable providers."""
    import app.rag
    store["openai_api_key"] = "sk-test"

    def creds():
        return {n for n in ("openai", "gemini") if store.get(f"{n}_api_key")}

    def effective():
        chain = json.loads(store.get("provider_chain") or '["openai", "gemini"]')
        active = store.get("active_provider") or "auto"
        return [n for n in chain if n in creds() and active in ("auto", n)]

    monkeypatch.setattr(m, "reload_providers", lambda: {})
    monkeypatch.setattr(m, "configured_provider_names", effective)
    monkeypatch.setattr(m, "_providers_with_credentials", creds)
    monkeypatch.setattr(app.rag, "reload_rag", lambda: {})  # key saves reload RAG
    add_user("admin")


@pytest.mark.parametrize("payload", [
    {"provider_chain": "[]"},
    {"provider_chain": "not json"},
    {"provider_chain": '["openai", "nope"]'},
    {"active_provider": "nope"},
])
def test_malformed_routing_is_rejected_before_saving(routing, store, payload):
    r = client_as("admin").put("/api/admin/settings", json=payload)
    assert r.status_code == 400
    assert "provider_chain" not in store and "active_provider" not in store


def test_routing_that_leaves_no_provider_is_rolled_back(routing, store):
    store["provider_chain"] = '["openai"]'
    c = client_as("admin")
    r = c.put("/api/admin/settings", json={"provider_chain": '["gemini"]'})
    assert r.status_code == 400 and "None of the providers" in r.json()["detail"]
    assert store["provider_chain"] == '["openai"]'
    r = c.put("/api/admin/settings", json={"active_provider": "gemini"})
    assert r.status_code == 400 and "not configured" in r.json()["detail"]
    assert "active_provider" not in store
    # Non-routing changes still save, with a warning instead of silent success
    r = c.put("/api/admin/settings", json={"openai_api_key": ""})
    assert r.status_code == 200 and r.json()["warning"] and "openai_api_key" not in store


@pytest.mark.parametrize("fix", [
    # Unpin first (the chain is still dead), then route the chain to OpenAI
    [{"active_provider": "auto"}, {"provider_chain": '["gemini", "openai"]'}],
    # Or add OpenAI to the chain first (the pin still blocks), then pin it
    [{"provider_chain": '["gemini", "openai"]'}, {"active_provider": "openai"}],
])
def test_routing_that_was_already_broken_can_be_fixed(routing, store, fix):
    """Pinned to Gemini, then its key cleared: routing is dead before any
    routing change. Rolling back every change that leaves it dead would leave
    no single save that gets out, so those save with a warning instead."""
    store.update({"gemini_api_key": "g-test", "provider_chain": '["gemini"]', "active_provider": "gemini"})
    c = client_as("admin")
    assert c.put("/api/admin/settings", json={"gemini_api_key": ""}).json()["warning"]
    assert c.put("/api/admin/settings", json={"openai_api_key": "sk-new"}).json()["warning"]
    first, second = fix
    r = c.put("/api/admin/settings", json=first)
    assert r.status_code == 200 and r.json()["effective_chain"] == []
    assert r.json()["warning"] and all(store[k] == v for k, v in first.items())
    if "provider_chain" in first:
        # The pin is what blocks the new chain, so the warning names it
        assert "Active provider Google Gemini is not configured" in r.json()["warning"]
    r = c.put("/api/admin/settings", json=second)
    assert r.status_code == 200 and r.json()["warning"] is None
    assert r.json()["effective_chain"] == ["openai"]


def test_routing_save_reports_effective_chain(routing, store):
    r = client_as("admin").put("/api/admin/settings", json={"provider_chain": '["openai"]'})
    assert r.status_code == 200
    assert r.json()["effective_chain"] == ["openai"] and r.json()["warning"] is None


# ── Connector tests ──────────────────────────────────────────────────────────

class _Resp:
    def __init__(self, status):
        self.status_code = status
        self.headers = {}

    def json(self):
        return {}


@pytest.fixture
def http(monkeypatch):
    import requests
    calls = []

    def fake_get(url, **kw):
        calls.append((url, kw))
        return _Resp(calls_status[0])

    calls_status = [200]
    monkeypatch.setattr(requests, "get", fake_get)
    return calls, calls_status


def test_connector_tests_require_csrf(store, http):
    add_user("admin")
    c = client_as("admin", csrf=False)
    assert c.post("/api/admin/connectors/vt/test", json={}).status_code == 403
    assert c.post("/api/admin/connectors/siem/wazuh/test", json={}).status_code == 403
    assert http[0] == []


def test_stored_secret_is_only_sent_to_the_stored_url(store, http):
    calls, _ = http
    add_user("admin")
    store.update({"wazuh_indexer_url": "https://idx:9200", "wazuh_indexer_user": "admin",
                  "wazuh_indexer_pass": "s3cret"})
    c = client_as("admin")
    r = c.post("/api/admin/connectors/siem/wazuh/test", json={"wazuh_indexer_url": "https://evil.example:9200"})
    assert r.json()["ok"] is False and calls == []
    r = c.post("/api/admin/connectors/siem/wazuh/test", json={"wazuh_indexer_url": "https://idx:9200/"})
    assert r.json() == {"ok": True}
    assert calls[0][0] == "https://idx:9200/_cluster/health" and calls[0][1]["auth"] == ("admin", "s3cret")


def test_vt_test_uses_the_typed_key(store, http, monkeypatch):
    calls, status = http
    add_user("admin")
    status[0] = 401
    r = client_as("admin").post("/api/admin/connectors/vt/test", json={"api_key": "typed-key"})
    assert r.json() == {"ok": False, "error": "VirusTotal rejected the key"}
    assert calls[0][1]["headers"] == {"x-apikey": "typed-key"}


def test_vision_table_comes_from_the_backend(store):
    add_user("admin")
    rows = {p["name"]: p for p in client_as("admin").get("/api/admin/vision").json()["providers"]}
    assert set(rows) == {e["name"] for e in m._PROVIDER_CATALOG}
    assert rows["deepseek"]["supported"] is None and "deepseek-flash" in rows["deepseek"]["note"]
    assert "grok-4.7" in rows["xai"]["note"]
