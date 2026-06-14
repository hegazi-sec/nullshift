import time
from pathlib import Path

import pytest

from app.db.chat_store import ChatStore
from app.db.summary_store import SummaryStore


@pytest.fixture
def stores(tmp_path: Path):
    db = tmp_path / "test_chat.db"
    return ChatStore(db_path=db), SummaryStore(db_path=db)


def test_get_missing_returns_none(stores):
    _, summaries = stores
    assert summaries.get("nope") is None


def test_set_and_get_roundtrip(stores):
    chat, summaries = stores
    conv = chat.create_conversation_for_user(user_id=1, title="Test")
    summaries.set(conv["id"], 1, "first summary", 5)
    row = summaries.get(conv["id"])
    assert row["summary_md"] == "first summary"
    assert row["message_count"] == 5
    assert row["user_id"] == 1


def test_upsert_overwrites(stores):
    chat, summaries = stores
    conv = chat.create_conversation_for_user(user_id=1)
    summaries.set(conv["id"], 1, "v1", 3)
    summaries.set(conv["id"], 1, "v2", 8)
    row = summaries.get(conv["id"])
    assert row["summary_md"] == "v2"
    assert row["message_count"] == 8


def test_list_recent_orders_by_conversation_updated_at(stores):
    chat, summaries = stores
    # Small sleeps so conversations.updated_at differs by more than the SQLite
    # second-resolution of datetime() comparisons isn't a factor — ordering
    # uses raw ISO strings which compare lexically.
    c1 = chat.create_conversation_for_user(user_id=1, title="oldest")
    chat.add_message_for_user(1, c1["id"], "user", "hello")
    summaries.set(c1["id"], 1, "summary-1", 1)
    time.sleep(0.01)

    c2 = chat.create_conversation_for_user(user_id=1, title="middle")
    chat.add_message_for_user(1, c2["id"], "user", "hello")
    summaries.set(c2["id"], 1, "summary-2", 1)
    time.sleep(0.01)

    c3 = chat.create_conversation_for_user(user_id=1, title="newest")
    chat.add_message_for_user(1, c3["id"], "user", "hello")
    summaries.set(c3["id"], 1, "summary-3", 1)

    out = summaries.list_recent_for_user(user_id=1, limit=3)
    assert [r["title"] for r in out] == ["newest", "middle", "oldest"]


def test_list_recent_excludes_current(stores):
    chat, summaries = stores
    c1 = chat.create_conversation_for_user(user_id=1, title="a")
    chat.add_message_for_user(1, c1["id"], "user", "hi")
    summaries.set(c1["id"], 1, "sa", 1)
    time.sleep(0.01)
    c2 = chat.create_conversation_for_user(user_id=1, title="b")
    chat.add_message_for_user(1, c2["id"], "user", "hi")
    summaries.set(c2["id"], 1, "sb", 1)

    out = summaries.list_recent_for_user(user_id=1, limit=3, exclude_conversation_id=c2["id"])
    assert len(out) == 1
    assert out[0]["conversation_id"] == c1["id"]


def test_list_recent_is_user_scoped(stores):
    chat, summaries = stores
    c1 = chat.create_conversation_for_user(user_id=1, title="u1")
    chat.add_message_for_user(1, c1["id"], "user", "x")
    summaries.set(c1["id"], 1, "s1", 1)
    c2 = chat.create_conversation_for_user(user_id=2, title="u2")
    chat.add_message_for_user(2, c2["id"], "user", "x")
    summaries.set(c2["id"], 2, "s2", 1)

    r1 = summaries.list_recent_for_user(user_id=1)
    r2 = summaries.list_recent_for_user(user_id=2)
    assert len(r1) == 1 and r1[0]["title"] == "u1"
    assert len(r2) == 1 and r2[0]["title"] == "u2"
