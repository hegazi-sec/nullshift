"""Regression test: ORDER BY must not wrap timestamps in datetime().

SQLite's datetime() function truncates microseconds, so any two rows written
within the same second collapse to equal sort keys and end up in undefined
(rowid) order. The stores use full-precision ISO timestamps; ordering must
compare them as raw strings so microsecond precision is preserved.
"""
import time
from pathlib import Path

import pytest

from app.db.chat_store import ChatStore


@pytest.fixture
def chat(tmp_path: Path) -> ChatStore:
    return ChatStore(db_path=tmp_path / "test_chat.db")


def test_list_conversations_newest_first_within_one_second(chat: ChatStore):
    c1 = chat.create_conversation_for_user(1, title="first")
    chat.add_message_for_user(1, c1["id"], "user", "hi")
    time.sleep(0.005)
    c2 = chat.create_conversation_for_user(1, title="second")
    chat.add_message_for_user(1, c2["id"], "user", "hi")
    time.sleep(0.005)
    c3 = chat.create_conversation_for_user(1, title="third")
    chat.add_message_for_user(1, c3["id"], "user", "hi")

    out = chat.list_conversations_for_user(1)
    assert [c["title"] for c in out] == ["third", "second", "first"]


def test_messages_oldest_first_within_one_second(chat: ChatStore):
    conv = chat.create_conversation_for_user(1)
    chat.add_message_for_user(1, conv["id"], "user", "m1")
    time.sleep(0.005)
    chat.add_message_for_user(1, conv["id"], "assistant", "m2")
    time.sleep(0.005)
    chat.add_message_for_user(1, conv["id"], "user", "m3")

    out = chat.last_messages_for_user(1, conv["id"], limit=10)
    assert [m["content"] for m in out] == ["m1", "m2", "m3"]
