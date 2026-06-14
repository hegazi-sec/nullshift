from pathlib import Path

import pytest

from app.db.prefs_store import PrefsStore


@pytest.fixture
def store(tmp_path: Path) -> PrefsStore:
    return PrefsStore(db_path=tmp_path / "test_prefs.db")


def test_empty_returns_empty_dict(store: PrefsStore):
    assert store.get_all(user_id=1) == {}


def test_set_and_get_roundtrip(store: PrefsStore):
    store.set_many(1, {"output_style": "concise", "default_time_window": "last_7d"})
    out = store.get_all(1)
    assert out == {"output_style": "concise", "default_time_window": "last_7d"}


def test_value_types_roundtrip(store: PrefsStore):
    store.set_many(1, {
        "skip_section_1_for_low_confidence": True,
        "max_results": 50,
        "tags": ["soc", "l1"],
        "nested": {"a": 1},
    })
    out = store.get_all(1)
    assert out["skip_section_1_for_low_confidence"] is True
    assert out["max_results"] == 50
    assert out["tags"] == ["soc", "l1"]
    assert out["nested"] == {"a": 1}


def test_upsert_overwrites_existing(store: PrefsStore):
    store.set_many(1, {"output_style": "concise"})
    store.set_many(1, {"output_style": "detailed"})
    assert store.get_all(1) == {"output_style": "detailed"}


def test_user_scoping(store: PrefsStore):
    store.set_many(1, {"output_style": "concise"})
    store.set_many(2, {"output_style": "detailed"})
    assert store.get_all(1) == {"output_style": "concise"}
    assert store.get_all(2) == {"output_style": "detailed"}


def test_none_value_deletes_key(store: PrefsStore):
    store.set_many(1, {"output_style": "concise", "default_time_window": "last_7d"})
    store.set_many(1, {"output_style": None})
    assert store.get_all(1) == {"default_time_window": "last_7d"}


def test_empty_or_invalid_keys_are_ignored(store: PrefsStore):
    store.set_many(1, {"": "x", "   ": "y", "valid": "z"})
    assert store.get_all(1) == {"valid": "z"}


def test_empty_dict_is_noop(store: PrefsStore):
    assert store.set_many(1, {}) == 0
    assert store.get_all(1) == {}
