import getpass
import os
import secrets
import sys

import pytest

# app.auth refuses to import without a JWT secret, and a fresh checkout has none configured.
os.environ.setdefault("JWT_SECRET", secrets.token_urlsafe(32))

import cli  # noqa: E402
from app.auth import verify_password  # noqa: E402
from app.db import user_store  # noqa: E402


def test_passwd_sets_hash_and_rejects_weak_or_mismatched(tmp_path, monkeypatch):
    monkeypatch.setattr(user_store, "DB_PATH", str(tmp_path / "users.db"))
    user_store.init_db()
    user_store.create_user("admin", "old-hash", "admin")
    monkeypatch.setattr(sys, "argv", ["nullshift", "passwd", "admin"])

    def answer(*replies):
        it = iter(replies)
        monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(it))

    for bad in (["too-short"], ["a-long-enough-password-1", "a-different-password-22"]):
        answer(*bad)
        with pytest.raises(SystemExit):
            cli.cmd_passwd()
    assert user_store.get_user_by_username("admin")["password_hash"] == "old-hash"

    answer("a-long-enough-password-1", "a-long-enough-password-1")
    cli.cmd_passwd()
    assert verify_password("a-long-enough-password-1", user_store.get_user_by_username("admin")["password_hash"])
