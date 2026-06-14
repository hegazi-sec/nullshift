import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from typing import Optional, List, Dict, Any

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'users.db'))

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin','l1','l2')),
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_login TEXT
);
"""


def _now_iso() -> str:
    return datetime.utcnow().isoformat(timespec='seconds') + 'Z'


@contextmanager
def get_conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with get_conn() as conn:
        conn.execute(SCHEMA)


def any_users_exist() -> bool:
    with get_conn() as conn:
        cur = conn.execute("SELECT COUNT(1) AS c FROM users")
        row = cur.fetchone()
        return (row[0] if row else 0) > 0


def create_user(username: str, password_hash: str, role: str) -> int:
    created_at = _now_iso()
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, role, is_active, created_at) VALUES (?,?,?,?,?)",
            (username, password_hash, role, 1, created_at)
        )
        return cur.lastrowid


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    with get_conn() as conn:
        cur = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    with get_conn() as conn:
        cur = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        return dict(row) if row else None


def list_users() -> List[Dict[str, Any]]:
    with get_conn() as conn:
        cur = conn.execute("SELECT id, username, role, is_active, created_at, last_login FROM users ORDER BY id ASC")
        return [dict(r) for r in cur.fetchall()]


def disable_user(user_id: int) -> None:
    with get_conn() as conn:
        conn.execute("UPDATE users SET is_active = 0 WHERE id = ?", (user_id,))


def update_last_login(username: str) -> None:
    with get_conn() as conn:
        conn.execute("UPDATE users SET last_login = ? WHERE username = ?", (_now_iso(), username))
