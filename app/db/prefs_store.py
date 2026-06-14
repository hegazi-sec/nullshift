"""Per-user analyst preferences, persisted in SQLite.

A flat key/value bag — the LLM sees the whole dict each turn as a
USER_PREFERENCES system message and is expected to honor recognized keys
(output style, default time window, preferred SIEM, etc.). The store itself
is schemaless to keep adding a new pref a one-line change in the prompt or
client.

Values are JSON-encoded on write and decoded on read so bool/int/string
round-trip cleanly without per-key type registries.

Shares chat.db with the other stores; WAL mode handles multi-connection writes.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


DB_PATH = Path(__file__).resolve().parent.parent / 'data' / 'chat.db'


class PrefsStore:
    def __init__(self, db_path: Path = DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        self._ensure()

    def _ensure(self) -> None:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL;")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS user_prefs(
                    user_id INTEGER NOT NULL,
                    key TEXT NOT NULL,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (user_id, key)
                )
                """
            )
            self.conn.commit()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def get_all(self, user_id: int) -> Dict[str, Any]:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT key, value FROM user_prefs WHERE user_id=?", (user_id,))
            rows = cur.fetchall()
        out: Dict[str, Any] = {}
        for r in rows:
            try:
                out[r["key"]] = json.loads(r["value"])
            except (json.JSONDecodeError, TypeError):
                out[r["key"]] = r["value"]
        return out

    def set_many(self, user_id: int, prefs: Dict[str, Any]) -> int:
        """Upsert each key/value. A value of None deletes the key. Returns the
        number of keys written (deletes don't count)."""
        if not prefs:
            return 0
        now = self._now()
        to_upsert = []
        to_delete = []
        for k, v in prefs.items():
            if not isinstance(k, str) or not k.strip():
                continue
            if v is None:
                to_delete.append((user_id, k))
                continue
            try:
                payload = json.dumps(v, ensure_ascii=False)
            except (TypeError, ValueError):
                payload = json.dumps(str(v))
            to_upsert.append((user_id, k, payload, now))
        with self.lock:
            cur = self.conn.cursor()
            if to_upsert:
                cur.executemany(
                    """
                    INSERT INTO user_prefs(user_id, key, value, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(user_id, key) DO UPDATE SET
                        value=excluded.value,
                        updated_at=excluded.updated_at
                    """,
                    to_upsert,
                )
            if to_delete:
                cur.executemany(
                    "DELETE FROM user_prefs WHERE user_id=? AND key=?",
                    to_delete,
                )
            self.conn.commit()
        return len(to_upsert)


prefs = PrefsStore()
