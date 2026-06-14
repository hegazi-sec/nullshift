"""Per-conversation investigation state, persisted in SQLite.

Replaces an in-process dict (`INVESTIGATION_STATE`) in main.py that was lost
on every uvicorn restart and didn't work with multiple workers — each worker
held its own copy, so a follow-up request hitting worker B couldn't see
state written by worker A on the same conversation.

The stored shape is dynamic (it evolves with the orchestration code), so
state is serialized as a JSON blob keyed by `conversation_id`.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


DB_PATH = Path(__file__).resolve().parent.parent / 'data' / 'chat.db'


class InvestigationStateStore:
    """SQLite-backed store for per-conversation investigation state.

    Shares the chat.db file with ChatStore but uses its own connection. SQLite
    with WAL mode handles multi-connection concurrency on the same file.
    """

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
                CREATE TABLE IF NOT EXISTS investigation_state(
                    conversation_id TEXT PRIMARY KEY,
                    state_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            self.conn.commit()

    def get(self, conversation_id: str) -> Optional[Dict[str, Any]]:
        """Return the stored state dict for a conversation, or None."""
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                "SELECT state_json FROM investigation_state WHERE conversation_id=?",
                (conversation_id,),
            )
            row = cur.fetchone()
        if not row:
            return None
        try:
            data = json.loads(row["state_json"])
        except (json.JSONDecodeError, TypeError):
            return None
        return data if isinstance(data, dict) else None

    def set(self, conversation_id: str, state: Dict[str, Any]) -> None:
        """Upsert the state dict for a conversation.

        Non-JSON-serializable values fall back to str() via json.dumps default.
        If serialization fails entirely we store an empty dict rather than
        crashing the caller.
        """
        try:
            payload = json.dumps(state, default=str, ensure_ascii=False)
        except Exception:
            payload = "{}"
        now = datetime.now(timezone.utc).isoformat()
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                """
                INSERT INTO investigation_state(conversation_id, state_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(conversation_id) DO UPDATE SET
                    state_json=excluded.state_json,
                    updated_at=excluded.updated_at
                """,
                (conversation_id, payload, now),
            )
            self.conn.commit()

    def delete(self, conversation_id: str) -> None:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                "DELETE FROM investigation_state WHERE conversation_id=?",
                (conversation_id,),
            )
            self.conn.commit()


inv_state = InvestigationStateStore()
