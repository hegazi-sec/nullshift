"""Per-conversation summary cache, persisted in SQLite.

Stores LLM-generated summaries of past chat conversations so that future
conversations can be primed with a short recap of the analyst's recent work,
without re-injecting every prior message.

Design notes:
- Generated lazily: a summary is only created when another conversation needs
  to reference this one. Conversations never read again incur zero cost.
- Stored verbatim from the LLM. We never re-summarize a summary (no recursive
  compression — drift would accumulate).
- `message_count` captures the snapshot size; if the conversation grows
  afterwards, the summary becomes stale but is still useful. Re-generation
  on staleness is out of scope for MVP.
- Shares chat.db with the other stores; JOINs to `conversations` for
  ordering by recent activity.
"""
from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


DB_PATH = Path(__file__).resolve().parent.parent / 'data' / 'chat.db'


class SummaryStore:
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
                CREATE TABLE IF NOT EXISTS conversation_summaries(
                    conversation_id TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    summary_md TEXT NOT NULL,
                    message_count INTEGER NOT NULL,
                    summarized_at TEXT NOT NULL
                )
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_conv_summaries_user ON conversation_summaries(user_id)"
            )
            self.conn.commit()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def get(self, conversation_id: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                """
                SELECT conversation_id, user_id, summary_md, message_count, summarized_at
                FROM conversation_summaries WHERE conversation_id=?
                """,
                (conversation_id,),
            )
            row = cur.fetchone()
        return dict(row) if row else None

    def set(self, conversation_id: str, user_id: int, summary_md: str, message_count: int) -> None:
        now = self._now()
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                """
                INSERT INTO conversation_summaries(conversation_id, user_id, summary_md, message_count, summarized_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(conversation_id) DO UPDATE SET
                    summary_md=excluded.summary_md,
                    message_count=excluded.message_count,
                    summarized_at=excluded.summarized_at
                """,
                (conversation_id, user_id, summary_md, message_count, now),
            )
            self.conn.commit()

    def list_recent_for_user(
        self,
        user_id: int,
        limit: int = 3,
        exclude_conversation_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return cached summaries for the user's most recently active
        conversations (ordered by conversations.updated_at DESC). Optionally
        excludes one conversation (typically the current one).
        """
        with self.lock:
            cur = self.conn.cursor()
            if exclude_conversation_id:
                cur.execute(
                    """
                    SELECT s.conversation_id, c.title, s.summary_md, s.message_count, s.summarized_at
                    FROM conversation_summaries s
                    JOIN conversations c ON c.id = s.conversation_id
                    WHERE s.user_id=? AND s.conversation_id<>?
                    ORDER BY c.updated_at DESC
                    LIMIT ?
                    """,
                    (user_id, exclude_conversation_id, limit),
                )
            else:
                cur.execute(
                    """
                    SELECT s.conversation_id, c.title, s.summary_md, s.message_count, s.summarized_at
                    FROM conversation_summaries s
                    JOIN conversations c ON c.id = s.conversation_id
                    WHERE s.user_id=?
                    ORDER BY c.updated_at DESC
                    LIMIT ?
                    """,
                    (user_id, limit),
                )
            return [dict(r) for r in cur.fetchall()]


summaries = SummaryStore()
