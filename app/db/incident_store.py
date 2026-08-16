"""Incident / case tracking, persisted in SQLite.

Turns ephemeral chat investigations into trackable SOC cases. An incident
groups one or more conversations under a case number with severity, status,
and a final verdict, so an analyst can follow a threat across sessions and
close it out formally.

Design notes:
- Scoped per-user, same as conversations and verdicts. Case numbers
  (INC-0001, INC-0002, ...) are sequential per user, allocated inside the
  store lock.
- Conversations link to incidents through a join table so one case can span
  multiple chats. Conversation ownership is verified by the caller (routes
  check via ChatStore) — this store only guards incident ownership.
- Shares chat.db with ChatStore/VerdictStore; WAL mode handles the
  multi-connection writes.
"""
from __future__ import annotations

import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


DB_PATH = Path(__file__).resolve().parent.parent / 'data' / 'chat.db'

SEVERITIES = ("low", "medium", "high", "critical")
STATUSES = ("open", "investigating", "closed")


def case_number(seq: int) -> str:
    return f"INC-{seq:04d}"


class IncidentStore:
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
                CREATE TABLE IF NOT EXISTS incidents(
                    id TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    case_seq INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL DEFAULT 'medium'
                        CHECK(severity IN ('low','medium','high','critical')),
                    status TEXT NOT NULL DEFAULT 'open'
                        CHECK(status IN ('open','investigating','closed')),
                    verdict TEXT,
                    notes TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    closed_at TEXT
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS incident_conversations(
                    incident_id TEXT NOT NULL,
                    conversation_id TEXT NOT NULL,
                    linked_at TEXT NOT NULL,
                    PRIMARY KEY (incident_id, conversation_id)
                )
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_incidents_user ON incidents(user_id, status)"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_inc_conv_conv ON incident_conversations(conversation_id)"
            )
            self.conn.commit()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["case_number"] = case_number(d["case_seq"])
        return d

    def create(
        self,
        user_id: int,
        title: str,
        severity: str = "medium",
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        if severity not in SEVERITIES:
            raise ValueError(f"invalid severity: {severity}")
        title = (title or "").strip() or "Untitled case"
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                "SELECT COALESCE(MAX(case_seq), 0) + 1 FROM incidents WHERE user_id=?",
                (user_id,),
            )
            seq = cur.fetchone()[0]
            inc_id = uuid.uuid4().hex
            now = self._now()
            cur.execute(
                """
                INSERT INTO incidents(id, user_id, case_seq, title, severity, status,
                                      verdict, notes, created_at, updated_at, closed_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,NULL)
                """,
                (inc_id, user_id, seq, title, severity, "open", None, notes, now, now),
            )
            self.conn.commit()
        return {
            "id": inc_id,
            "case_number": case_number(seq),
            "case_seq": seq,
            "title": title,
            "severity": severity,
            "status": "open",
            "verdict": None,
            "notes": notes,
            "created_at": now,
            "updated_at": now,
            "closed_at": None,
        }

    def list_for_user(
        self, user_id: int, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        with self.lock:
            cur = self.conn.cursor()
            if status:
                cur.execute(
                    """
                    SELECT i.*, COUNT(ic.conversation_id) AS conversation_count
                    FROM incidents i
                    LEFT JOIN incident_conversations ic ON ic.incident_id = i.id
                    WHERE i.user_id=? AND i.status=?
                    GROUP BY i.id
                    ORDER BY i.updated_at DESC
                    """,
                    (user_id, status),
                )
            else:
                cur.execute(
                    """
                    SELECT i.*, COUNT(ic.conversation_id) AS conversation_count
                    FROM incidents i
                    LEFT JOIN incident_conversations ic ON ic.incident_id = i.id
                    WHERE i.user_id=?
                    GROUP BY i.id
                    ORDER BY i.updated_at DESC
                    """,
                    (user_id,),
                )
            return [self._row_to_dict(r) for r in cur.fetchall()]

    def get_for_user(self, user_id: int, incident_id: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                "SELECT * FROM incidents WHERE id=? AND user_id=?",
                (incident_id, user_id),
            )
            row = cur.fetchone()
            if not row:
                return None
            inc = self._row_to_dict(row)
            try:
                cur.execute(
                    """
                    SELECT ic.conversation_id, ic.linked_at, c.title, c.updated_at
                    FROM incident_conversations ic
                    LEFT JOIN conversations c ON c.id = ic.conversation_id
                    WHERE ic.incident_id=?
                    ORDER BY ic.linked_at ASC
                    """,
                    (incident_id,),
                )
            except sqlite3.OperationalError:
                # conversations table lives in chat_store; if it hasn't been
                # created yet in this DB, return links without titles.
                cur.execute(
                    """
                    SELECT conversation_id, linked_at, NULL AS title, NULL AS updated_at
                    FROM incident_conversations
                    WHERE incident_id=?
                    ORDER BY linked_at ASC
                    """,
                    (incident_id,),
                )
            inc["conversations"] = [dict(r) for r in cur.fetchall()]
            return inc

    def update_for_user(
        self, user_id: int, incident_id: str, fields: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Apply a partial update. Returns the updated incident, or None if
        not found / not owned. Raises ValueError on invalid severity/status."""
        allowed = {"title", "severity", "status", "verdict", "notes"}
        updates = {k: v for k, v in fields.items() if k in allowed and v is not None}
        # Empty string clears the nullable free-text fields.
        for k in ("verdict", "notes"):
            if k in updates and not str(updates[k]).strip():
                updates[k] = None
        if not updates:
            return self.get_for_user(user_id, incident_id)
        if "severity" in updates and updates["severity"] not in SEVERITIES:
            raise ValueError(f"invalid severity: {updates['severity']}")
        if "status" in updates and updates["status"] not in STATUSES:
            raise ValueError(f"invalid status: {updates['status']}")
        if "title" in updates:
            updates["title"] = (updates["title"] or "").strip() or "Untitled case"
        now = self._now()
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                "SELECT status FROM incidents WHERE id=? AND user_id=?",
                (incident_id, user_id),
            )
            row = cur.fetchone()
            if not row:
                return None
            # closed_at follows status transitions
            if "status" in updates:
                if updates["status"] == "closed" and row["status"] != "closed":
                    updates["closed_at"] = now
                elif updates["status"] != "closed" and row["status"] == "closed":
                    updates["closed_at"] = None
            updates["updated_at"] = now
            set_clause = ", ".join(f"{k}=?" for k in updates)
            cur.execute(
                f"UPDATE incidents SET {set_clause} WHERE id=? AND user_id=?",
                (*updates.values(), incident_id, user_id),
            )
            self.conn.commit()
        return self.get_for_user(user_id, incident_id)

    def delete_for_user(self, user_id: int, incident_id: str) -> bool:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                "SELECT id FROM incidents WHERE id=? AND user_id=?",
                (incident_id, user_id),
            )
            if not cur.fetchone():
                return False
            cur.execute(
                "DELETE FROM incident_conversations WHERE incident_id=?", (incident_id,)
            )
            cur.execute("DELETE FROM incidents WHERE id=?", (incident_id,))
            self.conn.commit()
            return True

    def link_conversation(
        self, user_id: int, incident_id: str, conversation_id: str
    ) -> bool:
        """Link a conversation to an incident. Caller must have verified the
        conversation belongs to user_id. Returns False if the incident is not
        owned by user_id; True if linked (idempotent on duplicates)."""
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                "SELECT id FROM incidents WHERE id=? AND user_id=?",
                (incident_id, user_id),
            )
            if not cur.fetchone():
                return False
            now = self._now()
            cur.execute(
                """
                INSERT OR IGNORE INTO incident_conversations(incident_id, conversation_id, linked_at)
                VALUES (?,?,?)
                """,
                (incident_id, conversation_id, now),
            )
            cur.execute(
                "UPDATE incidents SET updated_at=? WHERE id=?", (now, incident_id)
            )
            self.conn.commit()
            return True

    def unlink_conversation(
        self, user_id: int, incident_id: str, conversation_id: str
    ) -> bool:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                "SELECT id FROM incidents WHERE id=? AND user_id=?",
                (incident_id, user_id),
            )
            if not cur.fetchone():
                return False
            cur.execute(
                "DELETE FROM incident_conversations WHERE incident_id=? AND conversation_id=?",
                (incident_id, conversation_id),
            )
            changed = cur.rowcount > 0
            if changed:
                cur.execute(
                    "UPDATE incidents SET updated_at=? WHERE id=?",
                    (self._now(), incident_id),
                )
            self.conn.commit()
            return changed

    def incidents_for_conversation(
        self, user_id: int, conversation_id: str
    ) -> List[Dict[str, Any]]:
        """Cases this conversation is attached to (for the chat header badge)."""
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                """
                SELECT i.* FROM incidents i
                JOIN incident_conversations ic ON ic.incident_id = i.id
                WHERE ic.conversation_id=? AND i.user_id=?
                ORDER BY i.updated_at DESC
                """,
                (conversation_id, user_id),
            )
            return [self._row_to_dict(r) for r in cur.fetchall()]


incidents = IncidentStore()
