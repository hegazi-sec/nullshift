import sqlite3
import threading
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timezone
import uuid


DB_PATH = Path(__file__).resolve().parent.parent / 'data' / 'chat.db'


class ChatStore:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        self._ensure()

    def _ensure(self):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL;")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS conversations(
                  id TEXT PRIMARY KEY,
                  title TEXT,
                  user_id INTEGER,
                  created_at TEXT,
                  updated_at TEXT
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS messages(
                  id TEXT PRIMARY KEY,
                  conversation_id TEXT,
                  role TEXT CHECK(role IN ('user','assistant','system')),
                  content TEXT,
                  created_at TEXT,
                  FOREIGN KEY(conversation_id) REFERENCES conversations(id)
                )
                """
            )
            # Migration: ensure user_id exists if DB was created before
            cur.execute("PRAGMA table_info(conversations)")
            cols = {r[1] for r in cur.fetchall()}
            if 'user_id' not in cols:
                try:
                    cur.execute("ALTER TABLE conversations ADD COLUMN user_id INTEGER")
                except Exception:
                    pass
            self.conn.commit()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def create_conversation(self, title: Optional[str] = None) -> Dict[str, str]:
        with self.lock:
            conv_id = uuid.uuid4().hex
            now = self._now()
            cur = self.conn.cursor()
            cur.execute(
                "INSERT INTO conversations(id,title,user_id,created_at,updated_at) VALUES(?,?,?,?,?)",
                (conv_id, title or "New chat", None, now, now),
            )
            self.conn.commit()
            return {"id": conv_id, "title": title or "New chat", "created_at": now, "updated_at": now}

    def create_conversation_for_user(self, user_id: int, title: Optional[str] = None) -> Dict[str, str]:
        with self.lock:
            conv_id = uuid.uuid4().hex
            now = self._now()
            cur = self.conn.cursor()
            cur.execute(
                "INSERT INTO conversations(id,title,user_id,created_at,updated_at) VALUES(?,?,?,?,?)",
                (conv_id, title or "New chat", user_id, now, now),
            )
            self.conn.commit()
            return {"id": conv_id, "title": title or "New chat", "created_at": now, "updated_at": now}

    def set_title_if_empty(self, conversation_id: str, title: str):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT title FROM conversations WHERE id=?", (conversation_id,))
            row = cur.fetchone()
            if not row:
                return
            if not row["title"] or row["title"] == "New chat":
                cur.execute(
                    "UPDATE conversations SET title=?, updated_at=? WHERE id=?",
                    (title, self._now(), conversation_id),
                )
                self.conn.commit()

    def list_conversations(self) -> List[Dict[str, str]]:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                "SELECT id, title, updated_at FROM conversations ORDER BY updated_at DESC"
            )
            return [dict(r) for r in cur.fetchall()]

    def list_conversations_for_user(self, user_id: int) -> List[Dict[str, str]]:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                """
                SELECT c.id, c.title, c.updated_at,
                       v.verdict as last_verdict
                FROM conversations c
                LEFT JOIN (
                    SELECT conversation_id, verdict
                    FROM verdicts
                    WHERE user_id = ?
                    GROUP BY conversation_id
                    HAVING max(created_at)
                ) v ON v.conversation_id = c.id
                WHERE c.user_id = ?
                ORDER BY c.updated_at DESC
                """,
                (user_id, user_id),
            )
            return [dict(r) for r in cur.fetchall()]

    def get_conversation(self, conversation_id: str) -> Optional[Dict]:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT id, title, created_at, updated_at FROM conversations WHERE id=?", (conversation_id,))
            conv = cur.fetchone()
            if not conv:
                return None
            cur.execute(
                "SELECT role, content, created_at FROM messages WHERE conversation_id=? ORDER BY created_at ASC",
                (conversation_id,),
            )
            msgs = [dict(r) for r in cur.fetchall()]
            return {"id": conv["id"], "title": conv["title"], "created_at": conv["created_at"], "updated_at": conv["updated_at"], "messages": msgs}

    def get_conversation_for_user(self, user_id: int, conversation_id: str) -> Optional[Dict]:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                "SELECT id, title, created_at, updated_at FROM conversations WHERE id=? AND user_id=?",
                (conversation_id, user_id),
            )
            conv = cur.fetchone()
            if not conv:
                return None
            cur.execute(
                "SELECT role, content, created_at FROM messages WHERE conversation_id=? ORDER BY created_at ASC",
                (conversation_id,),
            )
            msgs = [dict(r) for r in cur.fetchall()]
            return {"id": conv["id"], "title": conv["title"], "created_at": conv["created_at"], "updated_at": conv["updated_at"], "messages": msgs}

    def add_message(self, conversation_id: str, role: str, content: str) -> Dict[str, str]:
        with self.lock:
            msg_id = uuid.uuid4().hex
            now = self._now()
            cur = self.conn.cursor()
            cur.execute(
                "INSERT INTO messages(id, conversation_id, role, content, created_at) VALUES(?,?,?,?,?)",
                (msg_id, conversation_id, role, content, now),
            )
            cur.execute(
                "UPDATE conversations SET updated_at=? WHERE id=?",
                (now, conversation_id),
            )
            self.conn.commit()
            return {"id": msg_id, "created_at": now}

    def add_message_for_user(self, user_id: int, conversation_id: str, role: str, content: str) -> Dict[str, str]:
        """Insert a message only if the conversation belongs to user_id.

        Raises PermissionError if the conversation does not exist or is owned
        by a different user (including orphaned rows with user_id IS NULL).
        """
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT user_id FROM conversations WHERE id=?", (conversation_id,))
            row = cur.fetchone()
            if not row or row["user_id"] is None or row["user_id"] != user_id:
                raise PermissionError(f"conversation {conversation_id} not accessible")
            msg_id = uuid.uuid4().hex
            now = self._now()
            cur.execute(
                "INSERT INTO messages(id, conversation_id, role, content, created_at) VALUES(?,?,?,?,?)",
                (msg_id, conversation_id, role, content, now),
            )
            cur.execute(
                "UPDATE conversations SET updated_at=? WHERE id=?",
                (now, conversation_id),
            )
            self.conn.commit()
            return {"id": msg_id, "created_at": now}

    def set_title_if_empty_for_user(self, user_id: int, conversation_id: str, title: str) -> None:
        """Update title only if the conversation belongs to user_id and is empty/default."""
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT user_id, title FROM conversations WHERE id=?", (conversation_id,))
            row = cur.fetchone()
            if not row or row["user_id"] is None or row["user_id"] != user_id:
                raise PermissionError(f"conversation {conversation_id} not accessible")
            if not row["title"] or row["title"] == "New chat":
                cur.execute(
                    "UPDATE conversations SET title=?, updated_at=? WHERE id=?",
                    (title, self._now(), conversation_id),
                )
                self.conn.commit()

    def last_messages(self, conversation_id: str, limit: int = 20) -> List[Dict[str, str]]:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                """
                SELECT role, content, created_at FROM (
                  SELECT role, content, created_at
                  FROM messages WHERE conversation_id=?
                  ORDER BY created_at DESC
                  LIMIT ?
                ) sub
                ORDER BY created_at ASC
                """,
                (conversation_id, limit),
            )
            return [dict(r) for r in cur.fetchall()]

    def delete_conversation_for_user(self, user_id: int, conversation_id: str) -> bool:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT user_id FROM conversations WHERE id=?", (conversation_id,))
            row = cur.fetchone()
            if not row or row["user_id"] != user_id:
                return False
            cur.execute("DELETE FROM messages WHERE conversation_id=?", (conversation_id,))
            cur.execute("DELETE FROM conversations WHERE id=?", (conversation_id,))
            self.conn.commit()
            return True

    def last_messages_for_user(self, user_id: int, conversation_id: str, limit: int = 20) -> List[Dict[str, str]]:
        """Return last messages only if the conversation belongs to user_id.

        Raises PermissionError if the conversation does not exist or is owned
        by another user. Distinct from get_conversation_for_user, which
        silently returns None — writes upstream rely on a hard failure here.
        """
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT user_id FROM conversations WHERE id=?", (conversation_id,))
            row = cur.fetchone()
            if not row or row["user_id"] is None or row["user_id"] != user_id:
                raise PermissionError(f"conversation {conversation_id} not accessible")
            cur.execute(
                """
                SELECT role, content, created_at FROM (
                  SELECT role, content, created_at
                  FROM messages WHERE conversation_id=?
                  ORDER BY created_at DESC
                  LIMIT ?
                ) sub
                ORDER BY created_at ASC
                """,
                (conversation_id, limit),
            )
            return [dict(r) for r in cur.fetchall()]


store = ChatStore()
