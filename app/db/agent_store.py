"""Audit trail for the autonomous agents, plus containment proposals.

Every agent action lands in agent_log with the data needed to undo the
autonomous false-positive decisions (alert ids, case id, owner). Containment
proposals wait here until an analyst approves or rejects them.
Shares chat.db with the other stores; WAL handles multi-connection writes.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


DB_PATH = Path(__file__).resolve().parent.parent / 'data' / 'chat.db'


class AgentStore:
    def __init__(self, db_path: Path = DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            self.conn.execute("PRAGMA journal_mode=WAL;")
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS agent_log(
                    id TEXT PRIMARY KEY,
                    agent TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target_id TEXT,
                    detail TEXT,
                    data_json TEXT,
                    created_at TEXT NOT NULL,
                    undone_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_agent_log_time ON agent_log(created_at);
                CREATE TABLE IF NOT EXISTS containment_proposals(
                    id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    sid TEXT NOT NULL,
                    hostname TEXT,
                    reason TEXT,
                    status TEXT NOT NULL DEFAULT 'proposed'
                        CHECK(status IN ('proposed','rejected','executed','failed','released')),
                    created_at TEXT NOT NULL,
                    decided_by INTEGER,
                    decided_at TEXT,
                    result TEXT
                );
                """
            )
            self.conn.commit()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _rows(self, sql: str, *args: Any) -> List[Dict[str, Any]]:
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    # ── activity log ─────────────────────────────────────────────────
    def log(self, agent: str, action: str, target_id: Optional[str] = None,
            detail: str = "", data: Optional[Dict[str, Any]] = None) -> str:
        log_id = uuid.uuid4().hex
        with self.lock:
            self.conn.execute(
                "INSERT INTO agent_log(id, agent, action, target_id, detail, data_json, created_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (log_id, agent, action, target_id, detail, json.dumps(data or {}), self._now()),
            )
            self.conn.commit()
        return log_id

    def recent(self, limit: int = 60) -> List[Dict[str, Any]]:
        return self._rows("SELECT * FROM agent_log ORDER BY created_at DESC LIMIT ?", limit)

    def since(self, iso: str) -> List[Dict[str, Any]]:
        return self._rows("SELECT * FROM agent_log WHERE created_at >= ?", iso)

    def get(self, log_id: str) -> Optional[Dict[str, Any]]:
        rows = self._rows("SELECT * FROM agent_log WHERE id=?", log_id)
        return rows[0] if rows else None

    def entries(self, agent: str, action: str) -> List[Dict[str, Any]]:
        return self._rows(
            "SELECT * FROM agent_log WHERE agent=? AND action=? AND undone_at IS NULL ORDER BY created_at",
            agent, action,
        )

    def targets(self, agent: str) -> Set[str]:
        return {r["target_id"] for r in self._rows("SELECT target_id FROM agent_log WHERE agent=?", agent)}

    def last(self, agent: str, action: str) -> Optional[Dict[str, Any]]:
        rows = self._rows(
            "SELECT * FROM agent_log WHERE agent=? AND action=? ORDER BY created_at DESC LIMIT 1", agent, action
        )
        return rows[0] if rows else None

    def mark_undone(self, log_id: str) -> bool:
        with self.lock:
            cur = self.conn.execute(
                "UPDATE agent_log SET undone_at=? WHERE id=? AND undone_at IS NULL", (self._now(), log_id)
            )
            self.conn.commit()
            return cur.rowcount > 0

    # ── containment proposals ────────────────────────────────────────
    def propose(self, case_id: str, sid: str, hostname: Optional[str], reason: str) -> Optional[Dict[str, Any]]:
        """New isolation proposal, or None if one is already open for this case and sensor."""
        if self._rows(
            "SELECT id FROM containment_proposals WHERE case_id=? AND sid=? AND status IN ('proposed','executed')",
            case_id, sid,
        ):
            return None
        pid = uuid.uuid4().hex
        with self.lock:
            self.conn.execute(
                "INSERT INTO containment_proposals(id, case_id, sid, hostname, reason, created_at) "
                "VALUES (?,?,?,?,?,?)",
                (pid, case_id, sid, hostname, reason, self._now()),
            )
            self.conn.commit()
        return self.get_proposal(pid)

    def proposals(self, limit: int = 30) -> List[Dict[str, Any]]:
        return self._rows(
            "SELECT * FROM containment_proposals ORDER BY (status='proposed') DESC, created_at DESC LIMIT ?", limit
        )

    def get_proposal(self, pid: str) -> Optional[Dict[str, Any]]:
        rows = self._rows("SELECT * FROM containment_proposals WHERE id=?", pid)
        return rows[0] if rows else None

    def decide(self, pid: str, from_status: str, to_status: str, user_id: int, result: str = "") -> bool:
        """Move a proposal between states; False if it was not in from_status (e.g. a double click)."""
        with self.lock:
            cur = self.conn.execute(
                "UPDATE containment_proposals SET status=?, decided_by=?, decided_at=?, result=? "
                "WHERE id=? AND status=?",
                (to_status, user_id, self._now(), result, pid, from_status),
            )
            self.conn.commit()
            return cur.rowcount > 0


agent_store = AgentStore()
