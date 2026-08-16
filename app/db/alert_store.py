"""Webhook alert inbox, persisted in SQLite.

SIEMs push alerts to POST /api/alerts/ingest; they land here as a shared
inbox visible to every analyst. An analyst claims one by starting an
investigation (which creates a conversation owned by them) or dismisses it.

Design notes:
- Alerts arrive without a user context, so the inbox is global — unlike
  conversations/incidents which are per-user. `claimed_by` records who acted.
- The raw payload is stored verbatim (JSON text, size-capped at the route) so
  nothing the SIEM sent is lost; title/severity/source are best-effort
  extractions for list display.
- Shares chat.db with the other stores; WAL handles multi-connection writes.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


DB_PATH = Path(__file__).resolve().parent.parent / 'data' / 'chat.db'

ALERT_STATUSES = ("new", "investigating", "dismissed")

_SEVERITY_MAP = {
    # numeric levels (Wazuh 0-15, generic 1-10)
    **{str(n): "low" for n in range(0, 6)},
    **{str(n): "medium" for n in range(6, 10)},
    **{str(n): "high" for n in range(10, 13)},
    **{str(n): "critical" for n in range(13, 16)},
    # common words
    "info": "low", "informational": "low", "low": "low",
    "medium": "medium", "moderate": "medium",
    "high": "high", "important": "high",
    "critical": "critical", "severe": "critical",
}


def normalize_severity(raw: Any) -> str:
    if raw is None:
        return "medium"
    return _SEVERITY_MAP.get(str(raw).strip().lower(), "medium")


def extract_alert_fields(payload: Dict[str, Any]) -> Dict[str, str]:
    """Best-effort title/severity/source from common SIEM webhook shapes.

    Recognizes Wazuh ({rule:{description,level}}), LimaCharlie ({cat,detect}),
    Splunk ({search_name,result}), Elastic ({rule:{name,severity}} or
    {alert:{...}}), and generic {title|name|message, severity|level} bodies.
    """
    title = None
    severity = None
    source = None

    rule = payload.get("rule")
    if isinstance(rule, dict):
        title = rule.get("description") or rule.get("name")
        severity = rule.get("level") or rule.get("severity")
        if rule.get("description") and payload.get("agent"):
            source = "wazuh"
        elif rule.get("name"):
            source = "elastic"

    if not title and payload.get("cat"):
        title = str(payload["cat"])
        source = source or "limacharlie"
    if not title and payload.get("search_name"):
        title = str(payload["search_name"])
        source = source or "splunk"

    if not title:
        for key in ("title", "name", "alert_name", "message", "description"):
            if payload.get(key):
                title = str(payload[key])
                break
    if severity is None:
        for key in ("severity", "level", "priority", "risk_score"):
            if payload.get(key) is not None:
                severity = payload[key]
                break

    return {
        "title": (title or "Untitled alert")[:200],
        "severity": normalize_severity(severity),
        "source": (source or str(payload.get("source") or "unknown"))[:40],
    }


class AlertStore:
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
                CREATE TABLE IF NOT EXISTS ingested_alerts(
                    id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'new'
                        CHECK(status IN ('new','investigating','dismissed')),
                    claimed_by INTEGER,
                    conversation_id TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_alerts_status ON ingested_alerts(status, created_at)"
            )
            self.conn.commit()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def ingest(self, payload: Dict[str, Any], source_hint: Optional[str] = None) -> Dict[str, Any]:
        fields = extract_alert_fields(payload if isinstance(payload, dict) else {})
        if source_hint:
            fields["source"] = source_hint[:40]
        alert_id = uuid.uuid4().hex
        now = self._now()
        try:
            raw = json.dumps(payload, default=str, ensure_ascii=False)
        except Exception:
            raw = "{}"
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                """
                INSERT INTO ingested_alerts(id, source, title, severity, payload_json,
                                            status, claimed_by, conversation_id,
                                            created_at, updated_at)
                VALUES (?,?,?,?,?,'new',NULL,NULL,?,?)
                """,
                (alert_id, fields["source"], fields["title"], fields["severity"],
                 raw, now, now),
            )
            self.conn.commit()
        return {"id": alert_id, **fields, "status": "new", "created_at": now}

    def list(self, status: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Inbox listing — payload omitted to keep the response small."""
        with self.lock:
            cur = self.conn.cursor()
            if status:
                cur.execute(
                    """
                    SELECT id, source, title, severity, status, claimed_by,
                           conversation_id, created_at
                    FROM ingested_alerts WHERE status=?
                    ORDER BY created_at DESC LIMIT ?
                    """,
                    (status, limit),
                )
            else:
                cur.execute(
                    """
                    SELECT id, source, title, severity, status, claimed_by,
                           conversation_id, created_at
                    FROM ingested_alerts
                    ORDER BY created_at DESC LIMIT ?
                    """,
                    (limit,),
                )
            return [dict(r) for r in cur.fetchall()]

    def count_new(self) -> int:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT COUNT(*) FROM ingested_alerts WHERE status='new'")
            return int(cur.fetchone()[0])

    def get(self, alert_id: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT * FROM ingested_alerts WHERE id=?", (alert_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def mark_investigating(self, alert_id: str, user_id: int, conversation_id: str) -> bool:
        """Claim an alert. Only transitions from 'new' — first analyst wins."""
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                """
                UPDATE ingested_alerts
                SET status='investigating', claimed_by=?, conversation_id=?, updated_at=?
                WHERE id=? AND status='new'
                """,
                (user_id, conversation_id, self._now(), alert_id),
            )
            self.conn.commit()
            return cur.rowcount > 0

    def dismiss(self, alert_id: str, user_id: int) -> bool:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                """
                UPDATE ingested_alerts
                SET status='dismissed', claimed_by=?, updated_at=?
                WHERE id=? AND status IN ('new','investigating')
                """,
                (user_id, self._now(), alert_id),
            )
            self.conn.commit()
            return cur.rowcount > 0


alerts_inbox = AlertStore()
