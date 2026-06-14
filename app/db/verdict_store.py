"""IOC verdict cache, persisted in SQLite.

Records the LLM's per-investigation classification (Likely Benign / Suspicious
/ Malicious / Inconclusive) keyed by the IOCs that appeared in the user's
message. Subsequent investigations can look these up and surface them to the
LLM as additional evidence — always with an audit pointer (conversation_id +
timestamp) so the analyst can verify the source.

Design notes:
- Scoped per-user. Team-wide sharing would need an org/team concept that
  doesn't exist in the user model yet.
- Verdict text is preserved verbatim from the LLM reply; we never re-summarize
  a stored verdict before surfacing it again, to avoid drift.
- A row is inserted even when verdict/confidence parsing fails (NULL columns)
  so the analyst can still audit what was looked at and when.
- Shares chat.db with ChatStore and InvestigationStateStore; WAL mode handles
  multi-connection writes.
"""
from __future__ import annotations

import json
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


DB_PATH = Path(__file__).resolve().parent.parent / 'data' / 'chat.db'


_DECISION_TOKENS = ("Likely Benign", "Suspicious", "Malicious", "Inconclusive")
_DECISION_RE = re.compile(
    r"(Likely\s+Benign|Suspicious|Malicious|Inconclusive)",
    re.IGNORECASE,
)
_ANCHOR_RE = re.compile(r"(SECTION\s*3|Decision|Verdict)", re.IGNORECASE)
_CONFIDENCE_RE = re.compile(r"Confidence[^A-Za-z\n]*?(Low|Medium|High)", re.IGNORECASE)


def parse_decision(reply_md: str) -> Tuple[Optional[str], Optional[str]]:
    """Pull the SOC-format verdict + confidence out of an LLM reply.

    The system prompt asks the model to end with `SECTION 3 — Decision` and a
    `Confidence:` line, but real replies often drift (markdown bolding, no
    section header, decision on the same line as the label). We anchor on the
    last `SECTION 3`/`Decision` occurrence and take the first decision token
    after it; if no anchor exists we scan the last 1500 chars. Confidence is
    grabbed wherever it appears.

    Returns (verdict, confidence). Either may be None — callers must handle.
    """
    if not reply_md:
        return None, None
    text = reply_md
    anchors = list(_ANCHOR_RE.finditer(text))
    if anchors:
        scan_from = anchors[-1].end()
        m = _DECISION_RE.search(text, scan_from)
    else:
        m = _DECISION_RE.search(text[-1500:])
    verdict: Optional[str] = None
    if m:
        raw = m.group(1).strip()
        # Normalize whitespace and casing so 'likely  benign' → 'Likely Benign'
        canon = " ".join(raw.split()).lower()
        for tok in _DECISION_TOKENS:
            if canon == tok.lower():
                verdict = tok
                break
    cm = _CONFIDENCE_RE.search(text)
    confidence = cm.group(1).capitalize() if cm else None
    return verdict, confidence


def classify_ioc(value: str) -> str:
    """Return one of 'ip' | 'hash' | 'domain' for a raw IOC string."""
    v = (value or "").strip()
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", v):
        return "ip"
    if re.fullmatch(r"[a-fA-F0-9]{32,64}", v):
        return "hash"
    return "domain"


class VerdictStore:
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
                CREATE TABLE IF NOT EXISTS verdicts(
                    id TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    ioc_value TEXT NOT NULL,
                    ioc_type TEXT NOT NULL,
                    verdict TEXT,
                    confidence TEXT,
                    conversation_id TEXT NOT NULL,
                    message_excerpt TEXT,
                    evidence_summary_json TEXT,
                    created_at TEXT NOT NULL
                )
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_verdicts_user_ioc ON verdicts(user_id, ioc_value)"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_verdicts_conv ON verdicts(conversation_id)"
            )
            self.conn.commit()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def record(
        self,
        user_id: int,
        conversation_id: str,
        iocs: Sequence[str],
        verdict: Optional[str],
        confidence: Optional[str],
        message_excerpt: str,
        evidence_summary: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Insert one row per IOC. Returns count inserted. No-op if iocs empty."""
        if not iocs:
            return 0
        # Dedup within this call so the same IOC mentioned twice doesn't double-store.
        unique_iocs = list({v.strip() for v in iocs if v and v.strip()})
        if not unique_iocs:
            return 0
        try:
            ev_text = json.dumps(evidence_summary or {}, default=str, ensure_ascii=False)
        except Exception:
            ev_text = "{}"
        excerpt = (message_excerpt or "")[:300]
        now = self._now()
        rows = [
            (uuid.uuid4().hex, user_id, val, classify_ioc(val), verdict, confidence,
             conversation_id, excerpt, ev_text, now)
            for val in unique_iocs
        ]
        with self.lock:
            cur = self.conn.cursor()
            cur.executemany(
                """
                INSERT INTO verdicts(
                    id, user_id, ioc_value, ioc_type, verdict, confidence,
                    conversation_id, message_excerpt, evidence_summary_json, created_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
                rows,
            )
            self.conn.commit()
        return len(rows)

    def lookup_for_iocs(
        self,
        user_id: int,
        iocs: Sequence[str],
        limit_per_ioc: int = 3,
        exclude_conversation_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return prior verdicts for any of `iocs` belonging to this user.

        Up to `limit_per_ioc` most recent per IOC value. Multiple rows for the
        same IOC are returned intentionally so the LLM can notice disagreement
        between prior verdicts rather than being anchored to just the latest
        one. `exclude_conversation_id` skips rows from the current conversation
        (avoids the model citing itself in the same session).
        """
        unique = [v.strip() for v in iocs if v and v.strip()]
        if not unique:
            return []
        # SQLite IN-clause with placeholders, one query per IOC for the
        # per-IOC LIMIT (simpler than window functions on old SQLite).
        out: List[Dict[str, Any]] = []
        with self.lock:
            cur = self.conn.cursor()
            for val in unique:
                if exclude_conversation_id:
                    cur.execute(
                        """
                        SELECT ioc_value, ioc_type, verdict, confidence,
                               conversation_id, message_excerpt, created_at
                        FROM verdicts
                        WHERE user_id=? AND ioc_value=? AND conversation_id<>?
                        ORDER BY created_at DESC, rowid DESC
                        LIMIT ?
                        """,
                        (user_id, val, exclude_conversation_id, limit_per_ioc),
                    )
                else:
                    cur.execute(
                        """
                        SELECT ioc_value, ioc_type, verdict, confidence,
                               conversation_id, message_excerpt, created_at
                        FROM verdicts
                        WHERE user_id=? AND ioc_value=?
                        ORDER BY created_at DESC, rowid DESC
                        LIMIT ?
                        """,
                        (user_id, val, limit_per_ioc),
                    )
                out.extend(dict(r) for r in cur.fetchall())
        return out


verdicts = VerdictStore()
