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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from app import alert_severity
from app.alert_severity import normalize_severity  # noqa: F401 (imported from here elsewhere)
from app.db.incident_store import case_number


DB_PATH = Path(__file__).resolve().parent.parent / 'data' / 'chat.db'

# Host name across the webhook shapes we ingest.
# The alert's host, for every SIEM shape NullShift ingests. Triage groups alerts by it, so a
# shape missing here lumps different machines into one "unknown host" investigation.
HOST_EXPR = ("COALESCE(json_extract(payload_json, '$.routing.hostname'),"  # LimaCharlie
             " json_extract(payload_json, '$.agent.name'),"                # Wazuh
             " json_extract(payload_json, '$.host.name'),"                 # Elastic ECS
             " json_extract(payload_json, '$.result.host'),"               # Splunk webhook alert action
             " json_extract(payload_json, '$.CompromisedEntity'),"         # Sentinel
             " json_extract(payload_json, '$.hostname'))")                 # generic

ALERT_STATUSES = ("new", "investigating", "dismissed")


def extract_alert_fields(payload: Dict[str, Any], source_hint: Optional[str] = None,
                         cfg: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Best-effort title/severity/source from common SIEM webhook shapes.

    Recognizes Wazuh ({rule:{description,level}}), LimaCharlie ({cat,detect}),
    Splunk ({search_name,result}), Elastic ({rule:{name,severity}}), Sentinel
    ({AlertDisplayName,AlertSeverity} or an incident's {properties:{title,severity}})
    and generic {title|name|message, severity|level} bodies. The severity is read
    on the sending SIEM's own scale (app/alert_severity.py).
    """
    title = None
    rule = payload.get("rule")
    if isinstance(rule, dict):
        title = rule.get("description") or rule.get("name")
    if not title and payload.get("cat"):
        title = str(payload["cat"])
    if not title and payload.get("search_name"):
        title = str(payload["search_name"])
    props = payload.get("properties")
    if not title and isinstance(props, dict) and props.get("title"):
        title = str(props["title"])
    if not title:
        for key in ("title", "name", "alert_name", "AlertDisplayName", "DisplayName", "AlertName",
                    "message", "description"):
            if payload.get(key):
                title = str(payload[key])
                break
    title = (title or "Untitled alert")[:200]
    return {
        "title": title,
        "severity": alert_severity.classify(payload, source_hint, title, cfg),
        "source": (alert_severity.shape(payload) or str(payload.get("source") or "unknown"))[:40],
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
            cols = {r[1] for r in cur.execute("PRAGMA table_info(ingested_alerts)")}
            # agent_note/triaged_at: written by the triage/investigator agents;
            # resolution/resolution_note: why an analyst dismissed the alert;
            # incident_id: the case the alert was escalated or added to.
            # acked_at/acked_by: when the alert first left 'new' and who took it (NULL: an agent).
            for col in ("agent_note", "triaged_at", "resolution", "resolution_note", "incident_id", "acked_at"):
                if col not in cols:
                    cur.execute(f"ALTER TABLE ingested_alerts ADD COLUMN {col} TEXT")
            if "acked_by" not in cols:
                cur.execute("ALTER TABLE ingested_alerts ADD COLUMN acked_by INTEGER")
                # ponytail: one-off backfill, the last status change stands in for the first
                cur.execute("UPDATE ingested_alerts SET acked_at = updated_at, acked_by = claimed_by WHERE status != 'new'")
                cur.execute("UPDATE ingested_alerts SET resolution = 'false_positive' "
                            "WHERE status = 'dismissed' AND claimed_by IS NULL AND resolution IS NULL "
                            "AND agent_note LIKE '%false positive%'")
            # Every status write goes through here, whichever method made it. claimed_by is
            # NULL exactly when an agent acted (agents never set it), so acked_by tells the two
            # apart. Back to 'new' (chat deleted, agent decision undone) is unacknowledged again.
            cur.execute(
                """
                CREATE TRIGGER IF NOT EXISTS alerts_ack AFTER UPDATE OF status ON ingested_alerts
                WHEN (OLD.status = 'new') != (NEW.status = 'new')
                BEGIN
                    UPDATE ingested_alerts
                    SET acked_at = CASE WHEN NEW.status = 'new' THEN NULL ELSE NEW.updated_at END,
                        acked_by = CASE WHEN NEW.status = 'new' THEN NULL ELSE NEW.claimed_by END
                    WHERE id = NEW.id;
                END
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_alerts_status ON ingested_alerts(status, created_at)"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_alerts_incident ON ingested_alerts(incident_id)"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_alerts_detect_id "
                "ON ingested_alerts(json_extract(payload_json, '$.detect_id'))"
            )
            self.conn.commit()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def ingest(self, payload: Dict[str, Any], source_hint: Optional[str] = None) -> Dict[str, Any]:
        fields = extract_alert_fields(payload if isinstance(payload, dict) else {}, source_hint)
        if source_hint:
            fields["source"] = source_hint[:40]
        alert_id = uuid.uuid4().hex
        now = self._now()
        try:
            raw = json.dumps(payload, default=str, ensure_ascii=False)
        except Exception:
            raw = "{}"
        # LimaCharlie detections carry a stable detect_id: the webhook and the
        # inbox refresh pull can both deliver one, so the second is a no-op.
        detect_id = payload.get("detect_id") if isinstance(payload, dict) else None
        with self.lock:
            cur = self.conn.cursor()
            if detect_id:
                cur.execute(
                    """
                    SELECT id, source, title, severity, status, created_at
                    FROM ingested_alerts
                    WHERE json_extract(payload_json, '$.detect_id')=? LIMIT 1
                    """,
                    (str(detect_id),),
                )
                row = cur.fetchone()
                if row:
                    return {**dict(row), "duplicate": True}
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

    @staticmethod
    def _filter(status: Optional[str], severity: Optional[str], q: Optional[str],
                claimed_by: Optional[int] = None) -> tuple:
        """WHERE clause for the inbox filters. `q` matches title, source or anywhere in
        the raw payload (host names, IPs, users), case-insensitively; `claimed_by` is
        the inbox's "mine" filter."""
        # ponytail: LIKE over payload_json scans every row; fine at thousands, FTS5 past that
        conds, args = [], []
        if status:
            conds.append("status=?")
            args.append(status)
        if severity:
            conds.append("severity=?")
            args.append(severity)
        if q:
            like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            conds.append("(title LIKE ? ESCAPE '\\' OR source LIKE ? ESCAPE '\\' OR payload_json LIKE ? ESCAPE '\\')")
            args += [like] * 3
        if claimed_by is not None:
            conds.append("claimed_by=?")
            args.append(claimed_by)
        return (" WHERE " + " AND ".join(conds) if conds else ""), args

    def list(self, status: Optional[str] = None, limit: int = 100, offset: int = 0,
             severity: Optional[str] = None, q: Optional[str] = None,
             claimed_by: Optional[int] = None, oldest: bool = False) -> List[Dict[str, Any]]:
        """Inbox listing, newest first (oldest first with `oldest`), one page at a
        time — payload omitted to keep the response small. Rows carry the host and
        the linked case's number and owner (case_user_id; cases and their numbers
        are per analyst, so the caller decides who gets to see them)."""
        where, args = self._filter(status, severity, q, claimed_by)
        order = "ASC" if oldest else "DESC"

        def sql(case_cols: str) -> str:
            return f"""
                SELECT id, source, title, severity, status, claimed_by, conversation_id,
                       created_at, updated_at, agent_note, resolution, incident_id,
                       {HOST_EXPR} AS host, {case_cols}
                FROM ingested_alerts{where}
                ORDER BY created_at {order} LIMIT ? OFFSET ?
            """

        with self.lock:
            cur = self.conn.cursor()
            try:
                # Scalar subqueries, not a JOIN: incidents shares id/status/severity/title
                # column names with this table and the filters are unqualified.
                cur.execute(sql("(SELECT case_seq FROM incidents WHERE id = ingested_alerts.incident_id) AS case_seq, "
                                "(SELECT user_id FROM incidents WHERE id = ingested_alerts.incident_id) AS case_user_id"),
                            (*args, limit, offset))
            except sqlite3.OperationalError:
                # incidents lives in incident_store; a DB without it yet lists without case numbers
                cur.execute(sql("NULL AS case_seq, NULL AS case_user_id"), (*args, limit, offset))
            rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            seq = r.pop("case_seq")
            r["case_number"] = case_number(seq) if seq is not None else None
        return rows

    def count(self, status: Optional[str] = None, severity: Optional[str] = None, q: Optional[str] = None,
              claimed_by: Optional[int] = None) -> int:
        """Alerts matching the filters: the total a paged list is out of."""
        where, args = self._filter(status, severity, q, claimed_by)
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(f"SELECT COUNT(*) FROM ingested_alerts{where}", args)
            return int(cur.fetchone()[0])

    def count_new(self) -> int:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT COUNT(*) FROM ingested_alerts WHERE status='new'")
            return int(cur.fetchone()[0])

    def stats(self, hours: int, buckets: int = 24) -> Dict[str, Any]:
        """Dashboard aggregates for alerts received in the last `hours`, plus the
        all-time backlog (new / investigating) that the inbox badge counts and the
        arrival time of its oldest unacknowledged alert."""
        # ponytail: recomputed on every call and the UI polls each second; fine at
        # thousands of rows, pre-aggregate per hour if the inbox reaches millions
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        bucket_s = hours * 3600 / buckets
        win = "FROM ingested_alerts WHERE created_at >= ?"

        def q(sql: str, *args: Any) -> List[sqlite3.Row]:
            return self.conn.execute(sql, args).fetchall()

        with self.lock:
            volume = [0] * buckets
            for b, n in q(f"SELECT CAST((julianday(created_at) - julianday(?)) * 86400 / ? AS INT), COUNT(*) "
                          f"{win} GROUP BY 1", since, bucket_s, since):
                volume[min(max(int(b), 0), buckets - 1)] += n
            return {
                "since": since,
                "bucket_s": bucket_s,
                "volume": volume,
                "total": q(f"SELECT COUNT(*) {win}", since)[0][0],
                "by_severity": {s: n for s, n in q(f"SELECT severity, COUNT(*) {win} GROUP BY severity", since)},
                "top_rules": [dict(r) for r in q(
                    f"SELECT title AS name, COUNT(*) AS n {win} GROUP BY title ORDER BY n DESC LIMIT 6", since)],
                "top_hosts": [dict(r) for r in q(
                    f"SELECT {HOST_EXPR} AS name, COUNT(*) AS n {win} GROUP BY name HAVING name IS NOT NULL "
                    f"ORDER BY n DESC LIMIT 6", since)],
                "recent": [dict(r) for r in q(
                    f"SELECT id, source, title, severity, status, created_at {win} "
                    f"ORDER BY created_at DESC LIMIT 8", since)],
                "ack_s": q(f"SELECT AVG((julianday(acked_at) - julianday(created_at)) * 86400) {win} "
                           f"AND acked_at IS NOT NULL", since)[0][0],
                "resolve_s": self._resolve_s(since),
                # Alerts taken off the queue in this window, and how many an agent took.
                "handled": dict(zip(("total", "agents"), q(
                    f"SELECT COUNT(*), COUNT(*) - COUNT(acked_by) {win} AND acked_at IS NOT NULL", since)[0])),
                "noisy_rules": self._noisy_rules(since),
                "backlog": {s: n for s, n in q(
                    "SELECT status, COUNT(*) FROM ingested_alerts WHERE status != 'dismissed' GROUP BY status")},
                "oldest_new": q("SELECT MIN(created_at) FROM ingested_alerts WHERE status = 'new'")[0][0],
            }

    def _resolve_s(self, since: str) -> Optional[float]:
        """Mean arrival -> resolution for alerts received since `since`: a dismissal, or
        for an escalated alert its case closing. Caller holds the lock."""
        sql = ("SELECT AVG((julianday(done) - julianday(created_at)) * 86400) FROM ("
               " SELECT created_at, CASE WHEN status = 'dismissed' THEN updated_at ELSE {closed} END AS done"
               " FROM ingested_alerts WHERE created_at >= ?) WHERE done IS NOT NULL")
        try:
            return self.conn.execute(sql.format(
                closed="(SELECT closed_at FROM incidents WHERE id = ingested_alerts.incident_id)"), (since,)).fetchone()[0]
        except sqlite3.OperationalError:  # no incidents table yet: dismissals only
            return self.conn.execute(sql.format(closed="NULL"), (since,)).fetchone()[0]

    def _noisy_rules(self, since: str, min_decided: int = 3) -> List[Dict[str, Any]]:
        """Rules with the most false positives since `since`, out of the alerts worked
        (dismissed or under investigation); `tune` marks the ones mostly wrong. An alert still
        being investigated counts as not false, so the rate errs low. Caller holds the lock."""
        rows = self.conn.execute(
            "SELECT title AS name, SUM(resolution = 'false_positive') AS fp,"
            " SUM(status != 'new') AS decided, COUNT(*) AS n"
            " FROM ingested_alerts WHERE created_at >= ? GROUP BY title"
            " HAVING fp > 0 AND decided >= ? ORDER BY fp DESC, n DESC LIMIT 6", (since, min_decided)).fetchall()
        return [{**dict(r), "rate": r["fp"] / r["decided"], "tune": r["fp"] / r["decided"] >= 0.8} for r in rows]

    def rescore(self, cfg: Optional[Dict[str, Any]] = None) -> int:
        """Re-read every alert's severity (the severity settings changed, or the app started
        with newer rules). Only severity changes: updated_at is the resolve-time clock."""
        # ponytail: parses every stored payload; fine at tens of thousands, batch it past that
        cfg = alert_severity.load() if cfg is None else cfg
        with self.lock:
            rows = self.conn.execute("SELECT id, source, title, severity, payload_json FROM ingested_alerts").fetchall()
            changes = []
            for r in rows:
                try:
                    payload = json.loads(r["payload_json"])
                except ValueError:
                    continue
                sev = alert_severity.classify(payload if isinstance(payload, dict) else {}, r["source"], r["title"], cfg)
                if sev != r["severity"]:
                    changes.append((sev, r["id"]))
            self.conn.executemany("UPDATE ingested_alerts SET severity=? WHERE id=?", changes)
            self.conn.commit()
        return len(changes)

    def rule_counts(self, limit: int = 300) -> List[Dict[str, Any]]:
        """Alert titles (rules) by how often they fire, with their source and the severities they got."""
        with self.lock:
            rows = self.conn.execute(
                "SELECT title AS name, source, COUNT(*) AS n, GROUP_CONCAT(DISTINCT severity) AS severities "
                "FROM ingested_alerts GROUP BY title ORDER BY n DESC LIMIT ?", (limit,)).fetchall()
        return [{**dict(r), "severities": sorted(r["severities"].split(","), key=alert_severity.SEVERITIES.index)}
                for r in rows]

    def source_counts(self) -> Dict[str, int]:
        with self.lock:
            return {r[0]: r[1] for r in self.conn.execute("SELECT source, COUNT(*) FROM ingested_alerts GROUP BY source")}

    def any_investigated(self) -> bool:
        """Has any alert ever been opened as an investigation (first-run checklist)."""
        with self.lock:
            return self.conn.execute(
                "SELECT 1 FROM ingested_alerts WHERE conversation_id IS NOT NULL LIMIT 1").fetchone() is not None

    def untriaged(self, since: str, limit: int = 500) -> List[Dict[str, Any]]:
        """New alerts received since `since` that no agent has looked at, oldest first."""
        with self.lock:
            cur = self.conn.execute(
                f"""
                SELECT id, source, title, severity, created_at, payload_json, {HOST_EXPR} AS host
                FROM ingested_alerts
                WHERE status='new' AND triaged_at IS NULL AND created_at >= ?
                ORDER BY created_at LIMIT ?
                """,
                (since, limit),
            )
            return [dict(r) for r in cur.fetchall()]

    def set_agent_outcome(self, ids: List[str], status: str, note: str,
                          conversation_id: Optional[str] = None) -> None:
        """Record an agent decision (or its undo) on a group of alerts. Agents only
        dismiss false positives, so a dismissal records that resolution."""
        now = self._now()
        resolution = "false_positive" if status == "dismissed" else None
        with self.lock:
            self.conn.executemany(
                "UPDATE ingested_alerts SET status=?, agent_note=?, triaged_at=?, updated_at=?, resolution=?, "
                "conversation_id=COALESCE(?, conversation_id) WHERE id=?",
                [(status, note, now, now, resolution, conversation_id, i) for i in ids],
            )
            self.conn.commit()

    def mark_triaged(self, ids: List[str], note: str) -> None:
        """A shadow-mode agent assessed these alerts and changed nothing: keep them out
        of `untriaged` without touching status or the conversation link."""
        now = self._now()
        with self.lock:
            self.conn.executemany(
                "UPDATE ingested_alerts SET agent_note=?, triaged_at=?, updated_at=? WHERE id=?",
                [(note, now, now, i) for i in ids],
            )
            self.conn.commit()

    def hosts(self, ids: List[str]) -> List[str]:
        """Distinct host names behind these alerts, whatever SIEM sent them."""
        if not ids:
            return []
        with self.lock:
            cur = self.conn.execute(
                f"SELECT DISTINCT {HOST_EXPR} FROM ingested_alerts WHERE id IN ({','.join('?' * len(ids))})", ids)
            return sorted(r[0] for r in cur.fetchall() if r[0])

    def sensors(self, ids: List[str]) -> List[tuple]:
        """Distinct LimaCharlie (sensor id, hostname) pairs behind these alerts."""
        if not ids:
            return []
        with self.lock:
            cur = self.conn.execute(
                f"""
                SELECT DISTINCT json_extract(payload_json, '$.routing.sid'),
                                json_extract(payload_json, '$.routing.hostname')
                FROM ingested_alerts
                WHERE id IN ({','.join('?' * len(ids))})
                  AND json_extract(payload_json, '$.routing.sid') IS NOT NULL
                """,
                ids,
            )
            return [(r[0], r[1]) for r in cur.fetchall()]

    def get(self, alert_id: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT * FROM ingested_alerts WHERE id=?", (alert_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    @staticmethod
    def _reclaim_cond(conversation_id: Optional[str], user_id: int) -> tuple:
        """WHERE for re-claiming an 'investigating' alert the caller saw linked to
        conversation_id (or to none). IS, not =: an alert an agent's undo left
        'investigating' may have no link at all. With no link, a claim made without
        a chat (a bulk add to a case) still belongs to its claimant, so only that
        analyst, or anyone when nobody claimed it, may take it again."""
        cond, args = "status='investigating' AND conversation_id IS ?", (conversation_id,)
        if conversation_id is None:
            cond += " AND (claimed_by IS NULL OR claimed_by=?)"
            args += (user_id,)
        return cond, args

    def mark_investigating(self, alert_id: str, user_id: int, conversation_id: str,
                           stale_conversation_id: Optional[str] = None, reclaim: bool = False) -> bool:
        """Claim an alert. Only transitions from 'new' — first analyst wins.

        With reclaim (implied by stale_conversation_id), re-claims instead an
        'investigating' alert whose linked conversation (that id, or none when
        it is None) is gone; matching the old link keeps two analysts from
        both winning the re-claim (see _reclaim_cond for an alert with no link)."""
        if reclaim or stale_conversation_id:
            cond, args = self._reclaim_cond(stale_conversation_id, user_id)
        else:
            cond, args = "status='new'", ()
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                f"""
                UPDATE ingested_alerts
                SET status='investigating', claimed_by=?, conversation_id=?, updated_at=?
                WHERE id=? AND {cond}
                """,
                (user_id, conversation_id, self._now(), alert_id, *args),
            )
            self.conn.commit()
            return cur.rowcount > 0

    def detach_conversation(self, conversation_id: str) -> int:
        """A conversation was deleted: alerts it was investigating go back to the
        inbox as 'new' and unclaimed, and no alert keeps pointing at it
        (dismissed alerts stay dismissed)."""
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                """
                UPDATE ingested_alerts
                SET status = CASE WHEN status='investigating' THEN 'new' ELSE status END,
                    claimed_by = CASE WHEN status='investigating' THEN NULL ELSE claimed_by END,
                    updated_at = CASE WHEN status='investigating' THEN ? ELSE updated_at END,
                    conversation_id = NULL
                WHERE conversation_id=?
                """,
                (self._now(), conversation_id),
            )
            self.conn.commit()
            return cur.rowcount

    def dismiss(self, alert_id: str, user_id: int, resolution: Optional[str] = None,
                note: Optional[str] = None) -> bool:
        """Close the alert; claimed_by records who did it, resolution/note why (both optional)."""
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                """
                UPDATE ingested_alerts
                SET status='dismissed', claimed_by=?, resolution=?, resolution_note=?, updated_at=?
                WHERE id=? AND status IN ('new','investigating')
                """,
                (user_id, resolution, note, self._now(), alert_id),
            )
            self.conn.commit()
            return cur.rowcount > 0

    def restore(self, alert_id: str, status: str, claimed_by: Optional[int]) -> bool:
        """Undo a dismissal (api_restore_alert picks 'new' or 'investigating')."""
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                "UPDATE ingested_alerts SET status=?, claimed_by=?, resolution=NULL, resolution_note=NULL, "
                "updated_at=? WHERE id=? AND status='dismissed'",
                (status, claimed_by, self._now(), alert_id),
            )
            self.conn.commit()
            return cur.rowcount > 0

    def claim_group(self, alerts: List[Dict[str, Any]], user_id: int,
                    conversation_id: str) -> List[Dict[str, Any]]:
        """Claim several alerts into one conversation, each under
        mark_investigating's guard for the state the caller read it in: 'new',
        or 'investigating' still linked to the same (gone) conversation. Returns
        the rows that were won, oldest first, with their host; an alert missing
        from them changed meanwhile and is left as it is."""
        now = self._now()
        won: List[str] = []
        with self.lock:
            cur = self.conn.cursor()
            for a in alerts:
                if a["status"] == "investigating":
                    cond, args = self._reclaim_cond(a.get("conversation_id"), user_id)
                else:
                    cond, args = "status='new'", ()
                cur.execute(
                    f"""
                    UPDATE ingested_alerts
                    SET status='investigating', claimed_by=?, conversation_id=?, updated_at=?
                    WHERE id=? AND {cond}
                    """,
                    (user_id, conversation_id, now, a["id"], *args),
                )
                if cur.rowcount > 0:
                    won.append(a["id"])
            self.conn.commit()
            if not won:
                return []
            cur.execute(
                f"SELECT *, {HOST_EXPR} AS host FROM ingested_alerts "
                f"WHERE id IN ({','.join('?' * len(won))}) ORDER BY created_at",
                won,
            )
            return [dict(r) for r in cur.fetchall()]

    # ── Bulk actions and case links ──────────────────────────────────────────

    def get_many(self, ids: List[str]) -> Dict[str, Dict[str, Any]]:
        """Full rows for these ids, keyed by id (missing ids are simply absent)."""
        if not ids:
            return {}
        with self.lock:
            cur = self.conn.execute(
                f"SELECT * FROM ingested_alerts WHERE id IN ({','.join('?' * len(ids))})", ids)
            return {r["id"]: dict(r) for r in cur.fetchall()}

    def set_incident(self, ids: List[str], incident_id: str) -> int:
        """Attach alerts to a case. Dismissed alerts are left out; updated_at is not
        touched because it marks the last status change (see stats._resolve_s)."""
        if not ids:
            return 0
        with self.lock:
            cur = self.conn.execute(
                f"UPDATE ingested_alerts SET incident_id=? "
                f"WHERE id IN ({','.join('?' * len(ids))}) AND status != 'dismissed'",
                (incident_id, *ids),
            )
            self.conn.commit()
            return cur.rowcount

    def claim_new(self, ids: List[str], user_id: int) -> int:
        """Claim whichever of these alerts are still 'new' for user_id, leaving any
        conversation link as it is. A claim made meanwhile by someone else stands."""
        if not ids:
            return 0
        with self.lock:
            cur = self.conn.execute(
                f"UPDATE ingested_alerts SET status='investigating', claimed_by=?, updated_at=? "
                f"WHERE id IN ({','.join('?' * len(ids))}) AND status='new'",
                (user_id, self._now(), *ids),
            )
            self.conn.commit()
            return cur.rowcount

    def for_incident(self, incident_id: str) -> List[Dict[str, Any]]:
        """The alerts attached to a case, newest first (what the case page lists)."""
        with self.lock:
            cur = self.conn.execute(
                f"""
                SELECT id, title, severity, status, {HOST_EXPR} AS host, created_at
                FROM ingested_alerts WHERE incident_id=? ORDER BY created_at DESC
                """,
                (incident_id,),
            )
            return [dict(r) for r in cur.fetchall()]

    def unlink_incident(self, incident_id: str) -> int:
        """A case was deleted: its alerts keep their status but no longer point at it."""
        with self.lock:
            cur = self.conn.execute(
                "UPDATE ingested_alerts SET incident_id=NULL WHERE incident_id=?", (incident_id,))
            self.conn.commit()
            return cur.rowcount


alerts_inbox = AlertStore()
