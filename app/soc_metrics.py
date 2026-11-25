"""SOC-lead metrics for the dashboard: mean time to acknowledge and to resolve, the share
of alerts the agents took off the queue, and the rules worth tuning. Read from the alert
inbox (acked_at / acked_by are set by its `alerts_ack` trigger) for alerts received since
the dashboard window opened."""
from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional


def soc_lead(store: Any, since: str) -> Dict[str, Any]:
    """`store` is the AlertStore; its lock is held for every query."""
    win = "FROM ingested_alerts WHERE created_at >= ? AND acked_at IS NOT NULL"
    with store.lock:
        conn = store.conn
        return {
            "ack_s": conn.execute(
                f"SELECT AVG((julianday(acked_at) - julianday(created_at)) * 86400) {win}", (since,)).fetchone()[0],
            "resolve_s": _resolve_s(conn, since),
            # Alerts taken off the queue in this window, and how many an agent took.
            "handled": dict(zip(("total", "agents"), conn.execute(
                f"SELECT COUNT(*), COUNT(*) - COUNT(acked_by) {win}", (since,)).fetchone())),
            "noisy_rules": _noisy_rules(conn, since),
        }


def _resolve_s(conn: sqlite3.Connection, since: str) -> Optional[float]:
    """Mean arrival -> resolution for alerts received since `since`: a dismissal, or
    for an escalated alert its case closing."""
    sql = ("SELECT AVG((julianday(done) - julianday(created_at)) * 86400) FROM ("
           " SELECT created_at, CASE WHEN status = 'dismissed' THEN updated_at ELSE {closed} END AS done"
           " FROM ingested_alerts WHERE created_at >= ?) WHERE done IS NOT NULL")
    try:
        return conn.execute(sql.format(
            closed="(SELECT closed_at FROM incidents WHERE id = ingested_alerts.incident_id)"), (since,)).fetchone()[0]
    except sqlite3.OperationalError:  # no incidents table yet: dismissals only
        return conn.execute(sql.format(closed="NULL"), (since,)).fetchone()[0]


def _noisy_rules(conn: sqlite3.Connection, since: str, min_decided: int = 3) -> List[Dict[str, Any]]:
    """Rules with the most false positives since `since`, out of the alerts worked
    (dismissed or under investigation); `tune` marks the ones mostly wrong. An alert still
    being investigated counts as not false, so the rate errs low."""
    rows = conn.execute(
        "SELECT title AS name, SUM(resolution = 'false_positive') AS fp,"
        " SUM(status != 'new') AS decided, COUNT(*) AS n"
        " FROM ingested_alerts WHERE created_at >= ? GROUP BY title"
        " HAVING fp > 0 AND decided >= ? ORDER BY fp DESC, n DESC LIMIT 6", (since, min_decided)).fetchall()
    return [{**dict(r), "rate": r["fp"] / r["decided"], "tune": r["fp"] / r["decided"] >= 0.8} for r in rows]
