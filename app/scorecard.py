"""Scorecard for the triage agent's shadow mode.

In shadow mode the agent logs what it would do with each alert group (dismiss
as a false positive, or open a case) without acting. This compares those
decisions with what analysts then actually did to the same alerts, per
severity, and recommends the highest `triage.max_dismiss_severity` the numbers
support, so "is it safe to go autonomous?" has an answer with evidence.

An analyst outcome is read from the alert's current state: dismissed → "dismiss";
attached to a case (its incident_id, or its conversation linked to a case) →
"case"; anything else is still "pending". A false dismissal (agent would have
dismissed what became a case) is the dangerous miss; a missed dismissal (agent
wanted a case, the analyst dismissed) only means the agent was cautious.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from app.db import user_store
from app.db.agent_store import agent_store
from app.db.alert_store import alerts_inbox, normalize_severity
from app.db.incident_store import incidents as incident_store

SEVERITIES = ("low", "medium", "high", "critical")
MIN_DECIDED = 20  # decided assessments a severity needs before it can be recommended
MIN_AGREEMENT_PCT = 95


def _decision(entry: Dict[str, Any], data: Dict[str, Any]) -> Optional[str]:
    """'dismiss' | 'case', from the structured key or, for entries logged before it existed, the detail."""
    if data.get("decision") in ("dismiss", "case"):
        return data["decision"]
    detail = entry.get("detail") or ""
    if detail.startswith("Would dismiss"):
        return "dismiss"
    if detail.startswith("Would open a case"):
        return "case"
    return None


def _outcome(alert: Dict[str, Any]) -> str:
    if alert.get("status") == "dismissed":
        return "dismiss"
    if alert.get("incident_id"):
        return "case"
    cid = alert.get("conversation_id")
    if cid and incident_store.case_ids_for_conversation(cid):
        return "case"
    return "pending"


def _latest_assessments(since: str) -> Dict[str, Dict[str, Any]]:
    """alert id -> the newest shadow decision naming it (the investigator also logs 'shadow')."""
    entries = [e for e in agent_store.since(since) if e["agent"] == "triage" and e["action"] == "shadow"]
    latest: Dict[str, Dict[str, Any]] = {}
    for e in sorted(entries, key=lambda e: e["created_at"]):  # later entries overwrite earlier ones
        try:
            data = json.loads(e.get("data_json") or "{}")
        except ValueError:
            data = {}
        decision = _decision(e, data)
        ids = data.get("alert_ids")
        if not decision or not isinstance(ids, list):
            continue
        for aid in ids:
            latest[aid] = {"decision": decision, "severity": data.get("severity")}
    return latest


def _qualifies(row: Dict[str, int]) -> tuple:
    """(qualifies, why) for the recommendation walk, phrased with the numbers."""
    decided, agreed, fd = row["decided"], row["agreed"], row["false_dismissals"]
    if decided < MIN_DECIDED:
        return False, f"{decided} decided so far; {MIN_DECIDED} needed"
    if fd:
        return False, f"{fd} false dismissal{'s' if fd != 1 else ''}"
    if agreed * 100 < MIN_AGREEMENT_PCT * decided:
        return False, f"{agreed} of {decided} agreed ({agreed / decided:.1%}); {MIN_AGREEMENT_PCT}% needed"
    return True, f"{agreed} of {decided} agreed, no false dismissals"


def _recommend(by_severity: Dict[str, Dict[str, int]]) -> Dict[str, Any]:
    """The highest severity in the unbroken qualifying run from low, or None when low itself does not."""
    limit, sentences = None, []
    for sev in SEVERITIES:
        ok, why = _qualifies(by_severity[sev])
        sentences.append(f"{sev.capitalize()}: {why}.")
        if not ok:
            break
        limit = sev
    return {"max_dismiss_severity": limit, "reason": " ".join(sentences)}


def triage_scorecard(days: int) -> Dict[str, Any]:
    """Shadow decisions from the last `days` days against the alerts' current state."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    by_severity = {s: {"assessed": 0, "decided": 0, "agreed": 0, "false_dismissals": 0, "missed_dismissals": 0}
                   for s in SEVERITIES}
    disagreements: List[Dict[str, Any]] = []
    names: Dict[int, Optional[str]] = {}
    for aid, seen in _latest_assessments(since).items():
        alert = alerts_inbox.get(aid)
        if not alert:
            continue  # deleted since the agent looked at it
        # data.severity is the group's highest, which is what the dismiss limit is judged against
        sev = seen["severity"] if seen["severity"] in SEVERITIES else normalize_severity(alert["severity"])
        row = by_severity[sev]
        row["assessed"] += 1
        outcome = _outcome(alert)
        if outcome == "pending":
            continue
        row["decided"] += 1
        if outcome == seen["decision"]:
            row["agreed"] += 1
            continue
        row["false_dismissals" if seen["decision"] == "dismiss" else "missed_dismissals"] += 1
        who = alert.get("claimed_by")
        if who is not None and who not in names:
            user = user_store.get_user_by_id(who)
            names[who] = user["username"] if user else None
        disagreements.append({
            "alert_id": aid, "title": alert["title"], "severity": sev,
            "agent": seen["decision"], "analyst": outcome, "resolution": alert.get("resolution"),
            "by": names.get(who) if who is not None else None, "at": alert["updated_at"],
        })
    assessed = sum(r["assessed"] for r in by_severity.values())
    decided = sum(r["decided"] for r in by_severity.values())
    agreed = sum(r["agreed"] for r in by_severity.values())
    disagreements.sort(key=lambda d: d["at"] or "", reverse=True)
    return {
        "days": days,
        "triage": {
            "assessed": assessed, "decided": decided, "agreed": agreed, "pending": assessed - decided,
            "agreement": round(agreed / decided, 3) if decided else None,
            "by_severity": by_severity,
            "recommendation": _recommend(by_severity),
            "disagreements": disagreements[:20],
        },
    }
