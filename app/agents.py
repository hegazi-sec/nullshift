"""Autonomous SOC agents, modeled on refractionPOINT/lc-ai's Lean SOC.

  triage        every minute: groups new inbox alerts (same source + rule + host),
                investigates each group once, dismisses high-confidence false
                positives and opens a case for everything else
  investigator  every 2 minutes: L2 deep dive on the cases triage opened; closes
                confirmed false positives, flags the rest for a human and proposes
                host isolation for malicious findings
  reporter      once a day: shift report posted as a conversation
  responder     executes an isolation proposal only after an analyst approves it

Investigations run through the normal chat pipeline (SIEM evidence, playbooks,
approved tools), acting as the configured owner user because cases and chats
are per-user in NullShift. Every action is written to agent_log, and the
autonomous false-positive decisions can be undone from the Agents view.
"""
from __future__ import annotations

import json
import logging
import re
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from app.db import user_store
from app.db.agent_store import agent_store
from app.db.alert_store import alerts_inbox
from app.db.chat_store import store
from app.db.incident_store import incidents as incident_store
from app.db.settings_store import settings_store
from app.db.verdict_store import parse_decision

log = logging.getLogger("nullshift.agents")

AGENTS = ("triage", "investigator", "reporter", "responder")
DEFAULTS: Dict[str, Any] = {
    "owner": "admin",
    "triage": {"enabled": False, "max_per_run": 5, "enabled_at": None},
    "investigator": {"enabled": False, "max_per_run": 2},
    "reporter": {"enabled": False, "hour_utc": 6},
    "responder": {"enabled": False},
}
INTERVAL_S = {"triage": 60, "investigator": 120}
_SEVERITY_ORDER = ["low", "medium", "high", "critical"]
_VERDICT_ASK = ("End with **Verdict:** (Likely Benign | Suspicious | Malicious | Inconclusive) "
                "and **Confidence:** (Low | Medium | High).")
_SID_RE = re.compile(r"[0-9a-fA-F-]{36}")
_LLM_DOWN = "Model unavailable"  # app/llm.py answers with this instead of raising when every provider fails
BACKOFF_S = 900  # pause an agent this long after the model was unavailable
TTL_S = {"investigation_report": 300, "l2_investigation": 600}  # per investigation, like lc-ai's ttl_seconds
# ponytail: a timed-out call can't be killed, it finishes in the background; 2 workers bound the leak
_llm_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="agent-llm")

status: Dict[str, Dict[str, str]] = {a: {} for a in AGENTS}  # last run per agent, in memory
_locks = {a: threading.Lock() for a in AGENTS}
_stop_requested = {a: threading.Event() for a in AGENTS}  # checked between groups/cases
_paused_until: Dict[str, float] = {}


class LLMUnavailable(RuntimeError):
    """Every LLM provider failed, so nothing was decided; retry later."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── config ────────────────────────────────────────────────────────────
def load_config() -> Dict[str, Any]:
    try:
        saved = json.loads(settings_store.get("agents_config") or "{}")
    except ValueError:
        saved = {}
    cfg = json.loads(json.dumps(DEFAULTS))
    cfg["owner"] = saved.get("owner") or cfg["owner"]
    for a in AGENTS:
        if isinstance(saved.get(a), dict):
            cfg[a].update({k: v for k, v in saved[a].items() if k in cfg[a]})
    return cfg


def save_config(update: Dict[str, Any]) -> Dict[str, Any]:
    cfg = load_config()
    if update.get("owner"):
        cfg["owner"] = str(update["owner"])
    for a in AGENTS:
        for k, v in (update.get(a) or {}).items():
            if k == "enabled":
                cfg[a][k] = bool(v)
            elif k == "max_per_run":
                cfg[a][k] = max(1, min(int(v), 50))
            elif k == "hour_utc":
                cfg[a][k] = int(v) % 24
    # Triage only sees alerts that arrive after it is switched on, never the existing backlog.
    if not cfg["triage"]["enabled"]:
        cfg["triage"]["enabled_at"] = None
    elif not cfg["triage"]["enabled_at"]:
        cfg["triage"]["enabled_at"] = _now()
    settings_store.set_many({"agents_config": json.dumps(cfg)})
    return cfg


def _actor(user: Optional[Dict[str, Any]], who: Any) -> Dict[str, Any]:
    if not user or not user.get("is_active"):
        raise RuntimeError(f"agent owner {who!r} is not an active user")
    return {"id": user["id"], "username": user["username"], "role": user["role"]}  # same shape as get_current_user


def _owner(cfg: Dict[str, Any]) -> Dict[str, Any]:
    return _actor(user_store.get_user_by_username(cfg["owner"]), cfg["owner"])


def _investigate(actor: Dict[str, Any], conversation_id: str, message: str, mode: str) -> Tuple[str, Optional[str], Optional[str]]:
    """Send `message` through the normal chat pipeline; return (reply, verdict, confidence)."""
    from app.main import _do_message_work  # lazy: app.main imports this module
    from app.schemas import MessageCreate
    work = _llm_pool.submit(_do_message_work, conversation_id, MessageCreate(message=message), actor, mode=mode)
    try:
        reply = work.result(timeout=TTL_S[mode])["reply"]
    except FuturesTimeout:
        raise LLMUnavailable(f"no answer within {TTL_S[mode] // 60} minutes")
    if reply.lstrip().startswith(_LLM_DOWN):
        raise LLMUnavailable(reply.strip()[:200])
    verdict, confidence = parse_decision(reply)
    return reply, verdict, confidence


def _confident_fp(verdict: Optional[str], confidence: Optional[str]) -> bool:
    return verdict == "Likely Benign" and confidence == "High"


# ── triage ────────────────────────────────────────────────────────────
def run_triage(cfg: Dict[str, Any]) -> str:
    owner = _owner(cfg)
    groups: Dict[tuple, List[Dict[str, Any]]] = {}
    for a in alerts_inbox.untriaged(cfg["triage"]["enabled_at"] or _now()):
        groups.setdefault((a["source"], a["title"], a["host"] or "unknown host"), []).append(a)
    done = 0
    for (source, title, host), alerts in list(groups.items())[: cfg["triage"]["max_per_run"]]:
        if _stop_requested["triage"].is_set():
            break
        latest = alerts[-1]
        conv = store.create_conversation_for_user(owner["id"], title=f"[Triage] {title}"[:60])["id"]
        try:
            _, verdict, conf = _investigate(owner, conv, (
                f"[Triage agent] Investigate this alert group and decide whether it is a false positive.\n"
                f"{len(alerts)} alert(s) '{title}' from {source} on host {host}, "
                f"first at {alerts[0]['created_at']}, last at {latest['created_at']}.\n"
                f"Most recent alert payload:\n```json\n{latest['payload_json'][:4000]}\n```\n{_VERDICT_ASK}"
            ), "investigation_report")
        except LLMUnavailable:
            store.delete_conversation_for_user(owner["id"], conv)  # nothing decided: no orphan chat, alerts retry later
            raise
        ids = [a["id"] for a in alerts]
        data = {"alert_ids": ids, "conversation_id": conv, "owner_id": owner["id"]}
        label = f"{len(ids)} × {title} on {host}"
        if _confident_fp(verdict, conf):
            alerts_inbox.set_agent_outcome(ids, "dismissed", "Triage agent: false positive (High confidence)", conv)
            agent_store.log("triage", "dismissed", conv, f"False positive: {label}", data)
        else:
            outcome = f"{verdict or 'no verdict'} ({conf or 'unknown'} confidence)"
            inc = incident_store.create(
                user_id=owner["id"], title=f"{title} on {host}"[:120],
                severity=max((a["severity"] for a in alerts), key=_SEVERITY_ORDER.index),
                notes=f"Opened by the triage agent: {outcome}.",
            )
            incident_store.link_conversation(owner["id"], inc["id"], conv)
            alerts_inbox.set_agent_outcome(ids, "investigating", f"Triage agent: {outcome}, case {inc['case_number']}", conv)
            agent_store.log("triage", "case_opened", inc["id"], f"{inc['case_number']}: {label}, {outcome}",
                            {**data, "case_number": inc["case_number"]})
        done += 1
    waiting = len(groups) - done
    return f"{done} group(s) triaged" + (f", {waiting} waiting for the next run" if waiting else "")


# ── investigator ──────────────────────────────────────────────────────
_RECOMMEND_RE = re.compile(r"Recommended Response\W*(isolate|block|monitor|close)", re.IGNORECASE)


def run_investigator(cfg: Dict[str, Any]) -> str:
    seen = agent_store.targets("investigator")
    todo = [e for e in agent_store.entries("triage", "case_opened") if e["target_id"] not in seen]
    done = 0
    for entry in todo[: cfg["investigator"]["max_per_run"]]:
        if _stop_requested["investigator"].is_set():
            break
        data = json.loads(entry["data_json"] or "{}")
        actor = _actor(user_store.get_user_by_id(data["owner_id"]), data["owner_id"])  # the case and chat belong to them
        case = incident_store.get_for_user(actor["id"], entry["target_id"])
        if not case or case["status"] == "closed":
            agent_store.log("investigator", "skipped", entry["target_id"], f"{data.get('case_number')}: closed or deleted by an analyst")
            continue
        # L2 mode runs the IOC-following tool protocol and ends with Confidence + Recommended Response.
        reply, verdict, conf = _investigate(actor, data["conversation_id"], (
            f"[Investigator agent] L2 investigation of case {case['case_number']}: follow every IOC from the "
            f"triage findings above and decide whether this is a true positive or a false positive. "
            f"Also include a **Verdict:** line (Likely Benign | Suspicious | Malicious | Inconclusive)."
        ), "l2_investigation")
        m = _RECOMMEND_RE.search(reply)
        recommend = m.group(1).lower() if m else None
        outcome = f"{verdict or 'no verdict'} ({conf or 'unknown'} confidence), recommends {recommend or 'nothing'}"
        notes = f"{case.get('notes') or ''}\nInvestigator agent: {outcome}."
        ids = data.get("alert_ids", [])
        if conf == "High" and (verdict == "Likely Benign" or (verdict is None and recommend == "close")):
            incident_store.update_for_user(case["user_id"], case["id"], {
                "status": "closed", "verdict": "False positive", "notes": notes + " Closed as false positive."})
            alerts_inbox.set_agent_outcome(ids, "dismissed", f"Investigator agent: false positive, case {case['case_number']} closed")
            agent_store.log("investigator", "case_closed", case["id"], f"{case['case_number']}: closed as false positive", data)
        else:
            fields = {"status": "investigating", "verdict": verdict or "Inconclusive", "notes": notes + " Needs human review."}
            if verdict == "Malicious":
                fields["severity"] = "critical" if conf == "High" else "high"
            incident_store.update_for_user(case["user_id"], case["id"], fields)
            agent_store.log("investigator", "needs_review", case["id"], f"{case['case_number']}: {outcome}, needs human review", data)
            if verdict == "Malicious" or recommend == "isolate":
                for sid, host in alerts_inbox.sensors(ids):
                    p = agent_store.propose(case["id"], sid, host, f"{case['case_number']}: {outcome}")
                    if p:
                        agent_store.log("investigator", "proposed", p["id"], f"Isolate {host or sid} for {case['case_number']}")
        done += 1
    return f"{done} case(s) investigated"


# ── reporter ──────────────────────────────────────────────────────────
def run_reporter(cfg: Dict[str, Any]) -> str:
    owner = _owner(cfg)
    day_ago = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    s = alerts_inbox.stats(24)
    acts = Counter(f"{e['agent']}:{e['action']}" for e in agent_store.since(day_ago) if not e["undone_at"])
    cases = [c for c in incident_store.list_for_user(owner["id"]) if c["status"] != "closed"]
    stale = [c["case_number"] for c in cases if (c.get("updated_at") or "") < day_ago]
    pending = sum(p["status"] == "proposed" for p in agent_store.proposals(200))
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    lines = [
        f"## Shift report, {date} (last 24h)",
        f"- Alerts received: **{s['total']}**; unacknowledged backlog: **{s['backlog'].get('new', 0)}**; "
        f"being investigated: **{s['backlog'].get('investigating', 0)}**",
        f"- Triage agent: {acts['triage:dismissed']} alert group(s) dismissed as false positives, "
        f"{acts['triage:case_opened']} case(s) opened",
        f"- Investigator agent: {acts['investigator:case_closed']} case(s) closed as false positives, "
        f"{acts['investigator:needs_review']} flagged for human review, "
        f"{acts['investigator:proposed']} isolation proposal(s)",
        f"- Isolation proposals awaiting approval: **{pending}**",
        f"- Open cases: **{len(cases)}**" + (f"; no update for 24h: {', '.join(stale)}" if stale else ""),
    ]
    if s["top_rules"]:
        lines += ["", "### Top detection rules", *[f"- {r['name']}: {r['n']}" for r in s["top_rules"]]]
    conv = store.create_conversation_for_user(owner["id"], title=f"Shift report {date}")["id"]
    store.add_message_for_user(owner["id"], conv, "assistant", "\n".join(lines))
    agent_store.log("reporter", "report", conv, f"Shift report {date}", {"owner_id": owner["id"]})
    return "shift report posted"


def _reporter_due(cfg: Dict[str, Any]) -> bool:
    now = datetime.now(timezone.utc)
    last = agent_store.last("reporter", "report")
    return now.hour == int(cfg["reporter"]["hour_utc"]) and (not last or last["created_at"][:10] != now.strftime("%Y-%m-%d"))


# ── responder (approval-gated containment) ────────────────────────────
def _lc_isolation(sid: str, isolate: bool) -> Tuple[bool, str]:
    from app.connectors.limacharlie import LimaCharlieConnector
    if not _SID_RE.fullmatch(sid or ""):
        return False, "invalid sensor id"
    lc = LimaCharlieConnector()
    if not lc.is_available():
        return False, "LimaCharlie is not configured"
    r = lc._request("POST" if isolate else "DELETE", f"/v1/{sid}/isolation")
    if r is None:
        return False, "request failed (auth or network)"
    return r.status_code < 400, f"HTTP {r.status_code} {r.text[:200]}"


def decide(pid: str, decision: str, user: Dict[str, Any]) -> Dict[str, Any]:
    """approve (isolate), reject, or release (rejoin) a containment proposal."""
    p = agent_store.get_proposal(pid)
    if not p:
        raise LookupError("proposal not found")
    host = p["hostname"] or p["sid"]
    if decision == "reject":
        if not agent_store.decide(pid, "proposed", "rejected", user["id"]):
            raise ValueError("proposal was already decided")
        agent_store.log("responder", "rejected", pid, f"Isolation of {host} rejected by {user['username']}")
    elif decision in ("approve", "release"):
        if decision == "approve" and not load_config()["responder"]["enabled"]:
            raise PermissionError("containment is switched off in the Agents settings")
        before, after = ("proposed", "executed") if decision == "approve" else ("executed", "released")
        if p["status"] != before:
            raise ValueError(f"proposal is {p['status']}, not {before}")
        ok, result = _lc_isolation(p["sid"], isolate=decision == "approve")
        agent_store.decide(pid, before, after if ok else ("failed" if decision == "approve" else before), user["id"], result)
        verb = "Isolated" if decision == "approve" else "Released"
        agent_store.log("responder", verb.lower() if ok else "error", pid,
                        f"{verb} {host} (by {user['username']}): {result}" if ok else f"{verb} {host} failed: {result}")
    else:
        raise ValueError("decision must be approve, reject or release")
    return agent_store.get_proposal(pid)


# ── undo ──────────────────────────────────────────────────────────────
def undo(log_id: str, user: Dict[str, Any]) -> None:
    """Reverse an autonomous false-positive decision; the alerts go back to a human."""
    e = agent_store.get(log_id)
    if not e or e["undone_at"] or e["action"] not in ("dismissed", "case_closed"):
        raise ValueError("only an agent's false-positive decision can be undone, once")
    data = json.loads(e["data_json"] or "{}")
    note = f"Agent decision undone by {user['username']}"
    if e["action"] == "case_closed":
        incident_store.update_for_user(data["owner_id"], e["target_id"], {"status": "investigating", "verdict": ""})
        alerts_inbox.set_agent_outcome(data.get("alert_ids", []), "investigating", note)
    else:
        alerts_inbox.set_agent_outcome(data.get("alert_ids", []), "new", note)
    agent_store.mark_undone(log_id)
    agent_store.log(e["agent"], "undone", e["target_id"], f"{e['detail']}: undone by {user['username']}")


# ── runner ────────────────────────────────────────────────────────────
RUNNERS: Dict[str, Callable[[Dict[str, Any]], str]] = {
    "triage": run_triage, "investigator": run_investigator, "reporter": run_reporter,
}


def _run(name: str, cfg: Dict[str, Any]) -> None:
    if not _locks[name].acquire(blocking=False):
        return  # one run per agent at a time
    _stop_requested[name].clear()
    try:
        result = RUNNERS[name](cfg)
        if _stop_requested[name].is_set():
            result = f"stopped: {result}"
        status[name] = {"last_run": _now(), "result": result}
    except LLMUnavailable as e:
        _paused_until[name] = time.time() + BACKOFF_S
        status[name] = {"last_run": _now(), "result": "paused 15 min: model unavailable"}
        agent_store.log(name, "error", None, f"Model unavailable, nothing decided; retrying in 15 minutes. {e}")
    except Exception as e:
        log.exception("%s agent failed", name)
        status[name] = {"last_run": _now(), "result": f"error: {e}"}
        agent_store.log(name, "error", None, str(e)[:300])
    finally:
        _locks[name].release()


def halt(names: List[str], user: Dict[str, Any]) -> List[str]:
    """Switch agents off and end any run in progress after its current group or case
    (an LLM call already underway finishes first; it can't be killed)."""
    names = [n for n in names if n in AGENTS]
    if not names:
        raise ValueError("unknown agent")
    for n in names:
        _stop_requested[n].set()
    save_config({n: {"enabled": False} for n in names})
    agent_store.log(names[0] if len(names) == 1 else "all", "stopped", None,
                    f"{', '.join(names)} stopped by {user['username']}")
    return names


def run_now(name: str) -> bool:
    if name not in RUNNERS:
        raise ValueError("unknown agent")
    if _locks[name].locked():
        return False
    threading.Thread(target=_run, args=(name, load_config()), daemon=True).start()
    return True


def _loop(stop: threading.Event) -> None:
    last: Dict[str, float] = {}
    while not stop.wait(15):
        try:
            cfg = load_config()
            for name, every in INTERVAL_S.items():
                due = time.time() - last.get(name, 0) >= every and time.time() >= _paused_until.get(name, 0)
                if cfg[name]["enabled"] and due:
                    last[name] = time.time()
                    _run(name, cfg)
            if cfg["reporter"]["enabled"] and _reporter_due(cfg):
                _run("reporter", cfg)
        except Exception:
            log.exception("agent loop tick failed")


_stop = threading.Event()


def start() -> None:
    # ponytail: one in-process loop; if NullShift ever runs several workers, each would
    # run agents too, so move to a DB lease then
    threading.Thread(target=_loop, args=(_stop,), daemon=True, name="nullshift-agents").start()


def stop() -> None:
    _stop.set()
