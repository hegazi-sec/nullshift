"""HTTP routes of the autonomous agents, the triage scorecard and the case report
export. The shared stores are read through app.main at call time, the same objects the
core routes use."""
from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from app import agents
from app.auth import get_current_user, html_page, require_admin
from app.db import user_store
from app.reports import build_incident_report_html, build_incident_report_md
from app.scorecard import triage_scorecard

log = logging.getLogger("nullshift")
router = APIRouter()


def _core():
    from app import main  # lazy: app.main includes this router while it loads
    return main


@router.get('/api/agents')
def api_agents(current_user: Dict[str, Any] = Depends(get_current_user)):
    is_admin = current_user.get("role") == "admin"
    cfg = agents.load_config()
    agent_store = _core().agent_store
    return {
        "config": cfg,
        "active_now": agents._active(cfg),  # False: the UI says the agents are outside their active hours
        "status": agents.status,
        "running": [a for a in agents.AGENTS if agents._locks[a].locked()],
        "log": agent_store.recent(60),
        "proposals": agent_store.proposals(30),
        "users": [u["username"] for u in user_store.list_users() if u["is_active"]] if is_admin else [],
        "is_admin": is_admin,
        "can_decide": current_user.get("role") in ("admin", "l2"),
        "me": current_user["username"],
        "me_id": current_user["id"],  # agent log rows carry owner_id; the UI links only its own chats
    }


@router.get('/api/agents/scorecard')
def api_agents_scorecard(days: int = 7, current_user: Dict[str, Any] = Depends(get_current_user)):
    """How the triage agent's shadow decisions compare with what analysts then did
    with the same alerts, per severity, with a recommended auto-dismiss limit."""
    return triage_scorecard(max(1, min(days, 90)))


@router.put('/api/agents/config')
def api_agents_config(payload: Dict[str, Any], current_user: Dict[str, Any] = Depends(require_admin)):
    owner = payload.get("owner")
    if owner and not user_store.get_user_by_username(str(owner)):
        raise HTTPException(status_code=400, detail=f"No user named {owner!r}")
    try:
        cfg = agents.save_config(payload)
    except (TypeError, ValueError) as e:
        raise HTTPException(status_code=400, detail=f"Invalid agent setting: {e}")
    log.info("Agents config updated by %s", current_user["username"])
    return {"config": cfg}


@router.post('/api/agents/{name}/run')
def api_agents_run(name: str, current_user: Dict[str, Any] = Depends(require_admin)):
    try:
        return {"started": agents.run_now(name)}
    except ValueError:
        raise HTTPException(status_code=404, detail="Unknown agent")


@router.post('/api/agents/{name}/stop')
def api_agents_stop(name: str, current_user: Dict[str, Any] = Depends(require_admin)):
    """Switch an agent off (name 'all' = every agent) and end its run after the current step."""
    try:
        return {"stopped": agents.halt(list(agents.AGENTS) if name == "all" else [name], current_user)}
    except ValueError:
        raise HTTPException(status_code=404, detail="Unknown agent")


@router.post('/api/agents/log/{log_id}/undo')
def api_agents_undo(log_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    try:
        agents.undo(log_id, current_user)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    return {"ok": True}


@router.post('/api/agents/proposals/{pid}/{decision}')
def api_agents_proposal(pid: str, decision: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    """approve (isolates the host in LimaCharlie), reject, or release (rejoin)."""
    if current_user.get("role") not in ("admin", "l2"):
        raise HTTPException(status_code=403, detail="Only admins and L2 analysts can decide on containment")
    try:
        return agents.decide(pid, decision, current_user)
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))


@router.get('/api/incidents/{incident_id}/report')
def api_incident_report(incident_id: str, format: str = "html", current_user: Dict[str, Any] = Depends(get_current_user)):
    m = _core()
    inc = m.incident_store.get_for_user(current_user["id"], incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    conv_ids = [c["conversation_id"] for c in inc.get("conversations", [])]
    conversations = []
    for cid in conv_ids:
        conv = m.store.get_conversation_for_user(current_user["id"], cid)
        if conv:
            conversations.append(conv)
    ioc_verdicts = m.verdict_store.list_for_conversations(current_user["id"], conv_ids)
    if format == "md":
        md = build_incident_report_md(inc, conversations, ioc_verdicts)
        return Response(
            content=md,
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{inc["case_number"]}-report.md"'},
        )
    html_doc = build_incident_report_html(inc, conversations, ioc_verdicts)
    return html_page(html_doc)
