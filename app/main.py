from fastapi import FastAPI, Request, HTTPException, Depends, Header
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.exceptions import RequestValidationError
from app.schemas import ChatRequest, ConversationCreate, MessageCreate, ToolExecuteRequest, PrefsUpdate
from app.config import settings
from app.connectors import wazuh, virustotal
from app.llm import (
    chat_with_history, summarize_messages,
    any_provider_configured, configured_provider_names,
    reload_providers, get_active_provider, get_active_vision_info,
    get_last_call_info, get_last_rate_limit_info,
    _is_ollama_active, validate_and_retry_if_needed,
)
from app.db.settings_store import settings_store, mask_for_api, ALLOWED_KEYS, SECRET_KEYS
from app.execution.tool_runner import ToolRunner
from app.execution.investigation_service import run_investigation
from app.playbooks.runner import PlaybookRunner, SPARSE_THRESHOLD
from app.prompts import SYSTEM_PROMPT
from app import rag as _rag_mod
from app.auth import router as auth_router, get_current_user, require_admin, init_auth_startup, _validate_csrf
from app.db.chat_store import store
from app.db.investigation_state import inv_state
from app.db.verdict_store import verdicts as verdict_store, parse_decision
from app.db.prefs_store import prefs as prefs_store
from app.db.summary_store import summaries as summary_store
from app.deployment_memory import write_memory_file, get_cached_memory
import re
import logging
from typing import Optional, Dict, Any, List

class _SuppressPing(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return "GET /api/ping" not in record.getMessage()

logging.getLogger("uvicorn.access").addFilter(_SuppressPing())
from app.utils.debug_trace import DebugTrace

def _rag_query(message: str) -> str:
    """Build a focused RAG search query from the user message.

    Extracts MITRE ATT&CK technique IDs and security-relevant nouns so the
    vector search hits the right skill files instead of matching on conversational
    filler words in a long question.
    """
    if not message:
        return ""
    # Pull every MITRE technique / sub-technique ID (e.g. T1555, T1071.004)
    mitre_ids = re.findall(r'\bT\d{4}(?:\.\d{3})?\b', message)
    # Take the first 120 chars of the message as a seed (captures the core topic)
    seed = message[:120]
    parts = mitre_ids + [seed] if mitre_ids else [seed]
    return " ".join(parts)


def _strip_html_from_llm(text: str) -> str:
    if not text or '<' not in text:
        return text
    # Convert <li> to markdown list items with double newline prefix so inline
    # <ul><li> blocks become their own paragraph block in the frontend renderer
    text = re.sub(r'<li[^>]*>(.*?)</li>', lambda m: f'\n\n- {m.group(1).strip()}', text, flags=re.DOTALL | re.IGNORECASE)
    # Replace <ul>/<ol> tags with a newline to preserve block separation
    text = re.sub(r'</?(?:ul|ol)[^>]*>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'</?(?:div|p|span)[^>]*>', '', text, flags=re.IGNORECASE)
    text = re.sub(r'<(?:b|strong)[^>]*>(.*?)</(?:b|strong)>', r'**\1**', text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<(?:i|em)[^>]*>(.*?)</(?:i|em)>', r'_\1_', text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<code[^>]*>(.*?)</code>', r'`\1`', text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<[^>]+>', '', text)
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()


def _has_indicator(text: str) -> bool:
    if not text:
        return False
    # crude IP/domain/hash/CVE detection
    if re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text):
        return True
    if re.search(r"\b[A-Fa-f0-9]{32,64}\b", text):
        return True
    if re.search(r"\bCVE-\d{4}-\d{4,7}\b", text, flags=re.I):
        return True
    if re.search(r"\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", text):
        return True
    return False


def select_response_mode(user_message: str, last_assistant_message: Optional[str]) -> str:
    """Route the user's message to one of four response modes that map to
    the L1 SOC analyst workflow (INVESTIGATE → REASON → DISCUSS → HAND OFF):

    - l2_handoff: user is asking for a ticket-ready escalation summary
    - investigation_report: new evidence ask or verdict request (full SECTION 1/2/3)
    - clarifying_question: too vague to proceed, ask the one missing fact
    - targeted_answer: everything else — conversational follow-up
    """
    msg = (user_message or "").strip().lower()
    if not msg:
        return "clarifying_question"

    # L2 handoff cues come first — "escalate this" should NOT be re-classified
    # as an investigation just because it contains the word "this".
    handoff_phrases = (
        "escalate", "escalation", "handoff", "hand off", "hand-off",
        "prep for l2", "prepare for l2", "for the ticket", "ticket summary",
        "summarize for", "ready to escalate", "send to l2", "l2 handoff",
    )
    if any(p in msg for p in handoff_phrases):
        return "l2_handoff"

    decision_like = any(p in msg for p in ["true positive", "false positive", "verdict", "is this", "tp", "fp"])
    analysis_like = any(p in msg for p in ["investigate", "investigation", "analyze", "analysis", "check", "review"])
    has_indicator = _has_indicator(msg)

    # Behavioral asks: "any whoami activity in the last 24h?" / "show me detections
    # from yesterday" — no IOC, no "investigate" keyword, but still an evidence
    # request. Triggered by (time window OR behavioral noun) and NOT an explanation
    # request, so "explain whoami" stays a targeted_answer.
    time_window_phrase = any(p in msg for p in [
        "in the last", "past 24", "past hour", "today", "yesterday",
        "last 24", "last hour", "this hour", "this week", "last week",
    ])
    behavioral_noun = any(p in msg for p in [
        "activity", "detections", "logons", "logins",
        "process tree", "process executions",
    ])
    explain_like = any(p in msg for p in ["explain", "what is", "what does", "definition", "how does", "describe"])

    targeted_patterns = ["query", "queries", "kql", "command", "how to", "explain", "definition", "list", "summar", "show", "give me", "clarify", "what", "which", "do you"]
    targeted_like = any(p in msg for p in targeted_patterns)

    if len(msg) < 8 and not has_indicator and not targeted_like and not analysis_like and not decision_like:
        return "clarifying_question"

    if has_indicator or decision_like or analysis_like:
        return "investigation_report"

    if (time_window_phrase or behavioral_noun) and not explain_like:
        return "investigation_report"

    return "targeted_answer"


_TEMP_BY_MODE: Dict[str, float] = {
    "investigation_report": 0.1,   # evidence-faithful; lower = fewer invented facts
    "l2_handoff": 0.1,             # ticket must be exact
    "clarifying_question": 0.15,   # slightly more latitude for phrasing a question
    "targeted_answer": 0.1,        # follow-up answers; was 0.4 — that was the hallucination source
}


def _temperature_for_mode(mode: str, user_prefs: Optional[Dict[str, Any]] = None) -> float:
    # l2_handoff must always be exact — never allow user override
    if mode == "l2_handoff":
        return 0.1
    if user_prefs:
        override = user_prefs.get("temperature_override")
        if override is not None:
            try:
                return max(0.0, min(0.5, float(override)))
            except (TypeError, ValueError):
                pass
    return _TEMP_BY_MODE.get(mode, 0.2)


def classify_task_type(user_message: str) -> str:
    msg = (user_message or '').lower()
    if _has_indicator(msg) and any(w in msg for w in ["investigate", "investigation", "check", "review", "tp", "fp", "true positive", "false positive", "malicious", "verdict"]):
        return "ioc_investigation"
    if any(w in msg for w in ["query", "queries", "kql", "how to", "commands", "what query", "search in wazuh", "wazuh"]):
        return "wazuh_queries"
    if any(w in msg for w in ["latest cves", "top cves", "recent cves", "new cves", "advisories", "nist", "nvd"]):
        return "cve_lookup"
    if any(w in msg for w in ["top wazuh alerts", "most frequent wazuh alerts", "detections"]):
        return "top_wazuh_alerts"
    if any(w in msg for w in ["explain", "what is", "definition"]):
        return "generic_explain"
    return "other"


def choose_time_window(req_time: Optional[str]) -> Dict[str, Any]:
    # default last_24h with ask+proceed note per policy
    if req_time and req_time.strip():
        return {"time_range": req_time.strip(), "asked": False, "note": None}
    return {
        "time_range": "last_24h",
        "asked": True,
        "note": "Time range not provided. What time range should I use? Default 24h window used."
    }


FOLLOWUP_WORDS = {
    "show", "query", "queries", "send", "error", "errors", "what", "did", "you", "run", "ran",
    "executed", "tool", "tools", "call", "calls", "last", "previous", "details"
}


def _derive_subject_terms(msg: str) -> List[str]:
    text = msg or ""
    # Include IOCs first
    iocs = extract_iocs(text)
    # Extract simple keywords, exclude common follow-up/request words
    words = re.findall(r"[A-Za-z0-9_\-]{3,}", text.lower())
    kws: List[str] = []
    for w in words:
        if w in FOLLOWUP_WORDS:
            continue
        if w not in kws:
            kws.append(w)
    # Merge, preserve order (IOCs first)
    out: List[str] = []
    for t in (iocs + kws):
        if t not in out:
            out.append(t)
    return out[:10]


def _prime_prior_session_summaries(
    user_id: int,
    current_conv_id: str,
    max_results: int = 2,
    max_generations_per_call: int = 1,
    min_messages: int = 4,
) -> List[Dict[str, Any]]:
    """Return cached summaries for the user's recent prior conversations.

    Walks conversations newest-first; uses cached summaries when present and
    generates up to `max_generations_per_call` new ones synchronously per
    request. The bound keeps the first-turn latency hit small — subsequent
    turns warm the cache further. Conversations with fewer than
    `min_messages` are skipped (too small to be worth summarizing).
    """
    try:
        convs = store.list_conversations_for_user(user_id)
    except Exception:
        return []
    candidates = [c for c in convs if c["id"] != current_conv_id][: max_results + 3]
    out: List[Dict[str, Any]] = []
    generated = 0
    for c in candidates:
        if len(out) >= max_results:
            break
        existing = summary_store.get(c["id"])
        if existing:
            out.append({
                "conversation_id": c["id"],
                "title": c.get("title") or "Untitled",
                "summary": existing["summary_md"],
                "summarized_at": existing["summarized_at"],
                "message_count": existing["message_count"],
            })
            continue
        if generated >= max_generations_per_call:
            continue
        full = store.get_conversation_for_user(user_id, c["id"])
        if not full:
            continue
        msgs = full.get("messages") or []
        if len(msgs) < min_messages:
            continue
        sm = summarize_messages(msgs)
        if not sm:
            continue
        summary_store.set(c["id"], user_id, sm, len(msgs))
        generated += 1
        row = summary_store.get(c["id"]) or {}
        out.append({
            "conversation_id": c["id"],
            "title": c.get("title") or "Untitled",
            "summary": sm,
            "summarized_at": row.get("summarized_at"),
            "message_count": len(msgs),
        })
    return out


def _is_run_details_request(msg: str) -> bool:
    m = (msg or "").lower()
    phrases = [
        "show the query", "show query", "what did you run", "what did you execute",
        "show error", "show errors", "what error", "what errors", "last tool calls",
        "what tools did you run", "what query did you run",
    ]
    return any(p in m for p in phrases)


def handle_chat_orchestrated(req: ChatRequest, conv_id: str, last_assistant: Optional[str], current_user: Dict[str, Any]) -> str:
    # Determine mode and task
    response_mode = select_response_mode(req.message or '', last_assistant)
    task_type = classify_task_type(req.message or '')
    intent = route_intent(req.message or '')

    # Time window policy
    tw = choose_time_window(req.time_range)
    time_range = tw["time_range"]

    # Follow-up: user asks for what was executed or errors — do not run new searches
    if _is_run_details_request(req.message or ''):
        st = inv_state.get(conv_id)
        if not st or not st.get('last_tool_calls'):
            return (
                "No previous investigation found in this conversation. "
                "Ask me to investigate a subject (e.g., 'sqlmap') and I'll run the searches."
            )
        lines = [
            "Last executed tool calls (no new searches run):",
        ]
        for c in st.get('last_tool_calls', [])[:10]:
            try:
                lines.append(f"- {c.get('tool_name')}:{c.get('query_id')} params={c.get('params')} results={c.get('result_count')}")
            except Exception:
                continue
        errs = st.get('errors') or {}
        if errs:
            lines.append("Errors observed:")
            for k, v in list(errs.items())[:10]:
                lines.append(f"- {k}: {v}")
        return "\n".join(lines)

    # Determine/lock subject terms per conversation to avoid follow-up noise ('show query', etc.)
    st = inv_state.get(conv_id)
    if st and st.get('subject_terms'):
        subject_terms = st['subject_terms']
    else:
        subject_terms = _derive_subject_terms(req.message or '')

    subject_text = " ".join(subject_terms) if subject_terms else (req.message or '')

    # Prior-verdict lookup: any IOC the user is asking about (this turn OR
    # locked subject) that we've previously triaged for this user.
    lookup_iocs = extract_iocs((req.message or '') + ' ' + subject_text)
    prior_verdicts = verdict_store.lookup_for_iocs(
        current_user["id"], lookup_iocs, limit_per_ioc=3, exclude_conversation_id=conv_id,
    ) if lookup_iocs else []

    # Progressive Evidence Gathering pipeline (service)
    # Optional per-request debug trace
    debug = DebugTrace() if getattr(req, 'debug', False) else None

    # --- Step 1: Playbook-driven investigation ---
    # Run targeted SIEM queries derived from the best-matching playbook (if any).
    playbook_evidence = _playbook_runner.run(
        message=req.message or '',
        time_range=time_range,
        user=current_user,
        tool_runner=tool_runner,
    )

    # --- Step 2: Decide whether to also run the keyword-based investigation ---
    if (playbook_evidence["playbook_triggered"]
            and playbook_evidence["total_events"] >= SPARSE_THRESHOLD):
        # Playbook produced enough evidence — use it as the primary bundle and
        # skip the generic keyword hunt to avoid redundant queries.
        evidence_bundle: Dict[str, Any] = playbook_evidence
        evidence_bundle["investigation_method"] = "playbook"
    else:
        # Important: pass the ORIGINAL user message to preserve explicit time-window phrases
        # like "last 48h" or "last 1 month" for accurate parsing.
        evidence_bundle = run_investigation(intent, req.message or '', time_range, current_user, tool_runner, debug=debug)
        evidence_bundle["investigation_method"] = "keyword"

        # If a playbook matched but returned sparse events, prepend its calls so the
        # LLM sees the targeted evidence first, then the broader keyword results.
        if playbook_evidence["playbook_triggered"] and playbook_evidence["executed_calls"]:
            evidence_bundle["executed_calls"] = (
                playbook_evidence["executed_calls"]
                + evidence_bundle.get("executed_calls", [])
            )
            evidence_bundle["playbook_title"] = playbook_evidence["playbook_title"]
            evidence_bundle["investigation_method"] = "playbook+keyword"

    evidence_bundle["asked_time_range"] = tw["asked"]
    evidence_bundle["policy_note"] = tw.get("note")
    evidence_bundle["task_type"] = task_type
    if prior_verdicts:
        evidence_bundle["prior_verdicts"] = prior_verdicts

    prior_sessions = _prime_prior_session_summaries(current_user["id"], conv_id)
    if prior_sessions:
        evidence_bundle["prior_session_summaries"] = prior_sessions

    # Update per-conversation investigation state (persisted to SQLite)
    inv_state.set(conv_id, {
        "subject_terms": subject_terms,
        "intent": intent,
        "time_window": evidence_bundle.get("time_window"),
        "executed_calls": evidence_bundle.get("executed_calls", []),
        "last_tool_calls": evidence_bundle.get("executed_calls", []),
        "errors": evidence_bundle.get("errors", {}),
        "_debug_trace": evidence_bundle.get("_debug_trace"),
    })

    # Build augmented user message
    note = (tw.get("note") + "\n\n") if tw.get("note") else ""
    augmented_user = {
        "role": "user",
        "content": f"{note}User message: {req.message}\n\nUse evidence bundle to decide minimum necessary sources."
    }

    retrieved = _rag_mod.rag.retrieve(_rag_query(req.message or ""))
    if debug:
        debug.add({
            "type": "rag",
            "chunks_retrieved": len(retrieved),
            "sources": [r.split("\n")[0] for r in retrieved],
        })
    reply = orchestrated_llm_reply(augmented_user, conv_id, response_mode, evidence_bundle, current_user, retrieved=retrieved, debug=debug)

    # Record this turn's verdict for any IOCs the user mentioned, so future
    # investigations can surface it. Parsing is tolerant — a NULL verdict
    # still leaves an audit row.
    record_iocs = extract_iocs((req.message or '') + ' ' + subject_text)
    if record_iocs:
        v, c = parse_decision(reply)
        try:
            verdict_store.record(
                user_id=current_user["id"],
                conversation_id=conv_id,
                iocs=record_iocs,
                verdict=v,
                confidence=c,
                message_excerpt=req.message or '',
                evidence_summary={
                    "totals": evidence_bundle.get("totals"),
                    "sources_queried": evidence_bundle.get("sources_queried"),
                    "investigation_method": evidence_bundle.get("investigation_method"),
                    "time_window": evidence_bundle.get("time_window"),
                },
            )
        except Exception:
            log.exception("verdict_store.record failed")

    # Attach debug trace into a hidden marker the UI can parse if needed (keeps reply unchanged)
    # We do not expose here; /chat route will add debug_trace in JSON if requested.
    if debug:
        evidence_bundle["_debug_trace"] = debug.to_list()
    return reply


def _rag_is_ready() -> bool:
    """Return True if RAG is enabled and fully indexed (not mid-sync)."""
    try:
        st = _rag_mod.rag.status()
        return st.get("enabled", False) and st.get("sync_state") in ("complete", "skipped")
    except Exception:
        return False


def orchestrated_llm_reply(aug_user_msg: Dict[str, str], conv_id: str, response_mode: str, evidence: Dict[str, Any], current_user: Dict[str, Any], retrieved: Optional[List[str]] = None, debug=None) -> str:
    # Prepare history and call LLM (scoped — caller has already verified ownership,
    # but this is defense-in-depth: a stale conv_id won't leak another user's history)
    try:
        history = store.last_messages_for_user(current_user["id"], conv_id, limit=20)
    except PermissionError:
        history = []
    hist_trimmed = [m for m in history if not (m.get('role')=='user' and m.get('content')==aug_user_msg['content'])]
    hist_for_llm = hist_trimmed + [aug_user_msg]
    user_prefs = prefs_store.get_all(current_user["id"]) if current_user else {}
    temperature = _temperature_for_mode(response_mode, user_prefs)
    reply_md = chat_with_history(
        SYSTEM_PROMPT,
        hist_for_llm,
        retrieved=retrieved,
        response_mode=response_mode,
        evidence=evidence,
        temperature=temperature,
        tool_runner=tool_runner,
        current_user=current_user,
        user_prefs=user_prefs or None,
        deployment_memory=get_cached_memory(),
    )

    # RAG validation: only for Ollama, only when RAG is fully indexed and chunks were retrieved
    if retrieved and _is_ollama_active() and _rag_is_ready():
        reply_md, retried = validate_and_retry_if_needed(
            response=reply_md,
            retrieved=retrieved,
            system_prompt=SYSTEM_PROMPT,
            history_messages=hist_for_llm,
            evidence=evidence,
            response_mode=response_mode,
            temperature=temperature,
            tool_runner=tool_runner,
            current_user=current_user,
            user_prefs=user_prefs or None,
            deployment_memory=get_cached_memory(),
        )
        if debug:
            debug.add({"type": "rag_validation", "retried": retried})

    return reply_md

app = FastAPI()
app.include_router(auth_router)

# Serve static assets (logo, favicon) at /static/
from fastapi.staticfiles import StaticFiles
from pathlib import Path as _Path
_static_dir = _Path(__file__).resolve().parent / "static"
if _static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")

# Instantiate a single ToolRunner and PlaybookRunner for the app lifecycle
tool_runner = ToolRunner()
_playbook_runner = PlaybookRunner()


@app.on_event("startup")
async def _startup_init_auth():
    init_auth_startup()


@app.on_event("shutdown")
async def _shutdown_rag():
    if hasattr(_rag_mod.rag, "_stop_event"):
        _rag_mod.rag._stop_event.set()


@app.on_event("startup")
async def _startup_write_deployment_memory():
    """Regenerate data/memory.md describing the current connector set so the
    LLM can see (and the analyst can read) what toolkit this deployment has."""
    try:
        path = write_memory_file()
        log.info("Deployment memory written to %s", path)
    except Exception:
        log.exception("Failed to write deployment memory")


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Better error messages for validation errors."""
    return JSONResponse(
        status_code=422,
        content={
            "error": "Invalid JSON in request body",
            "detail": str(exc.errors()),
            "example": {"message": "text", "alert_id": None, "agent_id": None, "time_range": "last_24h"}
        }
    )


def _is_setup_complete() -> bool:
    """Return True if setup has been marked complete OR if users already exist.

    Belt-and-suspenders: if setup.py wrote admin account to chat.db but the
    browser opened before setup_complete was written in step 8, we don't want
    the web wizard to run and wipe config.db. Checking for existing users
    prevents that timing-window race.
    """
    try:
        if settings_store.get("setup_complete") == "true":
            return True
        # Also treat as complete if any user accounts exist
        from app.db.chat_store import store as _store
        users = _store.conn.execute("SELECT 1 FROM users LIMIT 1").fetchone()
        return users is not None
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Setup wizard — completely unprotected, only active before setup_complete
# ---------------------------------------------------------------------------

@app.get('/setup', response_class=HTMLResponse)
def setup_page():
    """Serve the web setup wizard. Returns 404 once setup is complete."""
    if _is_setup_complete():
        return RedirectResponse(url="/", status_code=303)
    import os as _os
    html_path = _os.path.join(_os.path.dirname(__file__), "setup.html")
    with open(html_path, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.post('/api/setup/complete')
async def api_setup_complete(payload: Dict[str, Any]):
    """Accept the setup wizard POST and persist all settings to config.db.

    No auth required — only works when setup_complete != 'true'.
    """
    if _is_setup_complete():
        raise HTTPException(status_code=403, detail="Setup already complete")

    import secrets as _secrets
    from app.auth import get_password_hash as _hash_pw
    from app.db import user_store as _user_store

    admin_username = (payload.get("admin_username") or "").strip()
    admin_password = payload.get("admin_password") or ""
    sdk_enabled    = bool(payload.get("sdk_enabled", False))
    siem_provider  = payload.get("siem_provider")

    # Validate
    if not admin_username:
        raise HTTPException(status_code=400, detail="admin_username is required")
    if len(admin_password) < 16:
        raise HTTPException(status_code=400, detail="admin_password must be at least 16 characters")

    # Generate JWT secret only if one isn't already stored (setup.py may have set it)
    existing_jwt = settings_store.get("jwt_secret")
    jwt_secret = existing_jwt or _secrets.token_urlsafe(32)
    updates: Dict[str, Any] = {"jwt_secret": jwt_secret}

    # Only set rag_enabled if not already configured by setup.py
    if not settings_store.get("rag_enabled"):
        updates["rag_enabled"] = "false"

    if sdk_enabled:
        updates["claude_agent_sdk_enabled"] = "true"
    elif not settings_store.get("claude_agent_sdk_enabled"):
        updates["claude_agent_sdk_enabled"] = "false"

    # Persist SIEM settings
    if siem_provider and siem_provider != "skip":
        updates["siem_provider"] = siem_provider
        if siem_provider == "limacharlie":
            if payload.get("limacharlie_oid"):
                updates["limacharlie_oid"] = payload["limacharlie_oid"]
            if payload.get("limacharlie_api_key"):
                updates["limacharlie_api_key"] = payload["limacharlie_api_key"]
        elif siem_provider == "wazuh":
            for k in ("wazuh_api_url", "wazuh_indexer_url", "wazuh_indexer_user",
                      "wazuh_indexer_pass", "wazuh_api_token"):
                if payload.get(k):
                    updates[k] = payload[k]
        elif siem_provider == "splunk":
            for k in ("splunk_url", "splunk_token", "splunk_index"):
                if payload.get(k):
                    updates[k] = payload[k]
        elif siem_provider == "elastic":
            for k in ("elastic_url", "elastic_api_key", "elastic_index"):
                if payload.get(k):
                    updates[k] = payload[k]
        elif siem_provider == "sentinel":
            for k in ("sentinel_workspace_id", "sentinel_tenant_id",
                      "sentinel_client_id", "sentinel_client_secret"):
                if payload.get(k):
                    updates[k] = payload[k]

    settings_store.set_many(updates)

    # Create admin user
    _user_store.init_db()
    existing = _user_store.get_user_by_username(admin_username)
    if not existing:
        _user_store.create_user(admin_username, _hash_pw(admin_password), role="admin")
        log.info("[setup] Created admin user: %s", admin_username)
    else:
        log.info("[setup] Admin user already exists: %s", admin_username)

    # Mark setup complete LAST (so a crash before this point leaves setup re-runnable)
    settings_store.set_many({"setup_complete": "true"})
    log.info("[setup] Setup marked complete.")

    return {"ok": True, "message": "Setup complete. Start uvicorn and open the app."}


@app.get('/health')
def health():
    return {"status": "ok"}


@app.get('/debug/siem')
def debug_siem():
    """Unauthenticated diagnostic: probe the configured SIEM provider with a
    small `recent_alerts` query so we can confirm the connector is reachable
    and authenticated, without sending a chat."""
    import time
    provider = (settings.SIEM_PROVIDER or "wazuh").lower().strip()
    out: Dict[str, Any] = {"SIEM_PROVIDER": provider}
    if provider not in ("splunk", "elastic", "sentinel", "limacharlie"):
        out["note"] = (
            f"Provider '{provider}' uses its own legacy code path (not the SIEMConnector "
            "ABC). This endpoint only probes Splunk/Elastic/Sentinel/LimaCharlie."
        )
        return out
    try:
        from app.connectors import get_siem_connector
        conn = get_siem_connector(provider)
    except Exception as e:
        out["error"] = f"Failed to load connector: {type(e).__name__}: {e}"
        return out
    out["is_available"] = conn.is_available()
    if not conn.is_available():
        out["hint"] = f"Connector reports missing credentials. Check the {provider.upper()}_* env vars in .env."
        return out
    t0 = time.monotonic()
    try:
        rows = tool_runner._exec_siem(provider, "recent_alerts", {}, "last_24h", "now")
        out["probe_query"] = "recent_alerts over last_24h"
        out["probe_result_count"] = len(rows)
        out["probe_elapsed_s"] = round(time.monotonic() - t0, 2)
        out["sample"] = rows[:1]
    except Exception as e:
        out["probe_error"] = f"{type(e).__name__}: {e}"
    return out


@app.get('/debug/llm')
def debug_llm():
    """Unauthenticated diagnostic: show which LLM providers the running
    server has loaded. Helps tell 'env-not-read' from 'sdk-not-installed'
    from 'old-uvicorn-process' apart without restarting."""
    import os, sys
    out = {
        "cwd": os.getcwd(),
        "pid": os.getpid(),
        "python": sys.executable,
        "USE_CLAUDE_AGENT_SDK": settings.USE_CLAUDE_AGENT_SDK,
        "ANTHROPIC_API_KEY_set": bool(settings.ANTHROPIC_API_KEY),
        "OPENAI_API_KEY_set": bool(settings.OPENAI_API_KEY),
        "configured_providers": configured_provider_names(),
        "any_configured": any_provider_configured(),
    }
    try:
        import claude_agent_sdk  # type: ignore
        out["claude_agent_sdk_version"] = getattr(claude_agent_sdk, "__version__", "unknown")
        out["claude_agent_sdk_path"] = getattr(claude_agent_sdk, "__file__", "unknown")
    except Exception as e:
        out["claude_agent_sdk_import_error"] = f"{type(e).__name__}: {e}"
    return out


# convenience debugging endpoint to verify Wazuh connectivity/token
@app.get('/wazuh/token')
def wazuh_token():
    """Return the current token (if any) and attempt a trivial search.
    Use this from curl or the browser to confirm that the WAZUH_API_TOKEN
    (or user/pass) settings are being applied correctly.  It is intentionally
    unprotected since it's only for local development.
    """
    from app.connectors import wazuh
    token = wazuh._get_token()
    result = {"token_present": bool(token), "token": token}
    # try a quick search to see if the API responds
    if token:
        try:
            events = wazuh.wazuh_search("", limit=1)  # should return empty list or hit
            result["probe_count"] = len(events)
        except Exception as e:
            result["probe_error"] = str(e)
    return result


@app.get('/debug/wazuh-indexer')
def debug_wazuh_indexer(current_user: Dict[str, Any] = Depends(require_admin)):
    """Admin-only: Check Wazuh Indexer (OpenSearch) connectivity and health."""
    from app.connectors import wazuh as wazuh_conn
    hc = wazuh_conn.wazuh_indexer_healthcheck()
    return JSONResponse(content=hc)


# ---------------------------------------------------------------------------
# Admin: provider settings + usage. Lets an admin change the active LLM
# provider, paste API keys, and read the most recent rate-limit telemetry
# without editing .env or restarting uvicorn.
# ---------------------------------------------------------------------------

_PROVIDER_CATALOG = [
    {
        "name": "claude_agent_sdk",
        "label": "Claude Agent SDK",
        "description": "Home-SOC mode — uses the local `claude` CLI with a Claude.ai Pro/Max subscription. No API key; bills your subscription.",
        "key_field": None,
        "model_field": "claude_agent_sdk_model",
        "enable_field": "claude_agent_sdk_enabled",
        "base_url_field": None,
        "model_options": [
            {"value": "opus",                       "label": "opus (alias — latest Opus)"},
            {"value": "sonnet",                     "label": "sonnet (alias — latest Sonnet)"},
            {"value": "haiku",                      "label": "haiku (alias — latest Haiku)"},
            {"value": "claude-opus-4-8",            "label": "claude-opus-4-8 (latest flagship)"},
            {"value": "claude-opus-4-7",            "label": "claude-opus-4-7"},
            {"value": "claude-sonnet-4-6",          "label": "claude-sonnet-4-6"},
            {"value": "claude-haiku-4-5-20251001",  "label": "claude-haiku-4-5-20251001"},
        ],
    },
    {
        "name": "anthropic",
        "label": "Anthropic API",
        "description": "Direct Anthropic API — best quality, supports prompt caching. Recommended for org/multi-analyst deployments.",
        "key_field": "anthropic_api_key",
        "model_field": "anthropic_model",
        "enable_field": None,
        "base_url_field": None,
        "model_options": [
            {"value": "claude-opus-4-8",            "label": "claude-opus-4-8 (latest, best)"},
            {"value": "claude-opus-4-7",            "label": "claude-opus-4-7"},
            {"value": "claude-sonnet-4-6",          "label": "claude-sonnet-4-6 (balanced)"},
            {"value": "claude-haiku-4-5-20251001",  "label": "claude-haiku-4-5-20251001 (fastest)"},
        ],
    },
    {
        "name": "openai",
        "label": "OpenAI",
        "description": "OpenAI GPT and reasoning models. Works as primary or fallback.",
        "key_field": "openai_api_key",
        "model_field": "openai_model",
        "enable_field": None,
        "base_url_field": None,
        "model_options": [
            {"value": "gpt-5.5",           "label": "gpt-5.5 (latest flagship, vision)"},
            {"value": "gpt-5.4",           "label": "gpt-5.4 (vision)"},
            {"value": "gpt-5.4-mini",      "label": "gpt-5.4-mini (fast, vision)"},
            {"value": "gpt-5",             "label": "gpt-5 (vision)"},
            {"value": "gpt-4.1",           "label": "gpt-4.1 (vision)"},
            {"value": "gpt-4.1-mini",      "label": "gpt-4.1-mini (fast, vision)"},
            {"value": "gpt-4.1-nano",      "label": "gpt-4.1-nano (cheapest)"},
            {"value": "gpt-4o",            "label": "gpt-4o (vision)"},
            {"value": "gpt-4o-mini",       "label": "gpt-4o-mini (vision)"},
            {"value": "o3",                "label": "o3 (reasoning, vision)"},
            {"value": "o3-pro",            "label": "o3-pro (best reasoning)"},
            {"value": "o3-mini",           "label": "o3-mini (fast reasoning)"},
            {"value": "o4-mini",           "label": "o4-mini (fast reasoning, vision)"},
            {"value": "o3-deep-research",  "label": "o3-deep-research"},
        ],
    },
    {
        "name": "gemini",
        "label": "Google Gemini",
        "description": "Google Gemini models via OpenAI-compatible endpoint. Free tier available.",
        "key_field": "gemini_api_key",
        "model_field": "gemini_model",
        "enable_field": None,
        "base_url_field": None,
        "model_options": [
            {"value": "gemini-3.5-flash",        "label": "gemini-3.5-flash (latest, vision)"},
            {"value": "gemini-3.1-pro-preview",  "label": "gemini-3.1-pro-preview (vision)"},
            {"value": "gemini-3.1-flash-lite",   "label": "gemini-3.1-flash-lite (cheap, vision)"},
            {"value": "gemini-2.5-pro",          "label": "gemini-2.5-pro (vision)"},
            {"value": "gemini-2.5-flash",        "label": "gemini-2.5-flash (fast, vision)"},
            {"value": "gemini-2.5-flash-lite",   "label": "gemini-2.5-flash-lite (cheapest, vision)"},
            {"value": "gemini-1.5-pro",          "label": "gemini-1.5-pro (vision)"},
        ],
    },
    {
        "name": "groq",
        "label": "Groq",
        "description": "Ultra-fast LPU inference — Llama 4, Qwen 3, and more. Generous free tier.",
        "key_field": "groq_api_key",
        "model_field": "groq_model",
        "enable_field": None,
        "base_url_field": None,
        "model_options": [
            {"value": "meta-llama/llama-4-scout-17b-16e-instruct",   "label": "llama-4-scout-17b (vision)"},
            {"value": "meta-llama/llama-4-maverick-17b-128e-instruct", "label": "llama-4-maverick-17b (vision)"},
            {"value": "openai/gpt-oss-120b",                         "label": "gpt-oss-120b"},
            {"value": "openai/gpt-oss-20b",                          "label": "gpt-oss-20b (fast)"},
            {"value": "qwen/qwen3-32b",                              "label": "qwen3-32b (128k, tools)"},
            {"value": "qwen/qwen3-vl-32b-instruct",                  "label": "qwen3-vl-32b (vision)"},
            {"value": "minimaxai/minimax-m2.5",                      "label": "minimax-m2.5"},
            {"value": "compound-beta",                               "label": "compound-beta (built-in tools)"},
            {"value": "llama-3.3-70b-versatile",                     "label": "llama-3.3-70b-versatile"},
            {"value": "llama-3.1-8b-instant",                        "label": "llama-3.1-8b-instant (fastest)"},
        ],
    },
    {
        "name": "mistral",
        "label": "Mistral AI",
        "description": "Mistral's cloud — frontier text, vision, code, reasoning, and audio models.",
        "key_field": "mistral_api_key",
        "model_field": "mistral_model",
        "enable_field": None,
        "base_url_field": None,
        "model_options": [
            {"value": "mistral-large-2512",    "label": "mistral-large-2512 (flagship)"},
            {"value": "mistral-large-latest",  "label": "mistral-large-latest (alias)"},
            {"value": "mistral-medium-2508",   "label": "mistral-medium-2508"},
            {"value": "mistral-small-2506",    "label": "mistral-small-2506"},
            {"value": "mistral-small-latest",  "label": "mistral-small-latest (alias)"},
            {"value": "ministral-14b-2512",    "label": "ministral-14b-2512 (edge)"},
            {"value": "ministral-8b-2512",     "label": "ministral-8b-2512 (edge)"},
            {"value": "ministral-3b-2512",     "label": "ministral-3b-2512 (ultralight)"},
            {"value": "magistral-medium-2507", "label": "magistral-medium-2507 (reasoning)"},
            {"value": "magistral-small-2507",  "label": "magistral-small-2507 (reasoning)"},
            {"value": "devstral-medium-2507",  "label": "devstral-medium-2507 (agentic code)"},
            {"value": "devstral-small-2507",   "label": "devstral-small-2507 (agentic code)"},
            {"value": "devstral-latest",       "label": "devstral-latest (alias)"},
            {"value": "pixtral-large-2411",    "label": "pixtral-large-2411 (vision)"},
            {"value": "pixtral-12b-2409",      "label": "pixtral-12b-2409 (vision, lighter)"},
            {"value": "codestral-2508",        "label": "codestral-2508"},
            {"value": "codestral-latest",      "label": "codestral-latest (alias)"},
            {"value": "mistral-ocr-2512",      "label": "mistral-ocr-2512 (document OCR)"},
        ],
    },
    {
        "name": "xai",
        "label": "xAI / Grok",
        "description": "xAI's Grok models — real-time web access and vision.",
        "key_field": "xai_api_key",
        "model_field": "xai_model",
        "enable_field": None,
        "base_url_field": None,
        "model_options": [
            {"value": "grok-4.3",           "label": "grok-4.3 (latest, vision)"},
            {"value": "grok-4-0709",        "label": "grok-4-0709 (pinned, vision)"},
            {"value": "grok-3",             "label": "grok-3 (→ redirects to grok-4.3)"},
            {"value": "grok-3-mini",        "label": "grok-3-mini (reasoning)"},
            {"value": "grok-code-fast-1",   "label": "grok-code-fast-1 (code)"},
            {"value": "grok-2-vision-1212", "label": "grok-2-vision-1212 (vision)"},
        ],
    },
    {
        "name": "cohere",
        "label": "Cohere",
        "description": "Cohere Command models — enterprise NLP, RAG, and reasoning.",
        "key_field": "cohere_api_key",
        "model_field": "cohere_model",
        "enable_field": None,
        "base_url_field": None,
        "model_options": [
            {"value": "command-a-plus-05-2026", "label": "command-a-plus-05-2026 (latest, best)"},
            {"value": "command-a-03-2025",      "label": "command-a-03-2025"},
            {"value": "command-r-plus-08-2024", "label": "command-r-plus-08-2024 (RAG)"},
            {"value": "command-r-08-2024",      "label": "command-r-08-2024"},
            {"value": "command-r7b-12-2024",    "label": "command-r7b-12-2024 (fastest)"},
        ],
    },
    {
        "name": "together",
        "label": "Together AI",
        "description": "Open-source model hosting — Llama 4, Qwen 3, Kimi K2, DeepSeek and more.",
        "key_field": "together_api_key",
        "model_field": "together_model",
        "enable_field": None,
        "base_url_field": None,
        "model_options": [
            {"value": "meta-llama/Llama-4-Maverick-17B-128E-Instruct",     "label": "Llama 4 Maverick 17B (vision)"},
            {"value": "meta-llama/Llama-4-Scout-17B-16E-Instruct",         "label": "Llama 4 Scout 17B (vision)"},
            {"value": "Qwen/Qwen3-235B-A22B-Instruct-2507-tput",           "label": "Qwen3 235B MoE (best)"},
            {"value": "Qwen/Qwen3.5-397B-A17B",                            "label": "Qwen3.5 397B (vision)"},
            {"value": "Qwen/Qwen3.5-9B",                                   "label": "Qwen3.5 9B (fast)"},
            {"value": "moonshotai/Kimi-K2-Instruct",                       "label": "Kimi K2 1T MoE (agentic)"},
            {"value": "deepseek-ai/DeepSeek-V4-Pro",                       "label": "DeepSeek V4 Pro (reasoning)"},
            {"value": "deepseek-ai/DeepSeek-V3.1",                         "label": "DeepSeek V3.1"},
            {"value": "deepseek-ai/DeepSeek-R1",                           "label": "DeepSeek R1 (chain-of-thought)"},
            {"value": "meta-llama/Llama-3.3-70B-Instruct-Turbo",           "label": "Llama 3.3 70B Turbo"},
            {"value": "MiniMaxAI/MiniMax-M2.7",                            "label": "MiniMax M2.7"},
        ],
    },
    {
        "name": "perplexity",
        "label": "Perplexity",
        "description": "Perplexity Sonar — LLMs with real-time internet search and citations built in.",
        "key_field": "perplexity_api_key",
        "model_field": "perplexity_model",
        "enable_field": None,
        "base_url_field": None,
        "model_options": [
            {"value": "sonar-pro",             "label": "sonar-pro (best, multi-source citations)"},
            {"value": "sonar",                 "label": "sonar (lightweight)"},
            {"value": "sonar-reasoning-pro",   "label": "sonar-reasoning-pro (chain-of-thought)"},
            {"value": "sonar-deep-research",   "label": "sonar-deep-research (exhaustive reports)"},
        ],
    },
    {
        "name": "openrouter",
        "label": "OpenRouter",
        "description": "Unified API routing to 300+ models across all major providers. Free models available.",
        "key_field": "openrouter_api_key",
        "model_field": "openrouter_model",
        "enable_field": None,
        "base_url_field": None,
        "model_options": [
            {"value": "openrouter/auto",                                 "label": "auto (OpenRouter picks best)"},
            {"value": "anthropic/claude-opus-4-8",                       "label": "anthropic/claude-opus-4-8"},
            {"value": "anthropic/claude-sonnet-4-6",                     "label": "anthropic/claude-sonnet-4-6"},
            {"value": "openai/gpt-5.5",                                  "label": "openai/gpt-5.5"},
            {"value": "openai/o4-mini",                                  "label": "openai/o4-mini"},
            {"value": "google/gemini-3.5-flash",                         "label": "google/gemini-3.5-flash"},
            {"value": "google/gemini-2.5-pro",                           "label": "google/gemini-2.5-pro"},
            {"value": "x-ai/grok-4.3",                                   "label": "x-ai/grok-4.3"},
            {"value": "meta-llama/llama-4-maverick",                     "label": "meta-llama/llama-4-maverick"},
            {"value": "deepseek/deepseek-v4-pro",                        "label": "deepseek/deepseek-v4-pro"},
            {"value": "qwen/qwen3-235b-a22b:free",                       "label": "qwen/qwen3-235b (free)"},
            {"value": "moonshotai/kimi-k2",                              "label": "moonshotai/kimi-k2"},
        ],
    },
    {
        "name": "deepseek",
        "label": "DeepSeek",
        "description": "DeepSeek V4 and reasoning models — extremely cost-effective Chinese frontier models.",
        "key_field": "deepseek_api_key",
        "model_field": "deepseek_model",
        "enable_field": None,
        "base_url_field": None,
        "model_options": [
            {"value": "deepseek-v4-pro",    "label": "deepseek-v4-pro (best, reasoning)"},
            {"value": "deepseek-v4-flash",  "label": "deepseek-v4-flash (fast, cheap)"},
            {"value": "deepseek-chat",      "label": "deepseek-chat (legacy alias, deprecated Jul 2026)"},
            {"value": "deepseek-reasoner",  "label": "deepseek-reasoner (legacy alias, deprecated Jul 2026)"},
        ],
    },
    {
        "name": "qwen",
        "label": "Qwen (Alibaba)",
        "description": "Alibaba Qwen3 models via DashScope — multilingual, vision, code, and reasoning. API key from dashscope.aliyuncs.com.",
        "key_field": "qwen_api_key",
        "model_field": "qwen_model",
        "enable_field": None,
        "base_url_field": None,
        "model_options": [
            {"value": "qwen3-max",          "label": "qwen3-max (best)"},
            {"value": "qwen3-max-2026-01-23", "label": "qwen3-max-2026-01-23 (pinned)"},
            {"value": "qwen3.5-plus",       "label": "qwen3.5-plus (balanced)"},
            {"value": "qwen3.5-flash",      "label": "qwen3.5-flash (fast)"},
            {"value": "qwen-turbo",         "label": "qwen-turbo (lightweight)"},
            {"value": "qwq-plus",           "label": "qwq-plus (extended reasoning)"},
            {"value": "qwen3-235b-a22b",    "label": "qwen3-235b-a22b (open MoE)"},
            {"value": "qwen3-32b",          "label": "qwen3-32b (open 32B)"},
            {"value": "qwen3-14b",          "label": "qwen3-14b (open 14B)"},
            {"value": "qwen3-8b",           "label": "qwen3-8b (open 8B)"},
            {"value": "qwen3-vl-plus",      "label": "qwen3-vl-plus (vision)"},
            {"value": "qwen3-vl-flash",     "label": "qwen3-vl-flash (vision, fast)"},
            {"value": "qwen3-coder-plus",   "label": "qwen3-coder-plus (code)"},
            {"value": "qwen3-coder-flash",  "label": "qwen3-coder-flash (code, fast)"},
        ],
    },
    {
        "name": "kimi",
        "label": "Kimi (Moonshot AI)",
        "description": "Moonshot AI Kimi K2 — agentic, long-context, vision. API key from platform.moonshot.cn.",
        "key_field": "kimi_api_key",
        "model_field": "kimi_model",
        "enable_field": None,
        "base_url_field": None,
        "model_options": [
            {"value": "kimi-k2.6",         "label": "kimi-k2.6 (latest, best coding + reasoning)"},
            {"value": "kimi-k2.5",         "label": "kimi-k2.5 (vision + thinking modes)"},
            {"value": "moonshot-v1-128k",  "label": "moonshot-v1-128k (128k ctx)"},
            {"value": "moonshot-v1-32k",   "label": "moonshot-v1-32k"},
            {"value": "moonshot-v1-8k",    "label": "moonshot-v1-8k (fastest)"},
        ],
    },
    {
        "name": "ollama",
        "label": "Ollama (local / self-hosted)",
        "description": "Run open-source models locally or on a remote Ollama instance.",
        "key_field": None,
        "model_field": "ollama_model",
        "enable_field": None,
        "base_url_field": "ollama_base_url",
        "model_options": [
            {"value": "qwen2.5:14b",           "label": "qwen2.5:14b ★ recommended for 12GB VRAM"},
            {"value": "qwen2.5:7b",            "label": "qwen2.5:7b (fast, 5GB VRAM)"},
            {"value": "qwen2.5:32b",           "label": "qwen2.5:32b (needs RAM offload)"},
            {"value": "qwen2.5:72b",           "label": "qwen2.5:72b (high-end GPU only)"},
            {"value": "llama4:scout",          "label": "llama4:scout (17B, vision)"},
            {"value": "llama4:maverick",       "label": "llama4:maverick (17B MoE, vision)"},
            {"value": "llama3.1:8b",           "label": "llama3.1:8b (fast, 5GB VRAM)"},
            {"value": "llama3.1:70b",          "label": "llama3.1:70b (high-end only)"},
            {"value": "qwen3:235b",            "label": "qwen3:235b (MoE flagship)"},
            {"value": "qwen3:32b",             "label": "qwen3:32b"},
            {"value": "qwen3:14b",             "label": "qwen3:14b"},
            {"value": "qwen3:8b",              "label": "qwen3:8b (fast)"},
            {"value": "qwen2.5-coder:32b",     "label": "qwen2.5-coder:32b (best open coder)"},
            {"value": "deepseek-r1:70b",       "label": "deepseek-r1:70b (reasoning)"},
            {"value": "deepseek-r1:32b",       "label": "deepseek-r1:32b"},
            {"value": "deepseek-r1:14b",       "label": "deepseek-r1:14b"},
            {"value": "deepseek-r1:8b",        "label": "deepseek-r1:8b"},
            {"value": "gemma3:27b",            "label": "gemma3:27b (vision, tools)"},
            {"value": "gemma3:12b",            "label": "gemma3:12b (vision)"},
            {"value": "gemma3:4b",             "label": "gemma3:4b (vision, 6GB RAM)"},
            {"value": "mistral-large",         "label": "mistral-large"},
            {"value": "mistral",               "label": "mistral (7B)"},
            {"value": "phi4",                  "label": "phi4 (14B, reasoning)"},
            {"value": "phi4-mini",             "label": "phi4-mini (3.8B, 128k)"},
        ],
    },
]


@app.get('/api/admin/providers')
def api_admin_providers(_: Dict[str, Any] = Depends(require_admin)):
    """Static catalog of providers + which are currently usable. The UI uses
    this to render the provider list and the active-provider dropdown."""
    from app.llm import _DEFAULT_CHAIN_ORDER
    configured = set(configured_provider_names())
    catalog = []
    for entry in _PROVIDER_CATALOG:
        catalog.append({**entry, "configured": entry["name"] in configured})

    user_chain_json = settings_store.get("provider_chain")
    user_chain = None
    if user_chain_json:
        try:
            import json as _json
            user_chain = _json.loads(user_chain_json)
        except Exception:
            user_chain = None

    return {
        "providers": catalog,
        "active_provider": get_active_provider(),
        "chain_order": configured_provider_names(),
        "user_chain": user_chain,
        "default_chain": _DEFAULT_CHAIN_ORDER,
    }


@app.get('/api/admin/settings')
def api_admin_get_settings(_: Dict[str, Any] = Depends(require_admin)):
    """Return current settings with API keys masked. The `env_defaults` block
    shows what would be used if the DB override is cleared, so the admin can
    tell whether an empty UI field means 'no key' or 'falling back to .env'."""
    raw = settings_store.get_all()
    return {
        "settings": mask_for_api(raw),
        "allowed_keys": sorted(ALLOWED_KEYS),
        "env_defaults": {
            "anthropic_api_key_set":   bool(settings.ANTHROPIC_API_KEY),
            "openai_api_key_set":      bool(settings.OPENAI_API_KEY),
            "deepseek_api_key_set":    bool(settings.DEEPSEEK_API_KEY),
            "gemini_api_key_set":      bool(settings.GEMINI_API_KEY),
            "groq_api_key_set":        bool(settings.GROQ_API_KEY),
            "mistral_api_key_set":     bool(settings.MISTRAL_API_KEY),
            "xai_api_key_set":         bool(settings.XAI_API_KEY),
            "cohere_api_key_set":      bool(settings.COHERE_API_KEY),
            "together_api_key_set":    bool(settings.TOGETHER_API_KEY),
            "perplexity_api_key_set":  bool(settings.PERPLEXITY_API_KEY),
            "openrouter_api_key_set":  bool(settings.OPENROUTER_API_KEY),
            "qwen_api_key_set":        bool(settings.QWEN_API_KEY),
            "kimi_api_key_set":        bool(settings.KIMI_API_KEY),
            "claude_agent_sdk_enabled": bool(settings.USE_CLAUDE_AGENT_SDK),
            "anthropic_model":         settings.ANTHROPIC_MODEL,
            "openai_model":            settings.OPENAI_MODEL,
            "claude_agent_sdk_model":  settings.CLAUDE_AGENT_SDK_MODEL,
            "ollama_base_url":         settings.OLLAMA_BASE_URL or "",
            "ollama_model":            settings.OLLAMA_MODEL,
        },
    }


@app.put('/api/admin/settings')
def api_admin_put_settings(
    request: Request,
    payload: Dict[str, Any],
    current_user: Dict[str, Any] = Depends(require_admin),
    csrf_hdr: Optional[str] = Header(None, alias="X-CSRF-Token"),
):
    """Apply partial settings update. Null/empty values delete the row
    (revert to .env). Reloads providers so changes take effect immediately."""
    _validate_csrf(request, csrf_hdr)
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="JSON object required")
    # Drop unknown keys silently rather than 400ing the whole request — UI
    # may post a few defaults we don't care about, and we don't want a typo
    # to wipe a real key. Whitelist is the safety net.
    cleaned = {k: v for k, v in payload.items() if k in ALLOWED_KEYS}
    if not cleaned:
        raise HTTPException(status_code=400, detail="No recognized settings in payload")
    # Audit log — keys only, never values. Lets us prove from the server side
    # whether a save round-trip actually carried the field the user expected
    # (without leaking secrets into logs).
    logging.getLogger("nullshift.admin").info(
        "settings PUT by user_id=%s keys=%s (secret keys touched: %s)",
        current_user.get("id"),
        sorted(cleaned.keys()),
        sorted(k for k in cleaned if k in SECRET_KEYS),
    )
    touched = settings_store.set_many(cleaned, updated_by=current_user.get("id"))
    state = reload_providers()

    # Reload RAG live if any RAG-related key was touched — no restart needed
    rag_keys = {"rag_enabled", "rag_embedding_provider", "rag_embedding_model", "gemini_api_key",
                "openai_api_key", "cohere_api_key", "ollama_base_url"}
    if cleaned.keys() & rag_keys:
        from app.rag import reload_rag
        reload_rag()

    return {
        "ok": True,
        "touched": touched,
        "configured_after_reload": state,
        "active_provider": get_active_provider(),
    }


@app.get('/api/admin/usage')
def api_admin_usage(_: Dict[str, Any] = Depends(require_admin)):
    """Snapshot of the most recent LLM call + rate-limit telemetry.

    For the SDK provider this includes the Claude subscription 5-hour
    window state (status, utilization, resets_at) captured from
    RateLimitEvent. Other providers expose rate-limit info per-response
    via 429 headers; we don't surface those yet since the SDK is the
    common case for this UI.
    """
    return {
        "active_provider": get_active_provider(),
        "configured_providers": configured_provider_names(),
        "last_call": get_last_call_info(),
        "last_rate_limit": get_last_rate_limit_info(),
    }


@app.get('/api/admin/rag/status')
def api_admin_rag_status(_: Dict[str, Any] = Depends(require_admin)):
    """Live RAG status — provider, collection name, chunk count, error state."""
    return _rag_mod.rag.status()


@app.get('/api/admin/connectors/vt/test')
def api_admin_vt_test(_: Dict[str, Any] = Depends(require_admin)):
    """Quick test: query VT for a known benign IP to verify the saved API key works."""
    from app.connectors.virustotal import vt_enrich_ioc, _get_vt_key
    if not _get_vt_key():
        return {"ok": False, "error": "No VT API key configured"}
    result = vt_enrich_ioc("8.8.8.8")  # Google DNS — always benign
    if "error" in result:
        return {"ok": False, "error": result["error"]}
    return {"ok": True}


# ---------------------------------------------------------------------------
# SIEM credentials test endpoints — prefer live form values from payload,
# fall back to stored values for fields the user left blank. Reading from
# settings_store covers the case where the user wants to test the saved
# config without re-typing secrets (the UI shows them as placeholders).
# ---------------------------------------------------------------------------
def _field(payload: Dict[str, Any], key: str) -> str:
    v = (payload.get(key) or "").strip()
    if v:
        return v
    return (settings_store.get(key) or "").strip()


@app.post('/api/admin/connectors/siem/limacharlie/test')
def api_test_limacharlie(payload: Dict[str, Any], _: Dict[str, Any] = Depends(require_admin)):
    import requests as _r
    oid = _field(payload, "limacharlie_oid")
    key = _field(payload, "limacharlie_api_key")
    if not oid or not key:
        return {"ok": False, "error": "OID and API key are required"}
    try:
        # LC exchanges OID + secret for a JWT — success means the credentials are valid
        r = _r.post("https://jwt.limacharlie.io", data={"oid": oid, "secret": key}, timeout=10)
        if r.status_code == 200 and r.json().get("jwt"):
            return {"ok": True}
        return {"ok": False, "error": f"LimaCharlie rejected credentials (HTTP {r.status_code})"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.post('/api/admin/connectors/siem/wazuh/test')
def api_test_wazuh(payload: Dict[str, Any], _: Dict[str, Any] = Depends(require_admin)):
    import requests as _r
    url = _field(payload, "wazuh_indexer_url").rstrip("/")
    user = _field(payload, "wazuh_indexer_user")
    pw = _field(payload, "wazuh_indexer_pass")
    if not url or not user or not pw:
        return {"ok": False, "error": "Indexer URL, user, and password are required"}
    try:
        r = _r.get(f"{url}/_cluster/health", auth=(user, pw), timeout=10, verify=False)
        if r.status_code == 200:
            return {"ok": True}
        return {"ok": False, "error": f"Indexer returned HTTP {r.status_code}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.post('/api/admin/connectors/siem/splunk/test')
def api_test_splunk(payload: Dict[str, Any], _: Dict[str, Any] = Depends(require_admin)):
    import requests as _r
    url = _field(payload, "splunk_url").rstrip("/")
    token = _field(payload, "splunk_token")
    if not url or not token:
        return {"ok": False, "error": "Splunk URL and token are required"}
    try:
        r = _r.get(
            f"{url}/services/server/info?output_mode=json",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10, verify=False,
        )
        if r.status_code == 200:
            return {"ok": True}
        return {"ok": False, "error": f"Splunk returned HTTP {r.status_code}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.post('/api/admin/connectors/siem/elastic/test')
def api_test_elastic(payload: Dict[str, Any], _: Dict[str, Any] = Depends(require_admin)):
    import requests as _r
    url = _field(payload, "elastic_url").rstrip("/")
    api_key = _field(payload, "elastic_api_key")
    if not url or not api_key:
        return {"ok": False, "error": "Elastic URL and API key are required"}
    try:
        r = _r.get(url, headers={"Authorization": f"ApiKey {api_key}"}, timeout=10, verify=False)
        if r.status_code == 200:
            return {"ok": True}
        return {"ok": False, "error": f"Elastic returned HTTP {r.status_code}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.post('/api/admin/connectors/siem/sentinel/test')
def api_test_sentinel(payload: Dict[str, Any], _: Dict[str, Any] = Depends(require_admin)):
    import requests as _r
    tenant = _field(payload, "sentinel_tenant_id")
    client = _field(payload, "sentinel_client_id")
    secret = _field(payload, "sentinel_client_secret")
    if not tenant or not client or not secret:
        return {"ok": False, "error": "Tenant ID, Client ID, and Client Secret are required"}
    try:
        r = _r.post(
            f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client,
                "client_secret": secret,
                "scope": "https://api.loganalytics.io/.default",
            },
            timeout=10,
        )
        if r.status_code == 200 and r.json().get("access_token"):
            return {"ok": True}
        err = (r.json().get("error_description") or "unknown error") if r.headers.get("content-type", "").startswith("application/json") else f"HTTP {r.status_code}"
        return {"ok": False, "error": err}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.get('/', response_class=HTMLResponse)
def ui(request: Request):
    # Redirect to setup wizard if not configured yet
    if not _is_setup_complete():
        return RedirectResponse(url="/setup", status_code=303)
    # Redirect unauthenticated users to the login page instead of 401 JSON
    try:
        _ = get_current_user(request)
    except HTTPException:
        return RedirectResponse(url="/login", status_code=303)
    with open('app/ui.html', 'r', encoding='utf-8') as f:
        return HTMLResponse(f.read())


def extract_iocs(text: str):
    ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text)
    hashes = re.findall(r"\b[a-fA-F0-9]{32,64}\b", text)
    domains = re.findall(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,6}\b", text)
    return list(set(ips+domains+hashes))

def extract_flow_id(text: str):
    if not text:
        return None
    m = re.search(r"flow[_\s-]?id\s*[:=]\s*(\d+)", text, flags=re.IGNORECASE)
    if m:
        return m.group(1)
    return None


def _wants_blocked_ips(text: str) -> bool:
    t = (text or '').lower()
    return ('blocked ip' in t) or ('blocked ips' in t) or ('list of blocked ip' in t) or ('firewall blocks' in t)


def route_intent(msg: str) -> str:
    m = (msg or '').lower()
    if any(w in m for w in ["investigate", "investigation", "ioc", "true positive", "false positive", "tp", "fp"]) or re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", m):
        return "ioc_investigation"
    if any(w in m for w in ["query", "queries", "kql", "give me wazuh queries", "search query"]):
        return "query_generation"
    if any(w in m for w in ["cve", "threat intel", "threat intelligence", "nvd", "virus total", "virustotal"]):
        return "threat_intelligence"
    if any(w in m for w in ["aggregate", "top", "most frequent", "count by", "sort by"]):
        return "aggregation"
    return "general"


log = logging.getLogger("nullshift")


@app.post('/chat')
def chat(req: ChatRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    if not any_provider_configured():
        return JSONResponse(
            status_code=500,
            content={"error": "No LLM provider available. Set one of USE_CLAUDE_AGENT_SDK=true (and install claude-agent-sdk + login with `claude`), ANTHROPIC_API_KEY, or OPENAI_API_KEY in .env."}
        )

    # Ensure conversation exists and belongs to the current user
    conv_id: Optional[str] = req.conversation_id
    if conv_id:
        if not store.get_conversation_for_user(current_user["id"], conv_id):
            raise HTTPException(status_code=404, detail="Conversation not found")
    else:
        conv = store.create_conversation_for_user(current_user["id"])
        conv_id = conv["id"]

    # Get last assistant message for routing context (scoped read)
    try:
        history = store.last_messages_for_user(current_user["id"], conv_id, limit=20)
    except PermissionError:
        raise HTTPException(status_code=404, detail="Conversation not found")
    last_assistant: Optional[str] = None
    for m in reversed(history):
        if m.get('role') == 'assistant':
            last_assistant = m.get('content')
            break

    # Orchestrated, query-as-needed flow
    reply_md = handle_chat_orchestrated(req, conv_id, last_assistant, current_user)
    reply_md = _strip_html_from_llm(reply_md)

    # Persist both the incoming user message and assistant reply (scoped writes)
    try:
        store.add_message_for_user(current_user["id"], conv_id, 'user', req.message or '')
        store.add_message_for_user(current_user["id"], conv_id, 'assistant', reply_md)
    except PermissionError:
        raise HTTPException(status_code=404, detail="Conversation not found")

    # Include debug_trace if requested
    content = {"conversation_id": conv_id, "reply": reply_md}
    try:
        if getattr(req, 'debug', False):
            # Pull from the latest investigation bundle stored in state
            st = inv_state.get(conv_id)
            if st:
                # Compose a simple debug trace from last_tool_calls and errors if investigation debug not available
                content["debug_trace"] = st.get("_debug_trace") or st.get("last_tool_calls") or []
    except Exception:
        pass
    return JSONResponse(content=content)


# New multi-chat API (per-user)
@app.get('/api/ping')
def api_ping(current_user: Dict[str, Any] = Depends(get_current_user)):
    vi = get_active_vision_info()
    return {
        "ok": True,
        "user": {"id": current_user["id"], "username": current_user["username"], "role": current_user["role"]},
        "model_ready": any_provider_configured(),
        "active_provider": get_active_provider(),
        "configured_providers": configured_provider_names(),
        "vision": {
            "supported": vi.get("supported"),
            "provider_note": vi.get("note", ""),
            "max_images": int(settings_store.get("vision_max_images") or 4),
            "max_size_mb": float(settings_store.get("vision_max_size_mb") or 5),
        },
    }

@app.get('/api/me/prefs')
def api_get_prefs(current_user: Dict[str, Any] = Depends(get_current_user)):
    return {"prefs": prefs_store.get_all(current_user["id"])}


@app.put('/api/me/prefs')
def api_put_prefs(payload: PrefsUpdate, current_user: Dict[str, Any] = Depends(get_current_user)):
    prefs_store.set_many(current_user["id"], payload.prefs)
    return {"prefs": prefs_store.get_all(current_user["id"])}


@app.get('/api/conversations')
def api_list_conversations(current_user: Dict[str, Any] = Depends(get_current_user)):
    return {"conversations": store.list_conversations_for_user(current_user["id"])}


@app.post('/api/conversations')
def api_create_conversation(payload: ConversationCreate, current_user: Dict[str, Any] = Depends(get_current_user)):
    conv = store.create_conversation_for_user(current_user["id"], title=payload.title)
    return {"id": conv["id"], "title": conv["title"], "created_at": conv["created_at"]}


@app.delete('/api/conversations/{conversation_id}')
def api_delete_conversation(conversation_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    deleted = store.delete_conversation_for_user(current_user["id"], conversation_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Conversation not found")
    inv_state.delete(conversation_id)
    return {"ok": True}


@app.get('/api/conversations/{conversation_id}/messages')
def api_get_messages(conversation_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    conv = store.get_conversation_for_user(current_user["id"], conversation_id)
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return {"messages": conv["messages"]}


@app.post('/api/conversations/{conversation_id}/messages')
def api_post_message(conversation_id: str, payload: MessageCreate, current_user: Dict[str, Any] = Depends(get_current_user)):
    if not any_provider_configured():
        return JSONResponse(status_code=500, content={"error": "No LLM provider available. Set one of USE_CLAUDE_AGENT_SDK=true, ANTHROPIC_API_KEY, or OPENAI_API_KEY in .env."})

    conv = store.get_conversation_for_user(current_user["id"], conversation_id)
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")

    # Store user message (scoped write)
    try:
        store.add_message_for_user(current_user["id"], conversation_id, 'user', payload.message)
    except PermissionError:
        raise HTTPException(status_code=404, detail="Conversation not found")

    # Validate images against admin-configured limits
    if payload.images:
        max_imgs = int(settings_store.get("vision_max_images") or 4)
        max_mb = float(settings_store.get("vision_max_size_mb") or 5)
        if len(payload.images) > max_imgs:
            return JSONResponse(status_code=400, content={"error": f"Too many images (admin limit: {max_imgs})"})
        for img in payload.images:
            b64 = img.split(",", 1)[1] if "," in img else img
            size_mb = len(b64) * 0.75 / (1024 * 1024)
            if size_mb > max_mb:
                return JSONResponse(status_code=400, content={"error": f"Image too large (admin limit: {max_mb} MB)"})

    # Build history for LLM
    if payload.images:
        user_content: Any = [{"type": "text", "text": payload.message or ""}]
        for img in payload.images:
            user_content.append({"type": "image_url", "image_url": {"url": img}})
        history = conv["messages"] + [{"role": "user", "content": user_content}]
    else:
        history = conv["messages"] + [{"role": "user", "content": payload.message}]

    # Response-mode routing (unified with /chat — workflow-stage based, not
    # legacy intent). route_intent() still drives run_investigation below for
    # the deterministic-pipeline selection.
    mode = select_response_mode(payload.message, last_assistant_message=None)
    intent = route_intent(payload.message)
    tw = choose_time_window(None)
    time_range = tw["time_range"]

    # Optional per-request debug trace
    debug = DebugTrace() if getattr(payload, 'debug', False) else None
    # Progressive Evidence Gathering (auto-run, tiered)
    evidence = run_investigation(intent, payload.message, time_range, current_user, tool_runner, debug=debug)
    evidence["asked_time_range"] = tw["asked"]
    evidence["policy_note"] = tw.get("note")

    # Surface prior verdicts for any IOC the user mentioned, scoped to this user.
    msg_iocs = extract_iocs(payload.message or '')
    if msg_iocs:
        prior = verdict_store.lookup_for_iocs(
            current_user["id"], msg_iocs, limit_per_ioc=3, exclude_conversation_id=conversation_id,
        )
        if prior:
            evidence["prior_verdicts"] = prior

    prior_sessions = _prime_prior_session_summaries(current_user["id"], conversation_id)
    if prior_sessions:
        evidence["prior_session_summaries"] = prior_sessions

    user_prefs_early = prefs_store.get_all(current_user["id"]) if current_user else {}
    temperature = _temperature_for_mode(mode, user_prefs_early)

    # Retrieve playbook snippets via RAG (no-op if disabled).
    # When the user sends images without text, fall back to a generic SOC query
    # so playbook snippets are still injected into the LLM context.
    rag_text = payload.message or ("security screenshot evidence analysis" if payload.images else "")
    retrieved = _rag_mod.rag.retrieve(_rag_query(rag_text))

    # Call LLM with full history and strict prompt
    user_prefs = prefs_store.get_all(current_user["id"])
    reply_md = chat_with_history(
        SYSTEM_PROMPT,
        history,
        retrieved=retrieved,
        response_mode=mode,
        evidence=evidence,
        temperature=temperature,
        tool_runner=tool_runner,
        current_user=current_user,
        user_prefs=user_prefs or None,
        deployment_memory=get_cached_memory(),
    )
    reply_md = _strip_html_from_llm(reply_md)

    # Persist assistant reply (scoped write)
    try:
        store.add_message_for_user(current_user["id"], conversation_id, 'assistant', reply_md)
    except PermissionError:
        raise HTTPException(status_code=404, detail="Conversation not found")

    # Record verdict for the IOCs in this turn (tolerant: NULL verdict still audits).
    if msg_iocs:
        v, c = parse_decision(reply_md)
        try:
            verdict_store.record(
                user_id=current_user["id"],
                conversation_id=conversation_id,
                iocs=msg_iocs,
                verdict=v,
                confidence=c,
                message_excerpt=payload.message or '',
                evidence_summary={
                    "totals": evidence.get("totals"),
                    "sources_queried": evidence.get("sources_queried"),
                    "time_window": evidence.get("time_window"),
                },
            )
        except Exception:
            log.exception("verdict_store.record failed")

    # Title heuristic on first turn
    if conv.get('title') in (None, '', 'New chat'):
        snippet = payload.message.strip().split('\n',1)[0][:60]
        try:
            store.set_title_if_empty_for_user(current_user["id"], conversation_id, snippet or 'New chat')
        except PermissionError:
            pass

    # Include debug trace if requested
    content = {"reply": reply_md}
    try:
        if getattr(payload, 'debug', False):
            # Prefer the debug trace from this run's evidence if present
            if evidence and evidence.get("_debug_trace"):
                content["debug_trace"] = evidence["_debug_trace"]
            else:
                st = inv_state.get(conversation_id)
                if st:
                    content["debug_trace"] = st.get("_debug_trace") or st.get("last_tool_calls") or []
    except Exception:
        pass
    return content


@app.post('/api/conversations/{conversation_id}/messages/stream')
async def api_stream_message(conversation_id: str, payload: MessageCreate, current_user: Dict[str, Any] = Depends(get_current_user)):
    """SSE streaming version of the message endpoint.
    Yields status events during processing, then a final 'done' event with the reply."""
    import asyncio, json as _json

    if not any_provider_configured():
        async def _err():
            yield f"data: {_json.dumps({'type':'error','text':'No LLM provider configured.'})}\n\n"
        return StreamingResponse(_err(), media_type="text/event-stream")

    conv = store.get_conversation_for_user(current_user["id"], conversation_id)
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")

    async def generate():
        loop = asyncio.get_event_loop()
        try:
            yield f"data: {_json.dumps({'type':'status','text':'Analyzing query…'})}\n\n"
            await asyncio.sleep(0)

            yield f"data: {_json.dumps({'type':'status','text':'Querying SIEM…'})}\n\n"
            await asyncio.sleep(0)

            yield f"data: {_json.dumps({'type':'status','text':'Retrieving playbooks…'})}\n\n"
            await asyncio.sleep(0)

            result = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: _do_message_work(conversation_id, payload, current_user)),
                timeout=180.0,
            )

            yield f"data: {_json.dumps({'type':'done', **result})}\n\n"
        except asyncio.TimeoutError:
            log.error("Streaming message handler timed out after 180s")
            yield f"data: {_json.dumps({'type':'error','text':'Request timed out — the LLM took too long to respond. Try again.'})}\n\n"
        except Exception as exc:
            log.exception("Streaming message handler failed: %s", exc)
            yield f"data: {_json.dumps({'type':'error','text':str(exc)})}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'},
    )


def _do_message_work(conversation_id: str, payload: MessageCreate, current_user: Dict[str, Any]) -> Dict[str, Any]:
    """Shared logic for both streaming and non-streaming message endpoints."""
    import json as _json
    conv = store.get_conversation_for_user(current_user["id"], conversation_id)

    try:
        store.add_message_for_user(current_user["id"], conversation_id, 'user', payload.message or '')
    except PermissionError:
        raise HTTPException(status_code=404, detail="Conversation not found")

    mode = select_response_mode(payload.message or '', None)
    intent = classify_task_type(payload.message or '')
    time_range = "last_24h"

    tool_runner_local = ToolRunner()
    debug = DebugTrace() if getattr(payload, 'debug', False) else None

    evidence = run_investigation(intent, payload.message or '', time_range, current_user, tool_runner_local, debug=debug)

    msg_iocs = extract_iocs(payload.message or '')
    if msg_iocs:
        prior = verdict_store.lookup_for_iocs(current_user["id"], msg_iocs, limit_per_ioc=3, exclude_conversation_id=conversation_id)
        if prior:
            evidence["prior_verdicts"] = prior

    prior_sessions = _prime_prior_session_summaries(current_user["id"], conversation_id)
    if prior_sessions:
        evidence["prior_session_summaries"] = prior_sessions

    user_prefs_early = prefs_store.get_all(current_user["id"]) if current_user else {}
    temperature = _temperature_for_mode(mode, user_prefs_early)

    rag_text = payload.message or ("security screenshot evidence analysis" if getattr(payload, 'images', None) else "")
    retrieved = _rag_mod.rag.retrieve(_rag_query(rag_text))
    if debug:
        debug.add({"type": "rag", "chunks_retrieved": len(retrieved), "sources": [r.split("\n")[0] for r in retrieved]})

    aug_user = {"role": "user", "content": f"User message: {payload.message}\n\nUse evidence bundle to decide minimum necessary sources."}
    reply_md = orchestrated_llm_reply(aug_user, conversation_id, mode, evidence, current_user, retrieved=retrieved, debug=debug)
    reply_md = _strip_html_from_llm(reply_md)

    if debug:
        evidence["_debug_trace"] = debug.to_list()

    try:
        store.add_message_for_user(current_user["id"], conversation_id, 'assistant', reply_md)
    except PermissionError:
        pass

    if msg_iocs:
        v, c = parse_decision(reply_md)
        try:
            verdict_store.record(
                user_id=current_user["id"],
                conversation_id=conversation_id,
                iocs=msg_iocs,
                verdict=v,
                confidence=c,
                message_excerpt=payload.message or '',
                evidence_summary={"totals": evidence.get("totals"), "sources_queried": evidence.get("sources_queried")},
            )
        except Exception:
            pass

    if conv.get('title') in (None, '', 'New chat'):
        snippet = (payload.message or '').strip().split('\n', 1)[0][:60]
        try:
            store.set_title_if_empty_for_user(current_user["id"], conversation_id, snippet or 'New chat')
        except PermissionError:
            pass

    result: Dict[str, Any] = {"reply": reply_md}
    if debug and evidence.get("_debug_trace"):
        result["debug_trace"] = evidence["_debug_trace"]
    return result


# Admin/debug endpoint to execute approved tools via API


@app.post('/api/tools/execute')
def api_tools_execute(payload: ToolExecuteRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    try:
        out = tool_runner.execute(
            payload.tool_name,
            payload.query_id,
            payload.params or {},
            payload.earliest,
            payload.latest,
            current_user,
        )
        return out
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
