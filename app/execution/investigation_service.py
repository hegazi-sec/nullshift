from typing import Any, Dict, List, Optional
import os
import re

from app.execution.tool_runner import ToolRunner
from app.execution.scoring import score as score_evidence
from app.execution.report import build_report
from app.utils.debug_trace import DebugTrace
from app.investigation.timewindow import parse_time_window, TimeWindow, NO_TIME_SPECIFIED
from app.investigation.scenario_detector import detect_web_scenario
from app.investigation.mode import determine_mode, InvestigationMode
from app.investigation.keywords import extract_security_keywords
from app.connectors import wazuh as wazuh_conn
from app.config import settings


STOPWORDS = set([
    "the", "and", "or", "to", "of", "a", "in", "is", "on", "for", "with", "by", "from",
    "this", "that", "it", "at", "as", "be", "are", "was", "were", "an", "if", "then",
])


def _compute_available_sources() -> List[str]:
    """Which connectors this deployment can actually reach. The LLM is told to
    enumerate only these in SECTION 1 so the report doesn't claim sources are
    'Not retrieved' for connectors this install isn't configured to use."""
    out: List[str] = []
    siem = (settings.SIEM_PROVIDER or "wazuh").lower().strip()
    if siem == "wazuh":
        if settings.wazuh_indexer_url:
            out.append("wazuh")
    elif siem in ("limacharlie", "splunk", "elastic", "sentinel"):
        try:
            from app.connectors import get_siem_connector
            if get_siem_connector(siem).is_available():
                out.append(siem)
        except Exception:
            pass
    if settings.VT_API_KEY:
        out.append("virustotal")
    return out


def extract_iocs(text: str) -> List[str]:
    ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text or "")
    hashes = re.findall(r"\b[a-fA-F0-9]{32,64}\b", text or "")
    domains = re.findall(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,6}\b", text or "")
    return list({*ips, *hashes, *domains})


def extract_keywords(text: str) -> List[str]:
    words = re.findall(r"[A-Za-z0-9_\-]{3,}", text or "")
    kws = [w.lower() for w in words if w.lower() not in STOPWORDS]
    # De-duplicate, keep order
    seen = set()
    out = []
    for w in kws:
        if w not in seen:
            seen.add(w)
            out.append(w)
    return out[:10]


def _derive_discovered_ids(executed: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    rule_ids: List[str] = []
    signatures: List[str] = []
    agents: List[str] = []
    # Use summaries where available from ToolRunner
    for call in executed:
        tool = call.get("tool_name")
        qid = call.get("query_id")
        summ = call.get("summary") or {}
        if tool == "wazuh":
            for ent in (summ.get("by_rule") or []):
                rid = str(ent.get("rule_id")) if ent.get("rule_id") is not None else None
                if rid and rid not in rule_ids:
                    rule_ids.append(rid)
            for ent in (summ.get("by_agent") or []):
                aid = str(ent.get("agent")) if ent.get("agent") is not None else None
                if aid and aid not in agents:
                    agents.append(aid)
    return {"rule_ids": rule_ids, "signatures": signatures, "agents": agents}


def _run_raw_hunt_wazuh(
    message: str,
    gte: str,
    lte: str,
    time_window: str,
    keywords: List[str],
    evidence: Dict[str, Any],
    tool_runner: ToolRunner,
    debug: Optional[DebugTrace],
) -> None:
    """Wazuh-specific RAW_HUNT logic: tier-0 web discovery, scenario detection
    (hydra/gobuster/nikto/xss), and follow-up keyword/scenario queries.

    Extracted so the caller can short-circuit it cleanly when Wazuh isn't
    the configured SIEM — otherwise every chat triggers the
    'Missing Wazuh Indexer credentials' error path and adds dead executed_calls
    entries the LLM has to reason around.
    """
    try:
        from app.connectors import wazuh as _wz
        _wz.reset_query_failure_state()
    except Exception:
        pass
    ip_re = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    ips = ip_re.findall(message or "")
    dst_ip = ips[-1] if ips else "10.10.10.20"  # common DVWA lab default
    dst_port = 8080

    ev_broad = tool_runner._exec_wazuh("web_unique_paths_high", {"dst_ip": dst_ip, "dst_port": dst_port}, time_window, debug=debug)
    evidence["executed_calls"].append({
        "tool_name": "wazuh",
        "query_id": "web_broad",
        "params": {"dst_ip": dst_ip, "dst_port": dst_port, "gte": gte, "lte": lte},
        "result_count": len(ev_broad),
        "samples": ev_broad[:5],
    })
    evidence["totals"]["wazuh"] += len(ev_broad)
    evidence["sources_queried"].append("wazuh")

    def _get(d: Dict[str, Any], path: List[str]) -> Optional[Any]:
        cur: Any = d
        for p in path:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(p)
        return cur

    urls_ct: Dict[str, int] = {}
    for ev in ev_broad[:200]:
        u = _get(ev, ["data", "http", "url"]) or "(unknown)"
        urls_ct[str(u)] = urls_ct.get(str(u), 0) + 1
    top_urls = sorted(urls_ct.items(), key=lambda x: x[1], reverse=True)[:10]

    ua_ct: Dict[str, int] = {}
    for ev in ev_broad[:200]:
        ua = _get(ev, ["data", "http", "http_user_agent"]) or "(unknown)"
        ua_ct[str(ua)] = ua_ct.get(str(ua), 0) + 1
    top_uas = sorted(ua_ct.items(), key=lambda x: x[1], reverse=True)[:10]

    m_ct: Dict[str, int] = {}
    for ev in ev_broad[:200]:
        m = _get(ev, ["data", "http", "http_method"]) or "(unknown)"
        m_ct[str(m)] = m_ct.get(str(m), 0) + 1

    unique_url_count = len(urls_ct)
    login_post_count = 0
    error_404_403_count = 0
    suspicious_payload_hits = 0
    payload_markers = ["<script", "alert(", "onerror=", "%3Cscript%3E", "%3Cimg", "javascript:"]
    for ev in ev_broad[:400]:
        u = _get(ev, ["data", "http", "url"]) or ""
        method = _get(ev, ["data", "http", "http_method"]) or ""
        status = _get(ev, ["data", "http", "status"]) or None
        if str(method).upper() == "POST" and "login.php" in str(u):
            login_post_count += 1
        try:
            sc = int(status) if status is not None else None
            if sc in (403, 404):
                error_404_403_count += 1
        except Exception:
            pass
        low = str(u).lower()
        if any(m in low for m in payload_markers):
            suspicious_payload_hits += 1

    tier0_summary = {
        "total_events": len(ev_broad),
        "top_urls": [{"url": k, "count": v} for k, v in top_urls],
        "top_user_agents": [{"ua": k, "count": v} for k, v in top_uas],
        "methods": {k: v for k, v in m_ct.items()},
        "unique_url_count": unique_url_count,
        "login_post_count": login_post_count,
        "error_404_403_count": error_404_403_count,
        "suspicious_payload_hits": suspicious_payload_hits,
    }

    wz_status = None
    try:
        from app.connectors import wazuh as _wz
        wz_status = _wz.get_last_query_failure_status()
    except Exception:
        wz_status = None

    if wz_status is not None:
        detection = {"scenario": "unknown", "signals": ["coverage_gap: wazuh query failed"], "confidence": 20, "recommended_followups": []}
        evidence.setdefault("errors", {})["wazuh"] = f"Wazuh query failed ({wz_status} Unauthorized)" if wz_status == 401 else "Wazuh query failed"
    else:
        detection = detect_web_scenario(tier0_summary)
    evidence["scenario_detection"] = detection
    if debug:
        debug.add({
            "type": "scenario_detect",
            "source": "analysis",
            "summary_keys": list(tier0_summary.keys()),
            "scenario": detection.get("scenario"),
            "signals": detection.get("signals"),
            "confidence": detection.get("confidence"),
        })

    scen = detection.get("scenario") or "unknown"
    if wz_status is not None:
        scen = "unknown"
    kw_hits: List[Dict[str, Any]] = []
    if keywords:
        kw_hits = tool_runner._exec_wazuh(
            "alerts_contains",
            {"keywords": keywords, "dst_ip": dst_ip, "dst_port": dst_port},
            time_window,
            debug=debug,
        )
        evidence["executed_calls"].append({
            "tool_name": "wazuh",
            "query_id": "keyword_constrained",
            "params": {"keywords": keywords, "dst_ip": dst_ip, "dst_port": dst_port, "gte": gte, "lte": lte},
            "result_count": len(kw_hits),
            "samples": kw_hits[:5],
        })
        evidence["totals"]["wazuh"] += len(kw_hits)
    if isinstance(kw_hits, list) and len(kw_hits) > 0:
        evidence["scenario_detection"] = {
            "scenario": "keyword_match",
            "signals": [f"keyword hits: {', '.join(keywords[:3])}"] if isinstance(keywords, list) else ["keyword hits"],
            "confidence": 80,
            "recommended_followups": [],
        }
        scen = "unknown"
    if scen == "hydra_bruteforce":
        ev_burst = tool_runner._exec_wazuh("web_login_post_burst", {"dst_ip": dst_ip, "dst_port": dst_port}, time_window, debug=debug)
        src_counts: Dict[str, int] = {}
        minute_counts: Dict[str, int] = {}
        for ev in ev_burst[:200]:
            src = ev.get("data", {}).get("src_ip") or ev.get("data", {}).get("client", {}).get("ip") or ev.get("srcip") or "(unknown)"
            src_counts[str(src)] = src_counts.get(str(src), 0) + 1
            ts = ev.get("@timestamp") or ev.get("timestamp")
            if isinstance(ts, str) and len(ts) >= 16:
                minute = ts[:16]
                minute_counts[minute] = minute_counts.get(minute, 0) + 1
        top_src = sorted(src_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        top_min = sorted(minute_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        evidence["executed_calls"].append({
            "tool_name": "wazuh",
            "query_id": "web_login_post_burst",
            "params": {"dst_ip": dst_ip, "dst_port": dst_port, "gte": gte, "lte": lte},
            "result_count": len(ev_burst),
            "summary": {"top_src_ip": [{"src_ip": k, "count": v} for k, v in top_src], "per_minute": top_min},
            "samples": ev_burst[:5],
        })
        evidence["totals"]["wazuh"] += len(ev_burst)
    elif scen == "gobuster_forced_browsing":
        ev_404 = tool_runner._exec_wazuh("web_404_spike", {"dst_ip": dst_ip, "dst_port": dst_port}, time_window, debug=debug)
        path_ct: Dict[str, int] = {}
        src_ct2: Dict[str, int] = {}
        for ev in ev_404[:200]:
            path = ev.get("data", {}).get("http", {}).get("url") or "(unknown)"
            path_ct[str(path)] = path_ct.get(str(path), 0) + 1
            src = ev.get("data", {}).get("src_ip") or "(unknown)"
            src_ct2[str(src)] = src_ct2.get(str(src), 0) + 1
        top_paths = sorted(path_ct.items(), key=lambda x: x[1], reverse=True)[:10]
        top_src2 = sorted(src_ct2.items(), key=lambda x: x[1], reverse=True)[:5]
        evidence["executed_calls"].append({
            "tool_name": "wazuh",
            "query_id": "web_404_spike",
            "params": {"dst_ip": dst_ip, "dst_port": dst_port, "gte": gte, "lte": lte},
            "result_count": len(ev_404),
            "summary": {"unique_paths": len(path_ct), "top_paths": [{"url": k, "count": v} for k, v in top_paths], "top_src_ip": [{"src_ip": k, "count": v} for k, v in top_src2]},
            "samples": ev_404[:5],
        })
        evidence["totals"]["wazuh"] += len(ev_404)
    elif scen == "nikto_scan":
        ev_many = tool_runner._exec_wazuh("web_unique_paths_high", {"dst_ip": dst_ip, "dst_port": dst_port}, time_window, debug=debug)
        path_ct2: Dict[str, int] = {}
        src_ct3: Dict[str, int] = {}
        for ev in ev_many[:200]:
            path = ev.get("data", {}).get("http", {}).get("url") or "(unknown)"
            path_ct2[str(path)] = path_ct2.get(str(path), 0) + 1
            src = ev.get("data", {}).get("src_ip") or "(unknown)"
            src_ct3[str(src)] = src_ct3.get(str(src), 0) + 1
        top_paths2 = sorted(path_ct2.items(), key=lambda x: x[1], reverse=True)[:10]
        top_src3 = sorted(src_ct3.items(), key=lambda x: x[1], reverse=True)[:5]
        evidence["executed_calls"].append({
            "tool_name": "wazuh",
            "query_id": "web_unique_paths_high",
            "params": {"dst_ip": dst_ip, "dst_port": dst_port, "gte": gte, "lte": lte},
            "result_count": len(ev_many),
            "summary": {"unique_paths": len(path_ct2), "top_paths": [{"url": k, "count": v} for k, v in top_paths2], "top_src_ip": [{"src_ip": k, "count": v} for k, v in top_src3]},
            "samples": ev_many[:5],
        })
        evidence["totals"]["wazuh"] += len(ev_many)
    elif scen == "xss_probing":
        ev_xss = tool_runner._exec_wazuh("web_payload_hunt", {"dst_ip": dst_ip, "dst_port": dst_port}, time_window, debug=debug)
        src_ct4: Dict[str, int] = {}
        payload_samples: List[str] = []
        for ev in ev_xss[:200]:
            path = ev.get("data", {}).get("http", {}).get("url") or "(unknown)"
            if len(payload_samples) < 10:
                payload_samples.append(str(path))
            src = ev.get("data", {}).get("src_ip") or "(unknown)"
            src_ct4[str(src)] = src_ct4.get(str(src), 0) + 1
        top_src4 = sorted(src_ct4.items(), key=lambda x: x[1], reverse=True)[:5]
        evidence["executed_calls"].append({
            "tool_name": "wazuh",
            "query_id": "web_payload_hunt",
            "params": {"dst_ip": dst_ip, "dst_port": dst_port, "gte": gte, "lte": lte},
            "result_count": len(ev_xss),
            "summary": {"top_src_ip": [{"src_ip": k, "count": v} for k, v in top_src4], "payload_samples": payload_samples},
            "samples": ev_xss[:5],
        })
        evidence["totals"]["wazuh"] += len(ev_xss)

    evidence["executed_calls"].append({
        "tool_name": "wazuh",
        "query_id": "web_tier0",
        "params": {"dst_ip": dst_ip, "dst_port": dst_port, "gte": gte, "lte": lte},
        "result_count": len(ev_broad),
        "summary": {
            "top_urls": tier0_summary.get("top_urls"),
            "top_user_agents": tier0_summary.get("top_user_agents"),
            "methods": tier0_summary.get("methods"),
            "unique_url_count": tier0_summary.get("unique_url_count"),
            "login_post_count": tier0_summary.get("login_post_count"),
            "error_404_403_count": tier0_summary.get("error_404_403_count"),
            "suspicious_payload_hits": tier0_summary.get("suspicious_payload_hits"),
        },
        "samples": ev_broad[:5],
    })

    has_url_field = any(_get(ev, ["data", "http", "url"]) for ev in ev_broad[:10])
    has_method_field = any(_get(ev, ["data", "http", "http_method"]) for ev in ev_broad[:10])
    if not has_url_field or not has_method_field:
        evidence.setdefault("anomalies", {})["coverage_gap"] = True


def run_investigation(intent: str, message: str, time_hint: Optional[str], current_user: Dict[str, Any], tool_runner: ToolRunner, debug: Optional[DebugTrace] = None) -> Dict[str, Any]:
    """Deterministic investigation based on mode and security keywords (no LLM)."""
    # Deterministic time parsing: derive from the user's message.
    # If no time is mentioned, NO_TIME_SPECIFIED is returned and we pull the
    # 200 most recent events with no time constraint (now-365d window, limit=200).
    # We do NOT silently default to 24h — the user's intent is "most recent".
    tw = parse_time_window(message or "")
    gte, lte, time_window = tw.gte, tw.lte, tw.label
    mode = determine_mode(message or "")
    keywords = extract_security_keywords(message or "")
    if debug:
        debug.add({
            "type": "planner",
            "selected_mode": str(mode),
            "keywords": keywords,
            "time_window_label": time_window,
            "gte": gte,
            "lte": lte,
        })

    evidence: Dict[str, Any] = {
        "time_window": time_window,
        "executed_calls": [],
        "sources_queried": [],
        "totals": {},
        "errors": {},
        "anomalies": {},
        "available_sources": _compute_available_sources(),
    }

    # Per-connector availability — short-circuits dead query paths so the LLM
    # doesn't see executed_calls entries (and the debug trace doesn't get
    # error spam) for sources this deployment isn't configured to reach.
    wz_ok = "wazuh" in evidence["available_sources"]

    if mode == InvestigationMode.RAW_HUNT:
        # Fix time window to last 24h for this flow
        time_window = "last_24h"
        if wz_ok:
            _run_raw_hunt_wazuh(message, gte, lte, time_window, keywords, evidence, tool_runner, debug)

    elif mode == InvestigationMode.ALERT_ANALYSIS:
        if wz_ok:
            waz_rows = wazuh_conn.wazuh_search("alert:*", limit=200, time_range=time_window, debug=debug)
            evidence["totals"]["wazuh"] = len(waz_rows)
            evidence["sources_queried"].append("wazuh")
            evidence["executed_calls"].append({"tool_name": "wazuh", "query_id": "alert_search", "params": {"q": "alert:*"}, "result_count": len(waz_rows), "samples": waz_rows[:5]})

    else:  # SUMMARY
        if wz_ok:
            waz_rows = wazuh_conn.wazuh_search("*", limit=100, time_range=time_window, debug=debug)
            evidence["totals"]["wazuh"] = len(waz_rows)
            evidence["sources_queried"].append("wazuh")
            evidence["executed_calls"].append({"tool_name": "wazuh", "query_id": "summary_sample", "params": {}, "result_count": len(waz_rows), "samples": waz_rows[:3]})

    # Secondary SIEM auto-query: when SIEM_PROVIDER points at one of the
    # SIEMConnector-backed providers (splunk/elastic/sentinel/limacharlie),
    # pull its detections so the LLM gets cross-source evidence on every turn.
    #
    # Query selection — we only use specific queries when the message contains
    # a real IOC or an explicit threat tool name. For all other natural-language
    # queries ("any suspicious activity?", "find detections", etc.) we pull the
    # most recent 200 events broadly and let the LLM analyse them. Sending the
    # user's generic English words as keyword filters to the SIEM is worse than
    # useless: it returns 0 results and causes false "Likely Benign" responses.
    secondary_siem = (settings.SIEM_PROVIDER or "wazuh").lower().strip()
    if secondary_siem in ("splunk", "elastic", "sentinel", "limacharlie"):
        ip_re_2 = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
        ips_in_msg = ip_re_2.findall(message or "")

        # `keywords` now only contains real IOCs / threat tool names (IPs,
        # hashes, CVEs, named tools like mimikatz).  Generic English words are
        # filtered out in extract_security_keywords() and won't appear here.
        if ips_in_msg:
            siem_qid = "alerts_by_ip"
            siem_params: Dict[str, Any] = {"ip": ips_in_msg[-1]}
        elif keywords:
            # Only reaches here when keywords are actual threat terms (mimikatz,
            # nmap, CVE-…, hash) — safe to use as targeted filters.
            siem_qid = "keyword_search"
            siem_params = {"keywords": keywords}
        else:
            # Generic question or vague suspicion — pull recent events broadly.
            # The LLM is the filter; it can answer "any suspicious activity?"
            # by reading actual detections far better than a keyword match can.
            siem_qid = "recent_alerts"
            siem_params = {}
        try:
            siem_rows = tool_runner._exec_siem(secondary_siem, siem_qid, siem_params, gte, lte)
            evidence["totals"][secondary_siem] = len(siem_rows)
            evidence["sources_queried"].append(secondary_siem)
            evidence["executed_calls"].append({
                "tool_name": secondary_siem,
                "query_id": siem_qid,
                "params": {**siem_params, "gte": gte, "lte": lte},
                "result_count": len(siem_rows),
                "samples": siem_rows[:5],
            })
        except Exception as e:
            evidence.setdefault("errors", {})[secondary_siem] = str(e)

    # Threat Intelligence — enrich IOCs via VirusTotal (always runs if key set)
    try:
        from app.connectors.virustotal import vt_enrich_ioc, _get_vt_key
        if _get_vt_key():
            iocs = extract_iocs(message or "")
            # Also extract from alert samples in evidence
            for call in evidence.get("executed_calls", []):
                for sample in (call.get("samples") or []):
                    iocs.extend(extract_iocs(str(sample)))
            # Deduplicate, skip private/loopback IPs, cap at 10
            _private = re.compile(
                r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|255\.)"
            )
            seen_iocs: set = set()
            clean_iocs = []
            for ioc in iocs:
                if ioc in seen_iocs:
                    continue
                seen_iocs.add(ioc)
                if _private.match(ioc):
                    continue
                clean_iocs.append(ioc)
                if len(clean_iocs) >= 10:
                    break
            ti_results = {}
            for ioc in clean_iocs:
                result = vt_enrich_ioc(ioc)
                if result and "error" not in result:
                    attrs = (result.get("data") or {}).get("attributes") or {}
                    stats = attrs.get("last_analysis_stats") or {}
                    ti_results[ioc] = {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "reputation": attrs.get("reputation"),
                        "country": attrs.get("country"),
                        "tags": (attrs.get("tags") or [])[:5],
                    }
            if ti_results:
                evidence["threat_intel"] = ti_results
                evidence["sources_queried"].append("virustotal")
    except Exception as _vt_err:
        evidence.setdefault("errors", {})["virustotal"] = str(_vt_err)

    # Scoring and report
    scores = score_evidence(evidence)
    evidence["scores"] = scores
    evidence["report_markdown"] = build_report(evidence, scores)
    if debug is not None:
        debug.add({"type": "response", "stage": "run_investigation_complete", "totals": evidence.get("totals")})
        evidence["_debug_trace"] = debug.to_list()
    return evidence
