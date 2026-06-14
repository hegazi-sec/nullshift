from typing import Dict, Any, List


def detect_web_scenario(events_summary: Dict[str, Any]) -> Dict[str, Any]:
    """Infer likely DVWA scenario from Tier-0 web activity summary.

    Input keys expected (best-effort):
    - total_events: int
    - top_urls: List[{url, count}]
    - top_src: List[{src_ip, count}]
    - methods: Dict[str, int]
    - top_user_agents: List[{ua, count}]
    - unique_url_count: int
    - login_post_count: int (if provided)
    - error_404_403_count: int (if provided)
    - suspicious_payload_hits: int (if provided)
    """
    total = int(events_summary.get("total_events", 0) or 0)
    methods = events_summary.get("methods", {}) or {}
    top_uas = events_summary.get("top_user_agents", []) or []
    uniq_paths = int(events_summary.get("unique_url_count", 0) or 0)
    login_posts = int(events_summary.get("login_post_count", 0) or 0)
    errs = int(events_summary.get("error_404_403_count", 0) or 0)
    payload_hits = int(events_summary.get("suspicious_payload_hits", 0) or 0)

    signals: List[str] = []
    scenario = "unknown"
    confidence = 25
    recs: List[str] = []

    post_ct = int(methods.get("POST", 0))
    get_ct = int(methods.get("GET", 0))

    # Fast-path: user-agent fingerprints (case-insensitive)
    for ent in top_uas:
        ua = str(ent.get("ua") or ent.get("user_agent") or "").lower()
        if not ua:
            continue
        if "nikto" in ua:
            return {
                "scenario": "nikto_scan",
                "signals": ["user_agent contains nikto"],
                "confidence": 95,
                "recommended_followups": ["wazuh.web_unique_paths_high", "check user_agent for nikto"],
            }
        if "gobuster" in ua:
            return {
                "scenario": "gobuster_forced_browsing",
                "signals": ["user_agent contains gobuster"],
                "confidence": 92,
                "recommended_followups": ["wazuh.web_404_spike", "list top unique paths by count"],
            }
        if "wfuzz" in ua:
            return {
                "scenario": "xss_probing",
                "signals": ["user_agent contains wfuzz"],
                "confidence": 88,
                "recommended_followups": ["wazuh.web_payload_hunt", "review parameters and src_ip"],
            }
        if "hydra" in ua:
            return {
                "scenario": "hydra_bruteforce",
                "signals": ["user_agent contains hydra"],
                "confidence": 90,
                "recommended_followups": ["wazuh.web_login_post_burst"],
            }

    # Hydra-like: many POSTs, high login.php hits
    if post_ct >= 20 and login_posts >= 10:
        scenario = "hydra_bruteforce"
        confidence = min(95, 50 + login_posts)
        signals += [f"high POST volume ({post_ct})", f"login.php POST count ({login_posts})"]
        recs += ["wazuh.web_login_post_burst", "review top src_ip for repeated attempts"]
        return {"scenario": scenario, "signals": signals, "confidence": confidence, "recommended_followups": recs}

    # Gobuster-like: many GETs across many unique paths + many 404/403
    if get_ct >= 50 and uniq_paths >= 40 and errs >= 10:
        scenario = "gobuster_forced_browsing"
        confidence = min(90, 40 + uniq_paths // 2)
        signals += [f"high GET volume ({get_ct})", f"unique paths ({uniq_paths})", f"4xx count ({errs})"]
        recs += ["wazuh.web_404_spike", "list top unique paths by count"]
        return {"scenario": scenario, "signals": signals, "confidence": confidence, "recommended_followups": recs}

    # Nikto-like: very high unique paths; UA or known probe paths may not be present
    if uniq_paths >= 80 and get_ct >= 50:
        scenario = "nikto_scan"
        confidence = min(85, 30 + uniq_paths // 2)
        signals += [f"very high unique paths ({uniq_paths})", f"GET volume ({get_ct})"]
        recs += ["wazuh.web_unique_paths_high", "check user_agent for nikto"]
        return {"scenario": scenario, "signals": signals, "confidence": confidence, "recommended_followups": recs}

    # Wfuzz XSS probing: payload markers present and xss endpoint hits
    if payload_hits >= 3:
        scenario = "xss_probing"
        confidence = min(90, 40 + payload_hits * 5)
        signals += [f"payload markers found ({payload_hits})"]
        recs += ["wazuh.web_payload_hunt", "review parameters and src_ip"]
        return {"scenario": scenario, "signals": signals, "confidence": confidence, "recommended_followups": recs}

    # Unknown or low signal; note potential coverage gaps
    if total > 0:
        signals += [f"events observed ({total})", f"unique paths ({uniq_paths})", f"methods: GET={get_ct}, POST={post_ct}"]
    if methods.get("(unknown)") or uniq_paths == 0:
        signals.append("coverage_gap: missing method/url fields in telemetry")
    return {"scenario": scenario, "signals": signals, "confidence": confidence, "recommended_followups": recs}
