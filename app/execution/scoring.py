import json as _json
import re as _re
from typing import Any, Dict, List


SEVERITY_BANDS = [
    (85, "critical"),
    (70, "high"),
    (50, "medium"),
    (30, "low"),
    (0, "informational"),
]


def _band(value: int) -> str:
    for thr, name in SEVERITY_BANDS:
        if value >= thr:
            return name
    return "informational"


def score(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Compute threat/coverage/confidence scores with penalties."""
    totals = evidence.get("totals") or {}
    errors = evidence.get("errors") or {}
    sources = evidence.get("sources_queried") or []
    normalized_calls: List[Dict[str, Any]] = evidence.get("normalized_calls") or []

    # Coverage: percent of configured sources that returned results
    expected_sources = max(1, len(sources) or 1)
    src_cov = 100 * len([s for s in sources if int(totals.get(s, 0)) > 0]) // expected_sources
    cov = src_cov

    capped_any = False
    sampling_only = True
    for call in normalized_calls:
        if call.get("meta", {}).get("capped"):
            capped_any = True
        # If any call returned > samples (we only keep samples, but use result_count to infer richness)
        if int(call.get("meta", {}).get("result_count", 0)) > 5:
            sampling_only = False
    if capped_any:
        cov -= 10
    cov -= 15 * len(errors)
    cov = max(0, min(100, cov))

    # Threat: heuristic based on event volume across all sources
    threat = 0
    total_events = sum(int(totals.get(s, 0)) for s in sources)
    if total_events > 0:
        threat += min(50, 10 + total_events // 20)
    threat = max(0, min(100, threat))

    # Hard caps
    if capped_any:
        threat = min(threat, 70)
    if sampling_only:
        threat = min(threat, 60)

    # Confidence derived from coverage
    confidence = max(0, min(100, cov))

    severity = _band(threat)

    return {
        "threat_score": threat,
        "coverage_score": cov,
        "confidence": confidence,
        "severity": severity,
        "capped_any": capped_any,
        "sampling_only": sampling_only,
    }


def ai_score_evidence(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """LLM scoring: maps evidence to MITRE ATT&CK + NIST CSF. Falls back to heuristic on error."""
    samples_data = [
        {
            "source": c.get("tool_name"),
            "query": c.get("query_id"),
            "count": c.get("result_count", 0),
            "samples": (c.get("samples") or [])[:3],
        }
        for c in (evidence.get("executed_calls") or [])[:4]
    ]

    payload = {
        "time_window": evidence.get("time_window"),
        "totals": evidence.get("totals"),
        "scenario": evidence.get("scenario_detection"),
        "threat_intel": evidence.get("threat_intel"),
        "executed_calls": samples_data,
    }

    system = (
        "You are a SOC threat-scoring engine. Analyse the security evidence and return ONLY "
        "valid JSON — no explanation, no markdown fences.\n\n"
        'Schema: {"threat_score":<0-100>,"severity":"<informational|low|medium|high|critical>",'
        '"mitre_tactics":["<TA00XX>",...],"mitre_techniques":["<T1XXX>",...],'
        '"nist_function":"<Identify|Protect|Detect|Respond|Recover>",'
        '"reasoning":"<one sentence>"}\n\n'
        "Rules:\n"
        "- threat_score reflects TTP severity, NOT event volume alone\n"
        "- map observable behaviour to the most specific MITRE ATT&CK technique(s)\n"
        "- pick the dominant NIST CSF function the activity triggers\n"
        "- if evidence is absent or ambiguous, threat_score <= 20\n"
        "- always include all six keys"
    )

    try:
        from app.llm import chat_with_history  # lazy — avoids circular dep at module load
        raw = chat_with_history(
            system_prompt=system,
            history_messages=[{"role": "user", "content": _json.dumps(payload, ensure_ascii=False)}],
            max_tokens=300,
            temperature=0.0,
        )
        clean = _re.sub(r"^```(?:json)?\s*|\s*```$", "", raw.strip(), flags=_re.DOTALL)
        parsed = _json.loads(clean)
        threat = max(0, min(100, int(parsed.get("threat_score", 0))))
        result: Dict[str, Any] = {
            "threat_score": threat,
            "severity": parsed.get("severity") or _band(threat),
            "mitre_tactics": parsed.get("mitre_tactics") or [],
            "mitre_techniques": parsed.get("mitre_techniques") or [],
            "nist_function": parsed.get("nist_function") or "Detect",
            "reasoning": parsed.get("reasoning") or "",
        }
    except Exception:
        # ponytail: silent fallback — heuristic beats a noisy failure mid-investigation
        result = score(evidence)
        result.setdefault("mitre_tactics", [])
        result.setdefault("mitre_techniques", [])
        result.setdefault("nist_function", "Detect")
        result.setdefault("reasoning", "")

    # Coverage is always deterministic — never delegated to LLM
    totals = evidence.get("totals") or {}
    errors = evidence.get("errors") or {}
    sources = evidence.get("sources_queried") or []
    cov = 100 * len([s for s in sources if int(totals.get(s, 0)) > 0]) // max(1, len(sources))
    cov -= 15 * len(errors)
    result["coverage_score"] = max(0, min(100, cov))
    result["confidence"] = result["coverage_score"]
    result["capped_any"] = any(
        c.get("meta", {}).get("capped") for c in (evidence.get("normalized_calls") or [])
    )
    result["sampling_only"] = False
    return result
