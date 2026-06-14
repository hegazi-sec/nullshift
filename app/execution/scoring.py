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
