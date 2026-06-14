from typing import Any, Dict, List


def _fmt_sources_coverage(sources: List[str], totals: Dict[str, int], errors: Dict[str, str]) -> str:
    lines = []
    have = set(sources or [])
    all_sources = list(have | set(totals.keys()) | set(errors.keys()))
    for s in sorted(all_sources):
        status = "OK" if s in have else "MISSING"
        err = "; error: " + errors[s] if s in errors else ""
        lines.append(f"- {s}: {status} (count={int(totals.get(s,0))}){err}")
    return "\n".join(lines)


def build_report(evidence: Dict[str, Any], scores: Dict[str, Any]) -> str:
    """Build a SOC-grade, compact Markdown report from evidence and scores.

    Sections: Evidence & Coverage, Behavior, Correlation, Verdict/Confidence, Next Actions
    """
    sources = evidence.get("sources_queried") or []
    totals = evidence.get("totals") or {}
    errors = evidence.get("errors") or {}

    # Evidence & Coverage
    sec_evidence = [
        "Evidence & Coverage:",
        f"- Time window used: {evidence.get('time_window')}",
        _fmt_sources_coverage(sources, totals, errors),
    ]

    # Correlation (very lightweight): if multiple sources fired together
    corr_lines = ["Correlation:"]
    active_sources = [s for s in sources if int(totals.get(s, 0)) > 0]
    if len(active_sources) >= 2:
        corr_lines.append("- Multiple sensors show activity in the same window (correlated signals).")
    else:
        corr_lines.append("- Limited cross-source correlation observed in this time window.")

    # Verdict
    verdict = [
        "Verdict & Confidence:",
        f"- Threat score: {scores.get('threat_score')} | Severity: {scores.get('severity').upper()}",
        f"- Coverage score: {scores.get('coverage_score')} | Confidence: {scores.get('confidence')}%",
    ]
    if scores.get("capped_any"):
        verdict.append("- Note: one or more queries hit caps; results may be partial.")

    # Next Actions
    next_actions = [
        "Next Actions:",
        "- Validate top talkers and destinations; confirm intent with asset owners.",
        "- Deep dive into high-volume signatures/agents using targeted queries.",
        "- If scan/lateral heuristics flagged, inspect east-west traffic and authentication logs.",
        "- Consider blocking or increased monitoring for suspicious sources/destinations.",
    ]

    sections = [
        "\n".join(sec_evidence),
        "\n".join(corr_lines),
        "\n".join(verdict),
        "\n".join(next_actions),
    ]
    return "\n\n".join(sections)
