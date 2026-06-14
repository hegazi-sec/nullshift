from __future__ import annotations
from enum import Enum


class InvestigationMode(str, Enum):
    RAW_HUNT = "raw_hunt"
    ALERT_ANALYSIS = "alert_analysis"
    SUMMARY = "summary"


def determine_mode(message: str) -> InvestigationMode:
    """Deterministically choose investigation mode from the user message.

    Priority:
    1) RAW_HUNT if threat terms appear (sqlmap, nmap, mimikatz, injection, etc.)
    2) SUMMARY if high-level summary terms appear (top alerts, summary, overview)
    3) ALERT_ANALYSIS for alert-centric asks (brute force alerts, malware alerts, rule id, alert id)
    4) Default RAW_HUNT (safest SOC behavior)
    """
    msg = (message or "").lower()

    threat_terms = [
        "sqlmap", "mimikatz", "nmap", "powershell", "injection", "exploit", "malware", "brute", "scan",
    ]
    if any(t in msg for t in threat_terms):
        return InvestigationMode.RAW_HUNT

    summary_terms = [
        "top alerts", "summary", "overview",
    ]
    if any(t in msg for t in summary_terms):
        return InvestigationMode.SUMMARY

    alert_analysis_terms = [
        "brute force alerts", "malware alerts", "rule id", "alert id",
    ]
    if any(t in msg for t in alert_analysis_terms):
        return InvestigationMode.ALERT_ANALYSIS

    return InvestigationMode.RAW_HUNT
