"""Alert severity: each SIEM's own severity field and scale, mapped onto low/medium/high/critical.

Which SIEM sent an alert comes from the webhook's ?source= hint, else the payload's shape,
else the SIEM this install is connected to. That SIEM's fields are read in order and the
first one present decides: a number goes through the SIEM's thresholds, a word through its
word map. An admin can change both per SIEM and pin a severity per rule (Settings ›
Connectors › Alert severity); a rule override wins over everything. A payload no profile
recognises gets the generic read (normalize_severity).
"""
from __future__ import annotations

import json
from typing import Any, Dict, Optional

SEVERITIES = ("low", "medium", "high", "critical")

# The generic read, for payloads no SIEM profile recognises.
_SEVERITY_MAP = {
    # numeric levels (Wazuh 0-15, generic 1-10)
    **{str(n): "low" for n in range(0, 6)},
    **{str(n): "medium" for n in range(6, 10)},
    **{str(n): "high" for n in range(10, 13)},
    **{str(n): "critical" for n in range(13, 16)},
    # common words
    "info": "low", "informational": "low", "low": "low",
    "medium": "medium", "moderate": "medium",
    "high": "high", "important": "high",
    "critical": "critical", "severe": "critical",
}


def normalize_severity(raw: Any) -> str:
    if raw is None:
        return "medium"
    return _SEVERITY_MAP.get(str(raw).strip().lower(), "medium")


# Each SIEM's own severity: the payload fields it puts it in (first present wins), its numeric
# scale with the default thresholds (a value at or above critical_min is critical, and so on;
# below medium_min is low), and its native words.
PROFILES: Dict[str, Dict[str, Any]] = {
    "limacharlie": {
        "label": "LimaCharlie",
        # the D&R report action's priority (0-10), else its free-form metadata;
        # the thresholds are LimaCharlie's own Cases mapping
        "fields": ["priority", "detect_mtd.severity", "detect_mtd.level"],
        "scale": {"field": "priority", "min": 0, "max": 10},
        "thresholds": {"medium_min": 3, "high_min": 5, "critical_min": 8},
        "words": {"info": "low", "informational": "low", "low": "low",
                  "medium": "medium", "high": "high", "critical": "critical"},
    },
    "wazuh": {
        "label": "Wazuh",
        # rule level 0-15: 0-6 low, 7-9 medium, 10-12 high, 13-15 critical
        "fields": ["rule.level"],
        "scale": {"field": "rule.level", "min": 0, "max": 15},
        "thresholds": {"medium_min": 7, "high_min": 10, "critical_min": 13},
        "words": {},
    },
    "splunk": {
        "label": "Splunk",
        # whatever the alert's search puts in its results: Enterprise Security urgency,
        # or a severity as a word or on the 1-6 alert.severity scale
        "fields": ["result.urgency", "result.severity", "urgency", "severity", "alert.severity"],
        "scale": {"field": "result.severity", "min": 1, "max": 6},
        "thresholds": {"medium_min": 4, "high_min": 5, "critical_min": 6},
        "words": {"informational": "low", "info": "low", "low": "low",
                  "medium": "medium", "high": "high", "critical": "critical"},
    },
    "elastic": {
        "label": "Elastic",
        # the rule's severity word, else its risk score (0-100, Elastic's own bands)
        "fields": ["rule.severity", "kibana.alert.severity", "kibana.alert.rule.severity",
                   "rule.risk_score", "kibana.alert.risk_score", "risk_score", "severity"],
        "scale": {"field": "risk_score", "min": 0, "max": 100},
        "thresholds": {"medium_min": 22, "high_min": 48, "critical_min": 74},
        "words": {"low": "low", "medium": "medium", "high": "high", "critical": "critical"},
    },
    "sentinel": {
        "label": "Microsoft Sentinel",
        # incident (Logic App) or SecurityAlert shape; Sentinel has no Critical
        "fields": ["properties.severity", "AlertSeverity", "Severity", "severity"],
        "scale": None,
        "thresholds": None,
        "words": {"informational": "low", "low": "low", "medium": "medium", "high": "high"},
    },
}

_ALIASES = {
    **{sid: sid for sid in PROFILES},
    "lc": "limacharlie",
    "elasticsearch": "elastic", "kibana": "elastic", "elastic-security": "elastic",
    "azure-sentinel": "sentinel", "microsoft-sentinel": "sentinel", "azuresentinel": "sentinel",
}


def siem_id(name: Any) -> Optional[str]:
    return _ALIASES.get(str(name or "").strip().lower())


def shape(p: Dict[str, Any]) -> Optional[str]:
    """The SIEM a payload's shape points to, if any."""
    rule = p.get("rule")
    if isinstance(rule, dict):
        if rule.get("description") and p.get("agent"):
            return "wazuh"
        if rule.get("name"):
            return "elastic"
    if p.get("cat"):
        return "limacharlie"
    if p.get("search_name"):
        return "splunk"
    props = p.get("properties")
    if any(k in p for k in ("AlertSeverity", "AlertDisplayName", "CompromisedEntity")) or (
            isinstance(props, dict) and "severity" in props and ("incidentNumber" in props or "title" in props)):
        return "sentinel"
    if any(str(k).startswith("kibana.alert.") for k in p):
        return "elastic"
    return None


def siem_of(payload: Dict[str, Any], hint: Any = None, configured: Any = None) -> Optional[str]:
    """The ?source= hint, else the payload's shape, else the connected SIEM."""
    return siem_id(hint) or shape(payload) or siem_id(configured)


def load() -> Dict[str, Any]:
    """The admin's customisations ({thresholds, words, rules}) and the connected SIEMs."""
    from app.connectors import configured_siems
    from app.db.settings_store import settings_store
    try:
        custom = json.loads(settings_store.get("alert_severity") or "{}")
    except ValueError:
        custom = {}
    siems = configured_siems()
    # an alert whose shape names no SIEM is read on the primary (first) SIEM's scale
    return {**(custom if isinstance(custom, dict) else {}), "configured": siems[0] if siems else None, "connected": siems}


def save(custom: Dict[str, Any]) -> None:
    from app.db.settings_store import settings_store
    settings_store.set_many({"alert_severity": json.dumps(custom) if any(custom.values()) else None})


def profile(sid: str, cfg: Dict[str, Any]) -> Dict[str, Any]:
    """A SIEM's profile with the admin's thresholds and words over the defaults."""
    base = PROFILES[sid]
    t = (cfg.get("thresholds") or {}).get(sid)
    w = (cfg.get("words") or {}).get(sid)
    thresholds = base["thresholds"]
    if thresholds and isinstance(t, dict):
        thresholds = {**thresholds, **{k: v for k, v in t.items()
                                       if k in thresholds and isinstance(v, int) and not isinstance(v, bool)}}
    words = {**base["words"], **{k: v for k, v in (w if isinstance(w, dict) else {}).items()
                                 if k in base["words"] and v in SEVERITIES}}
    return {**base, "thresholds": thresholds, "words": words}


def _get(p: Dict[str, Any], path: str) -> Any:
    cur: Any = p
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return p.get(path)  # ECS documents can arrive flattened: {"kibana.alert.severity": ...}
        cur = cur[part]
    return cur


def _read(value: Any, prof: Dict[str, Any]) -> Optional[str]:
    if value is None or isinstance(value, (bool, dict, list)):
        return None
    try:
        n = float(value)
    except (TypeError, ValueError):
        word = str(value).strip().lower()
        return prof["words"].get(word) or (_SEVERITY_MAP.get(word) if word else None)
    t = prof["thresholds"]
    if not t:
        return None  # a number where the SIEM has no scale: leave it to the generic read
    return ("critical" if n >= t["critical_min"] else "high" if n >= t["high_min"]
            else "medium" if n >= t["medium_min"] else "low")


def _generic(p: Dict[str, Any]) -> str:
    rule = p.get("rule") if isinstance(p.get("rule"), dict) else {}
    meta = p.get("detect_mtd") if isinstance(p.get("detect_mtd"), dict) else {}
    for raw in (rule.get("level"), rule.get("severity"), meta.get("severity"),
                *(p.get(k) for k in ("severity", "level", "priority", "risk_score"))):
        if raw is not None:
            return normalize_severity(raw)
    return "medium"


def classify(payload: Dict[str, Any], source: Any = None, title: Optional[str] = None,
             cfg: Optional[Dict[str, Any]] = None) -> str:
    cfg = load() if cfg is None else cfg
    pinned = (cfg.get("rules") or {}).get(title) if title else None
    if pinned in SEVERITIES:
        return pinned
    sid = siem_of(payload, source, cfg.get("configured"))
    if sid:
        prof = profile(sid, cfg)
        for path in prof["fields"]:
            sev = _read(_get(payload, path), prof)
            if sev:
                return sev
    return _generic(payload)


def validate(body: Dict[str, Any]) -> Dict[str, Any]:
    """An admin's PUT, checked and reduced to what differs from the defaults. ValueError says what's wrong."""
    out: Dict[str, Any] = {"thresholds": {}, "words": {}, "rules": {}}
    for sid, t in (body.get("thresholds") or {}).items():
        prof = PROFILES.get(sid)
        if not prof or not prof["scale"] or not isinstance(t, dict):
            raise ValueError(f"{sid} has no numeric scale")
        lo, hi = prof["scale"]["min"], prof["scale"]["max"]
        vals = {}
        for k in ("medium_min", "high_min", "critical_min"):
            v = t.get(k)
            if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
                raise ValueError(f"{prof['label']}: {k.split('_')[0].title()} from must be a whole number from {lo} to {hi}")
            vals[k] = v
        if not vals["medium_min"] <= vals["high_min"] <= vals["critical_min"]:
            raise ValueError(f"{prof['label']}: Medium from ≤ High from ≤ Critical from")
        if vals != prof["thresholds"]:
            out["thresholds"][sid] = vals
    for sid, w in (body.get("words") or {}).items():
        prof = PROFILES.get(sid)
        if not prof or not isinstance(w, dict):
            raise ValueError(f"Unknown SIEM {sid!r}")
        for word, sev in w.items():
            if word not in prof["words"]:
                raise ValueError(f"{prof['label']} has no severity word {word!r}")
            if sev not in SEVERITIES:
                raise ValueError(f"{prof['label']}: {word} must map to one of {', '.join(SEVERITIES)}")
        changed = {k: v for k, v in w.items() if prof["words"][k] != v}
        if changed:
            out["words"][sid] = changed
    rules = body.get("rules") or {}
    if not isinstance(rules, dict) or len(rules) > 500:
        raise ValueError("At most 500 rule overrides")
    for name, sev in rules.items():
        if not name.strip() or len(name) > 200:
            raise ValueError("A rule name must be 1 to 200 characters (the alert's title as NullShift shows it)")
        if sev not in SEVERITIES:
            raise ValueError(f"{name}: severity must be one of {', '.join(SEVERITIES)}")
    out["rules"] = dict(rules)
    return out
