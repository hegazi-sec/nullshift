"""Parse YAML front-matter from playbook markdown files.

Front-matter sits between the opening and closing --- delimiters and encodes
the structured query hints the PlaybookRunner uses to drive SIEM searches.

Supported front-matter keys:
    title           Human-readable playbook name
    tactics         List of MITRE ATT&CK tactic names (informational)
    ioc_fields      List of field names that hold IOCs in this playbook's events
    siem_queries    Dict of provider → list of {query_id, params} dicts.
                    Supported provider keys: wazuh, splunk, elastic, sentinel,
                    limacharlie

Example front-matter:

    ---
    title: SSH Brute Force
    tactics: [credential-access]
    ioc_fields: [src_ip, username]
    siem_queries:
      wazuh:
        - query_id: alerts_by_rule
          params:
            rule_id: "5763"
      splunk:
        - query_id: keyword_search
          params:
            keywords: [failed password, authentication failure]
    ---
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

_KB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "kb"
_FRONT_MATTER_RE = re.compile(r"^---[ \t]*\r?\n(.*?)\r?\n---[ \t]*\r?\n", re.DOTALL)

def parse_front_matter(filename: str) -> Optional[Dict[str, Any]]:
    """Return the parsed YAML front-matter dict for a playbook file, or None."""
    if not _YAML_AVAILABLE:
        return None
    path = _KB_PATH / filename
    if not path.exists():
        return None
    try:
        text = path.read_text(encoding="utf-8")
        m = _FRONT_MATTER_RE.match(text)
        if not m:
            return None
        meta = yaml.safe_load(m.group(1))
        return meta if isinstance(meta, dict) else None
    except Exception:
        return None


def get_queries_for_provider(meta: Dict[str, Any], provider: str) -> List[Dict[str, Any]]:
    """Return query dicts for the primary SIEM provider (e.g. wazuh, splunk).

    Each returned dict has the shape: {'query_id': str, 'params': dict}.
    """
    return _extract_queries(meta, provider.lower())


def get_ioc_fields(meta: Dict[str, Any]) -> List[str]:
    """List of event field names that carry IOC values for this playbook."""
    return list(meta.get("ioc_fields") or [])


def _extract_queries(meta: Dict[str, Any], tool: str) -> List[Dict[str, Any]]:
    siem_queries = meta.get("siem_queries") or {}
    raw = siem_queries.get(tool) or []
    result: List[Dict[str, Any]] = []
    for q in raw:
        if not isinstance(q, dict) or "query_id" not in q:
            continue
        result.append({
            "query_id": str(q["query_id"]),
            "params": dict(q.get("params") or {}),
        })
    return result
