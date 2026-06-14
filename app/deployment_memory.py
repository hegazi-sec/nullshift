"""Auto-generated deployment description, written to data/memory.md on startup.

Inspects current settings (SIEM provider, LLM provider, optional connectors)
and emits a human-readable markdown summary. Both the analyst and the LLM
read this file — the analyst to see what's configured at a glance, the LLM
as system context so every chat turn knows what toolkit it has without
having to re-derive from `available_sources` in the evidence bundle.

Regenerated on every server startup (overwrites any manual edits to the
auto-generated sections — restart uvicorn after editing .env to refresh).
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from app.config import settings


DEFAULT_PATH = Path(__file__).resolve().parent / "data" / "memory.md"


def _llm_section() -> str:
    lines: List[str] = []
    if settings.USE_CLAUDE_AGENT_SDK:
        model = settings.CLAUDE_AGENT_SDK_MODEL or "SDK default"
        lines.append(f"- **Claude Agent SDK** (primary, subscription-billed) — model: `{model}`")
    if settings.ANTHROPIC_API_KEY:
        lines.append(f"- **Anthropic API** — model: `{settings.ANTHROPIC_MODEL}`")
    if settings.OPENAI_API_KEY:
        lines.append(f"- **OpenAI API** — model: `{settings.OPENAI_MODEL}`")
    if settings.DEEPSEEK_API_KEY:
        lines.append("- **DeepSeek** (fallback)")
    return "\n".join(lines) if lines else "- _none configured — chat will return errors_"


def _siem_section() -> str:
    siem = (settings.SIEM_PROVIDER or "wazuh").lower().strip()
    if siem == "wazuh":
        if settings.wazuh_indexer_url:
            return f"- **Wazuh** (active) — indexer: `{settings.wazuh_indexer_url}`"
        return "- ⚠️ Wazuh selected but `WAZUH_INDEXER_URL` is not set — queries will fail"
    if siem == "limacharlie":
        oid = (settings.LIMACHARLIE_OID or "").strip()
        if oid and settings.LIMACHARLIE_API_KEY:
            redacted = f"{oid[:8]}…{oid[-4:]}" if len(oid) > 14 else "set"
            return f"- **LimaCharlie** (active) — OID: `{redacted}` — endpoint: `/v1/insight/<oid>/detections`"
        return "- ⚠️ LimaCharlie selected but `LIMACHARLIE_OID` or `LIMACHARLIE_API_KEY` missing"
    if siem == "splunk":
        return f"- **Splunk** (active) — URL: `{settings.SPLUNK_URL or 'not set'}` — index: `{settings.SPLUNK_INDEX}`"
    if siem == "elastic":
        return f"- **Elastic** (active) — URL: `{settings.ELASTIC_URL or 'not set'}` — index: `{settings.ELASTIC_INDEX}`"
    if siem == "sentinel":
        ws = (settings.SENTINEL_WORKSPACE_ID or "").strip()
        return f"- **Microsoft Sentinel** (active) — workspace: `{ws[:8]}…` " if ws else "- ⚠️ Sentinel selected but workspace ID missing"
    return f"- ⚠️ Unknown SIEM_PROVIDER `{siem}`"


def _aux_section() -> List[str]:
    lines: List[str] = []
    if settings.VT_API_KEY:
        lines.append("- **VirusTotal** — IOC enrichment (hash/IP/domain lookups)")
    return lines


def build_memory_md() -> str:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    aux_lines = _aux_section()
    aux_text = "\n".join(aux_lines) if aux_lines else "- _none configured_"
    return f"""# NullShift — Deployment Memory

_Auto-generated at {now}. Regenerated on every server startup; manual edits to this file are overwritten on restart._

## LLM providers
{_llm_section()}

## SIEM (primary detection source)
{_siem_section()}

## Auxiliary connectors
{aux_text}

## Implications for chat reasoning
The investigation pipeline will only query the connectors listed above.
SECTION 1 of every assistant response enumerates exactly these sources —
absent connectors are NEVER mentioned (no "Not retrieved" noise).

To add or remove a connector: edit `.env` (or re-run `python setup_wizard.py`),
then restart uvicorn. This file regenerates automatically.
"""


_cached: Optional[str] = None


def write_memory_file(path: Path = DEFAULT_PATH) -> Path:
    """Write the deployment memory to disk and refresh the in-process cache."""
    global _cached
    path.parent.mkdir(parents=True, exist_ok=True)
    content = build_memory_md()
    path.write_text(content, encoding="utf-8")
    _cached = content
    return path


def get_cached_memory() -> Optional[str]:
    """Return the cached memory content. Returns None until write_memory_file()
    has been called at least once (typically by the FastAPI startup hook)."""
    return _cached
