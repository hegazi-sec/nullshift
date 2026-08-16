import requests
from app.config import settings
from app.utils.cache import SimpleCache
from typing import Any
import time

cache = SimpleCache()


def _get_vt_key() -> str:
    """Read VT API key from settings_store (DB) first, fall back to .env."""
    try:
        from app.db.settings_store import settings_store
        v = settings_store.get("vt_api_key")
        if v:
            return v
    except Exception:
        pass
    return settings.VT_API_KEY or ""


def vt_summarize(ioc: str, raw: Any) -> dict:
    """Reduce a raw VT v3 response to a compact, LLM-friendly verdict dict.

    Shared by the ToolRunner lookup_ioc path and the auto-enrichment step so
    both surface the same shape. Returns an {"error": ...} dict unchanged.
    """
    if not isinstance(raw, dict) or "error" in raw:
        return {"ioc": ioc, "error": (raw or {}).get("error", "unknown") if isinstance(raw, dict) else "unknown"}
    attrs = (raw.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) if stats else 0
    return {
        "ioc": ioc,
        "malicious_votes": malicious,
        "suspicious_votes": suspicious,
        "total_engines": total,
        "verdict": "malicious" if malicious >= 3 else ("suspicious" if (malicious + suspicious) >= 1 else "clean"),
        "reputation": attrs.get("reputation"),
        "country": attrs.get("country"),
        "as_owner": attrs.get("as_owner"),
        "registrar": attrs.get("registrar"),
        "meaningful_name": attrs.get("meaningful_name"),
    }


def vt_enrich_compact(ioc: str) -> dict:
    """Look up an IOC and return only the compact summary (never the raw blob)."""
    return vt_summarize(ioc, vt_enrich_ioc(ioc))


def vt_enrich_ioc(ioc: str) -> Any:
    """Enrich IP/domain/hash via VirusTotal v3 APIs, with simple caching."""
    api_key = _get_vt_key()
    if not api_key:
        return {"error": "no_vt_key"}
    try:
        cached = cache.get(ioc)
        if cached:
            return cached
    except Exception as e:
        # Do not fail the whole request if cache backend has an issue
        cached = None
    headers = {"x-apikey": api_key}
    base = "https://www.virustotal.com/api/v3"
    # crude type detection
    if "." in ioc and all(ch.isdigit() or ch=='.' for ch in ioc.replace(':','')):
        url = f"{base}/ip_addresses/{ioc}"
    elif "." in ioc:
        url = f"{base}/domains/{ioc}"
    else:
        url = f"{base}/files/{ioc}"
    try:
        r = requests.get(url, headers=headers, timeout=10)
        r.raise_for_status()
        data = r.json()
        try:
            cache.set(ioc, data)
        except Exception:
            pass
        # sleep briefly to respect rate limits
        time.sleep(0.2)
        return data
    except Exception as e:
        return {"error": str(e)}
