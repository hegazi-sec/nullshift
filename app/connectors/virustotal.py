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
