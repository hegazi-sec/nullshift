import requests
import urllib3
from urllib.parse import urlparse
import re
import logging
from app.config import settings
from app.utils.debug_trace import DebugTrace
from typing import Optional, Dict, Any, Tuple, List, Set
import time
"""Wazuh connector with optional TLS verification control.
Set settings.WAZUH_VERIFY_SSL=True and configure a valid CA bundle to avoid warnings.
"""

# Optionally suppress InsecureRequestWarning when verification is disabled
if not settings.WAZUH_VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


logger = logging.getLogger("connectors.wazuh")

_BASE_PATH_CANDIDATES = ["", "/api", "/v4", "/api/v4", "/wazuh", "/wazuh/api", "/wazuh/api/v4"]
_detected_base_path: Optional[str] = None
_cached_token: Optional[str] = None
_cached_token_expiry: float = 0
_failed_request_signatures: set = set()
_last_query_failure_status: Optional[int] = None


def _headers() -> Dict[str, str]:
    token = _get_token()
    return {"Authorization": f"Bearer {token}"} if token else {}


def _get_token() -> Optional[str]:
    global _cached_token, _cached_token_expiry
    # 1) Use static token if provided
    if settings.WAZUH_API_TOKEN:
        return settings.WAZUH_API_TOKEN
    # 2) Use cached token if still fresh (assume 10 minutes lifetime)
    if _cached_token and time.time() < _cached_token_expiry:
        return _cached_token
    # 3) If user/pass provided, try to authenticate and cache token
    if settings.WAZUH_USER and settings.WAZUH_PASS and settings.WAZUH_API_URL:
        base_url = settings.WAZUH_API_URL.rstrip("/")
        for bp in _BASE_PATH_CANDIDATES:
            # Prefer raw token endpoint via Basic Auth
            url = f"{base_url}{bp}/security/user/authenticate?raw=true"
            try:
                r = requests.get(url, auth=(settings.WAZUH_USER, settings.WAZUH_PASS),
                                 verify=settings.WAZUH_VERIFY_SSL, timeout=10)
                if r.status_code == 200:
                    tok = r.text.strip().strip('"')
                    if tok and len(tok) > 10:
                        global _detected_base_path
                        _detected_base_path = bp
                        _cached_token = tok
                        _cached_token_expiry = time.time() + 600  # 10 minutes
                        return _cached_token
            except Exception:
                pass
            # Fallback: JSON POST variant
            urlp = f"{base_url}{bp}/security/user/authenticate"
            try:
                r = requests.post(urlp, json={"username": settings.WAZUH_USER, "password": settings.WAZUH_PASS},
                                  verify=settings.WAZUH_VERIFY_SSL, timeout=10)
                if r.status_code == 200:
                    try:
                        j = r.json()
                        tok = j.get('data') or j.get('token') or j.get('jwt')
                        if isinstance(tok, dict):
                            tok = tok.get('token') or tok.get('jwt')
                    except Exception:
                        tok = None
                    if not tok:
                        tok = r.text.strip().strip('"')
                    if tok and len(tok) > 10:
                        _detected_base_path = bp
                        _cached_token = tok
                        _cached_token_expiry = time.time() + 600
                        return _cached_token
            except Exception:
                pass
    return None


def _extract_event(payload):
    """Best-effort: find first dict that looks like a Wazuh event with agent info."""
    if isinstance(payload, dict):
        # A typical event has an 'agent' object with an 'id'
        agent = payload.get("agent")
        if isinstance(agent, dict) and agent.get("id"):
            return payload
        for v in payload.values():
            ev = _extract_event(v)
            if ev:
                return ev
    elif isinstance(payload, list):
        for item in payload:
            ev = _extract_event(item)
            if ev:
                return ev
    return None


def _try_get(path: str, params: Optional[Dict[str, Any]] = None, debug: Optional[DebugTrace] = None) -> Tuple[int, Optional[Dict[str, Any]], Optional[str]]:
    """Try a GET across possible base paths, return (status_code, json_or_none, used_base_path)."""
    global _detected_base_path
    base_url = settings.WAZUH_API_URL.rstrip("/") if settings.WAZUH_API_URL else None
    if not base_url:
        return (0, None, None)
    # Prefer previously detected base path
    paths = [_detected_base_path] + _BASE_PATH_CANDIDATES if _detected_base_path else _BASE_PATH_CANDIDATES
    for bp in paths:
        url = f"{base_url}{bp}{path}"
        try:
            if debug:
                debug.add({
                    "type": "request",
                    "source": "wazuh",
                    "path": f"{bp}{path}",
                    "params_keys": list((params or {}).keys()),
                })
            r = requests.get(url, headers=_headers(), params=params, verify=settings.WAZUH_VERIFY_SSL, timeout=10)
            if r.status_code < 400:
                try:
                    data = r.json()
                except Exception:
                    data = None
                _detected_base_path = bp
                if debug:
                    debug.add({
                        "type": "response",
                        "source": "wazuh",
                        "path": f"{bp}{path}",
                        "status": r.status_code,
                    })
                return (r.status_code, data, bp)
        except Exception:
            if debug:
                debug.add({
                    "type": "error",
                    "source": "wazuh",
                    "path": f"{bp}{path}",
                    "error": "request failed",
                })
            continue
    return (404, None, None)


def wazuh_get_alert(alert_id: str, debug: Optional[DebugTrace] = None) -> Optional[Dict[str, Any]]:
    """
    Retrieve a Wazuh event by its event.id. Tries multiple compatible endpoints:
    1) /security/events?event_ids={id}
    2) /alerts/{id} (older installs)
    3) /alerts?q=event.id:"{id}" (fallback search)
    Returns a best-effort flattened event dict (with 'agent' if possible).
    """
    if not settings.WAZUH_API_URL:
        return None
    try:
        # Preferred: indexer-backed endpoint
        sc1, data1, bp1 = _try_get("/security/events", params={"event_ids": alert_id}, debug=debug)
        if sc1 and sc1 < 400 and data1:
            ev = _extract_event(data1)
            if ev:
                logger.debug("wazuh_get_alert: matched via %s/security/events", (settings.WAZUH_API_URL.rstrip('/') + (bp1 or '')))
                return ev
        # Legacy direct alert path
        sc2, data2, bp2 = _try_get(f"/alerts/{alert_id}", debug=debug)
        if sc2 and sc2 < 400 and data2:
            ev2 = _extract_event(data2) or data2
            logger.debug("wazuh_get_alert: matched via %s/alerts/{id}", (settings.WAZUH_API_URL.rstrip('/') + (bp2 or '')))
            return ev2
        # Fallback: search by query (Elasticsearch DSL-like)
        sc3, data3, bp3 = _try_get("/alerts", params={"q": f"event.id:\"{alert_id}\""}, debug=debug)
        if sc3 and sc3 < 400 and data3:
            ev3 = _extract_event(data3) or data3
            logger.debug("wazuh_get_alert: matched via %s/alerts?q=...", (settings.WAZUH_API_URL.rstrip('/') + (bp3 or '')))
            return ev3
    except Exception:
        pass
    return None


def wazuh_get_agent(agent_id: str) -> Optional[Dict[str, Any]]:
    if not settings.WAZUH_API_URL or not settings.WAZUH_API_TOKEN:
        return None
    try:
        url = f"{settings.WAZUH_API_URL.rstrip('/')}/agents/{agent_id}"
        r = requests.get(url, headers=_headers(), verify=settings.WAZUH_VERIFY_SSL, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def _build_time_query(time_range: Optional[str]) -> Optional[str]:
    """Return a Lucene-like time filter usable across Wazuh indexer endpoints.
    Examples accepted: 'last_24h', '24h', 'now-2d', 'last_7d'. Returns an
    expression that tries both '@timestamp' and 'timestamp'. If time_range is
    falsy, returns None (API defaults apply).
    """
    if not time_range:
        return None
    tr = (time_range or '').lower().strip()
    # Normalize common aliases
    if tr.startswith('last_'):
        tr = tr.replace('last_', 'now-')
    if tr.isdigit():
        tr = f"now-{tr}h"
    if tr.endswith('h') or tr.endswith('d') or tr.endswith('m'):
        # looks like now-24h or 24h; ensure it has now-
        if re.match(r"^\d+[hdm]$", tr):
            tr = f"now-{tr}"
    # final guardrail
    if not tr.startswith('now-'):
        tr = f"now-24h"
    # Range syntax compatible with Lucene style
    return f"(@timestamp:[{tr} TO now] OR timestamp:[{tr} TO now])"


def _to_indexer_gte(time_range: Optional[str]) -> str:
    """Convert internal time_range strings (e.g., 'last_24h', '24h') to indexer 'now-24h' form.
    Falls back to 'now-24h' when unknown.
    """
    if not time_range:
        return "now-24h"
    tr = (time_range or '').lower().strip()
    if tr.startswith('last_'):
        tr = tr.replace('last_', '')
    if tr.startswith('now-'):
        return tr
    # If numeric unit like 24h / 2d / 30m
    if re.match(r"^\d+[hdm]$", tr):
        return f"now-{tr}"
    # If absolute or unrecognized, default 24h
    return "now-24h"


def _post_indexer_search(query_string: str, gte: str, limit: int, debug: Optional[DebugTrace], lte: str = "now", auth: Optional[Tuple[str, str]] = None) -> List[Dict[str, Any]]:
    global _last_query_failure_status
    # Require Indexer URL; add debug error and raise if missing (do not silently return empty)
    base_url = (settings.wazuh_indexer_url or "").rstrip('/') if settings.wazuh_indexer_url else None
    index_patterns = getattr(settings, 'wazuh_index_patterns', None) or settings.WAZUH_INDEX_PATTERNS
    url = f"{(settings.wazuh_indexer_url or '').rstrip('/')}/{index_patterns}/_search" if settings.wazuh_indexer_url else None
    if not base_url:
        if debug:
            debug.add({
                "type": "error",
                "source": "wazuh",
                "error": "WAZUH_INDEXER_URL not configured. Set it in .env to enable Wazuh index searches.",
                "url": url,
            })
        raise ValueError("WAZUH_INDEXER_URL not configured. Set it in .env to enable Wazuh index searches.")
    # Log explicitly which Indexer URL we are using (not the Manager API)
    logger.info("Using Wazuh Indexer URL: %s", settings.wazuh_indexer_url)
    body = {
        "size": int(limit),
        "sort": [{"@timestamp": "desc"}],
        "query": {
            "bool": {
                "must": [
                    {"query_string": {"query": query_string or "*"}},
                    {"range": {"@timestamp": {"gte": gte, "lte": lte}}},
                ]
            }
        },
    }
    # For Indexer (OpenSearch), do not use Manager's Bearer token header
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if debug:
        debug.add({
            "type": "request",
            "source": "wazuh",
            "index_patterns": index_patterns,
            "url": url,
            "query_preview": query_string,
            "gte": gte,
            "limit": limit,
            "lte": lte,
        })
    # Prepare a request signature to avoid repeating known-failing calls within a run
    try:
        req_sig = f"{url}|{str(body)[:1000]}"
    except Exception:
        req_sig = url or ""
    if req_sig in _failed_request_signatures:
        if debug:
            pu2 = urlparse(url or "")
            debug.add({
                "type": "error",
                "source": "wazuh",
                "url": url,
                "scheme": pu2.scheme,
                "host": pu2.hostname,
                "port": pu2.port,
                "error": "skipping duplicate request after prior 401",
                "query_failed": True,
                "status_code": 401,
            })
        return []
    try:
        r = requests.post(
            url,
            headers=headers,
            json=body,
            verify=settings.WAZUH_VERIFY_SSL,
            timeout=15,
            auth=auth,
        )
        r.raise_for_status()
        j = r.json()
        took = j.get("took")
        hits_obj = (j.get("hits") or {})
        total_val = None
        try:
            total_field = hits_obj.get("total")
            if isinstance(total_field, dict):
                total_val = int(total_field.get("value"))
            elif isinstance(total_field, int):
                total_val = total_field
        except Exception:
            total_val = None
        hits_list = hits_obj.get("hits") or []
        rows: List[Dict[str, Any]] = []
        for h in hits_list:
            if isinstance(h, dict) and "_source" in h:
                rows.append(h.get("_source"))
            else:
                rows.append(h)
        if debug:
            debug.add({
                "type": "response",
                "source": "wazuh",
                "url": url,
                "status_code": r.status_code,
                "took_ms": took,
                "result_count": len(rows),
                "capped": (total_val is not None and total_val > int(limit)),
            })
        return rows[:limit]
    except requests.exceptions.HTTPError as e:
        status = getattr(e.response, 'status_code', None)
        text = None
        try:
            text = e.response.text
        except Exception:
            text = None
        # Parse URL for diagnostics
        try:
            pu = urlparse(url or "")
            scheme, host, port = pu.scheme, pu.hostname, pu.port
        except Exception:
            scheme = host = None
            port = None
        if debug:
            debug.add({
                "type": "error",
                "source": "wazuh",
                "url": url,
                "status_code": status,
                "error": str(e),
                "response_text": text[:500] if isinstance(text, str) else None,
                "scheme": scheme,
                "host": host,
                "port": port,
                "exception_type": type(e).__name__,
                "query_failed": True,
            })
        # Record last failure and avoid re-trying same request on 401
        _last_query_failure_status = status
        try:
            if status == 401 and req_sig:
                _failed_request_signatures.add(req_sig)
        except Exception:
            pass
        return []
    except requests.exceptions.RequestException as e:
        try:
            pu = urlparse(url or "")
            scheme, host, port = pu.scheme, pu.hostname, pu.port
        except Exception:
            scheme = host = None
            port = None
        if debug:
            debug.add({
                "type": "error",
                "source": "wazuh",
                "url": url,
                "error": str(e),
                "scheme": scheme,
                "host": host,
                "port": port,
                "exception_type": type(e).__name__,
                "query_failed": True,
            })
        _last_query_failure_status = None
        return []


def wazuh_search(query: str, limit: int = 50, time_range: Optional[str] = None,
                 index_patterns: Optional[str] = None, debug: Optional[DebugTrace] = None) -> List[Dict[str, Any]]:
    """Search Wazuh indexer directly using Elasticsearch DSL with query_string and time range.
    Uses settings.WAZUH_INDEX_PATTERNS exactly as-is.
    """
    gte = _to_indexer_gte(time_range)
    # If query includes a prebuilt Lucene string (from upstream), wrap as-is into query_string
    qs = (query or "*").strip()
    # Build basic auth from preferred settings; enforce presence
    user = getattr(settings, 'wazuh_indexer_username', None) or getattr(settings, 'WAZUH_INDEXER_USER', None)
    pwd = getattr(settings, 'wazuh_indexer_password', None) or getattr(settings, 'WAZUH_INDEXER_PASS', None)
    if not user or not pwd:
        if debug:
            debug.add({
                "type": "error",
                "source": "wazuh",
                "error": "Missing Wazuh Indexer credentials",
                "query_failed": True,
            })
        return []
    return _post_indexer_search(qs, gte, limit, debug, auth=(user, pwd))


def wazuh_raw_search(keywords: List[str], gte: str, lte: str = "now", limit: int = 200, debug: Optional[DebugTrace] = None) -> List[Dict[str, Any]]:
    """Direct indexer _search for raw keyword hunts with wildcard substring matching.

    - Transforms each keyword k -> *k* (escaped for query_string)
    - Searches structured HTTP fields and raw text fallbacks:
        data.http.http_user_agent, data.http.url, data.http.hostname, data.http.http_method,
        full_log, message
    - Final query shape: (field1:*k* OR field2:*k* ...) over all provided keywords (any match)
    - Applies @timestamp range gte .. lte
    - Uses settings.WAZUH_INDEX_PATTERNS exactly as configured
    - Returns list of event _source dicts
    """
    kws = [str(k) for k in (keywords or []) if str(k).strip()]

    def _escape_qs(tok: str) -> str:
        # Escape Lucene query_string special chars, keep '*' we'll add deliberately
        # + - = && || > < ! ( ) { } [ ] ^ " ~ ? : \\ /
        s = str(tok)
        specials = r"[+\-=!(){}\[\]^\"~?:\\/<>]"
        return re.sub(specials, lambda m: f"\\{m.group(0)}", s)

    wildcards = [f"*{_escape_qs(w)}*" for w in kws]
    fields = [
        "data.http.http_user_agent",
        "data.http.url",
        "data.http.hostname",
        "data.http.http_method",
        # raw fallbacks
        "full_log",
        "message",
    ]
    field_terms: List[str] = []
    for f in fields:
        for wc in wildcards:
            field_terms.append(f"{f}:{wc}")
    qs = "(" + " OR ".join(field_terms) + ")" if field_terms else "*"

    if debug:
        try:
            debug.add({
                "type": "build",
                "source": "wazuh",
                "original_keywords": kws,
                "wildcard_keywords": wildcards,
                "query_preview": qs[:500],
                "gte": gte,
                "lte": lte,
                "limit": limit,
            })
        except Exception:
            pass
    # Build basic auth from preferred settings; allow fallback to legacy vars
    user = (
        getattr(settings, 'wazuh_indexer_username', None)
        or getattr(settings, 'WAZUH_INDEXER_USER', None)
    )
    pwd = (
        getattr(settings, 'wazuh_indexer_password', None)
        or getattr(settings, 'WAZUH_INDEXER_PASS', None)
    )
    if not user or not pwd:
        if debug:
            debug.add({
                "type": "error",
                "source": "wazuh",
                "error": "Missing Wazuh Indexer credentials",
                "query_failed": True,
            })
        return []
    return _post_indexer_search(qs, gte, limit, debug, lte=lte, auth=(user, pwd))


def get_last_query_failure_status() -> Optional[int]:
    return _last_query_failure_status


def reset_query_failure_state() -> None:
    try:
        _failed_request_signatures.clear()
    except Exception:
        pass
    global _last_query_failure_status
    _last_query_failure_status = None


def wazuh_indexer_healthcheck() -> Dict[str, Any]:
    """Probe the Wazuh Indexer (OpenSearch) for connectivity and basic health.
    Returns a dict: {ok, status_code, error, reachable, url}
    """
    base_url = (settings.wazuh_indexer_url or "").rstrip('/') if settings.wazuh_indexer_url else None
    if not base_url:
        return {"ok": False, "reachable": False, "status_code": None, "error": "WAZUH_INDEXER_URL not configured", "url": None}

    # Auth: use preferred username/password, fallback to legacy
    user = getattr(settings, 'wazuh_indexer_username', None) or getattr(settings, 'WAZUH_INDEXER_USER', None)
    pwd = getattr(settings, 'wazuh_indexer_password', None) or getattr(settings, 'WAZUH_INDEXER_PASS', None)
    auth = (user, pwd) if (user and pwd) else None

    headers = {"Accept": "application/json"}
    urls = [f"{base_url}/_cluster/health", f"{base_url}/"]
    last_err: Optional[str] = None
    for u in urls:
        try:
            r = requests.get(u, headers=headers, auth=auth, verify=settings.WAZUH_VERIFY_SSL, timeout=5)
            reachable = True
            ok = 200 <= r.status_code < 300
            if ok:
                return {"ok": True, "reachable": True, "status_code": r.status_code, "error": None, "url": u}
            else:
                # Not OK but reachable (e.g., 401/403)
                return {"ok": False, "reachable": True, "status_code": r.status_code, "error": r.text[:300] if isinstance(r.text, str) else str(r.status_code), "url": u}
        except requests.exceptions.RequestException as e:
            last_err = str(e)
            continue
    return {"ok": False, "reachable": False, "status_code": None, "error": last_err, "url": urls[0]}


def wazuh_search_field(field_name: str, field_value: str, limit: int = 200,
                       time_range: Optional[str] = None, debug: Optional[DebugTrace] = None) -> List[Dict[str, Any]]:
    """Field-agnostic search across Wazuh indices.
    - Does NOT assume a single index or specific field layout
    - Dynamically builds a safe query using the provided field and value
    - Adds a portable time filter using _build_time_query
    - Supports wildcard or exact matching based on the 'field_value' content

    We intentionally avoid validating the field against a fixed schema so the
    search is future-proof to new fields (e.g., rule.id, agent.name, src.ip).
    """
    if not field_name or not field_value:
        return []
    # Escape double quotes inside value
    value = str(field_value).replace('"', '\\"').strip()
    # If user provided wildcard(s), keep them; otherwise do exact match via quotes
    if any(ch in value for ch in ['*', '?']):
        q = f"{field_name}:{value}"
    else:
        q = f"{field_name}:\"{value}\""
    return wazuh_search(q, limit=limit, time_range=time_range or settings.WAZUH_DEFAULT_TIME_RANGE,
                        index_patterns=settings.WAZUH_INDEX_PATTERNS, debug=debug)


# Optional: simple sanity helper for debugging connector correctness
def sanity_test_sqlmap_last24h(limit: int = 10) -> Dict[str, Any]:
    """Run a quick search for 'sqlmap' in last 24h across the configured Wazuh indices.
    Returns a small dict with count and first few samples for manual verification.
    """
    try:
        evs = wazuh_search("sqlmap", limit=limit, time_range="last_24h")
        return {"count": len(evs), "samples": evs[: min(3, len(evs))]}
    except Exception as e:
        return {"count": 0, "error": str(e)}


def extract_indicators_from_events(events: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Best-effort IOC extraction from arbitrary Wazuh events without assuming schema.
    - Scans nested dicts for keys related to IPs, ports, hashes, and usernames
    - Falls back to regex search over the JSON string as a catch-all
    """
    ips: Set[str] = set()
    ports: Set[str] = set()
    hashes: Set[str] = set()
    users: Set[str] = set()

    def _walk(obj: Any, path: str = ""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                lk = k.lower()
                p = f"{path}.{lk}" if path else lk
                # Heuristics for keys
                if lk.endswith('ip') or '.ip' in lk or lk in {'srcip', 'dstip', 'client_ip', 'server_ip'}:
                    if isinstance(v, str):
                        ips.add(v)
                if lk.endswith('port') or 'srcport' in lk or 'dstport' in lk:
                    if isinstance(v, (int, str)):
                        ports.add(str(v))
                if 'hash' in lk or lk in {'md5', 'sha1', 'sha256'}:
                    if isinstance(v, str):
                        hashes.add(v)
                if 'user' in lk or 'username' in lk or 'account' in lk:
                    if isinstance(v, str):
                        users.add(v)
                _walk(v, p)
        elif isinstance(obj, list):
            for i, it in enumerate(obj):
                _walk(it, f"{path}[{i}]")

    for ev in events:
        _walk(ev)
        # Regex fallback on flattened string
        try:
            s = str(ev)
        except Exception:
            s = ''
        for m in re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", s):
            ips.add(m)
        for m in re.findall(r"\b[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}\b", s):
            hashes.add(m)
        for m in re.findall(r"\b(?:src|dst)?port\s*[:=]\s*(\d{1,5})\b", s, flags=re.I):
            ports.add(m)

    return {
        "ips": sorted(ips),
        "ports": sorted(ports),
        "hashes": sorted(hashes),
        "usernames": sorted(users),
    }
