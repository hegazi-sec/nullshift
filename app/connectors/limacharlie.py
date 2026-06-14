"""LimaCharlie SecOps Cloud connector.

Authenticates via short-lived JWT obtained from app.limacharlie.io/jwt and
queries the Insight detection store at api.limacharlie.io. JWTs live ~30 min
and are cached + refreshed lazily on 401 responses.

Detections are LC's alert primitive — outputs of D&R rules carrying enough
context (routing, src/dst IPs, rule category, sensor) for L1 triage. The
Detection store is used as the canonical source. For each query we pull
detections in the requested time window and filter client-side for IP /
rule / keyword matches — matches the pattern used by the Sentinel/Elastic
connectors when server-side filtering doesn't cover every common case.

Configuration (.env):
    LIMACHARLIE_OID         - Org ID (UUID-shaped)
    LIMACHARLIE_API_KEY     - Secret API key with read access to detections
    LIMACHARLIE_API_BASE    - Override default https://api.limacharlie.io
    LIMACHARLIE_AUTH_BASE   - Override default https://app.limacharlie.io
"""
from __future__ import annotations

import base64
import json
import logging
import re
import time
import zlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

from app.config import settings
from .base import NormalizedAlert, SIEMConnector

logger = logging.getLogger("nullshift.limacharlie")

_DEFAULT_AUTH_BASE = "https://app.limacharlie.io"
_DEFAULT_API_BASE = "https://api.limacharlie.io"
_JWT_LIFETIME_S = 30 * 60      # LC JWTs are typically valid for ~30 minutes
_JWT_REFRESH_BUFFER_S = 60     # refresh JWT 60s before it expires
_REQUEST_TIMEOUT_S = 30


_RELATIVE_RE = re.compile(r"^(?:now-|last_)(\d+)([smhdw])$", re.IGNORECASE)
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def _to_epoch_s(value: str) -> int:
    """Convert a time spec to Unix epoch seconds (the unit LC's REST API expects).

    Accepts:
    - `"now"`
    - `"now-<N><unit>"` (Wazuh / OpenSearch style, e.g. `"now-24h"`)
    - `"last_<N><unit>"` (NullShift's internal label, e.g. `"last_24h"`)
    - ISO 8601 strings (with `Z` or `+00:00`; naive treated as UTC)
    """
    if not value:
        return int(time.time())
    s = value.strip()
    if s.lower() == "now":
        return int(time.time())
    rel = _RELATIVE_RE.match(s)
    if rel:
        n = int(rel.group(1))
        unit = rel.group(2).lower()
        return int(time.time() - n * _UNIT_SECONDS[unit])
    iso = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        return int(time.time())
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def _unwrap_compressed(payload: str) -> Any:
    """Decode LC's base64+gzip+json wrapper used when is_compressed=true."""
    return json.loads(zlib.decompress(base64.b64decode(payload), 16 + zlib.MAX_WBITS).decode("utf-8"))


class LimaCharlieConnector(SIEMConnector):
    """LimaCharlie REST connector against the Insight detection endpoint."""

    def __init__(self) -> None:
        self.oid = (settings.LIMACHARLIE_OID or "").strip()
        self.api_key = (settings.LIMACHARLIE_API_KEY or "").strip()
        self.api_base = (settings.LIMACHARLIE_API_BASE or _DEFAULT_API_BASE).rstrip("/")
        self.auth_base = (settings.LIMACHARLIE_AUTH_BASE or _DEFAULT_AUTH_BASE).rstrip("/")
        self._session = requests.Session()
        self._jwt: Optional[str] = None
        self._jwt_expires_at: float = 0.0

    # ------------------------------------------------------------------
    # SIEMConnector interface
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        return bool(self.oid and self.api_key)

    def search(self, query: str, gte: str, lte: str = "now", limit: int = 200) -> List[Dict[str, Any]]:
        """Free-form: pull detections in window, optional substring filter on JSON blob."""
        rows = self._fetch_detections(gte, lte, limit=limit)
        if query:
            q = query.lower()
            rows = [r for r in rows if q in json.dumps(r, default=str).lower()]
        return rows[:limit]

    def search_by_ip(self, ip: str, gte: str, lte: str, limit: int = 200) -> List[NormalizedAlert]:
        # Over-fetch so client-side filtering still has enough material to return `limit`
        rows = self._fetch_detections(gte, lte, limit=min(limit * 2, 1000))
        hits = [r for r in rows if self._row_mentions_ip(r, ip)]
        return [self.normalize(r) for r in hits[:limit]]

    def search_by_rule(self, rule_id: str, gte: str, lte: str, limit: int = 200) -> List[NormalizedAlert]:
        rows = self._fetch_detections(gte, lte, limit=min(limit * 2, 1000))
        target = rule_id.lower()
        hits = [r for r in rows if self._row_rule_matches(r, target)]
        return [self.normalize(r) for r in hits[:limit]]

    def recent_alerts(self, gte: str, lte: str, limit: int = 200) -> List[NormalizedAlert]:
        rows = self._fetch_detections(gte, lte, limit=limit)
        return [self.normalize(r) for r in rows]

    def keyword_search(self, keywords: List[str], gte: str, lte: str, limit: int = 200) -> List[NormalizedAlert]:
        kws = [k.lower() for k in keywords if k and k.strip()]
        if not kws:
            return self.recent_alerts(gte, lte, limit)
        rows = self._fetch_detections(gte, lte, limit=min(limit * 2, 1000))
        hits: List[Dict[str, Any]] = []
        for r in rows:
            blob = json.dumps(r, default=str).lower()
            if any(k in blob for k in kws):
                hits.append(r)
        return [self.normalize(r) for r in hits[:limit]]

    def normalize(self, raw: Dict[str, Any]) -> NormalizedAlert:
        detect = raw.get("detect") if isinstance(raw.get("detect"), dict) else {}
        routing = raw.get("routing") if isinstance(raw.get("routing"), dict) else {}

        ts_raw = raw.get("ts") or routing.get("event_time")
        ts_iso = ""
        if isinstance(ts_raw, (int, float)) and ts_raw > 0:
            # LC's detection endpoint returns ms; older Insight endpoints used
            # us. Detect by magnitude rather than hardcoding so both work.
            if ts_raw > 1e16:        # nanoseconds
                ts_s = ts_raw / 1e9
            elif ts_raw > 1e14:      # microseconds
                ts_s = ts_raw / 1e6
            elif ts_raw > 1e11:      # milliseconds
                ts_s = ts_raw / 1e3
            else:                    # seconds
                ts_s = float(ts_raw)
            try:
                ts_iso = datetime.fromtimestamp(ts_s, tz=timezone.utc).isoformat()
            except (OSError, OverflowError, ValueError):
                ts_iso = ""

        rule_name = raw.get("cat") or detect.get("cat") or routing.get("cat") or ""
        sev = self._normalize_severity(detect.get("priority") or detect.get("severity"))

        src_ip = self._extract_first(raw, ("src_ip", "source_ip", "SourceAddress", "NETWORK_ADDRESS"))
        dst_ip = self._extract_first(raw, ("dst_ip", "destination_ip", "DestinationAddress"))

        return NormalizedAlert(
            id=str(raw.get("id") or routing.get("event_id") or raw.get("event_id") or ""),
            timestamp=ts_iso,
            severity=sev,
            rule_id=str(rule_name) if rule_name else None,
            rule_name=str(rule_name) if rule_name else "limacharlie-detection",
            src_ip=src_ip,
            dst_ip=dst_ip,
            agent=routing.get("hostname") or routing.get("sid"),
            message=(detect.get("message") if isinstance(detect.get("message"), str) else "") or json.dumps(detect, default=str)[:300],
            raw=raw,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_jwt(self) -> Optional[str]:
        """Return a valid JWT, refreshing if missing or near expiry."""
        if not self.is_available():
            return None
        now = time.time()
        if self._jwt and now < self._jwt_expires_at - _JWT_REFRESH_BUFFER_S:
            return self._jwt
        try:
            resp = self._session.post(
                f"{self.auth_base}/jwt",
                params={"oid": self.oid, "secret": self.api_key},
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            logger.error("LimaCharlie JWT refresh failed: %s", exc)
            return None
        jwt = data.get("jwt") if isinstance(data, dict) else None
        if not jwt:
            logger.error("LimaCharlie /jwt returned no token: %s", str(data)[:200])
            return None
        self._jwt = jwt
        self._jwt_expires_at = now + _JWT_LIFETIME_S
        return jwt

    def _request(self, method: str, path: str, **kwargs) -> Optional[requests.Response]:
        """Authenticated request with one retry on 401 (forces JWT refresh)."""
        jwt = self._ensure_jwt()
        if not jwt:
            return None
        headers = kwargs.pop("headers", {}) or {}
        headers["Authorization"] = f"Bearer {jwt}"
        url = f"{self.api_base}{path}"
        try:
            resp = self._session.request(method, url, headers=headers, timeout=_REQUEST_TIMEOUT_S, **kwargs)
        except Exception as exc:
            logger.error("LimaCharlie %s %s failed: %s", method, path, exc)
            return None

        if resp.status_code == 401:
            logger.info("LimaCharlie 401, forcing JWT refresh and retrying once")
            self._jwt = None
            self._jwt_expires_at = 0.0
            jwt2 = self._ensure_jwt()
            if not jwt2:
                return None
            headers["Authorization"] = f"Bearer {jwt2}"
            try:
                resp = self._session.request(method, url, headers=headers, timeout=_REQUEST_TIMEOUT_S, **kwargs)
            except Exception as exc:
                logger.error("LimaCharlie %s %s retry failed: %s", method, path, exc)
                return None
        return resp

    def _fetch_detections(self, gte: str, lte: str, limit: int = 200) -> List[Dict[str, Any]]:
        """GET /v1/insight/{oid}/detections in [gte, lte], capped at `limit`.

        LC's API expects start/end as Unix SECONDS and returns the detects
        field as a base64+gzip-encoded JSON string when is_compressed=true
        (which we always send to match the official Python SDK's behavior).
        Older versions of this connector were wrong on both points and
        always returned [].
        """
        if not self.is_available():
            return []
        start_s = _to_epoch_s(gte)
        end_s = _to_epoch_s(lte)
        resp = self._request(
            "GET",
            f"/v1/insight/{self.oid}/detections",
            params={
                "start": start_s,
                "end": end_s,
                "limit": min(limit, 1000),
                "is_compressed": "true",
            },
        )
        if resp is None:
            raise RuntimeError("LimaCharlie: request failed (auth or network error)")
        if resp.status_code >= 400:
            raise RuntimeError(
                f"LimaCharlie API returned {resp.status_code}: {resp.text[:200]}"
            )
        try:
            data = resp.json()
        except Exception:
            return []
        detects_raw: Any = None
        if isinstance(data, dict):
            detects_raw = data.get("detects") if data.get("detects") is not None else data.get("detections")
        elif isinstance(data, list):
            return data[:limit]
        if isinstance(detects_raw, str) and detects_raw:
            try:
                parsed = _unwrap_compressed(detects_raw)
            except Exception as e:
                logger.warning("LimaCharlie compressed payload unwrap failed: %s", e)
                return []
            return parsed[:limit] if isinstance(parsed, list) else []
        if isinstance(detects_raw, list):
            return detects_raw[:limit]
        return []

    # ------------------------------------------------------------------
    # Tiny static helpers (no I/O, safe to unit-test directly)
    # ------------------------------------------------------------------

    @staticmethod
    def _row_mentions_ip(row: Dict[str, Any], ip: str) -> bool:
        """Cheap substring check against the JSON blob — LC detection events
        embed IPs under many keys depending on the source event type."""
        try:
            return ip in json.dumps(row, default=str)
        except Exception:
            return False

    @staticmethod
    def _row_rule_matches(row: Dict[str, Any], target_lower: str) -> bool:
        candidates = [
            row.get("cat"),
            (row.get("detect") or {}).get("cat") if isinstance(row.get("detect"), dict) else None,
            (row.get("detect") or {}).get("rule_name") if isinstance(row.get("detect"), dict) else None,
            (row.get("routing") or {}).get("cat") if isinstance(row.get("routing"), dict) else None,
        ]
        for c in candidates:
            if c and target_lower in str(c).lower():
                return True
        return False

    @staticmethod
    def _normalize_severity(raw: Any) -> str:
        """Map LC priority (int 1-10) or string severity to base.NormalizedAlert vocab."""
        if isinstance(raw, (int, float)):
            v = int(raw)
            if v >= 8:
                return "critical"
            if v >= 5:
                return "high"
            if v >= 3:
                return "medium"
            return "low"
        s = str(raw or "").lower()
        if s in ("critical", "crit"):
            return "critical"
        if s in ("high", "warn", "warning"):
            return "high"
        if s in ("medium", "med"):
            return "medium"
        if s in ("low", "info", "informational"):
            return "low"
        return "medium"

    @staticmethod
    def _extract_first(row: Dict[str, Any], keys: Tuple[str, ...]) -> Optional[str]:
        """Walk a couple of nesting levels looking for the first string under any of `keys`."""
        if not isinstance(row, dict):
            return None
        candidates: List[Dict[str, Any]] = [row]
        for nested in ("routing", "detect", "event"):
            v = row.get(nested)
            if isinstance(v, dict):
                candidates.append(v)
        for d in candidates:
            for k in keys:
                v = d.get(k)
                if isinstance(v, str) and v:
                    return v
        return None
