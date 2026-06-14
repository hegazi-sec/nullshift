import logging
import re
from typing import Any, Dict, List, Optional

import requests
from requests.auth import HTTPBasicAuth

from app.config import settings
from .base import NormalizedAlert, SIEMConnector

logger = logging.getLogger("nullshift.splunk")

_SEV_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "informational": "low"}


class SplunkConnector(SIEMConnector):
    """Splunk Enterprise / Cloud REST connector (port 8089).

    Auth priority: token (Bearer) > username/password (Basic).
    Uses the oneshot search endpoint so each query is synchronous — suitable
    for queries that complete in <60s, which covers all SOC triage use cases.
    """

    def __init__(self):
        self.base_url = (settings.SPLUNK_URL or "").rstrip("/")
        self.token = settings.SPLUNK_TOKEN
        self.username = settings.SPLUNK_USER
        self.password = settings.SPLUNK_PASS
        self.index = settings.SPLUNK_INDEX or "*"
        self.verify_ssl = settings.SPLUNK_VERIFY_SSL
        self._session = requests.Session()
        if self.token:
            self._session.headers["Authorization"] = f"Bearer {self.token}"
        elif self.username and self.password:
            self._session.auth = HTTPBasicAuth(self.username, self.password)

    def is_available(self) -> bool:
        return bool(self.base_url and (self.token or (self.username and self.password)))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _dt_to_splunk(self, iso: str) -> str:
        """Convert ISO 8601 datetime string to Splunk's YYYY-MM-DDTHH:MM:SS format."""
        # Strip timezone suffix for Splunk absolute time tokens
        return iso.replace("Z", "").replace("+00:00", "").split(".")[0]

    def _run_spl(self, spl: str, limit: int = 200) -> List[Dict[str, Any]]:
        """Submit a SPL query via the oneshot endpoint and return raw result dicts."""
        if not self.is_available():
            return []
        try:
            resp = self._session.post(
                f"{self.base_url}/services/search/jobs/oneshot",
                data={
                    "search": f"search {spl}",
                    "output_mode": "json",
                    "count": min(limit, 200),
                },
                verify=self.verify_ssl,
                timeout=45,
            )
            resp.raise_for_status()
            return resp.json().get("results", [])
        except Exception as exc:
            logger.error("Splunk query failed: %s", exc)
            return []

    def _time_bounds(self, gte: str, lte: str) -> str:
        """Return SPL time clause: earliest=... latest=..."""
        e = self._dt_to_splunk(gte)
        l = self._dt_to_splunk(lte)
        return f'earliest="{e}" latest="{l}"'

    # ------------------------------------------------------------------
    # SIEMConnector interface
    # ------------------------------------------------------------------

    def search(self, query: str, gte: str, lte: str = "now", limit: int = 200) -> List[Dict[str, Any]]:
        spl = f"index={self.index} {query} {self._time_bounds(gte, lte)} | head {limit}"
        return self._run_spl(spl, limit)

    def search_by_ip(self, ip: str, gte: str, lte: str, limit: int = 200) -> List[NormalizedAlert]:
        spl = (
            f'index={self.index} '
            f'(src_ip="{ip}" OR dest_ip="{ip}" OR src="{ip}" OR dest="{ip}" '
            f'OR SourceIP="{ip}" OR DestinationIP="{ip}" OR clientip="{ip}") '
            f'{self._time_bounds(gte, lte)} | head {limit}'
        )
        return [self.normalize(e) for e in self._run_spl(spl, limit)]

    def search_by_rule(self, rule_id: str, gte: str, lte: str, limit: int = 200) -> List[NormalizedAlert]:
        safe = re.sub(r'["\']', "", rule_id)
        spl = (
            f'index={self.index} '
            f'(rule_name="{safe}" OR signature="{safe}" OR EventCode="{safe}" '
            f'OR alert_type="{safe}" OR Type="{safe}") '
            f'{self._time_bounds(gte, lte)} | head {limit}'
        )
        return [self.normalize(e) for e in self._run_spl(spl, limit)]

    def recent_alerts(self, gte: str, lte: str, limit: int = 200) -> List[NormalizedAlert]:
        spl = f"index={self.index} {self._time_bounds(gte, lte)} | sort -_time | head {limit}"
        return [self.normalize(e) for e in self._run_spl(spl, limit)]

    def keyword_search(self, keywords: List[str], gte: str, lte: str, limit: int = 200) -> List[NormalizedAlert]:
        terms = [f'"{re.sub(chr(34), "", k)}"' for k in keywords if k.strip()]
        if not terms:
            return self.recent_alerts(gte, lte, limit)
        kw_clause = " OR ".join(terms)
        spl = f"index={self.index} ({kw_clause}) {self._time_bounds(gte, lte)} | head {limit}"
        return [self.normalize(e) for e in self._run_spl(spl, limit)]

    def normalize(self, raw: Dict[str, Any]) -> NormalizedAlert:
        raw_sev = str(raw.get("severity") or raw.get("urgency") or "medium").lower()
        return NormalizedAlert(
            id=raw.get("_cd") or raw.get("event_hash") or "",
            timestamp=raw.get("_time") or "",
            severity=_SEV_MAP.get(raw_sev, "medium"),
            rule_id=raw.get("rule_id") or raw.get("EventCode"),
            rule_name=raw.get("rule_name") or raw.get("signature") or raw.get("Type") or (raw.get("_raw") or "")[:80],
            src_ip=raw.get("src_ip") or raw.get("src") or raw.get("SourceIP") or raw.get("clientip"),
            dst_ip=raw.get("dest_ip") or raw.get("dest") or raw.get("DestinationIP"),
            agent=raw.get("host") or raw.get("hostname") or raw.get("ComputerName"),
            message=raw.get("_raw") or "",
            raw=raw,
        )
