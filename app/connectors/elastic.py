import logging
from typing import Any, Dict, List, Optional

import requests

from app.config import settings
from .base import NormalizedAlert, SIEMConnector

logger = logging.getLogger("nullshift.elastic")

_SEV_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "informational": "low"}

# ECS numeric severity (1-100 scale used by Elastic Security alerts)
_NUMERIC_SEV = {range(1, 25): "low", range(25, 50): "medium", range(50, 75): "high", range(75, 101): "critical"}


def _numeric_to_sev(val: int) -> str:
    for rng, label in _NUMERIC_SEV.items():
        if val in rng:
            return label
    return "medium"


class ElasticConnector(SIEMConnector):
    """Elasticsearch / Elastic SIEM connector using the standard REST API.

    Supports both Elastic Security alerts (.alerts-security.alerts-*) and
    raw log indices. Uses ECS field names (source.ip, destination.ip, rule.name…).

    Auth priority: API key > username/password (Basic).
    """

    def __init__(self):
        self.base_url = (settings.ELASTIC_URL or "").rstrip("/")
        self.username = settings.ELASTIC_USERNAME
        self.password = settings.ELASTIC_PASSWORD
        self.api_key = settings.ELASTIC_API_KEY
        self.index = settings.ELASTIC_INDEX or "logs-*,.alerts-security.alerts-*"
        self.verify_ssl = settings.ELASTIC_VERIFY_SSL

    def is_available(self) -> bool:
        return bool(self.base_url and (self.api_key or (self.username and self.password)))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _headers(self) -> Dict[str, str]:
        h: Dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"ApiKey {self.api_key}"
        return h

    def _req_kwargs(self) -> Dict[str, Any]:
        kwargs: Dict[str, Any] = {"verify": self.verify_ssl, "timeout": 30}
        if not self.api_key and self.username:
            kwargs["auth"] = (self.username, self.password)
        return kwargs

    def _time_filter(self, gte: str, lte: str) -> Dict[str, Any]:
        return {"range": {"@timestamp": {"gte": gte, "lte": lte}}}

    def _run_query(self, body: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not self.is_available():
            return []
        try:
            resp = requests.post(
                f"{self.base_url}/{self.index}/_search",
                headers=self._headers(),
                json=body,
                **self._req_kwargs(),
            )
            resp.raise_for_status()
            return [h["_source"] for h in resp.json()["hits"]["hits"]]
        except Exception as exc:
            logger.error("Elasticsearch query failed: %s", exc)
            return []

    # ------------------------------------------------------------------
    # SIEMConnector interface
    # ------------------------------------------------------------------

    def search(self, query: str, gte: str, lte: str = "now", limit: int = 200) -> List[Dict[str, Any]]:
        body = {
            "query": {
                "bool": {
                    "must": [{"query_string": {"query": query, "allow_leading_wildcard": True}}],
                    "filter": [self._time_filter(gte, lte)],
                }
            },
            "size": min(limit, 200),
            "sort": [{"@timestamp": "desc"}],
        }
        return self._run_query(body)

    def search_by_ip(self, ip: str, gte: str, lte: str, limit: int = 200) -> List[NormalizedAlert]:
        body = {
            "query": {
                "bool": {
                    "filter": [self._time_filter(gte, lte)],
                    "should": [
                        {"term": {"source.ip": ip}},
                        {"term": {"destination.ip": ip}},
                        {"term": {"client.ip": ip}},
                        {"term": {"server.ip": ip}},
                        {"term": {"host.ip": ip}},
                    ],
                    "minimum_should_match": 1,
                }
            },
            "size": min(limit, 200),
            "sort": [{"@timestamp": "desc"}],
        }
        return [self.normalize(e) for e in self._run_query(body)]

    def search_by_rule(self, rule_id: str, gte: str, lte: str, limit: int = 200) -> List[NormalizedAlert]:
        body = {
            "query": {
                "bool": {
                    "filter": [self._time_filter(gte, lte)],
                    "should": [
                        {"match": {"rule.name": rule_id}},
                        {"term": {"rule.id": rule_id}},
                        {"match": {"signal.rule.name": rule_id}},
                        {"term": {"kibana.alert.rule.rule_id": rule_id}},
                    ],
                    "minimum_should_match": 1,
                }
            },
            "size": min(limit, 200),
            "sort": [{"@timestamp": "desc"}],
        }
        return [self.normalize(e) for e in self._run_query(body)]

    def recent_alerts(self, gte: str, lte: str, limit: int = 200) -> List[NormalizedAlert]:
        body = {
            "query": {"bool": {"filter": [self._time_filter(gte, lte)]}},
            "size": min(limit, 200),
            "sort": [{"@timestamp": "desc"}],
        }
        return [self.normalize(e) for e in self._run_query(body)]

    def keyword_search(self, keywords: List[str], gte: str, lte: str, limit: int = 200) -> List[NormalizedAlert]:
        terms = [f'*{k}*' for k in keywords if k.strip()]
        if not terms:
            return self.recent_alerts(gte, lte, limit)
        kw_query = " OR ".join(terms)
        body = {
            "query": {
                "bool": {
                    "must": [{"query_string": {"query": kw_query, "allow_leading_wildcard": True}}],
                    "filter": [self._time_filter(gte, lte)],
                }
            },
            "size": min(limit, 200),
            "sort": [{"@timestamp": "desc"}],
        }
        return [self.normalize(e) for e in self._run_query(body)]

    def normalize(self, raw: Dict[str, Any]) -> NormalizedAlert:
        rule = raw.get("rule") or {}
        signal = raw.get("signal") or {}
        # Explicit isinstance guard before calling .get() — avoids precedence surprises
        signal_rule = signal.get("rule") or {} if isinstance(signal, dict) else {}
        signal_rule = signal_rule if isinstance(signal_rule, dict) else {}
        kibana_rule = raw.get("kibana.alert.rule") or {}

        # Severity: Elastic Security uses string labels; some indices use int (1-100)
        raw_sev = (
            raw.get("kibana.alert.severity")
            or (raw.get("event") or {}).get("severity")
            or signal_rule.get("severity")
            or kibana_rule.get("severity")
            or "medium"
        )
        if isinstance(raw_sev, int):
            severity = _numeric_to_sev(raw_sev)
        else:
            severity = _SEV_MAP.get(str(raw_sev).lower(), "medium")

        src_ip = (raw.get("source") or {}).get("ip") or (raw.get("client") or {}).get("ip")
        dst_ip = (raw.get("destination") or {}).get("ip") or (raw.get("server") or {}).get("ip")
        agent_name = (raw.get("agent") or {}).get("name") or (raw.get("host") or {}).get("name")

        rule_id = rule.get("id") or signal_rule.get("rule_id") or kibana_rule.get("rule_id")
        rule_name = (
            rule.get("name")
            or signal_rule.get("name")
            or kibana_rule.get("name")
            or raw.get("message", "")[:80]
        )

        return NormalizedAlert(
            id=raw.get("_id") or "",
            timestamp=raw.get("@timestamp") or "",
            severity=severity,
            rule_id=rule_id,
            rule_name=rule_name,
            src_ip=src_ip,
            dst_ip=dst_ip,
            agent=agent_name,
            message=raw.get("message") or "",
            raw=raw,
        )
