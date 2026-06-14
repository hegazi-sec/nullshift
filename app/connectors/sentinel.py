import json
import logging
import time
from typing import Any, Dict, List, Optional

import requests

from app.config import settings
from .base import NormalizedAlert, SIEMConnector

logger = logging.getLogger("nullshift.sentinel")

_SEV_MAP = {
    "high": "high", "medium": "medium", "low": "low",
    "informational": "low", "information": "low",
}

_TOKEN_ENDPOINT = "https://login.microsoftonline.com/{tenant_id}/oauth2/token"
_QUERY_ENDPOINT = "https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"


class SentinelConnector(SIEMConnector):
    """Microsoft Sentinel connector via the Azure Log Analytics Query API.

    Authenticates with a service-principal client credential grant (OAuth 2.0).
    Queries use KQL against the Sentinel workspace.

    Required settings:
        SENTINEL_WORKSPACE_ID   Log Analytics workspace GUID
        SENTINEL_TENANT_ID      Azure AD tenant ID
        SENTINEL_CLIENT_ID      App registration client ID
        SENTINEL_CLIENT_SECRET  App registration client secret
    """

    def __init__(self):
        self.workspace_id = settings.SENTINEL_WORKSPACE_ID
        self.tenant_id = settings.SENTINEL_TENANT_ID
        self.client_id = settings.SENTINEL_CLIENT_ID
        self.client_secret = settings.SENTINEL_CLIENT_SECRET
        self._token: Optional[str] = None
        self._token_expiry: float = 0.0

    def is_available(self) -> bool:
        return bool(
            self.workspace_id
            and self.tenant_id
            and self.client_id
            and self.client_secret
        )

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    def _get_token(self) -> str:
        if self._token and time.time() < self._token_expiry - 60:
            return self._token
        resp = requests.post(
            _TOKEN_ENDPOINT.format(tenant_id=self.tenant_id),
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "resource": "https://api.loganalytics.io",
            },
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        self._token = data["access_token"]
        self._token_expiry = time.time() + float(data.get("expires_in", 3600))
        return self._token

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_kql(self, kql: str) -> List[Dict[str, Any]]:
        if not self.is_available():
            return []
        try:
            token = self._get_token()
            resp = requests.post(
                _QUERY_ENDPOINT.format(workspace_id=self.workspace_id),
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                json={"query": kql},
                timeout=60,
            )
            resp.raise_for_status()
            rows: List[Dict[str, Any]] = []
            for table in resp.json().get("tables", []):
                cols = [c["name"] for c in table["columns"]]
                for row in table["rows"]:
                    rows.append(dict(zip(cols, row)))
            return rows
        except Exception as exc:
            logger.error("Sentinel KQL query failed: %s", exc)
            return []

    def _time_clause(self, gte: str, lte: str) -> str:
        """Convert ISO datetimes to a KQL TimeGenerated filter."""
        g = gte.replace("Z", "").replace("+00:00", "")
        # "now" is not valid inside KQL datetime() — use the now() function instead
        if lte.strip().lower() == "now":
            return f'TimeGenerated >= datetime("{g}")'
        l = lte.replace("Z", "").replace("+00:00", "")
        return f'TimeGenerated between (datetime("{g}") .. datetime("{l}"))'

    # ------------------------------------------------------------------
    # SIEMConnector interface
    # ------------------------------------------------------------------

    def search(self, query: str, gte: str, lte: str = "now", limit: int = 200) -> List[Dict[str, Any]]:
        # query is assumed to be a KQL table expression or filter
        kql = f"{query}\n| where {self._time_clause(gte, lte)}\n| take {limit}"
        return self._run_kql(kql)

    def search_by_ip(self, ip: str, gte: str, lte: str, limit: int = 200) -> List[NormalizedAlert]:
        tc = self._time_clause(gte, lte)
        # isfuzzy=true makes union skip tables that don't exist in this workspace
        kql = f"""
let _ip = "{ip}";
union isfuzzy=true
    (SecurityAlert | where {tc} | where Entities has _ip),
    (CommonSecurityLog | where {tc} | where SourceIP == _ip or DestinationIP == _ip)
| take {limit}
"""
        return [self.normalize(e) for e in self._run_kql(kql)]

    def search_by_rule(self, rule_id: str, gte: str, lte: str, limit: int = 200) -> List[NormalizedAlert]:
        safe = rule_id.replace('"', "")
        kql = f"""
SecurityAlert
| where {self._time_clause(gte, lte)}
| where AlertName has "{safe}" or AlertType has "{safe}"
| take {limit}
"""
        return [self.normalize(e) for e in self._run_kql(kql)]

    def recent_alerts(self, gte: str, lte: str, limit: int = 200) -> List[NormalizedAlert]:
        kql = f"""
SecurityAlert
| where {self._time_clause(gte, lte)}
| order by TimeGenerated desc
| take {limit}
"""
        return [self.normalize(e) for e in self._run_kql(kql)]

    def keyword_search(self, keywords: List[str], gte: str, lte: str, limit: int = 200) -> List[NormalizedAlert]:
        kw_clause = " or ".join(f'Description has "{k.replace(chr(34), "")}"' for k in keywords if k.strip())
        kql = f"""
SecurityAlert
| where {self._time_clause(gte, lte)}
| where {kw_clause or "true"}
| take {limit}
"""
        return [self.normalize(e) for e in self._run_kql(kql)]

    def normalize(self, raw: Dict[str, Any]) -> NormalizedAlert:
        raw_sev = str(raw.get("AlertSeverity") or raw.get("LogSeverity") or "medium").lower()

        # Extract src IP: prefer flat field, fall back to Entities JSON
        src_ip: Optional[str] = raw.get("SourceIP")
        if not src_ip:
            try:
                entities = raw.get("Entities", "[]")
                if isinstance(entities, str):
                    entities = json.loads(entities)
                for ent in (entities or []):
                    if isinstance(ent, dict) and ent.get("Type") == "ip":
                        src_ip = ent.get("Address")
                        break
            except Exception:
                pass

        return NormalizedAlert(
            id=raw.get("SystemAlertId") or str(raw.get("TimeGenerated", "")),
            timestamp=str(raw.get("TimeGenerated") or ""),
            severity=_SEV_MAP.get(raw_sev, "medium"),
            rule_id=raw.get("AlertType"),
            rule_name=raw.get("AlertName") or raw.get("Activity") or "",
            src_ip=src_ip,
            dst_ip=raw.get("DestinationIP"),
            agent=raw.get("CompromisedEntity") or raw.get("WorkspaceResourceGroup"),
            message=raw.get("Description") or "",
            raw=raw,
        )
