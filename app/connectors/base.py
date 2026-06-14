from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class NormalizedAlert:
    """Canonical alert shape shared across all SIEM connectors."""

    id: str
    timestamp: str                   # ISO 8601
    severity: str                    # low | medium | high | critical
    rule_id: Optional[str]
    rule_name: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    agent: Optional[str] = None      # hostname / sensor / agent name
    message: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Return a flat dict with normalized keys prefixed with _ plus all raw fields."""
        return {
            "_siem_id": self.id,
            "_timestamp": self.timestamp,
            "_severity": self.severity,
            "_rule_id": self.rule_id,
            "_rule_name": self.rule_name,
            "_src_ip": self.src_ip,
            "_dst_ip": self.dst_ip,
            "_agent": self.agent,
            "_message": self.message,
            **self.raw,
        }


class SIEMConnector(ABC):
    """Abstract base for all SIEM connectors.

    Each connector translates a common query vocabulary into its native API
    (SPL for Splunk, KQL for Sentinel, Lucene/DSL for Elastic, OpenSearch for Wazuh).
    """

    @abstractmethod
    def is_available(self) -> bool:
        """True if this connector is configured and ready to use."""

    @abstractmethod
    def search(self, query: str, gte: str, lte: str = "now", limit: int = 200) -> List[Dict[str, Any]]:
        """Free-form native query. Returns raw dicts (connector format)."""

    @abstractmethod
    def search_by_ip(self, ip: str, gte: str, lte: str, limit: int = 200) -> List[NormalizedAlert]:
        """Alerts where src or dst IP matches."""

    @abstractmethod
    def search_by_rule(self, rule_id: str, gte: str, lte: str, limit: int = 200) -> List[NormalizedAlert]:
        """Alerts matching a rule ID / name / signature."""

    @abstractmethod
    def recent_alerts(self, gte: str, lte: str, limit: int = 200) -> List[NormalizedAlert]:
        """Most recent alerts in the time window."""

    @abstractmethod
    def keyword_search(self, keywords: List[str], gte: str, lte: str, limit: int = 200) -> List[NormalizedAlert]:
        """Full-text keyword search across event fields."""

    @abstractmethod
    def normalize(self, raw: Dict[str, Any]) -> NormalizedAlert:
        """Translate a connector-native event dict into NormalizedAlert."""
