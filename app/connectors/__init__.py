from . import wazuh, virustotal
from .base import NormalizedAlert, SIEMConnector
from .splunk import SplunkConnector
from .elastic import ElasticConnector
from .sentinel import SentinelConnector
from .limacharlie import LimaCharlieConnector

__all__ = [
    "wazuh", "virustotal",
    "NormalizedAlert", "SIEMConnector",
    "SplunkConnector", "ElasticConnector", "SentinelConnector", "LimaCharlieConnector",
    "get_siem_connector",
]

# Module-level singletons so connectors reuse HTTP sessions / cached tokens
# across multiple tool_runner.execute() calls.
_splunk: SplunkConnector | None = None
_elastic: ElasticConnector | None = None
_sentinel: SentinelConnector | None = None
_limacharlie: LimaCharlieConnector | None = None


def get_siem_connector(provider: str) -> SIEMConnector:
    """Return the cached connector instance for the named provider.

    Raises ValueError if the provider name is not recognised.
    Does NOT check is_available() — callers should do that themselves.
    """
    global _splunk, _elastic, _sentinel, _limacharlie
    p = provider.lower().strip()
    if p == "splunk":
        if _splunk is None:
            _splunk = SplunkConnector()
        return _splunk
    if p == "elastic":
        if _elastic is None:
            _elastic = ElasticConnector()
        return _elastic
    if p == "sentinel":
        if _sentinel is None:
            _sentinel = SentinelConnector()
        return _sentinel
    if p == "limacharlie":
        if _limacharlie is None:
            _limacharlie = LimaCharlieConnector()
        return _limacharlie
    raise ValueError(f"Unknown SIEM provider: {provider!r}. Valid: splunk, elastic, sentinel, limacharlie")
