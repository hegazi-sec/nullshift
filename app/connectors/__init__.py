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
    "get_siem_connector", "connected_siems", "configured_siems", "siem_available", "SIEMS",
]

SIEMS = ("limacharlie", "wazuh", "splunk", "elastic", "sentinel")


def connected_siems() -> list:
    """The SIEMs this install queries, primary first. Community queries only the primary;
    querying several at once is licensed (multi_siem)."""
    from app import licensing
    siems = configured_siems()
    return siems if licensing.has("multi_siem") else siems[:1]


def configured_siems() -> list:
    """Every SIEM set up, primary first, licensed or not: siem_providers (a comma list;
    "none" means none), else the single siem_provider the setup wizard writes. Ingestion
    reads alerts from all of them."""
    from app.config import settings
    raw = settings.SIEM_PROVIDERS or settings.SIEM_PROVIDER or ""
    out: list = []
    for p in str(raw).split(","):
        p = p.strip().lower()
        if p in SIEMS and p not in out:
            out.append(p)
    return out


def siem_available(provider: str) -> bool:
    """Credentials are set for this SIEM (not a reachability check)."""
    from app.config import settings
    if provider == "wazuh":
        return bool(settings.wazuh_indexer_url)
    try:
        return get_siem_connector(provider).is_available()
    except Exception:
        return False

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
