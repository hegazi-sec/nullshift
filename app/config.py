from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    OPENAI_API_KEY: Optional[str] = None
    OPENAI_MODEL: str = "gpt-4.1"

    WAZUH_API_URL: Optional[str] = None
    # Wazuh Indexer (OpenSearch) base URL, e.g. https://indexer:9200
    wazuh_indexer_url: Optional[str] = None
    WAZUH_API_TOKEN: Optional[str] = None
    WAZUH_USER: Optional[str] = None
    WAZUH_PASS: Optional[str] = None
    WAZUH_VERIFY_SSL: bool = False  # set True with a valid CA/cert to remove TLS warnings
    # Optional: dedicated credentials for Wazuh Indexer (OpenSearch) basic auth
    WAZUH_INDEXER_USER: Optional[str] = None
    WAZUH_INDEXER_PASS: Optional[str] = None
    # Preferred names for Indexer basic auth (env: WAZUH_INDEXER_USERNAME/PASSWORD)
    wazuh_indexer_username: Optional[str] = None
    wazuh_indexer_password: Optional[str] = None
    # Optional index pattern(s) used by Wazuh indexer queries. Supports wildcards or comma-separated list
    # Default to common indices for alerts and archives; can be overridden via .env
    WAZUH_INDEX_PATTERNS: Optional[str] = "wazuh-alerts-*,wazuh-archives-*"
    # Default time range for Wazuh-first investigations (e.g. "last_24h", "now-2d", "48h")
    WAZUH_DEFAULT_TIME_RANGE: str = "last_24h"

    VT_API_KEY: Optional[str] = None

    # Active SIEM provider: wazuh | splunk | elastic | sentinel | limacharlie
    # When multiple SIEMs are configured, this selects which one the
    # investigation and tool_runner use for primary queries.
    SIEM_PROVIDER: str = "wazuh"

    # Splunk Enterprise / Cloud (port 8089 REST API)
    SPLUNK_URL: Optional[str] = None          # e.g. https://splunk.corp:8089
    SPLUNK_TOKEN: Optional[str] = None        # Bearer token (preferred)
    SPLUNK_USER: Optional[str] = None         # Basic auth fallback
    SPLUNK_PASS: Optional[str] = None
    SPLUNK_INDEX: str = "*"                   # target index(es)
    SPLUNK_VERIFY_SSL: bool = False

    # Elasticsearch / Elastic SIEM (ECS field names)
    ELASTIC_URL: Optional[str] = None         # e.g. https://elastic.corp:9200
    ELASTIC_API_KEY: Optional[str] = None     # preferred
    ELASTIC_USERNAME: Optional[str] = None    # Basic auth fallback
    ELASTIC_PASSWORD: Optional[str] = None
    ELASTIC_INDEX: str = "logs-*,.alerts-security.alerts-*"
    ELASTIC_VERIFY_SSL: bool = False

    # Microsoft Sentinel (Azure Log Analytics)
    SENTINEL_WORKSPACE_ID: Optional[str] = None   # Log Analytics workspace GUID
    SENTINEL_TENANT_ID: Optional[str] = None      # Azure AD tenant ID
    SENTINEL_CLIENT_ID: Optional[str] = None      # App registration client ID
    SENTINEL_CLIENT_SECRET: Optional[str] = None  # App registration client secret

    # LimaCharlie SecOps Cloud
    LIMACHARLIE_OID: Optional[str] = None         # Org ID (UUID)
    LIMACHARLIE_API_KEY: Optional[str] = None     # Secret API key for JWT refresh
    LIMACHARLIE_API_BASE: Optional[str] = None    # Override https://api.limacharlie.io
    LIMACHARLIE_AUTH_BASE: Optional[str] = None   # Override https://app.limacharlie.io

    # Anthropic (primary when configured; OpenAI is fallback)
    ANTHROPIC_API_KEY: Optional[str] = None
    ANTHROPIC_MODEL: str = "claude-sonnet-4-6"

    # Claude Agent SDK — toggles routing chat through the local `claude` CLI
    # (using the operator's Claude.ai Pro/Max subscription) instead of the
    # Anthropic API. For SINGLE-USER / home-SOC testing only — multi-analyst
    # deployments would bill all chats to the operator's personal subscription
    # quota. Requires the `claude` CLI installed and authenticated on the host.
    USE_CLAUDE_AGENT_SDK: bool = False
    CLAUDE_AGENT_SDK_MODEL: Optional[str] = None  # let the SDK pick its default

    # DeepSeek (optional fallback LLM provider)
    DEEPSEEK_API_KEY: Optional[str] = None
    DEEPSEEK_BASE_URL: str = "https://api.deepseek.com/v1"
    LLM_FALLBACK_PROVIDER: str = "deepseek"

    # Additional OpenAI-compatible providers
    GEMINI_API_KEY: Optional[str] = None
    GROQ_API_KEY: Optional[str] = None
    MISTRAL_API_KEY: Optional[str] = None
    XAI_API_KEY: Optional[str] = None
    COHERE_API_KEY: Optional[str] = None
    TOGETHER_API_KEY: Optional[str] = None
    PERPLEXITY_API_KEY: Optional[str] = None
    OPENROUTER_API_KEY: Optional[str] = None
    QWEN_API_KEY: Optional[str] = None       # Alibaba DashScope / Qwen
    KIMI_API_KEY: Optional[str] = None       # Moonshot AI / Kimi

    # Ollama (local / self-hosted) — set OLLAMA_BASE_URL to enable
    OLLAMA_BASE_URL: Optional[str] = None        # e.g. http://localhost:11434/v1
    OLLAMA_MODEL: str = "llama3.3"

    UI_BASIC_USER: Optional[str] = None
    UI_BASIC_PASS: Optional[str] = None

    # Auth / Admin bootstrap + JWT config
    ADMIN_USERNAME: Optional[str] = None
    ADMIN_PASSWORD: Optional[str] = None
    JWT_SECRET: Optional[str] = None
    JWT_EXPIRE_MINUTES: int = 480

    class Config:
        env_file = ".env"

    # Lowercase alias properties for convenience in code
    @property
    def wazuh_index_patterns(self) -> str:
        return (self.WAZUH_INDEX_PATTERNS or "").strip()

    def require_wazuh_indexer_url(self) -> str:
        """Return the configured Wazuh Indexer base URL or raise a clear error if missing.
        Loaded from env var WAZUH_INDEXER_URL.
        """
        url = (self.wazuh_indexer_url or "").strip()
        if not url:
            raise ValueError("WAZUH_INDEXER_URL not configured. Set it in .env to enable Wazuh index searches.")
        return url


_MISSING = object()


class _SettingsProxy:
    """Proxy over pydantic Settings — config.db overrides .env.

    Every attribute lookup checks settings_store (the runtime config DB
    written by the Admin UI / setup wizard) first, falling back to the
    underlying pydantic settings object (which loaded its values from
    env / .env at import time). Methods and properties continue to work
    via the fallback path; bool / int / float fields are cast from the
    string the DB stores back to their declared python type.
    """

    def __init__(self, base):
        object.__setattr__(self, "_base", base)

    def __getattr__(self, name):
        if name.startswith("_"):
            return getattr(self._base, name)

        base_val = getattr(self._base, name, _MISSING)

        # Never override bound methods or non-scalar callables
        if callable(base_val) and not isinstance(base_val, (str, int, float, bool)):
            return base_val

        try:
            from app.db.settings_store import settings_store
            v = settings_store.get(name.lower())
        except Exception:
            v = None

        if v is not None and v != "":
            if isinstance(base_val, bool):
                return v.lower() in ("true", "1", "yes", "on")
            if isinstance(base_val, int) and not isinstance(base_val, bool):
                try:
                    return int(v)
                except (ValueError, TypeError):
                    pass
            if isinstance(base_val, float):
                try:
                    return float(v)
                except (ValueError, TypeError):
                    pass
            return v

        if base_val is _MISSING:
            raise AttributeError(name)
        return base_val

    def __setattr__(self, name, value):
        setattr(self._base, name, value)


settings = _SettingsProxy(Settings())
