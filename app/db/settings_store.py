"""Runtime app settings, persisted in SQLite (config.db).

Lets an admin change the LLM provider, paste API keys, and override model
names from the UI without editing .env or restarting. Read precedence is
DB-row -> environment (.env), so existing deployments keep working
unchanged until something is saved through the admin UI.

Stored values are plain text on purpose: the NullShift SQLite file is
already inside the same trust boundary as the .env file, and adding
encryption with no key-management story would just give a false sense of
safety. Anyone who can read config.db can already read .env.

Recognized keys (defined in ALLOWED_KEYS below):
- active_provider: 'auto' | 'claude_agent_sdk' | 'anthropic' | 'openai' | 'deepseek'
- claude_agent_sdk_enabled: 'true' | 'false'
- anthropic_api_key / openai_api_key / deepseek_api_key
- anthropic_model / openai_model / deepseek_model / claude_agent_sdk_model
- SIEM connector keys (siem_provider, wazuh_*, splunk_*, elastic_*, sentinel_*, limacharlie_*)
- setup_complete: 'true' | 'false'
- jwt_secret: the runtime JWT secret (used when JWT_SECRET env var is not set)

Stored in config.db (separate from chat.db which holds user/chat data).
"""
from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


DB_PATH = Path(__file__).resolve().parent.parent / 'data' / 'config.db'


# Whitelist — refuses to store anything else so a buggy/malicious caller
# can't pollute the row set or shadow unrelated config.
ALLOWED_KEYS = frozenset({
    # Routing
    "active_provider",
    "provider_chain",           # JSON array of provider names, user-defined fallback order
    # Claude
    "claude_agent_sdk_enabled",
    "claude_agent_sdk_model",
    # Anthropic API
    "anthropic_api_key",
    "anthropic_model",
    # OpenAI
    "openai_api_key",
    "openai_model",
    # DeepSeek
    "deepseek_api_key",
    "deepseek_model",
    # Google Gemini
    "gemini_api_key",
    "gemini_model",
    # Groq
    "groq_api_key",
    "groq_model",
    # Mistral
    "mistral_api_key",
    "mistral_model",
    # xAI / Grok
    "xai_api_key",
    "xai_model",
    # Cohere
    "cohere_api_key",
    "cohere_model",
    # Together AI
    "together_api_key",
    "together_model",
    # Perplexity
    "perplexity_api_key",
    "perplexity_model",
    # OpenRouter
    "openrouter_api_key",
    "openrouter_model",
    # Qwen (Alibaba / DashScope)
    "qwen_api_key",
    "qwen_model",
    # Kimi (Moonshot AI)
    "kimi_api_key",
    "kimi_model",
    # Ollama (local / self-hosted)
    "ollama_base_url",
    "ollama_model",
    # RAG / Knowledge Base
    "rag_enabled",             # 'true' | 'false'
    "rag_embedding_provider",  # 'auto' | 'openai' | 'gemini' | 'cohere' | 'ollama'
    "rag_embedding_model",     # override model name (e.g. nomic-embed-text, gemini-embedding-001)
    # Vision / Image Upload
    "vision_max_images",       # int, default 4
    "vision_max_size_mb",      # float, default 5
    # SIEM provider selection
    "siem_provider",
    # LimaCharlie
    "limacharlie_oid",
    "limacharlie_api_key",
    # Wazuh
    "wazuh_api_url",
    "wazuh_indexer_url",
    "wazuh_indexer_user",
    "wazuh_indexer_pass",
    "wazuh_api_token",
    "wazuh_verify_ssl",
    # Splunk
    "splunk_url",
    "splunk_token",
    "splunk_user",
    "splunk_pass",
    "splunk_index",
    "splunk_verify_ssl",
    # Elasticsearch / Elastic SIEM
    "elastic_url",
    "elastic_api_key",
    "elastic_username",
    "elastic_password",
    "elastic_index",
    "elastic_verify_ssl",
    # Microsoft Sentinel
    "sentinel_workspace_id",
    "sentinel_tenant_id",
    "sentinel_client_id",
    "sentinel_client_secret",
    # Threat Intelligence
    "vt_api_key",              # VirusTotal v3 API key
    # Setup / Auth
    "setup_complete",
    "jwt_secret",
})

# Keys whose values must never be returned in full over the API. We surface
# a `<set>` flag + last 4 chars so an admin can tell whether a key is
# configured and recognize it, without exposing it to anyone who shoulder-
# surfs the screen.
SECRET_KEYS = frozenset({
    "anthropic_api_key",
    "openai_api_key",
    "deepseek_api_key",
    "gemini_api_key",
    "groq_api_key",
    "mistral_api_key",
    "xai_api_key",
    "cohere_api_key",
    "together_api_key",
    "perplexity_api_key",
    "openrouter_api_key",
    "qwen_api_key",
    "kimi_api_key",
    # SIEM secrets
    "limacharlie_api_key",
    "wazuh_indexer_pass",
    "wazuh_api_token",
    "splunk_token",
    "splunk_pass",
    "elastic_api_key",
    "elastic_password",
    "sentinel_client_secret",
    # Threat Intelligence
    "vt_api_key",
    # Runtime auth secret — never expose in API
    "jwt_secret",
})


class SettingsStore:
    def __init__(self, db_path: Path = DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        self._ensure()

    def _ensure(self) -> None:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL;")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS app_settings(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    updated_by INTEGER
                )
                """
            )
            self.conn.commit()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def get(self, key: str) -> Optional[str]:
        if key not in ALLOWED_KEYS:
            return None
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT value FROM app_settings WHERE key=?", (key,))
            row = cur.fetchone()
        return row["value"] if row else None

    def get_all(self) -> Dict[str, str]:
        """Return every stored setting. Caller is responsible for masking
        secrets before exposing externally — use mask_for_api()."""
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT key, value, updated_at FROM app_settings")
            rows = cur.fetchall()
        return {r["key"]: r["value"] for r in rows if r["key"] in ALLOWED_KEYS}

    def set_many(self, updates: Dict[str, Any], updated_by: Optional[int] = None) -> int:
        """Upsert each whitelisted key. None or empty-string deletes the key
        (so the .env value takes effect again). Returns rows touched."""
        if not updates:
            return 0
        now = self._now()
        to_upsert = []
        to_delete = []
        for k, v in updates.items():
            if k not in ALLOWED_KEYS:
                continue
            if v is None or (isinstance(v, str) and v.strip() == ""):
                to_delete.append(k)
            else:
                # Coerce bools/ints/etc. to string; complex types not allowed
                # at the storage layer to keep the read path simple.
                to_upsert.append((k, str(v), now, updated_by))
        touched = 0
        with self.lock:
            cur = self.conn.cursor()
            if to_upsert:
                cur.executemany(
                    """
                    INSERT INTO app_settings(key, value, updated_at, updated_by)
                    VALUES (?,?,?,?)
                    ON CONFLICT(key) DO UPDATE SET
                        value=excluded.value,
                        updated_at=excluded.updated_at,
                        updated_by=excluded.updated_by
                    """,
                    to_upsert,
                )
                touched += len(to_upsert)
            if to_delete:
                placeholders = ",".join(["?"] * len(to_delete))
                cur.execute(
                    f"DELETE FROM app_settings WHERE key IN ({placeholders})",
                    to_delete,
                )
                touched += len(to_delete)
            self.conn.commit()
        return touched

    def migrate_from_chat_db(self, chat_db_path: Path) -> int:
        """One-time migration: copy app_settings rows from chat.db into config.db.

        Only runs if config.db currently has no rows (fresh install or first
        run after the split). Safe to call on every startup — it is a no-op
        once config.db has any data.

        Returns the number of rows migrated (0 if already migrated or no
        chat.db to read from).
        """
        # Skip if config.db already has settings
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT COUNT(*) FROM app_settings")
            count = cur.fetchone()[0]
        if count > 0:
            return 0

        chat_db_path = Path(chat_db_path)
        if not chat_db_path.exists():
            return 0

        try:
            src = sqlite3.connect(str(chat_db_path), check_same_thread=False)
            src.row_factory = sqlite3.Row
            src_cur = src.cursor()
            # Check if the old app_settings table exists in chat.db
            src_cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='app_settings'"
            )
            if not src_cur.fetchone():
                src.close()
                return 0
            src_cur.execute("SELECT key, value, updated_at, updated_by FROM app_settings")
            rows = src_cur.fetchall()
            src.close()
        except Exception:
            return 0

        if not rows:
            return 0

        now = self._now()
        to_upsert = []
        for r in rows:
            if r["key"] in ALLOWED_KEYS:
                to_upsert.append((
                    r["key"],
                    r["value"],
                    r["updated_at"] or now,
                    r["updated_by"],
                ))

        if not to_upsert:
            return 0

        with self.lock:
            cur = self.conn.cursor()
            cur.executemany(
                """
                INSERT INTO app_settings(key, value, updated_at, updated_by)
                VALUES (?,?,?,?)
                ON CONFLICT(key) DO UPDATE SET
                    value=excluded.value,
                    updated_at=excluded.updated_at,
                    updated_by=excluded.updated_by
                """,
                to_upsert,
            )
            self.conn.commit()

        return len(to_upsert)


def mask_for_api(settings_dict: Dict[str, str]) -> Dict[str, Any]:
    """Replace SECRET_KEYS values with a {present, suffix} stub so the API
    response shows enough to recognize the key without leaking it."""
    out: Dict[str, Any] = {}
    for k, v in settings_dict.items():
        if k in SECRET_KEYS:
            v = v or ""
            out[k] = {
                "present": bool(v),
                "suffix": v[-4:] if len(v) >= 4 else "",
            }
        else:
            out[k] = v
    return out


settings_store = SettingsStore()

# Run migration from old chat.db on module load (no-op if already done)
try:
    _chat_db = Path(__file__).resolve().parent.parent / 'data' / 'chat.db'
    _migrated = settings_store.migrate_from_chat_db(_chat_db)
    if _migrated:
        import logging as _logging
        _logging.getLogger("nullshift.settings").info(
            "Migrated %d settings rows from chat.db -> config.db", _migrated
        )
except Exception:
    pass
