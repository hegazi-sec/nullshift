from openai import OpenAI
import json
import re
import logging
from datetime import datetime, timezone
from app.config import settings
from app.db.settings_store import settings_store
from typing import List, Optional, Dict, Any, Tuple
from app.execution.tool_runner import ToolRunner

logger = logging.getLogger("nullshift.llm")


def _effective(key: str, env_value: Any) -> Any:
    """Return the SQLite-saved value for `key` if set, else the .env value.

    Lets the admin override any provider config at runtime via the settings
    UI without losing the .env-based bootstrap path. Empty strings in the
    DB are treated as 'use env' so an admin can clear an override.
    """
    db_val = settings_store.get(key)
    if db_val is None or db_val == "":
        return env_value
    return db_val


def _effective_bool(key: str, env_value: bool) -> bool:
    db_val = settings_store.get(key)
    if db_val is None or db_val == "":
        return env_value
    return str(db_val).strip().lower() in ("1", "true", "yes", "on")


# Telemetry captured from the last LLM call so the admin Usage page can
# show what's happening. Module-level dict + a tiny accessor so callers
# don't import the variable directly (makes future serialization easy).
_LAST_CALL_INFO: Dict[str, Any] = {
    "provider": None,
    "model": None,
    "ok": None,
    "error": None,
    "ts": None,
    "duration_ms": None,
}
_LAST_RATE_LIMIT_INFO: Optional[Dict[str, Any]] = None


def get_last_call_info() -> Dict[str, Any]:
    return dict(_LAST_CALL_INFO)


def get_last_rate_limit_info() -> Optional[Dict[str, Any]]:
    return dict(_LAST_RATE_LIMIT_INFO) if _LAST_RATE_LIMIT_INFO else None


def _record_call(provider: str, model: Optional[str], ok: bool, error: Optional[str], duration_ms: Optional[int]) -> None:
    _LAST_CALL_INFO.update({
        "provider": provider,
        "model": model,
        "ok": ok,
        "error": error,
        "ts": datetime.now(timezone.utc).isoformat(),
        "duration_ms": duration_ms,
    })


def _record_rate_limit(info: Dict[str, Any]) -> None:
    global _LAST_RATE_LIMIT_INFO
    info["captured_at"] = datetime.now(timezone.utc).isoformat()
    _LAST_RATE_LIMIT_INFO = info


# ---------------------------------------------------------------------------
# OpenAI <-> Anthropic shape adapters.
#
# The rest of chat_with_history is written against OpenAI's response shape
# (resp.choices[0].message.tool_calls, tc.function.name, etc.). The
# AnthropicProvider takes OpenAI-shaped input, calls Anthropic, then wraps
# the response in tiny namespace objects with the same attribute paths so
# the consumer code doesn't care which provider answered.
# ---------------------------------------------------------------------------


class _AdaptedFunction:
    __slots__ = ("name", "arguments")

    def __init__(self, name: str, arguments: str) -> None:
        self.name = name
        self.arguments = arguments  # JSON string, matching OpenAI's shape


class _AdaptedToolCall:
    __slots__ = ("id", "type", "function")

    def __init__(self, id: str, name: str, arguments_json: str) -> None:
        self.id = id
        self.type = "function"
        self.function = _AdaptedFunction(name, arguments_json)


class _AdaptedMessage:
    __slots__ = ("content", "tool_calls")

    def __init__(self, content: Optional[str], tool_calls: Optional[List[_AdaptedToolCall]]) -> None:
        self.content = content
        self.tool_calls = tool_calls


class _AdaptedChoice:
    __slots__ = ("message",)

    def __init__(self, message: _AdaptedMessage) -> None:
        self.message = message


class _AdaptedResponse:
    __slots__ = ("choices",)

    def __init__(self, message: _AdaptedMessage) -> None:
        self.choices = [_AdaptedChoice(message)]


def _openai_msgs_to_anthropic(messages: List[Dict[str, Any]]) -> Tuple[str, List[Dict[str, Any]]]:
    """Convert OpenAI-shaped messages to Anthropic format.

    Returns (system_prompt_text, anthropic_messages). System messages are
    concatenated and returned separately because Anthropic uses a top-level
    `system` parameter. Consecutive `tool` messages are batched into one user
    message with multiple `tool_result` blocks, which is what Anthropic requires.
    """
    system_parts: List[str] = []
    out: List[Dict[str, Any]] = []
    i = 0
    while i < len(messages):
        m = messages[i]
        role = m.get("role")
        if role == "system":
            txt = m.get("content")
            if txt:
                system_parts.append(txt)
            i += 1
            continue
        if role == "user":
            content = m.get("content")
            if isinstance(content, list):
                # Convert OpenAI content blocks (text + image_url) to Anthropic format
                blocks: List[Dict[str, Any]] = []
                for blk in content:
                    btype = blk.get("type")
                    if btype == "text":
                        blocks.append({"type": "text", "text": blk.get("text", "")})
                    elif btype == "image_url":
                        url = (blk.get("image_url") or {}).get("url", "")
                        if url.startswith("data:"):
                            try:
                                meta, b64 = url.split(",", 1)
                                media_type = meta.split(";")[0].split(":")[1]
                                blocks.append({
                                    "type": "image",
                                    "source": {"type": "base64", "media_type": media_type, "data": b64},
                                })
                            except Exception:
                                pass
                out.append({"role": "user", "content": blocks or [{"type": "text", "text": ""}]})
            else:
                out.append({"role": "user", "content": content or ""})
            i += 1
            continue
        if role == "assistant":
            tool_calls = m.get("tool_calls") or []
            blocks: List[Dict[str, Any]] = []
            text = m.get("content")
            if text:
                blocks.append({"type": "text", "text": text})
            for tc in tool_calls:
                fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except Exception:
                    args = {}
                blocks.append({
                    "type": "tool_use",
                    "id": tc.get("id"),
                    "name": fn.get("name", ""),
                    "input": args,
                })
            if not blocks:
                # Anthropic rejects empty assistant content
                blocks = [{"type": "text", "text": "(no content)"}]
            out.append({"role": "assistant", "content": blocks})
            i += 1
            continue
        if role == "tool":
            # Batch consecutive tool messages into a single user-role tool_result message
            results: List[Dict[str, Any]] = []
            while i < len(messages) and messages[i].get("role") == "tool":
                t = messages[i]
                results.append({
                    "type": "tool_result",
                    "tool_use_id": t.get("tool_call_id"),
                    "content": t.get("content") or "",
                })
                i += 1
            out.append({"role": "user", "content": results})
            continue
        # unknown role — skip
        i += 1

    return "\n\n".join(system_parts), out


def _openai_tools_to_anthropic(tools_spec: Optional[List[Dict[str, Any]]]) -> Optional[List[Dict[str, Any]]]:
    """Translate OpenAI function-tool defs to Anthropic's input_schema shape."""
    if not tools_spec:
        return None
    out: List[Dict[str, Any]] = []
    for t in tools_spec:
        if t.get("type") != "function":
            continue
        fn = t.get("function") or {}
        out.append({
            "name": fn.get("name"),
            "description": fn.get("description"),
            "input_schema": fn.get("parameters") or {"type": "object"},
        })
    return out or None


def _anthropic_response_to_adapted(response: Any) -> _AdaptedResponse:
    """Wrap an Anthropic Message in the OpenAI-shaped namespace the consumer expects."""
    text_parts: List[str] = []
    tool_calls: List[_AdaptedToolCall] = []
    for block in (getattr(response, "content", None) or []):
        btype = getattr(block, "type", None)
        if btype == "text":
            text_parts.append(getattr(block, "text", "") or "")
        elif btype == "tool_use":
            tool_calls.append(_AdaptedToolCall(
                id=getattr(block, "id", "") or "",
                name=getattr(block, "name", "") or "",
                arguments_json=json.dumps(getattr(block, "input", {}) or {}),
            ))
    content_str = ("\n".join(p for p in text_parts if p)) or None
    msg = _AdaptedMessage(content=content_str, tool_calls=tool_calls or None)
    return _AdaptedResponse(msg)


def _extract_json_block(text: str) -> Optional[str]:
    """Try to extract a JSON object/array from raw model text, stripping code fences if present."""
    if not text:
        return None
    fenced = re.match(r"^```(?:json)?\s*(.*)\s*```\s*$", text, flags=re.DOTALL | re.IGNORECASE)
    if fenced:
        candidate = fenced.group(1).strip()
        try:
            json.loads(candidate)
            return candidate
        except Exception:
            pass
        text = candidate
    m = re.search(r"(\{[\s\S]*\}|\[[\s\S]*\])", text)
    if m:
        return m.group(1)
    return None


class LLMProvider:
    def chat(self, model: str, messages: List[Dict[str, Any]], max_tokens: int, temperature: float, tools: Optional[List[Dict[str, Any]]] = None, tool_choice: Optional[str] = None):
        raise NotImplementedError()


class OpenAIProvider(LLMProvider):
    def __init__(self):
        key = _effective("openai_api_key", settings.OPENAI_API_KEY)
        self.client = OpenAI(api_key=key) if key else None

    def chat(self, model: str, messages: List[Dict[str, Any]], max_tokens: int, temperature: float, tools: Optional[List[Dict[str, Any]]] = None, tool_choice: Optional[str] = None):
        if not self.client:
            raise RuntimeError("OpenAI API key not configured")
        logger.debug("Calling OpenAI model")
        return self.client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
            tools=tools if tools else None,
            tool_choice=tool_choice if tool_choice else None,
        )


class GenericOpenAICompatibleProvider(LLMProvider):
    """Generic provider for any OpenAI-compatible /chat/completions endpoint.

    Covers DeepSeek, Gemini, Groq, xAI, Perplexity, OpenRouter, Qwen,
    Kimi, and Ollama — all speak the same API shape.
    Ollama doesn't require a real API key; pass None and we substitute a
    placeholder so the OpenAI SDK initializes without complaint.
    """

    def __init__(self, provider_name: str, base_url: str, api_key: Optional[str]) -> None:
        self.provider_name = provider_name
        self.client: Optional[OpenAI] = None
        if not base_url:
            return
        effective_key = api_key or "local"
        try:
            self.client = OpenAI(api_key=effective_key, base_url=base_url)
        except Exception as e:
            logger.warning("Failed to init %s provider: %s", provider_name, e)

    def chat(self, model: str, messages: List[Dict[str, Any]], max_tokens: int, temperature: float, tools: Optional[List[Dict[str, Any]]] = None, tool_choice: Optional[str] = None):
        if not self.client:
            raise RuntimeError(f"{self.provider_name} not configured (missing API key or base URL)")
        logger.debug("Calling %s model %s", self.provider_name, model)
        return self.client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
            tools=tools if tools else None,
            tool_choice=tool_choice if tool_choice else None,
        )


class AnthropicProvider(LLMProvider):
    """Claude provider via the Anthropic API.

    Translates the OpenAI-shaped input the rest of the codebase uses into
    Anthropic's format, then wraps the response in an OpenAI-shaped namespace
    so the tool-call loop downstream doesn't have to know which provider
    answered. Prompt caching is enabled on the system prompt and tool defs,
    which together account for most input tokens on a SOC investigation.
    """

    def __init__(self) -> None:
        self.client = None
        key = _effective("anthropic_api_key", settings.ANTHROPIC_API_KEY)
        if not key:
            return
        try:
            from anthropic import Anthropic
            self.client = Anthropic(api_key=key)
        except ImportError as e:
            logger.warning("anthropic SDK not installed (%s); Anthropic disabled.", e)
            self.client = None

    def chat(self, model: str, messages: List[Dict[str, Any]], max_tokens: int, temperature: float, tools: Optional[List[Dict[str, Any]]] = None, tool_choice: Optional[str] = None):
        if not self.client:
            raise RuntimeError("Anthropic API key not configured")

        system_text, anthropic_messages = _openai_msgs_to_anthropic(messages)
        anthropic_tools = _openai_tools_to_anthropic(tools)

        # Prompt caching: mark system prompt + tools as cacheable. These repeat
        # across requests so cache hits dominate input cost on a busy SOC.
        system_param: Any
        if system_text:
            system_param = [{
                "type": "text",
                "text": system_text,
                "cache_control": {"type": "ephemeral"},
            }]
        else:
            system_param = ""

        if anthropic_tools:
            # cache_control on the last tool caches the whole tools array
            anthropic_tools[-1]["cache_control"] = {"type": "ephemeral"}

        kwargs: Dict[str, Any] = {
            "model": model or settings.ANTHROPIC_MODEL,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "system": system_param,
            "messages": anthropic_messages,
        }
        if anthropic_tools:
            kwargs["tools"] = anthropic_tools
            if tool_choice == "auto":
                kwargs["tool_choice"] = {"type": "auto"}

        logger.debug("Calling Anthropic model %s", kwargs["model"])
        response = self.client.messages.create(**kwargs)
        return _anthropic_response_to_adapted(response)


class ClaudeAgentSDKProvider(LLMProvider):
    """LLM provider backed by `claude-agent-sdk`, which spawns the local
    `claude` CLI and authenticates against the operator's Claude.ai Pro/Max
    subscription instead of an Anthropic API key.

    Intended for single-user / home-SOC operation. Multi-analyst deployments
    should keep the AnthropicProvider as primary — every chat through this
    provider bills to whichever subscription the host machine's `claude` CLI
    is logged into.

    Constraints baked into this adapter:
    - `claude` CLI must be installed on the host and authenticated
      (`~/.claude/.credentials.json` must exist).
    - Doesn't work in Docker out of the box — bind-mount `~/.claude` and
      install the `claude` CLI inside the image first.
    - The LLM tool-calling loop is NOT bridged. The SDK has its own tool
      protocol; the deterministic investigation pipeline still pre-computes
      the evidence bundle and injects it via the system prompt, so the LLM
      sees Wazuh/LC/Suricata data — it just can't iteratively ask for more
      mid-response.
    """

    def __init__(self) -> None:
        self.client: Any = None
        self._query = None
        self._opts_cls = None
        self._assistant_msg_cls = None
        self._text_block_cls = None
        try:
            from claude_agent_sdk import (
                query as _query,
                ClaudeAgentOptions,
                AssistantMessage,
                TextBlock,
            )
            self._query = _query
            self._opts_cls = ClaudeAgentOptions
            self._assistant_msg_cls = AssistantMessage
            self._text_block_cls = TextBlock
            # Truthy sentinel so _provider_chain() recognises us as available.
            self.client = self
        except ImportError as e:
            logger.warning("claude-agent-sdk not installed (%s); SDK provider disabled.", e)

    def chat(
        self,
        model: Optional[str],
        messages: List[Dict[str, Any]],
        max_tokens: int,
        temperature: float,
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: Optional[str] = None,
    ):
        if not self.client:
            raise RuntimeError("claude-agent-sdk not installed")
        # Each query() call is a fresh agent invocation, so we fold the
        # OpenAI-shape conversation into a single prompt string and a single
        # system_prompt rather than relying on SDK session state.
        system_parts: List[str] = []
        convo_lines: List[str] = []
        for m in messages:
            role = m.get("role")
            content = m.get("content")
            if isinstance(content, list):
                # Extract text blocks; images can't be passed via SDK CLI
                text_parts = [b.get("text", "") for b in content if b.get("type") == "text"]
                has_images = any(b.get("type") == "image_url" for b in content)
                content = " ".join(text_parts)
                if has_images:
                    note = "[Image attached — switch to Anthropic API or GPT-4 for vision analysis]"
                    content = (content + " " + note).strip() if content else note
            if not content or not isinstance(content, str):
                continue
            if role == "system":
                system_parts.append(content)
            elif role == "user":
                convo_lines.append(f"USER: {content}")
            elif role == "assistant":
                convo_lines.append(f"ASSISTANT: {content}")

        system_prompt = "\n\n".join(p for p in system_parts if p) or None
        prompt = "\n\n".join(convo_lines) or "(image attached — no text)"

        # ARG_MAX guard: the SDK puts --system-prompt <text> on argv, which on
        # macOS caps at 1MB total. A SOC investigation easily blows past that
        # (system prompt + DEPLOYMENT_MEMORY + EVIDENCE_BUNDLE + RAG snippets).
        # The SDK accepts a {"type": "file", "path": ...} dict that maps to
        # --system-prompt-file, sidestepping the limit. Threshold is well
        # below ARG_MAX so the prompt + rest of argv still fits comfortably.
        import os as _os, tempfile as _tempfile
        sys_prompt_tmpfile: Optional[str] = None
        if system_prompt and len(system_prompt) > 32_000:
            tf = _tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", prefix="soc-sysprompt-",
                delete=False, encoding="utf-8",
            )
            tf.write(system_prompt)
            tf.close()
            sys_prompt_tmpfile = tf.name
            system_prompt_param: Any = {"type": "file", "path": sys_prompt_tmpfile}
        else:
            system_prompt_param = system_prompt

        opts_kwargs: Dict[str, Any] = {
            "system_prompt": system_prompt_param,
            "max_turns": 1,
            # Disable Claude Code's built-in tools (Read/Bash/Write/etc.).
            # Evidence is already pre-injected via system_prompt.
            "allowed_tools": [],
        }
        if model:
            opts_kwargs["model"] = model
        options = self._opts_cls(**opts_kwargs)

        try:
            text = self._run_async_sync(self._collect_response(prompt, options))
        finally:
            if sys_prompt_tmpfile is not None:
                try:
                    _os.unlink(sys_prompt_tmpfile)
                except OSError:
                    pass
        msg = _AdaptedMessage(content=text or None, tool_calls=None)
        return _AdaptedResponse(msg)

    async def _collect_response(self, prompt: str, options: Any) -> str:
        parts: List[str] = []
        result_error: Optional[str] = None
        async for msg in self._query(prompt=prompt, options=options):
            if isinstance(msg, self._assistant_msg_cls):
                for block in (getattr(msg, "content", None) or []):
                    if isinstance(block, self._text_block_cls):
                        parts.append(getattr(block, "text", "") or "")
                continue
            # Surface SDK-level errors (rate limit, auth, CLI failure) instead
            # of returning empty text and letting the caller guess. We look at
            # the message class name rather than importing every type, so the
            # check survives SDK version bumps.
            cls_name = type(msg).__name__
            if cls_name == "ResultMessage":
                if getattr(msg, "is_error", False):
                    subtype = getattr(msg, "subtype", None) or "error"
                    reason = getattr(msg, "result", None) or subtype
                    result_error = f"claude_agent_sdk: {subtype}: {reason}"
            elif cls_name == "RateLimitEvent":
                info = getattr(msg, "rate_limit_info", None)
                if info is not None:
                    # Snapshot every rate-limit event regardless of status —
                    # the Usage page wants to show "52% used" even when the
                    # call is still allowed through.
                    snapshot = {
                        "status": getattr(info, "status", None),
                        "rate_limit_type": getattr(info, "rate_limit_type", None),
                        "utilization": getattr(info, "utilization", None),
                        "resets_at": getattr(info, "resets_at", None),
                        "overage_status": getattr(info, "overage_status", None),
                        "overage_resets_at": getattr(info, "overage_resets_at", None),
                    }
                    _record_rate_limit(snapshot)
                    status = snapshot["status"]
                    if status and status not in ("allowed", "ok"):
                        rl_type = snapshot["rate_limit_type"] or "unknown"
                        result_error = (
                            f"claude_agent_sdk rate limit ({rl_type}): status={status}, "
                            f"overage={snapshot['overage_status']}"
                        )
        text = "".join(parts)
        if not text and result_error:
            raise RuntimeError(result_error)
        return text

    @staticmethod
    def _run_async_sync(coro: Any) -> Any:
        """Run an async coroutine from sync code whether or not the caller is
        already inside an event loop. FastAPI's `def` endpoints run in a
        threadpool worker (no loop), so the fast path here is asyncio.run.
        The slow path covers being called from an `async def` context."""
        import asyncio
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()


def _is_retryable_error(exc: Exception) -> bool:
    s = str(exc).lower()
    # Inspect common attributes
    code = None
    try:
        code = getattr(exc, 'status_code', None) or getattr(exc, 'http_status', None) or getattr(exc, 'code', None)
    except Exception:
        code = None
    try:
        if code is not None:
            c = int(code)
            if c == 429 or (500 <= c <= 599):
                return True
    except Exception:
        pass
    # Textual indicators
    if 'rate limit' in s or 'rate_limit' in s or '429' in s:
        return True
    if 'insufficient' in s and 'quota' in s:
        return True
    if re.search(r'5\d{2}', s):
        return True
    return False


# Provider registry. Holds the actual instances; reload_providers() recycles
# them after a settings-store write so admin changes take effect without an
# uvicorn restart.
_PROVIDERS: Dict[str, Optional[LLMProvider]] = {
    "claude_agent_sdk": None,
    "anthropic": None,
    "openai": None,
    "gemini": None,
    "groq": None,
    "xai": None,
    "perplexity": None,
    "openrouter": None,
    "deepseek": None,
    "qwen": None,
    "kimi": None,
    "ollama": None,
}

# Fixed base URLs for each cloud provider; not user-configurable (except ollama).
_PROVIDER_BASE_URLS: Dict[str, str] = {
    "gemini":     "https://generativelanguage.googleapis.com/v1beta/openai/",
    "groq":       "https://api.groq.com/openai/v1",
    "xai":        "https://api.x.ai/v1",
    "perplexity": "https://api.perplexity.ai",
    "openrouter": "https://openrouter.ai/api/v1",
    "deepseek":   "https://api.deepseek.com/v1",
    "qwen":       "https://dashscope.aliyuncs.com/compatible-mode/v1",
    "kimi":       "https://api.moonshot.cn/v1",
}

# Default fallback order when no custom chain is stored in DB.
_DEFAULT_CHAIN_ORDER = [
    "claude_agent_sdk",
    "anthropic",
    "openai",
    "gemini",
    "groq",
    "xai",
    "perplexity",
    "openrouter",
    "deepseek",
    "qwen",
    "kimi",
    "ollama",
]


def _default_model_for(name: str) -> Optional[str]:
    if name == "anthropic":
        return settings.ANTHROPIC_MODEL
    if name == "openai":
        return settings.OPENAI_MODEL
    if name == "claude_agent_sdk":
        return settings.CLAUDE_AGENT_SDK_MODEL
    if name == "ollama":
        return settings.OLLAMA_MODEL
    return None


def reload_providers() -> Dict[str, bool]:
    """Re-instantiate every provider from current settings (DB-overrides + .env).
    Returns {name: configured?} so the caller can confirm the new state."""
    _PROVIDERS["claude_agent_sdk"] = (
        ClaudeAgentSDKProvider()
        if _effective_bool("claude_agent_sdk_enabled", settings.USE_CLAUDE_AGENT_SDK)
        else None
    )
    _PROVIDERS["anthropic"] = AnthropicProvider()
    _PROVIDERS["openai"] = OpenAIProvider()

    # Generic cloud providers (all OpenAI-compatible)
    for name in ("gemini", "groq", "xai", "perplexity", "openrouter", "qwen", "kimi"):
        env_key = getattr(settings, f"{name.upper()}_API_KEY", None)
        api_key = _effective(f"{name}_api_key", env_key)
        if api_key:
            _PROVIDERS[name] = GenericOpenAICompatibleProvider(
                name, _PROVIDER_BASE_URLS[name], api_key
            )
        else:
            _PROVIDERS[name] = None

    # DeepSeek — API key + configurable base URL
    ds_key = _effective("deepseek_api_key", settings.DEEPSEEK_API_KEY)
    ds_url = _PROVIDER_BASE_URLS["deepseek"]  # base URL not user-overridable via UI
    _PROVIDERS["deepseek"] = GenericOpenAICompatibleProvider("deepseek", ds_url, ds_key) if ds_key else None

    # Ollama — no API key needed; base URL determines whether it's enabled
    ollama_url = _effective("ollama_base_url", settings.OLLAMA_BASE_URL)
    _PROVIDERS["ollama"] = GenericOpenAICompatibleProvider("ollama", ollama_url, None) if ollama_url else None

    return {name: (p is not None and getattr(p, "client", None) is not None)
            for name, p in _PROVIDERS.items()}


# Initial bootstrap at import time.
reload_providers()


def any_provider_configured() -> bool:
    """True if at least one LLM provider is wired and ready. Used by request
    guards in main.py to fail fast with an actionable error instead of
    pretending to chat and then returning 'Model unavailable'."""
    return bool(_provider_chain())


def configured_provider_names() -> List[str]:
    """Names of currently-available providers, in fallback order."""
    return [name for (name, _, _) in _provider_chain()]


_VISION_CAPS: Dict[str, Dict[str, Any]] = {
    "anthropic":         {"supported": True,  "note": "Claude API — vision on all models (JPEG/PNG/GIF/WebP, up to 20 images, 5 MB each)"},
    "openai":            {"supported": True,  "note": "OpenAI — vision on gpt-5.x, gpt-4.1, gpt-4o, o3, o4-mini (up to 10 images, 20 MB each)"},
    "gemini":            {"supported": True,  "note": "Gemini — all current models support vision (up to 16 images per request)"},
    "groq":              {"supported": True,  "note": "Groq — use llama-4-scout, llama-4-maverick, or qwen3-vl-32b for vision"},
    "xai":               {"supported": True,  "note": "xAI — grok-4.3 and grok-4-0709 support vision"},
    "openrouter":        {"supported": True,  "note": "OpenRouter — vision depends on the routed model"},
    "claude_agent_sdk":  {"supported": False, "note": "Claude Agent SDK — vision not supported via CLI; switch to Anthropic API for image analysis"},
    "deepseek":          {"supported": False, "note": "DeepSeek V4 — text only, no vision support"},
    "ollama":            {"supported": None,  "note": "Ollama — vision depends on loaded model (llama4:scout, qwen3-vl, gemma3 support vision)"},
    "perplexity":        {"supported": False, "note": "Perplexity Sonar — vision not supported"},
    "qwen":              {"supported": True,  "note": "Qwen — vision via qwen3-vl-plus or qwen3-vl-flash models"},
    "kimi":              {"supported": True,  "note": "Kimi — vision via kimi-k2.5 model"},
}


def get_active_vision_info() -> Dict[str, Any]:
    """Return vision capabilities for the first available provider in the active chain."""
    active = get_active_provider()
    if active == "auto":
        chain = _provider_chain()
        active = chain[0][0] if chain else "unknown"
    caps = _VISION_CAPS.get(active, {"supported": None, "note": "Vision support unknown for this provider"})
    return {"provider": active, **caps}


def get_active_provider() -> str:
    """Return the admin-selected provider, or 'auto' for chain-order
    fallback. Used by the Usage page to show the current pinning."""
    v = settings_store.get("active_provider") or "auto"
    return v if v in ("auto",) + tuple(_PROVIDERS.keys()) else "auto"


def _provider_chain() -> List[Tuple[str, LLMProvider, Optional[str]]]:
    """Return the priority-ordered list of (name, provider, model) tuples
    for available providers only.

    Order is determined by the user-stored `provider_chain` JSON array in DB;
    falls back to _DEFAULT_CHAIN_ORDER when no custom chain is set. Providers
    not in the user's chain are appended at the end in default order so newly-
    added providers still participate without requiring a chain re-save.

    If active_provider is pinned (not 'auto'), only that provider is returned.
    """
    active = get_active_provider()

    # Determine chain order (user-defined or default)
    # When user has explicitly saved a chain, respect it exactly — no auto-appending.
    # This ensures if a user puts only Ollama in the chain, Claude SDK is never
    # used as a silent fallback even if it's configured.
    chain_json = settings_store.get("provider_chain")
    if chain_json:
        try:
            user_order: List[str] = json.loads(chain_json)
            known = set(_PROVIDERS.keys())
            ordered = [n for n in user_order if n in known]
        except Exception:
            ordered = list(_DEFAULT_CHAIN_ORDER)
    else:
        ordered = list(_DEFAULT_CHAIN_ORDER)

    full: List[Tuple[str, LLMProvider, Optional[str]]] = []
    for name in ordered:
        p = _PROVIDERS.get(name)
        if p is None or getattr(p, "client", None) is None:
            continue
        model = _effective(f"{name}_model", _default_model_for(name))
        full.append((name, p, model))

    if active != "auto":
        return [t for t in full if t[0] == active]
    return full


_RATE_LIMIT_HINT_PATTERNS = (
    "rate limit", "rate_limit", "quota", "overage", "429",
    "exceeded", "five_hour", "5_hour", "hourly", "daily limit",
)

# The Claude Code CLI raises a generic "returned an error result: success"
# when the subprocess exits cleanly but the API call inside got rejected —
# the "success" is the subprocess subtype, not the actual outcome. In
# practice this signature ~always means the 5-hour Claude subscription
# window is full (the CLI checks quota before issuing the request, so the
# RateLimitEvent never even fires).
_SDK_CLI_QUOTA_SIGNATURE = "returned an error result"

# API-side credit/key failure signatures. These are matched in the raw
# error string from the Anthropic / OpenAI SDKs.
_API_INVALID_KEY_PATTERNS = (
    "invalid api key", "invalid_api_key", "authentication_error",
    "401", "unauthorized", "incorrect api key",
)
_API_OUT_OF_CREDITS_PATTERNS = (
    "credit balance", "credit_balance", "insufficient_quota",
    "insufficient credits", "billing", "402 payment required",
)


def _format_reset_in(resets_at: Any) -> str:
    """Return ' (resets in 2h 44m)' or '' if we can't compute it. resets_at
    from the SDK is Unix seconds; tolerate strings, missing values, etc."""
    try:
        if resets_at is None:
            return ""
        ts = int(resets_at)
        from time import time as _now
        ms = ts - int(_now())
        if ms <= 0:
            return " (window already reset)"
        h, m = divmod(ms // 60, 60)
        return f" (resets in {h}h {m}m)"
    except (TypeError, ValueError):
        return ""


def _sdk_quota_hint() -> str:
    """SDK quota hint, enriched with live rate-limit telemetry if we have it.
    Pulls from the snapshot ClaudeAgentSDKProvider captures on each call —
    so the user sees "0% remaining, resets in 2h 44m" not just a generic
    "looks like a rate limit" message."""
    rl = _LAST_RATE_LIMIT_INFO or {}
    util = rl.get("utilization")
    pct_str = ""
    if util is not None:
        try:
            pct = int(round(util * 100 if float(util) <= 1 else float(util)))
            pct_str = f" (currently {pct}% used)"
        except (TypeError, ValueError):
            pass
    reset_str = _format_reset_in(rl.get("resets_at"))
    return (
        f" Claude subscription 5-hour session window{pct_str}{reset_str}. "
        "Wait for the window to reset, or open Settings → LLM Providers → "
        "Anthropic API, paste a key from console.anthropic.com, and Save — "
        "the chain will fall through to the API on the next request."
    )


def _format_chain_failure(failures: List[Tuple[str, str]]) -> str:
    """Build a user-facing error message when every LLM provider failed.

    Names the providers that were actually tried (vs. the old generic
    "check ANTHROPIC_API_KEY/OPENAI_API_KEY" that misleads SDK users), and
    classifies the failure: SDK quota, API invalid key, API out of credits,
    generic rate-limit, or unknown. Each gets an actionable hint.
    """
    if not failures:
        return (
            "Model unavailable: no LLM provider is configured. "
            "Open Settings → LLM Providers to paste an API key or enable the "
            "Claude Agent SDK, or set ANTHROPIC_API_KEY / OPENAI_API_KEY in .env."
        )
    tried = ", ".join(name for name, _ in failures)
    last_name, last_err = failures[-1]
    blob = " ".join(err for _, err in failures).lower()
    hint = ""
    sdk_failed = any(name == "claude_agent_sdk" for name, _ in failures)
    api_failed = any(name != "claude_agent_sdk" for name, _ in failures)

    if sdk_failed and (_SDK_CLI_QUOTA_SIGNATURE in blob
                       or any(p in blob for p in _RATE_LIMIT_HINT_PATTERNS)):
        hint = _sdk_quota_hint()
    elif api_failed and any(p in blob for p in _API_OUT_OF_CREDITS_PATTERNS):
        hint = (
            " API credit balance is empty. Recharge at console.anthropic.com "
            "(Settings → Billing) or platform.openai.com (Settings → Billing). "
            "Once topped up the next chat works without restart."
        )
    elif api_failed and any(p in blob for p in _API_INVALID_KEY_PATTERNS):
        hint = (
            " API key is invalid or expired. Open Settings → LLM Providers, "
            "paste a fresh key, and Save."
        )
    elif any(p in blob for p in _RATE_LIMIT_HINT_PATTERNS):
        hint = (
            " Provider quota/rate-limit. Check the provider dashboard or "
            "wait for the window to reset."
        )
    return (
        f"Model unavailable: tried {tried}; last error from {last_name}: {last_err}."
        f"{hint}"
    )


def chat_with_history(
    system_prompt: str,
    history_messages: List[dict],
    retrieved: List[str] = None,
    max_tokens: int = 1600,
    response_mode: Optional[str] = None,
    evidence: Optional[Dict[str, Any]] = None,
    temperature: float = 0.2,
    tool_runner: Optional[ToolRunner] = None,
    current_user: Optional[Dict[str, Any]] = None,
    user_prefs: Optional[Dict[str, Any]] = None,
    deployment_memory: Optional[str] = None,
) -> str:
    messages = [{"role": "system", "content": system_prompt}]
    if deployment_memory:
        messages.append({"role": "system", "content": f"DEPLOYMENT_MEMORY:\n{deployment_memory}"})
    if response_mode:
        messages.append({"role": "system", "content": f"RESPONSE_MODE: {response_mode}"})
    if user_prefs:
        try:
            prefs_text = json.dumps(user_prefs, ensure_ascii=False)
        except Exception:
            prefs_text = str(user_prefs)
        messages.append({"role": "system", "content": f"USER_PREFERENCES: {prefs_text}"})
    if evidence:
        try:
            ev_text = json.dumps(evidence, ensure_ascii=False)
        except Exception:
            ev_text = str(evidence)
        messages.append({"role": "system", "content": f"EVIDENCE_BUNDLE: {ev_text}"})
    if retrieved:
        messages.append({"role": "system", "content": (
            "PLAYBOOK KNOWLEDGE (from your organization's indexed security runbooks):\n\n"
            + "\n---\n".join(retrieved)
            + "\n\n"
            "INSTRUCTIONS — you MUST apply this knowledge:\n"
            "- Use the specific investigation steps, commands, and procedures from these playbooks to answer the analyst.\n"
            "- Replace generic advice with the exact steps from the playbook (e.g. specific log queries, file paths, commands to run).\n"
            "- In Section 2, structure your reasoning around what the playbook says about this type of activity.\n"
            "- End Section 2 with: _(playbook: <source filename>)_\n"
            "- If the playbook does not cover this specific case, say so and fall back to your training knowledge."
        )})
    for m in history_messages:
        if m.get("role") in ("user", "assistant") and m.get("content"):
            messages.append({"role": m["role"], "content": m["content"]})

    # Tool spec generation (unchanged behavior)
    tools_spec = None
    if tool_runner is not None:
        approved = ToolRunner.approved_queries()
        all_qids = sorted({q for qlist in approved.values() for q in qlist})
        tools_spec = [
            {
                "type": "function",
                "function": {
                    "name": "tool_execute",
                    "description": "Execute approved read-only SOC tools to gather evidence from configured connectors (see DEPLOYMENT_MEMORY for active sources).",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "tool_name": {"type": "string", "enum": list(approved.keys())},
                            "query_id": {"type": "string", "enum": all_qids},
                            "params": {"type": "object", "additionalProperties": True},
                            "earliest": {"type": ["string", "null"]},
                            "latest": {"type": ["string", "null"]},
                        },
                        "required": ["tool_name", "query_id"],
                    },
                },
            }
        ]

    def _call_provider(provider: LLMProvider, model: Optional[str]):
        return provider.chat(model, messages, max_tokens=max_tokens, temperature=temperature, tools=tools_spec, tool_choice=("auto" if tools_spec else None))

    chain_failures: List[Tuple[str, str]] = []

    def _call_chain():
        """Try providers in priority order; return the first success or None.

        The chain is built dynamically each call so newly-configured providers
        are picked up without process restart (relevant for tests). Any
        exception from a provider falls through to the next provider —
        retryable/non-retryable distinctions don't matter here because we
        don't retry the same provider with the same args.

        Side effect: appends (provider_name, error_str) to chain_failures so
        the outer caller can surface a meaningful error message instead of a
        generic "Model unavailable" when the whole chain fails.
        """
        chain_failures.clear()
        chain = _provider_chain()
        if not chain:
            logger.error("No LLM providers configured (no API keys set)")
            return None
        import time
        for name, provider, model in chain:
            t0 = time.monotonic()
            try:
                logger.debug("LLM chain: trying %s (model=%s)", name, model)
                resp = _call_provider(provider, model)
                _record_call(name, model, ok=True, error=None,
                             duration_ms=int((time.monotonic() - t0) * 1000))
                return resp
            except Exception as e:
                chain_failures.append((name, str(e)))
                logger.warning("%s provider failed: %s", name, str(e))
                _record_call(name, model, ok=False, error=str(e),
                             duration_ms=int((time.monotonic() - t0) * 1000))
        if chain_failures:
            logger.error("All providers failed: %s", chain_failures)
        return None

    def _is_valid_markdown(s: str) -> bool:
        if not s:
            return False
        st = s.strip()
        if st.startswith('{') or st.startswith('['):
            return False
        return True

    # Primary call through the provider chain (Anthropic -> OpenAI -> DeepSeek)
    resp = _call_chain()
    if resp is None:
        return _format_chain_failure(chain_failures)

    # Proceed with tool-calling loop if model responded (reuse existing code semantics)
    try:
        choice = resp.choices[0]
        msg = choice.message
    except Exception:
        # Unexpected shape
        return f"Error generating response: unexpected provider response"

    # Autonomous tool-calling loop (max 5 steps, prevents infinite repeats)
    MAX_STEPS = 5
    tool_step = 0
    executed_tools_in_cycle = []  # Track (tool_name, query_id, params_hash) to prevent repeats
    
    while tool_runner is not None and msg and getattr(msg, "tool_calls", None) and tool_step < MAX_STEPS:
        tool_step += 1
        logger.info("Tool execution step %d/%d", tool_step, MAX_STEPS)
        
        messages.append({
            "role": "assistant",
            "content": msg.content or "",
            "tool_calls": [
                {
                    "id": tc.id,
                    "type": tc.type,
                    "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                }
                for tc in (msg.tool_calls or [])
            ],
        })

        tools_executed_this_step = []
        for tc in (msg.tool_calls or []):
            if not tc or not tc.function or tc.function.name != "tool_execute":
                tool_content = json.dumps({"error": f"Unsupported tool {getattr(tc.function,'name',None)}"})
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": tool_content})
                continue
            try:
                args = json.loads(tc.function.arguments or "{}")
            except Exception:
                args = {}
            tname = args.get("tool_name")
            qid = args.get("query_id")
            params = args.get("params") or {}
            earliest = args.get("earliest")
            latest = args.get("latest")
            
            # Check for infinite repeat: same tool + query_id + params combo in this cycle
            params_hash = json.dumps(params, sort_keys=True)
            tool_sig = (tname, qid, params_hash)
            if tool_sig in executed_tools_in_cycle:
                logger.warning("Detected repeated tool call (tool=%s, query_id=%s). Breaking loop to prevent infinite repeat.", tname, qid)
                tool_content = json.dumps({"error": "Skipped: repeated tool call (infinite loop prevention)"})
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": tool_content})
                continue
            
            executed_tools_in_cycle.append(tool_sig)
            tools_executed_this_step.append(f"{tname}:{qid}")
            
            try:
                tool_out = tool_runner.execute(tname, qid, params, earliest, latest, current_user or {})
                tool_blob = {"EVIDENCE_BUNDLE": {"tool_results": tool_out}}
                tool_content = json.dumps(tool_blob, ensure_ascii=False)
            except Exception as ex:
                tool_content = json.dumps({"error": str(ex)})
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": tool_content})
        
        logger.info("Step %d executed tools: %s", tool_step, ", ".join(tools_executed_this_step))

        # Re-call the provider chain with the tool results in context
        resp = _call_chain()
        if resp is None:
            logger.error("All providers failed during tool-loop step %d", tool_step)
            break
        try:
            choice = resp.choices[0]
            msg = choice.message
        except Exception:
            return f"Error generating response: unexpected provider response"
    
    if tool_step >= MAX_STEPS:
        logger.info("Tool execution loop reached MAX_STEPS (%d). Returning final answer.", MAX_STEPS)
    elif tool_step > 0:
        logger.info("Tool execution loop completed after %d steps. No further tool calls.", tool_step)

    text = (msg.content or "") if msg else ""
    if _is_valid_markdown(text):
        return text

    retry_msg = (
        "Return Markdown only. Start with a 1–3 line direct answer to the user's last question, then include the three sections only if relevant: \n"
        "SECTION 1 — Automated Analysis (Transparent)\n"
        "SECTION 2 — Directed L1 Next Steps (Actionable)\n"
        "SECTION 3 — Current Verdict (Decision). Do NOT return JSON or code fences."
    )
    messages.append({"role": "user", "content": retry_msg})

    # Final retry through the chain. If even this fails, return what we had.
    resp2 = _call_chain()
    if resp2 is None:
        return text or "Model unavailable on retry."
    try:
        return resp2.choices[0].message.content or text
    except Exception:
        return f"Error generating response: unexpected provider response"


def _is_ollama_active() -> bool:
    """Return True if the first available provider in the chain is ollama."""
    try:
        chain = _provider_chain()
        return bool(chain) and chain[0][0] == "ollama"
    except Exception:
        return False


def validate_and_retry_if_needed(
    response: str,
    retrieved: List[str],
    system_prompt: str,
    history_messages: List[dict],
    evidence: Optional[Dict[str, Any]],
    response_mode: Optional[str],
    temperature: float,
    tool_runner: Optional[Any],
    current_user: Optional[Dict[str, Any]],
    user_prefs: Optional[Dict[str, Any]],
    deployment_memory: Optional[str],
) -> Tuple[str, bool]:
    """Validate that the LLM response used playbook content. If not, retry once.

    Returns (final_response, was_retried).
    Only called when provider is ollama and RAG retrieved chunks.
    """
    playbook_text = "\n---\n".join(retrieved)

    # Cheap YES/NO validation call
    validation_system = (
        "You are a quality checker. Answer with YES or NO only — no explanation."
    )
    validation_question = (
        "A cybersecurity AI had access to these playbook steps:\n\n"
        f"{playbook_text}\n\n"
        f"The AI gave this response:\n\n{response}\n\n"
        "Did the response use SPECIFIC steps, commands, thresholds, or tool names "
        "from the playbook above? Answer YES or NO only."
    )
    try:
        verdict = chat_with_history(
            system_prompt=validation_system,
            history_messages=[{"role": "user", "content": validation_question}],
            max_tokens=5,
            temperature=0,
        )
        used_playbook = "YES" in verdict.upper()
    except Exception:
        logger.warning("RAG validation call failed — returning original response.")
        return response, False

    if used_playbook:
        return response, False

    # Retry with a stricter prompt that quotes the playbook directly
    retry_history = list(history_messages)
    last = retry_history[-1]
    retry_history[-1] = {
        "role": last.get("role", "user"),
        "content": (
            last.get("content", "") +
            "\n\nYour previous response was too generic and did not use the playbook. "
            "You MUST answer using ONLY the specific steps below — do not add anything not in the playbook:\n\n"
            f"{playbook_text}"
        ),
    }
    try:
        retried = chat_with_history(
            system_prompt=system_prompt,
            history_messages=retry_history,
            retrieved=retrieved,
            max_tokens=1600,
            response_mode=response_mode,
            evidence=evidence,
            temperature=temperature,
            tool_runner=tool_runner,
            current_user=current_user,
            user_prefs=user_prefs,
            deployment_memory=deployment_memory,
        )
        return retried, True
    except Exception:
        logger.warning("RAG validation retry failed — returning original response.")
        return response, False


_SUMMARIZE_SYSTEM = (
    "You are summarizing a past SOC chat conversation for the same analyst's future reference. "
    "Produce a single-paragraph markdown summary of 80-150 words. Cover: "
    "(1) what the analyst investigated (IOCs, alerts, scenarios); "
    "(2) what evidence was gathered (sources queried, key findings); "
    "(3) what verdict was reached, if any; "
    "(4) any explicit follow-ups, escalations, or open questions. "
    "Do not invent facts not present in the messages. Do not include section headers, bullet "
    "lists, or framing like 'In this conversation'. Output the summary text only."
)


def summarize_messages(messages: List[Dict[str, str]], max_tokens: int = 400) -> Optional[str]:
    """One-shot LLM call to compress a conversation. Returns None on failure
    (no provider configured, model errored, empty/garbage output) so callers
    can skip silently rather than store junk."""
    try:
        history = [m for m in (messages or []) if m.get("role") in ("user", "assistant") and m.get("content")]
        if not history:
            return None
        out = chat_with_history(
            system_prompt=_SUMMARIZE_SYSTEM,
            history_messages=history,
            max_tokens=max_tokens,
            temperature=0.2,
            tool_runner=None,
        )
    except Exception:
        logger.exception("summarize_messages failed")
        return None
    if not out:
        return None
    bad_prefixes = ("Model unavailable", "Error generating response")
    if any(out.startswith(p) for p in bad_prefixes):
        return None
    return out.strip() or None
