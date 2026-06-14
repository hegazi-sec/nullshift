"""RAG over local markdown playbooks using Chroma + embeddings.

On startup we walk ./data/kb/ recursively and re-index any .md file whose
mtime is newer than what is already stored in the Chroma collection.

The embedding provider is chosen by walking the same provider_chain the user
configured in Admin Settings → LLM Providers, in the same order. The first
provider in that chain that supports embeddings AND has a key configured is
used. Providers that are LLM-only (Claude, Groq, etc.) are skipped
silently. If none qualify, RAG is disabled and chat still works without it.

Providers with embedding support: openai, gemini, ollama.
"""
from __future__ import annotations

import json
import logging
import re
import shutil
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, cast

from app.config import settings

logger = logging.getLogger("nullshift.rag")

_APP_DIR = Path(__file__).resolve().parent
KB_PATH = _APP_DIR.parent / "data" / "kb"
CHROMA_PATH = _APP_DIR.parent / "data" / "chroma"
CHUNK_SIZE = 600
CHUNK_OVERLAP = 80
DEFAULT_TOP_K = 4
EMBED_BATCH_SIZE = 100  # Gemini BatchEmbed limit is 100; safe for all providers

# The same default order used by llm.py when no chain is stored in DB.
# Keep in sync with _DEFAULT_CHAIN_ORDER in llm.py.
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
    "ollama",
]


def _chunk_markdown(text: str) -> List[str]:
    """Split markdown into ~CHUNK_SIZE chunks with overlap, respecting H1/H2 boundaries."""
    out: List[str] = []
    if not text:
        return out
    sections = re.split(r"(?m)^(?=#{1,2}\s)", text)
    for section in sections:
        section = section.strip()
        if not section:
            continue
        if len(section) <= CHUNK_SIZE:
            out.append(section)
            continue
        start = 0
        while start < len(section):
            end = min(start + CHUNK_SIZE, len(section))
            if end < len(section):
                break_at = section.rfind("\n\n", start + CHUNK_SIZE // 2, end)
                if break_at != -1:
                    end = break_at
            chunk = section[start:end].strip()
            if chunk:
                out.append(chunk)
            if end >= len(section):
                break
            start = max(end - CHUNK_OVERLAP, start + 1)
    return out


def _try_provider_embedding(
    provider_name: str,
    eff: Callable[[str, Optional[str]], Optional[str]],
) -> Optional[Any]:
    """Return a chromadb embedding function for the given provider, or None.

    Providers without embedding support (claude_agent_sdk, anthropic, groq,
    xai, perplexity, openrouter, deepseek) return None
    without logging — they are silently skipped in the chain walk.
    """
    custom_model = eff("rag_embedding_model", None)

    if provider_name == "openai":
        key = eff("openai_api_key", settings.OPENAI_API_KEY)
        if not key:
            return None
        try:
            from chromadb.utils.embedding_functions import OpenAIEmbeddingFunction
            return OpenAIEmbeddingFunction(api_key=key, model_name=custom_model or "text-embedding-3-small")
        except Exception as e:
            logger.warning("OpenAI embedding init failed: %s", e)
            return None

    if provider_name == "gemini":
        key = eff("gemini_api_key", settings.GEMINI_API_KEY)
        if not key:
            return None
        try:
            import os as _os
            from chromadb.utils.embedding_functions.google_embedding_function import GoogleGeminiEmbeddingFunction
            _os.environ.setdefault("GEMINI_API_KEY", key)
            return GoogleGeminiEmbeddingFunction(model_name=custom_model or "gemini-embedding-001")
        except Exception as e:
            logger.warning("Gemini embedding init failed: %s", e)
            return None

    if provider_name == "ollama":
        url = eff("ollama_base_url", settings.OLLAMA_BASE_URL)
        if not url:
            logger.warning("Ollama selected for RAG but no URL configured — set it in Admin → LLM Providers or Admin → RAG. Trying http://localhost:11434 as fallback.")
            url = "http://localhost:11434"
        try:
            from chromadb.utils.embedding_functions import OpenAIEmbeddingFunction
            base = url.rstrip("/")
            if not base.endswith("/v1"):
                base = f"{base}/v1"
            if not custom_model:
                logger.warning("Ollama embedding model not set — configure it in Admin → RAG → Embedding model.")
                return None
            return OpenAIEmbeddingFunction(
                api_key="ollama",
                api_base=base,
                model_name=custom_model,
            )
        except Exception as e:
            logger.warning("Ollama embedding init failed: %s", e)
            return None

    # LLM-only providers — no embedding API: claude_agent_sdk, anthropic,
    # groq, xai, perplexity, openrouter, deepseek.
    return None


def _build_embedding_fn() -> Tuple[Optional[Any], Optional[str]]:
    """Return (embed_fn, provider_name) based on Admin Settings configuration.

    Respects two settings written by the admin UI:
      rag_enabled            — 'false' short-circuits immediately (RAG off)
      rag_embedding_provider — 'auto' walks the provider chain; any specific
                               name (openai/gemini/ollama) goes direct.
    """
    ss = None
    try:
        from app.db.settings_store import settings_store  # type: ignore[attr-defined]
        ss = settings_store
    except Exception:
        pass

    def _eff(key: str, env_val: Optional[str]) -> Optional[str]:
        if ss:
            try:
                v = ss.get(key)
                if v:
                    return v
            except Exception:
                pass
        return env_val

    # Respect the RAG enabled/disabled toggle (default: disabled)
    rag_enabled = _eff("rag_enabled", "false")
    if rag_enabled == "false":
        logger.info("RAG disabled via Admin Settings.")
        return None, None

    # Respect the explicit embedding provider choice
    chosen = _eff("rag_embedding_provider", "auto")

    if chosen and chosen != "auto":
        fn = _try_provider_embedding(chosen, _eff)
        if fn is not None:
            logger.info("RAG embedding provider: %s (explicitly configured)", chosen)
            return fn, chosen
        logger.warning(
            "RAG embedding provider '%s' is configured but has no API key set. "
            "Add the key in Admin Settings or switch to Auto.",
            chosen,
        )
        return None, None

    # Auto mode — walk the provider chain in the user's configured order
    chain: List[str] = []
    try:
        raw = ss.get("provider_chain") if ss else None
        if raw:
            chain = json.loads(raw)
    except Exception:
        pass

    if not chain:
        chain = list(_DEFAULT_CHAIN_ORDER)

    for provider_name in chain:
        fn = _try_provider_embedding(provider_name, _eff)
        if fn is not None:
            logger.info(
                "RAG embedding provider: %s (auto, chain position %d)",
                provider_name, chain.index(provider_name) + 1,
            )
            return fn, provider_name

    logger.warning(
        "RAG: no embedding-capable provider found in chain %s. "
        "RAG disabled. Go to Admin Settings → RAG and pick a provider, "
        "or add OpenAI / Gemini / Ollama to your chain.",
        chain,
    )
    return None, None


class _NoOpRAG:
    """Used when no embedding provider is available. Always returns no hits."""

    def __init__(self, reason: str = "no embedding provider configured") -> None:
        self._reason = reason

    def status(self) -> Dict[str, Any]:
        return {"enabled": False, "reason": self._reason}

    def retrieve(self, query: str, k: int = DEFAULT_TOP_K) -> List[str]:
        return []

    def retrieve_with_scores(self, query: str, k: int = DEFAULT_TOP_K) -> List[Dict[str, Any]]:
        return []


class RAG:
    def __init__(self) -> None:
        self.client = None
        self.collection = None
        self._embed_fn: Optional[Any] = None
        self._provider_name: Optional[str] = None
        self._collection_name: Optional[str] = None
        self._init_error: Optional[str] = None
        self._stop_event = threading.Event()
        self._sync_state: str = "idle"        # idle | running | complete | skipped
        self._sync_progress: str = ""         # human-readable progress line
        self._files_indexed: int = 0          # cached count, updated during sync
        self._chunks_indexed: int = 0         # cached chunk count, avoids DB query in status()
        self._init_chroma()
        if self.collection is not None:
            t = threading.Thread(target=self._sync_index, daemon=True, name="rag-sync")
            t.start()

    def status(self) -> Dict[str, Any]:
        """Return live RAG state for the Admin UI status panel."""
        if self.collection is None:
            return {
                "enabled": False,
                "reason": self._init_error or "unknown init failure",
            }
        return {
            "enabled": True,
            "provider": self._provider_name,
            "collection": self._collection_name,
            "chunks_indexed": self._chunks_indexed,
            "files_indexed": self._files_indexed,
            "sync_state": self._sync_state,
            "sync_progress": self._sync_progress,
        }

    def _init_chroma(self) -> None:
        try:
            import chromadb
        except ImportError as e:
            logger.warning("chromadb not installed (%s); RAG retrieval disabled.", e)
            return

        embed_fn, provider_name = _build_embedding_fn()
        if embed_fn is None:
            self._init_error = "no embedding-capable provider found in chain"
            return

        # Collection name is provider-specific to avoid vector incompatibility when
        # the user switches embedding providers (different models → incompatible vectors)
        collection_name = f"playbooks_{provider_name}"

        for attempt in range(2):
            try:
                CHROMA_PATH.mkdir(parents=True, exist_ok=True)
                self.client = chromadb.PersistentClient(path=str(CHROMA_PATH))
                self.collection = self.client.get_or_create_collection(
                    name=collection_name,
                    embedding_function=cast(Any, embed_fn),
                )
                self._embed_fn = embed_fn
                self._provider_name = provider_name
                self._collection_name = collection_name
                try:
                    self._chunks_indexed = self.collection.count()
                except Exception:
                    pass
                logger.info("RAG collection: %s (%d chunks)", collection_name, self._chunks_indexed)
                return
            except Exception as e:
                if attempt == 0:
                    logger.warning(
                        "Chroma init failed (attempt 1): %s — index may be corrupt. "
                        "Wiping %s and retrying.",
                        e, CHROMA_PATH,
                    )
                    try:
                        shutil.rmtree(CHROMA_PATH, ignore_errors=True)
                    except Exception as rm_err:
                        logger.warning("Failed to wipe Chroma dir: %s", rm_err)
                else:
                    logger.warning("Chroma init failed after wipe: %s. RAG disabled.", e)
                    self._init_error = str(e)
                    self.client = None
                    self.collection = None

    @property
    def _mtime_cache_path(self) -> Path:
        return CHROMA_PATH / "mtime_cache.json"

    def _existing_mtimes(self) -> Dict[str, float]:
        """Return {relative_source_path: mtime} from the local JSON cache (fast)."""
        try:
            return json.loads(self._mtime_cache_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except Exception as e:
            logger.warning("mtime cache unreadable (%s); treating all files as new.", e)
            return {}

    def _save_mtime_cache(self, mtimes: Dict[str, float]) -> None:
        try:
            self._mtime_cache_path.write_text(
                json.dumps(mtimes, indent=None), encoding="utf-8"
            )
        except Exception as e:
            logger.warning("Failed to save mtime cache: %s", e)

    def _delete_source(self, source: str) -> None:
        if self.collection is None:
            return
        try:
            self.collection.delete(where={"source": source})
        except Exception as e:
            err = str(e)
            if "compaction" in err.lower() or "hnsw" in err.lower():
                logger.warning(
                    "Chroma index corrupt (delete %s: %s) — wiping and reinitialising.", source, e
                )
                self.collection = None
                self.client = None
                try:
                    shutil.rmtree(CHROMA_PATH, ignore_errors=True)
                except Exception:
                    pass
                self._init_chroma()
                if self.collection is not None:
                    logger.info("Chroma rebuilt after corruption — restarting sync.")
                    self._sync_index()
                return
            logger.warning("Failed to delete old chunks for %s: %s", source, e)

    def _embed_batch_with_retry(
        self, docs: List[str], chunk_start: int, chunk_end: int, max_retries: int = 6
    ) -> Optional[Any]:
        """Call self._embed_fn with exponential backoff on rate-limit (429) errors."""
        delay = 5.0
        for attempt in range(max_retries):
            try:
                return self._embed_fn(docs)
            except Exception as e:
                err = str(e)
                is_rate_limit = "429" in err or "rate_limit" in err.lower()
                if not is_rate_limit or attempt == max_retries - 1:
                    logger.warning(
                        "RAG embed batch %d–%d failed (attempt %d): %s",
                        chunk_start, chunk_end, attempt + 1, e,
                    )
                    return None
                # Parse suggested wait from OpenAI error ("try again in 1.5s")
                m = re.search(r"try again in (\d+(?:\.\d+)?)(ms|s)", err)
                if m:
                    wait = float(m.group(1)) / 1000 if m.group(2) == "ms" else float(m.group(1))
                    wait = max(wait + 1.0, delay)
                else:
                    wait = delay
                logger.info(
                    "RAG rate-limited on chunks %d–%d; waiting %.1fs (attempt %d/%d).",
                    chunk_start, chunk_end, wait, attempt + 1, max_retries,
                )
                self._stop_event.wait(timeout=wait)
                if self._stop_event.is_set():
                    return None
                delay = min(delay * 2, 60.0)
        return None

    def _sync_index(self) -> None:
        """Re-embed any .md file whose mtime is newer than the indexed value."""
        self._sync_state = "running"
        self._sync_progress = "Checking index…"
        if self.collection is None:
            self._sync_state = "idle"
            return
        if not KB_PATH.exists():
            logger.info("RAG kb directory %s does not exist; no playbooks loaded.", KB_PATH)
            self._sync_state = "skipped"
            self._sync_progress = "KB directory not found"
            return

        existing = self._existing_mtimes()
        current_mtimes: Dict[str, float] = {}
        # rglob picks up nested skill directories (e.g. data/kb/cybersecurity-skills/**/*.md).
        # For nested files we only index SKILL.md — this filters out repo meta-files
        # (README, CONTRIBUTING, CODE_OF_CONDUCT, etc.) that live alongside the skills.
        # Top-level files directly under KB_PATH are always indexed regardless of name.
        files = sorted(
            f for f in KB_PATH.rglob("*.md")
            if f.parent == KB_PATH or f.name == "SKILL.md"
        )
        self._files_indexed = len(existing)
        # _chunks_indexed already set from collection.count() in _init_chroma()
        logger.info(
            "RAG sync: %d total files, %d already indexed (skipping those).",
            len(files), len(existing),
        )
        if not files:
            logger.info("RAG kb directory %s is empty; no playbooks to index.", KB_PATH)
            return

        # Collect all new/changed chunks first, then add in one bulk call.
        # A single collection.add() means one API roundtrip to the embedding
        # provider regardless of file count — vs. one roundtrip per file.
        all_ids: List[str] = []
        all_docs: List[str] = []
        all_metas: List[Dict[str, Any]] = []
        to_delete: List[str] = []

        for f in files:
            try:
                mtime = f.stat().st_mtime
            except OSError as e:
                logger.warning("Cannot stat %s: %s", f, e)
                continue

            rel_source = str(f.relative_to(KB_PATH))
            current_mtimes[rel_source] = mtime

            if existing.get(rel_source, 0.0) >= mtime:
                continue

            try:
                text = f.read_text(encoding="utf-8")
            except OSError as e:
                logger.warning("Cannot read %s: %s", f, e)
                continue

            chunks = _chunk_markdown(text)
            if not chunks:
                continue

            id_prefix = rel_source.replace("/", "_").replace("\\", "_")
            all_ids.extend(f"{id_prefix}:{i}" for i in range(len(chunks)))
            all_docs.extend(chunks)
            all_metas.extend({"source": rel_source, "mtime": mtime} for _ in chunks)
            to_delete.append(rel_source)

        if not to_delete:
            logger.info("RAG sync complete: nothing to re-index.")
            self._files_indexed = len(files)
            self._sync_state = "skipped"
            self._sync_progress = f"All {len(files)} files already indexed — nothing to re-index"
            self._save_mtime_cache(current_mtimes)
            return

        logger.info(
            "RAG indexing %d file(s) → %d chunks…",
            len(to_delete), len(all_ids),
        )
        self._sync_progress = f"Indexing {len(to_delete)} file(s) — 0 / {len(all_ids)} chunks done"

        for source in to_delete:
            self._delete_source(source)

        total = len(all_ids)
        failed = 0
        source_to_mtime: Dict[str, float] = {
            meta["source"]: meta["mtime"] for meta in all_metas
        }
        failed_sources: set = set()

        for start in range(0, total, EMBED_BATCH_SIZE):
            end = min(start + EMBED_BATCH_SIZE, total)
            self._sync_progress = f"Indexing — {start} / {total} chunks done"
            vecs = self._embed_batch_with_retry(all_docs[start:end], start + 1, end)
            if vecs is None:
                failed_sources.update(meta["source"] for meta in all_metas[start:end])
                failed += end - start
                continue
            try:
                self.collection.add(
                    ids=all_ids[start:end],
                    documents=all_docs[start:end],
                    embeddings=cast(Any, vecs),
                    metadatas=cast(Any, all_metas[start:end]),
                )
                logger.info("RAG indexed chunks %d–%d of %d.", start + 1, end, total)
            except Exception as e:
                logger.warning("RAG Chroma write %d–%d failed: %s", start + 1, end, e)
                failed_sources.update(meta["source"] for meta in all_metas[start:end])
                failed += end - start

        indexed = total - failed
        logger.info(
            "RAG sync complete: %d file(s), %d/%d chunks indexed.",
            len(to_delete), indexed, total,
        )
        self._files_indexed = len(existing) + len(to_delete)
        try:
            self._chunks_indexed = self.collection.count()
        except Exception:
            self._chunks_indexed = self._chunks_indexed + indexed
        self._sync_state = "complete"
        self._sync_progress = f"{len(to_delete)} file(s), {indexed}/{total} chunks indexed"
        for src, mtime in source_to_mtime.items():
            if src not in failed_sources:
                existing[src] = mtime
        existing = {k: v for k, v in existing.items() if k in current_mtimes}
        self._save_mtime_cache(existing)

    def retrieve(self, query: str, k: int = DEFAULT_TOP_K) -> List[str]:
        if self.collection is None or not query:
            return []
        try:
            res = self.collection.query(query_texts=[query], n_results=k)
        except Exception as e:
            logger.warning("RAG query failed: %s", e)
            return []
        docs = (res.get("documents") or [[]])[0]
        metas = (res.get("metadatas") or [[]])[0]
        out: List[str] = []
        for doc, md in zip(docs, metas):
            src = (md or {}).get("source", "unknown")
            out.append(f"[{src}]\n{doc}")
        if out:
            sources = [((m or {}).get("source", "?")) for m in metas]
            logger.info("RAG retrieved %d chunk(s): %s", len(out), ", ".join(sources))
        else:
            logger.info("RAG retrieved 0 chunks for query: %.80s", query)
        return out

    def retrieve_with_scores(self, query: str, k: int = DEFAULT_TOP_K) -> List[Dict[str, Any]]:
        """Like retrieve() but returns structured dicts with similarity scores and source paths."""
        if self.collection is None or not query:
            return []
        try:
            res = self.collection.query(
                query_texts=[query],
                n_results=k,
                include=["documents", "metadatas", "distances"],
            )
        except Exception as e:
            logger.warning("RAG scored query failed: %s", e)
            return []
        docs = (res.get("documents") or [[]])[0]
        metas = (res.get("metadatas") or [[]])[0]
        distances = (res.get("distances") or [[]])[0]
        out: List[Dict[str, Any]] = []
        for doc, md, dist in zip(docs, metas, distances):
            src = (md or {}).get("source", "unknown")
            score = max(0.0, 1.0 - float(dist) / 2.0)
            out.append({
                "text": f"[{src}]\n{doc}",
                "source": src,
                "score": round(score, 4),
                "distance": round(float(dist), 4),
            })
        out.sort(key=lambda x: x["score"], reverse=True)
        return out


def _build_rag():
    try:
        r = RAG()
        if r.collection is None:
            return _NoOpRAG(reason=r._init_error or "init failed")
        return r
    except Exception as e:
        logger.warning("RAG construction failed (%s); falling back to no-op.", e)
        return _NoOpRAG(reason=str(e))


rag = _build_rag()


def reload_rag() -> Dict[str, Any]:
    """Re-initialise RAG from current settings (DB overrides + env).

    Called automatically by the admin settings PUT endpoint when RAG-related
    keys change, so the user never needs to restart the server.
    Returns the new RAG status dict.
    """
    global rag
    # Stop any in-progress sync on the old instance
    old = rag
    if isinstance(old, RAG) and hasattr(old, "_stop_event"):
        old._stop_event.set()
    rag = _build_rag()
    logger.info("RAG reloaded: %s", rag.status())
    return rag.status()
