"""Playbook-driven investigation runner.

Flow:
1. retrieve_with_scores() finds the best-matching playbook (threshold ≥ 0.60).
2. parse_front_matter() extracts SIEM query hints from its YAML front-matter.
3. Queries are executed via tool_runner for the active SIEM_PROVIDER.
4. The caller decides whether to use the playbook evidence alone (≥ SPARSE_THRESHOLD
   events) or merge it with the standard keyword-based investigation.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from app.config import settings
from app.execution.tool_runner import ToolRunner
from app.rag import rag
from .parser import (
    get_ioc_fields,
    get_queries_for_provider,
    parse_front_matter,
)

logger = logging.getLogger("nullshift.playbooks")

MATCH_THRESHOLD: float = 0.60   # minimum cosine-similarity score to activate a playbook
SPARSE_THRESHOLD: int = 10      # event count below which the caller should also run keyword hunt

_IP_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")


def _extract_ips(text: str) -> List[str]:
    return _IP_RE.findall(text)


class PlaybookRunner:
    """Orchestrates playbook-driven SIEM queries for a single user message."""

    def run(
        self,
        message: str,
        time_range: str,
        user: Dict[str, Any],
        tool_runner: ToolRunner,
    ) -> Dict[str, Any]:
        """Run playbook queries and return an evidence bundle.

        Returns a dict with keys:
            playbook_triggered  bool    — whether a playbook was activated
            playbook_title      str     — human-readable name of the matched playbook
            playbook_source     str     — filename of the matched playbook
            playbook_score      float   — RAG similarity score (0–1)
            time_window         str     — time_range string passed in
            executed_calls      list    — tool_runner result dicts
            sources_queried     list    — provider names that were queried
            total_events        int     — sum of result_count across all calls
            errors              dict    — {tool.query_id: error_message}
            anomalies           list    — always [] (compatible with investigation_service format)
        """
        bundle: Dict[str, Any] = {
            "playbook_triggered": False,
            "playbook_title": None,
            "playbook_source": None,
            "playbook_score": 0.0,
            "time_window": time_range,
            "executed_calls": [],
            "sources_queried": [],
            "total_events": 0,
            "errors": {},
            "anomalies": [],
        }

        # --- Step 1: find a matching playbook ---
        if not hasattr(rag, "retrieve_with_scores"):
            return bundle

        hits = rag.retrieve_with_scores(message, k=4)
        matches = [h for h in hits if h["score"] >= MATCH_THRESHOLD]
        if not matches:
            return bundle

        best = matches[0]
        source: str = best["source"]
        meta = parse_front_matter(source)
        if not meta:
            return bundle

        bundle["playbook_triggered"] = True
        bundle["playbook_title"] = meta.get("title", source.replace(".md", "").replace("-", " ").title())
        bundle["playbook_source"] = source
        bundle["playbook_score"] = best["score"]

        logger.info(
            "Playbook activated: %s (score=%.2f) for provider=%s",
            source, best["score"], settings.SIEM_PROVIDER,
        )

        # --- Step 2: build query list ---
        primary_queries = get_queries_for_provider(meta, settings.SIEM_PROVIDER)

        # Extract IPs from user message for alerts_by_ip queries
        ips = _extract_ips(message)

        # --- Step 3: run primary SIEM queries ---
        for q in primary_queries:
            self._run_query(
                tool_name=settings.SIEM_PROVIDER,
                query_id=q["query_id"],
                params=q["params"],
                ips=ips,
                time_range=time_range,
                user=user,
                tool_runner=tool_runner,
                bundle=bundle,
            )

        return bundle

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_query(
        self,
        tool_name: str,
        query_id: str,
        params: Dict[str, Any],
        ips: List[str],
        time_range: str,
        user: Dict[str, Any],
        tool_runner: ToolRunner,
        bundle: Dict[str, Any],
    ) -> None:
        """Execute one tool query and update the bundle in place."""
        params = dict(params)   # don't mutate the playbook's original dict

        # Inject the first IP from the message if the query needs one and none is set
        if query_id == "alerts_by_ip" and not params.get("ip"):
            if not ips:
                return      # no IP available — skip this query
            params["ip"] = ips[0]

        try:
            result = tool_runner.execute(
                tool_name=tool_name,
                query_id=query_id,
                params=params,
                earliest=time_range,
                latest=None,
                user=user,
            )
            bundle["executed_calls"].append(result)
            bundle["total_events"] += result.get("result_count", 0)
            if tool_name not in bundle["sources_queried"]:
                bundle["sources_queried"].append(tool_name)

        except Exception as exc:
            key = f"{tool_name}.{query_id}"
            logger.warning("Playbook query %s failed: %s", key, exc)
            bundle["errors"][key] = str(exc)
