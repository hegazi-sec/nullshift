from typing import Any, Dict, List, Optional, Tuple, Set
import json

from app.execution.tool_runner import ToolRunner
from app.utils.debug_trace import DebugTrace


class Executor:
    """Executes a planned set of connector calls with deduplication and normalization.

    - Executes via existing ToolRunner (guardrails preserved)
    - Tracks meta per call: result_count, capped (>= MAX_RESULTS), error
    - Deduplicates by (tool_name, query_id, params, time_range) within the same request
    - Normalizes outputs into: {source, query_id, params, aggregates, events, meta}
    """

    def __init__(self, tool_runner: ToolRunner):
        self.tool_runner = tool_runner

    @staticmethod
    def _sig(tool_name: str, query_id: str, params: Dict[str, Any], time_range: Optional[str]) -> str:
        try:
            params_s = json.dumps(params or {}, sort_keys=True)
        except Exception:
            params_s = str(params)
        return f"{tool_name}::{query_id}::{params_s}::{time_range or ''}"

    def execute_plan(
        self,
        plan: List[Dict[str, Any]],
        user: Dict[str, Any],
        executed_signatures: Optional[Set[str]] = None,
        debug: Optional[DebugTrace] = None,
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Execute calls in order, skipping duplicates, returning (normalized_calls, rollup_meta).

        rollup_meta contains:
          - sources_queried: List[str]
          - totals: Dict[str, int]
          - errors: Dict[str, str]
          - capped_any: bool
        """
        if executed_signatures is None:
            executed_signatures = set()

        results: List[Dict[str, Any]] = []
        sources_queried: List[str] = []
        totals: Dict[str, int] = {}
        errors: Dict[str, str] = {}
        capped_any = False

        for call in plan:
            tname = call.get("tool_name")
            qid = call.get("query_id")
            params = call.get("params") or {}
            earliest = call.get("earliest")
            latest = call.get("latest")

            # Signature includes time range to allow safe expansion across buckets
            sig = self._sig(tname, qid, params, earliest)
            if sig in executed_signatures:
                # Skip duplicate in this request
                continue

            executed_signatures.add(sig)
            try:
                if debug:
                    debug.add({
                        "type": "request",
                        "source": tname,
                        "query_id": qid,
                        "params": {k: (v if k != "_subject_terms" else v) for k, v in (params or {}).items() if k != "headers"},
                        "earliest": earliest,
                        "latest": latest,
                    })
                out = self.tool_runner.execute(tname, qid, params, earliest, latest, user, debug=debug)
                rc = int(out.get("result_count", 0))
                capped = rc >= getattr(self.tool_runner, "MAX_RESULTS", 200)
                if capped:
                    capped_any = True
                if debug:
                    debug.add({
                        "type": "response",
                        "source": tname,
                        "query_id": qid,
                        "result_count": rc,
                        "capped": capped,
                        "time_range": earliest,
                    })
                normalized = {
                    "source": tname,
                    "query_id": qid,
                    "params": params,
                    "aggregates": out.get("summary") or {},
                    # We only keep samples from ToolRunner for now to minimize payload size
                    "events": out.get("samples") or [],
                    "meta": {
                        "result_count": rc,
                        "capped": capped,
                        "time_range": earliest,
                    },
                }
                results.append(normalized)
                if tname not in sources_queried:
                    sources_queried.append(tname)
                totals[tname] = int(totals.get(tname, 0)) + rc
            except Exception as ex:
                key = f"{tname}.{qid}"
                errors[key] = str(ex)
                if debug:
                    debug.add({
                        "type": "error",
                        "source": tname,
                        "query_id": qid,
                        "error": str(ex),
                    })
                results.append({
                    "source": tname,
                    "query_id": qid,
                    "params": params,
                    "aggregates": {},
                    "events": [],
                    "meta": {"result_count": 0, "capped": False, "time_range": earliest, "error": str(ex)},
                })

        rollup = {
            "sources_queried": sources_queried,
            "totals": totals,
            "errors": errors,
            "capped_any": capped_any,
        }
        return results, rollup
