import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional


LOG_DIR = os.path.join(os.getcwd(), "logs")
LOG_PATH = os.path.join(LOG_DIR, "tool_audit.jsonl")


def _ensure_log_dir():
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
    except Exception:
        pass


def audit_log(
    username: str,
    tool_name: str,
    query_id: str,
    params: Dict[str, Any],
    earliest: Optional[str],
    latest: Optional[str],
    result_count: int,
    success: bool,
    error: Optional[str] = None,
) -> None:
    """Append a single JSONL audit record for tool execution attempts/results.

    Fields: timestamp, username, tool_name, query_id, params, earliest, latest,
    result_count, success, error
    """
    _ensure_log_dir()
    rec = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "username": username,
        "tool_name": tool_name,
        "query_id": query_id,
        "params": params or {},
        "earliest": earliest,
        "latest": latest,
        "result_count": int(result_count or 0),
        "success": bool(success),
        "error": error,
    }
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        # Best-effort logging only; do not raise.
        pass
