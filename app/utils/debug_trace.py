from __future__ import annotations
from typing import Any, Dict, List, Optional
import copy
import time


SENSITIVE_KEYS = {"authorization", "api_key", "apikey", "token", "secret", "password", "bearer"}


def sanitize_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Return a shallow-deep sanitized copy of the event dict.

    - Removes Authorization and obvious secrets
    - Avoids logging full query params; only allow safe summaries
    - Keeps URL path strings if provided, but callers should avoid attaching raw query strings
    """
    def _scrub(obj: Any) -> Any:
        if isinstance(obj, dict):
            out: Dict[str, Any] = {}
            for k, v in obj.items():
                lk = str(k).lower()
                if lk in SENSITIVE_KEYS or lk == "headers":
                    continue
                out[k] = _scrub(v)
            return out
        if isinstance(obj, list):
            return [_scrub(x) for x in obj]
        return obj

    return _scrub(copy.deepcopy(event))


class DebugTrace:
    def __init__(self) -> None:
        self._events: List[Dict[str, Any]] = []

    def add(self, event: Dict[str, Any]) -> None:
        try:
            ev = sanitize_event(event)
            ev["ts"] = time.time()
            self._events.append(ev)
        except Exception:
            # Never raise from tracing
            pass

    def to_list(self) -> List[Dict[str, Any]]:
        return list(self._events)
