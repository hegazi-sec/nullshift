"""Smoke-test the Claude Agent SDK provider by calling chat_with_history
directly — no uvicorn, no auth, no FastAPI in the way.

Run from nullshift/ with venv activated:
    python scripts/test_sdk.py
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.llm import chat_with_history, configured_provider_names  # noqa: E402


def main() -> int:
    print(f"Provider chain: {configured_provider_names()}")
    if "claude_agent_sdk" not in configured_provider_names():
        print("SDK is not in the chain — investigate diag.py output first.")
        return 1

    print("Calling chat_with_history with a trivial prompt...")
    t0 = time.monotonic()
    try:
        reply = chat_with_history(
            system_prompt="You are a friendly assistant. Reply briefly.",
            history_messages=[{"role": "user", "content": "Say hello in 5 words."}],
            max_tokens=200,
            temperature=0.2,
            tool_runner=None,
        )
    except Exception as e:
        print(f"FAILED ({type(e).__name__}): {e}")
        import traceback
        traceback.print_exc()
        return 1
    dt = time.monotonic() - t0
    print(f"--- Reply ({dt:.2f}s): ---")
    print(reply)
    print("--- end ---")
    return 0


if __name__ == "__main__":
    sys.exit(main())
