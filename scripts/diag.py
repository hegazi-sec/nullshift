"""Print LLM-provider configuration so we can tell why /chat is failing.

Run from the nullshift/ directory (with the venv activated):
    python scripts/diag.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Make sure `import app.*` works when run as `python scripts/diag.py`
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main() -> int:
    print("=" * 60)
    print(f"CWD                 : {os.getcwd()}")
    print(f"Project root        : {ROOT}")
    print(f".env exists here    : {(ROOT / '.env').exists()}")
    print(f".env size           : {(ROOT / '.env').stat().st_size if (ROOT / '.env').exists() else 'N/A'} bytes")
    print("-" * 60)

    try:
        from app.config import settings
    except Exception as e:
        print(f"FAILED to import app.config: {type(e).__name__}: {e}")
        return 1

    print(f"USE_CLAUDE_AGENT_SDK  : {settings.USE_CLAUDE_AGENT_SDK!r}")
    print(f"CLAUDE_AGENT_SDK_MODEL: {settings.CLAUDE_AGENT_SDK_MODEL!r}")
    print(f"ANTHROPIC_API_KEY set : {bool(settings.ANTHROPIC_API_KEY)}")
    print(f"ANTHROPIC_MODEL       : {settings.ANTHROPIC_MODEL!r}")
    print(f"OPENAI_API_KEY set    : {bool(settings.OPENAI_API_KEY)}")
    print(f"OPENAI_MODEL          : {settings.OPENAI_MODEL!r}")
    print(f"SIEM_PROVIDER         : {settings.SIEM_PROVIDER!r}")
    print("-" * 60)

    # Try importing the SDK directly so we can see the real exception
    print("Trying `import claude_agent_sdk` ...")
    try:
        import claude_agent_sdk  # type: ignore
        print(f"  ✓ imported (version: {getattr(claude_agent_sdk, '__version__', 'unknown')})")
    except Exception as e:
        print(f"  ✗ FAILED: {type(e).__name__}: {e}")

    print("-" * 60)
    try:
        from app.llm import configured_provider_names
        chain = configured_provider_names()
        print(f"Provider chain        : {chain or '[]  ← empty: no provider will answer'}")
    except Exception as e:
        print(f"FAILED to load chain: {type(e).__name__}: {e}")
        return 1

    print("=" * 60)
    if not chain:
        print()
        print("No provider available. Most common causes:")
        print("  1. .env not loaded (check CWD vs project root above).")
        print("  2. claude-agent-sdk import failed (see error above).")
        print("  3. All keys really are unset (check the bool() lines above).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
