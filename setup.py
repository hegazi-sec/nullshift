#!/usr/bin/env python3
"""NullShift — Interactive Setup Wizard (terminal)

Run once to configure, or re-run at any time to reconfigure.

    python setup.py

The wizard will:
  1. Create / activate a Python virtual environment (.venv)
  2. Install all dependencies from requirements.txt
  3. Generate a secure JWT secret → write to data/config.db
  4. Create the admin account → write to data/config.db (password hashed)
  5. Ask: use Claude Agent SDK? → check `claude` CLI, write to config.db
  6. Ask: configure a SIEM now? → collect credentials, write to config.db
  7. Set RAG to disabled by default in config.db
  8. Print final "run uvicorn" instructions

After setup, start the server with:
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
"""
from __future__ import annotations
import getpass
import json as _json
import os
import secrets
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional

# ---------------------------------------------------------------------------
# Venv bootstrap — must run before any third-party imports
# ---------------------------------------------------------------------------
def _bootstrap_venv() -> None:
    """If not already inside a venv, create .venv, install requirements, re-exec."""
    if sys.prefix != sys.base_prefix:
        return  # already inside a venv

    base = Path(__file__).resolve().parent
    venv_dir = base / ".venv"
    venv_python = venv_dir / ("Scripts" if sys.platform == "win32" else "bin") / "python"

    # Raw ANSI — color helpers not defined yet at this point
    _tty = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
    def _B(t):  return f"\033[1m{t}\033[0m"   if _tty else t   # bold
    def _C(t):  return f"\033[96m{t}\033[0m"  if _tty else t   # bright cyan
    def _Y(t):  return f"\033[93m{t}\033[0m"  if _tty else t   # yellow
    def _G(t):  return f"\033[92m{t}\033[0m"  if _tty else t   # green
    def _D(t):  return f"\033[2m{t}\033[0m"   if _tty else t   # dim
    W = 62

    print()
    print("  " + _C("╔" + "═" * W + "╗"))
    print("  " + _C("║") + " " * W + _C("║"))
    print("  " + _C("║") + "  " + _B(_C("NULLSHIFT")) + " " * (W - 11) + _C("║"))
    print("  " + _C("║") + "  " + _D("AI-Powered Security Operations Center") + " " * (W - 40) + _C("║"))
    print("  " + _C("║") + " " * W + _C("║"))
    print("  " + _C("║") + "  " + _D("Created by ") + _Y("Ahmed Hegazi") + " " * (W - 25) + _C("║"))
    print("  " + _C("╚" + "═" * W + "╝"))
    print()
    print(f"  {_C('→')}  Welcome! Preparing your environment before setup begins.")
    print()
    print("  " + _D("─" * (W + 2)))
    print(f"  {_B('Step 1 / 7')} {_D('—')} {_C('Environment')}")
    print("  " + _D("─" * (W + 2)))
    print()

    if not venv_python.exists():
        print(f"  {_C('○')}  Creating virtual environment (.venv)…")
        subprocess.check_call([sys.executable, "-m", "venv", str(venv_dir)])
        print(f"  {_G('✓')}  Virtual environment created.")

    req_file = base / "requirements.txt"
    if req_file.exists():
        print(f"  {_C('○')}  Installing dependencies (this may take a minute)…")
        subprocess.check_call([str(venv_python), "-m", "pip", "install", "-q", "-r", str(req_file)])
        print(f"  {_G('✓')}  Dependencies installed.")

    print()
    print(f"  {_C('→')}  Restarting inside virtual environment…")
    print()
    os.execv(str(venv_python), [str(venv_python)] + sys.argv)

_bootstrap_venv()

# ---------------------------------------------------------------------------
# Terminal colours — graceful fallback on Windows cmd / non-TTY
# ---------------------------------------------------------------------------
def _supports_color() -> bool:
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    if sys.platform == "win32":
        return bool(os.environ.get("WT_SESSION") or os.environ.get("COLORTERM"))
    return True

_COLOR = _supports_color()

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text

def cyan(t: str)   -> str: return _c("96", t)
def green(t: str)  -> str: return _c("92", t)
def yellow(t: str) -> str: return _c("93", t)
def red(t: str)    -> str: return _c("91", t)
def bold(t: str)   -> str: return _c("1",  t)
def dim(t: str)    -> str: return _c("2",  t)

def hr(char: str = "─", width: int = 60) -> None:
    print(dim(char * width))

def banner() -> None:
    W = 62
    print()
    print("  " + cyan("╔" + "═" * W + "╗"))
    print("  " + cyan("║") + " " * W + cyan("║"))
    print("  " + cyan("║") + "  " + bold(cyan("NULLSHIFT")) + " " * (W - 11) + cyan("║"))
    print("  " + cyan("║") + "  " + dim("AI-Powered Security Operations Center") + " " * (W - 40) + cyan("║"))
    print("  " + cyan("║") + " " * W + cyan("║"))
    print("  " + cyan("║") + "  " + dim("Created by ") + yellow("Ahmed Hegazi") + " " * (W - 25) + cyan("║"))
    print("  " + cyan("╚" + "═" * W + "╝"))
    print()
    print(f"  {cyan('→')}  Welcome! This wizard configures NullShift in 7 steps.")
    print(f"  {dim('   Admin account · SIEM connector · AI providers · RAG')}")
    print()

def step_header(n: int, total: int, title: str) -> None:
    print()
    hr()
    print(bold(f"  Step {n} / {total} — {title}"))
    hr()
    print()

def ok(msg: str)   -> None: print(f"  {green('✓')} {msg}")
def warn(msg: str) -> None: print(f"  {yellow('⚠')}  {msg}")
def info(msg: str) -> None: print(f"  {cyan('ℹ')}  {msg}")
def err(msg: str)  -> None: print(f"  {red('✗')} {msg}")

# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------
def ask(prompt: str, default: str = "", secret: bool = False) -> str:
    hint = f" [{dim(default)}]" if default and not secret else ""
    try:
        if secret:
            val = getpass.getpass(f"  {prompt}: ")
        else:
            val = input(f"  {prompt}{hint}: ").strip()
    except (KeyboardInterrupt, EOFError):
        print()
        print(yellow("\nSetup cancelled."))
        sys.exit(0)
    return val if val else default


def ask_yn(prompt: str, default: bool = True) -> bool:
    yn = "Y/n" if default else "y/N"
    raw = ask(f"{prompt} ({yn})").lower()
    if not raw:
        return default
    return raw.startswith("y")


def ask_choice(prompt: str, choices: list, default: int = 1) -> int:
    """Show a numbered menu, return the 1-based index of the selection."""
    for i, (label, desc) in enumerate(choices, 1):
        marker = green("→") if i == default else " "
        print(f"  {marker} {bold(str(i))})  {label}")
        if desc:
            print(f"         {dim(desc)}")
    print()
    while True:
        raw = ask(f"{prompt} [1-{len(choices)}]", str(default))
        try:
            n = int(raw)
            if 1 <= n <= len(choices):
                return n
        except ValueError:
            pass
        warn(f"Enter a number between 1 and {len(choices)}.")


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE = Path(__file__).resolve().parent
# IMPORTANT: must match settings_store.py and chat_store.py which use
# `Path(__file__).resolve().parent.parent / 'data'` from app/db/, i.e. app/data/.
# If we wrote to BASE/data/ instead, setup would write to one place and the
# running server would read from another — config silently lost.
DATA_DIR = BASE / "app" / "data"


# ---------------------------------------------------------------------------
# CLI command registration
# ---------------------------------------------------------------------------
def _register_cli_command() -> None:
    """Install a nullshift wrapper script into a directory on the user's PATH
    so the command works from anywhere without activating the venv first.

    Strategy:
      - Write the wrapper to ~/.local/bin/ (standard user binaries directory)
      - Also write to the venv bin (works when venv is activated)
      - If ~/.local/bin is not on PATH, print clear instructions to add it
    """
    try:
        cli_py = (BASE / "cli.py").resolve()
        python_exe = Path(sys.executable).resolve()
        path_dirs = os.environ.get("PATH", "").split(os.pathsep)

        if sys.platform == "win32":
            venv_bin = Path(sys.prefix) / "Scripts"
            candidates = [Path.home() / "AppData" / "Local" / "nullshift" / "bin"]
            wrapper_content = f'@echo off\n"{python_exe}" "{cli_py}" %*\n'
            wrapper_name = "nullshift.bat"
        else:
            venv_bin = Path(sys.prefix) / "bin"
            # Try ~/.local/bin first (XDG standard), fall back to ~/bin
            candidates = [Path.home() / ".local" / "bin", Path.home() / "bin"]
            wrapper_content = f'#!/bin/sh\nexec "{python_exe}" "{cli_py}" "$@"\n'
            wrapper_name = "nullshift"

        # Write to venv bin (always works when venv is activated)
        venv_wrapper = venv_bin / wrapper_name
        venv_wrapper.write_text(wrapper_content, encoding="utf-8")
        if sys.platform != "win32":
            venv_wrapper.chmod(0o755)

        # Find a user-writable directory among candidates
        user_bin = None
        for cand in candidates:
            try:
                cand.mkdir(parents=True, exist_ok=True)
                # Verify we can actually write to it
                test = cand / ".nullshift_write_test"
                test.write_text("ok")
                test.unlink()
                user_bin = cand
                break
            except (PermissionError, OSError):
                continue

        if user_bin is None:
            warn("Could not find a user-writable bin directory.")
            info(f"The command is available inside the venv: {venv_wrapper}")
            return

        user_wrapper = user_bin / wrapper_name
        user_wrapper.write_text(wrapper_content, encoding="utf-8")
        if sys.platform != "win32":
            user_wrapper.chmod(0o755)

        ok(f"nullshift command installed to {dim(str(user_bin))}")

        # If user_bin is already on PATH, nothing else to do
        if str(user_bin) in path_dirs:
            return

        # Auto-add to shell profile (Mac/Linux) or PATH (Windows)
        _auto_add_to_path(user_bin)
    except Exception as e:
        warn(f"Could not register nullshift command: {e}")
        info("You can still run: python cli.py <command>")


def _auto_add_to_path(user_bin: Path) -> None:
    """Append the user_bin to the user's shell profile so nullshift is on
    PATH in every new terminal. Idempotent — won't add duplicate entries."""
    if sys.platform == "win32":
        # Windows: use setx to persist into the user environment
        try:
            current = os.environ.get("PATH", "")
            if str(user_bin) in current.split(os.pathsep):
                return
            subprocess.run(
                ["setx", "PATH", f"%PATH%;{user_bin}"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            ok(f"Added {user_bin} to your user PATH.")
            info("Open a new terminal to use the nullshift command.")
        except Exception as e:
            warn(f"Could not auto-update PATH: {e}")
            info(f'Manually run: setx PATH "%PATH%;{user_bin}"')
        return

    # Mac / Linux — append an export line to the user's shell profile
    shell = os.environ.get("SHELL", "")
    home = Path.home()
    if "zsh" in shell:
        profile = home / ".zshrc"
    elif "bash" in shell:
        # Prefer .bashrc on Linux, .bash_profile on Mac (which is what login shells read)
        profile = home / ".bash_profile" if sys.platform == "darwin" else home / ".bashrc"
    elif "fish" in shell:
        profile = home / ".config" / "fish" / "config.fish"
    else:
        profile = home / ".profile"

    try:
        rel = user_bin.relative_to(home)
        bin_for_export = f'$HOME/{rel}'
    except ValueError:
        bin_for_export = str(user_bin)

    if "fish" in shell:
        export_line = f'set -gx PATH {bin_for_export} $PATH'
        marker = export_line
    else:
        export_line = f'export PATH="{bin_for_export}:$PATH"'
        marker = bin_for_export  # detect any pre-existing entry pointing to this dir

    try:
        # Skip if already present
        if profile.exists() and marker in profile.read_text(encoding="utf-8"):
            ok(f"PATH already configured in {dim(str(profile))}")
        else:
            profile.parent.mkdir(parents=True, exist_ok=True)
            with profile.open("a", encoding="utf-8") as f:
                f.write(f"\n# Added by NullShift setup\n{export_line}\n")
            ok(f"Added {user_bin} to PATH in {dim(str(profile))}")

        print()
        info("To use nullshift in this terminal session, run:")
        print(f"    {bold(cyan(f'source {profile}'))}")
        info("(New terminals will pick it up automatically.)")
        print()
    except Exception as e:
        warn(f"Could not update {profile}: {e}")
        print(f"  Manually add this line to your shell profile:")
        print(f"    {bold(cyan(export_line))}")


# ---------------------------------------------------------------------------
# Step 1 — Environment (venv + dependencies combined)
# ---------------------------------------------------------------------------
def step_environment() -> None:
    ok(f"Running inside virtual environment: {dim(sys.prefix)}")

    req = BASE / "requirements.txt"
    if not req.exists():
        warn("requirements.txt not found — skipping dependency check.")
        return

    info("Checking and installing Python dependencies …")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(req), "--upgrade", "-q"],
    )
    if result.returncode == 0:
        ok("Dependencies up to date.")
    else:
        err("pip install encountered errors — check output above.")
        if not ask_yn("Continue setup anyway?", default=False):
            sys.exit(1)

    # Register the `nullshift` CLI command by writing a wrapper into the venv bin
    _register_cli_command()


# ---------------------------------------------------------------------------
# config.db helpers (avoid circular imports — access SQLite directly)
# ---------------------------------------------------------------------------
def _open_config_db():
    """Return a sqlite3 connection to data/config.db (creates it if needed)."""
    import sqlite3
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    db_path = DATA_DIR / "config.db"
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS app_settings(
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            updated_by INTEGER
        )
    """)
    conn.commit()
    return conn


def _config_set(updates: Dict[str, Any]) -> None:
    """Upsert rows into data/config.db."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    conn = _open_config_db()
    rows = [(k, str(v), now, None) for k, v in updates.items() if v is not None]
    if rows:
        conn.executemany("""
            INSERT INTO app_settings(key, value, updated_at, updated_by)
            VALUES (?,?,?,?)
            ON CONFLICT(key) DO UPDATE SET
                value=excluded.value,
                updated_at=excluded.updated_at,
                updated_by=excluded.updated_by
        """, rows)
        conn.commit()
    conn.close()


def _config_get(key: str) -> Optional[str]:
    """Read a single key from data/config.db."""
    conn = _open_config_db()
    row = conn.execute("SELECT value FROM app_settings WHERE key=?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else None


# ---------------------------------------------------------------------------
# Step 3 — JWT secret
# ---------------------------------------------------------------------------
def step_jwt() -> None:
    existing = _config_get("jwt_secret")
    if existing and len(existing) >= 32:
        ok(f"jwt_secret already set in config.db (…{existing[-4:]})")
        if not ask_yn("Regenerate a new secret?", default=False):
            return

    secret = secrets.token_urlsafe(32)
    _config_set({"jwt_secret": secret})
    ok(f"jwt_secret generated and written to config.db (…{secret[-4:]})")


# ---------------------------------------------------------------------------
# Step 4 — Admin account
# ---------------------------------------------------------------------------
def step_admin() -> None:
    info("These credentials are used to log into the NullShift web UI.")
    print()

    # Check if an admin already exists
    import sqlite3 as _sq
    _users_db = DATA_DIR / "users.db"
    _existing_admin = None
    if _users_db.exists():
        try:
            _c = _sq.connect(str(_users_db))
            _row = _c.execute("SELECT username FROM users WHERE role='admin' LIMIT 1").fetchone()
            _c.close()
            if _row:
                _existing_admin = _row[0]
        except Exception:
            pass

    if _existing_admin:
        ok(f"Admin account already configured: {bold(_existing_admin)}")
        if not ask_yn("Update admin credentials?", default=False):
            info("Keeping existing admin account.")
            return
        print()

    username = ask("Admin username", default=_existing_admin or "admin")

    # Auto-generate a strong password; allow override
    generated = secrets.token_urlsafe(16)
    info(f"A secure password has been generated for you.")
    info(f"You can press Enter to accept it or type your own (min 16 chars).")
    print()
    print(f"  Generated password: {bold(cyan(generated))}")
    print()

    while True:
        pw = ask("Admin password (Enter to use generated)", default=generated, secret=False)
        if len(pw) < 16:
            err("Password must be at least 16 characters.")
            continue
        break

    if pw == generated:
        ok(f"Using generated password — save it now: {bold(cyan(pw))}")

    # Hash the password using passlib (same scheme as auth.py)
    try:
        from passlib.context import CryptContext
        pwd_ctx = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
        pw_hash = pwd_ctx.hash(pw)
    except ImportError:
        err("passlib is not installed — cannot hash password.")
        err("Run: pip install passlib and re-run setup.")
        sys.exit(1)

    # Write user to users.db (auth store — separate from chat.db)
    import sqlite3
    chat_db = DATA_DIR / "users.db"
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(chat_db))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'l1',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT,
            last_login TEXT
        )
    """)
    conn.commit()
    existing_user = conn.execute(
        "SELECT id FROM users WHERE username=?", (username,)
    ).fetchone()
    if existing_user:
        conn.execute(
            "UPDATE users SET password_hash=?, role='admin', is_active=1 WHERE username=?",
            (pw_hash, username),
        )
        conn.commit()
        conn.close()
        ok(f"Admin account updated: {bold(username)}")
    else:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO users(username, password_hash, role, is_active, created_at) VALUES (?,?,?,1,?)",
            (username, pw_hash, "admin", now),
        )
        conn.commit()
        conn.close()
        ok(f"Admin account created: {bold(username)}")

    print()
    print(dim("  ┌─────────────────────────────────────────┐"))
    print(dim("  │") + f"  Login credentials — save these now!    " + dim("│"))
    print(dim("  │") + f"  Username: {bold(cyan(username)):<30}" + dim("│"))
    print(dim("  │") + f"  Password: {bold(cyan(pw)):<30}" + dim("│"))
    print(dim("  └─────────────────────────────────────────┘"))
    print()

    # Mark setup complete immediately after admin account exists so the web
    # wizard never triggers if the browser opens before step 8 finishes.
    _config_set({"setup_complete": "true"})
    ok("setup_complete written to config.db.")


# ---------------------------------------------------------------------------
# Step 5 — Claude Agent SDK
# ---------------------------------------------------------------------------
def step_sdk() -> None:
    info("To use Claude Agent SDK, make sure you have run:")
    print(f"    {bold(cyan('claude login'))}")
    info("with a Claude.ai Pro or Max subscription.")
    info("If not, skip this — you can configure any LLM provider in the Admin panel after startup.")
    print()

    if not ask_yn("Use Claude Agent SDK?", default=False):
        info("Skipped. Configure any LLM provider in Admin → LLM Providers after startup.")
        return

    # Check `claude` CLI is in PATH
    claude_bin = shutil.which("claude")
    if not claude_bin:
        warn("`claude` CLI not found in PATH.")
        info("Install it from: https://claude.ai/download  (Claude Desktop → CLI)")
        info("Then run: claude login")
        print()
        if not ask_yn("Have you installed and authenticated `claude` already?", default=False):
            warn("Claude Agent SDK not enabled. Re-run setup after installing the CLI.")
            return
        claude_bin = shutil.which("claude")
        if not claude_bin:
            err("`claude` still not found — please add it to your PATH and re-run.")
            return

    ok(f"`claude` found: {dim(claude_bin)}")

    # Check authentication using `claude auth status` — the official way.
    # macOS stores OAuth tokens in Keychain, not as a file, so file-based
    # checks don't work. The status command exits 0 when authenticated.
    def _is_authenticated() -> bool:
        try:
            r = subprocess.run(
                [claude_bin, "auth", "status"],
                capture_output=True, text=True, timeout=10,
            )
            # Exit 0 = authenticated. The output usually shows account info.
            return r.returncode == 0
        except Exception:
            return False

    if not _is_authenticated():
        print()
        warn("Claude is not authenticated yet.")
        info("Your browser will open for Claude.ai authentication.")
        info("Sign in with your Pro or Max account and return here when done.")
        print()
        # `claude auth login` is the OAuth flow; bare `claude login` starts
        # an interactive chat with "login" as the prompt instead.
        os.system(f'"{claude_bin}" auth login')
        # Re-check after login attempt
        if not _is_authenticated():
            print()
            warn("Authentication not detected. Try running in a plain terminal:")
            print(f"    {bold(cyan('claude auth login'))}")
            warn("Claude Agent SDK not enabled. Re-run setup after authenticating.")
            return

    ok("Claude Agent SDK authentication confirmed.")
    _config_set({"claude_agent_sdk_enabled": "true"})
    ok("claude_agent_sdk_enabled=true written to config.db")


# ---------------------------------------------------------------------------
# Step 6 — SIEM connector
# ---------------------------------------------------------------------------
def step_siem() -> None:
    info("NullShift can connect to your SIEM to pull live alerts and logs.")
    print()

    existing_siem = _config_get("siem_provider") or ""
    if existing_siem:
        ok(f"SIEM already configured: {bold(existing_siem)}")
        if not ask_yn("Reconfigure SIEM?", default=False):
            info("Keeping existing SIEM configuration.")
            return
        print()

    siem_choices = [
        ("Wazuh",                 "Open-source SIEM + XDR — most common for home/SMB SOCs"),
        ("Splunk",                "Enterprise SIEM"),
        ("Elastic / Elastic SIEM","Self-hosted or Elastic Cloud"),
        ("Microsoft Sentinel",    "Azure cloud-native SIEM"),
        ("LimaCharlie",           "Cloud SecOps platform"),
        ("Skip — no SIEM yet",   "Configure connectors later in Admin Settings"),
    ]
    idx = ask_choice("Which SIEM / data source do you use?", siem_choices, default=6)

    updates: Dict[str, Any] = {}

    if idx == 1:   # Wazuh
        updates["siem_provider"]    = "wazuh"
        print()
        updates["wazuh_api_url"]      = ask("Wazuh Manager URL", default="https://wazuh-manager.local:55000")
        updates["wazuh_indexer_url"]  = ask("Wazuh Indexer (OpenSearch) URL", default="https://wazuh-indexer.local:9200")
        updates["wazuh_indexer_user"] = ask("Indexer username", default="admin")
        updates["wazuh_indexer_pass"] = ask("Indexer password", secret=True)
        updates["wazuh_api_token"]    = ask("Wazuh API token (leave blank if using user/pass)", secret=True) or None
        ssl = ask_yn("Disable SSL verification? (self-signed certs)", default=True)
        updates["wazuh_verify_ssl"]   = "false" if ssl else "true"
        if updates["wazuh_api_token"] is None:
            del updates["wazuh_api_token"]
        ok("Wazuh settings written to config.db.")

    elif idx == 2:  # Splunk
        updates["siem_provider"] = "splunk"
        print()
        updates["splunk_url"]   = ask("Splunk URL", default="https://splunk.corp.local:8089")
        updates["splunk_token"] = ask("Splunk bearer token", secret=True)
        updates["splunk_index"] = ask("Splunk index", default="*")
        ok("Splunk settings written to config.db.")

    elif idx == 3:  # Elastic
        updates["siem_provider"]  = "elastic"
        print()
        updates["elastic_url"]     = ask("Elasticsearch URL", default="https://elastic.corp.local:9200")
        updates["elastic_api_key"] = ask("Elastic API key (base64 id:key)", secret=True)
        updates["elastic_index"]   = ask("Index pattern", default="logs-*,.alerts-security.alerts-*")
        ok("Elastic settings written to config.db.")

    elif idx == 4:  # Sentinel
        updates["siem_provider"]         = "sentinel"
        print()
        updates["sentinel_workspace_id"] = ask("Log Analytics workspace ID")
        updates["sentinel_tenant_id"]    = ask("Azure tenant ID")
        updates["sentinel_client_id"]    = ask("App registration client ID")
        updates["sentinel_client_secret"]= ask("App registration client secret", secret=True)
        ok("Sentinel settings written to config.db.")

    elif idx == 5:  # LimaCharlie
        updates["siem_provider"]     = "limacharlie"
        print()
        updates["limacharlie_oid"]    = ask("Organisation ID (OID)")
        updates["limacharlie_api_key"]= ask("Secret API key", secret=True)
        ok("LimaCharlie settings written to config.db.")

    else:
        info("SIEM setup skipped.")

    if updates:
        _config_set(updates)


# ---------------------------------------------------------------------------
# Step 7 — RAG / Knowledge Base
# ---------------------------------------------------------------------------
def step_rag() -> None:
    info("RAG indexes your local playbooks (data/kb/) so the AI answers from your")
    info("knowledge base. It needs an embedding provider with an API key.")
    info("Providers: OpenAI, Gemini (free tier), Cohere, or Ollama (fully local).")
    print()

    existing_rag = _config_get("rag_enabled") or ""
    if existing_rag:
        state = green("enabled") if existing_rag == "true" else yellow("disabled")
        ok(f"RAG already configured: {state}")
        if not ask_yn("Change RAG setting?", default=False):
            info("Keeping existing RAG configuration.")
            return
        print()

    if not ask_yn("Enable RAG / Knowledge Base?", default=False):
        _config_set({"rag_enabled": "false"})
        info("RAG disabled. Enable it any time in Admin → Settings → RAG.")
        return

    _config_set({"rag_enabled": "true"})
    ok("RAG enabled.")
    print()

    info("Which embedding provider do you want to use?")
    providers = [
        ("OpenAI",           "text-embedding-3-small — needs OPENAI_API_KEY"),
        ("Gemini",           "text-embedding-004 — free tier available, needs GEMINI_API_KEY"),
        ("Cohere",           "embed-english-v3.0 — needs COHERE_API_KEY"),
        ("Ollama (local)",   "nomic-embed-text — fully local, no API key needed"),
        ("Skip / configure later", "Set the embedding provider in Admin → Settings → RAG"),
    ]
    idx = ask_choice("Embedding provider", providers, default=2) - 1

    provider_map = ["openai", "gemini", "cohere", "ollama", "auto"]
    provider_name = provider_map[idx]
    _config_set({"rag_embedding_provider": provider_name})

    if idx < 4:
        key_map = {
            "openai":  ("openai_api_key",  "OpenAI API key"),
            "gemini":  ("gemini_api_key",  "Gemini API key"),
            "cohere":  ("cohere_api_key",  "Cohere API key"),
        }
        if provider_name in key_map:
            db_key, label = key_map[provider_name]
            existing = _config_get(db_key) or ""
            if existing:
                info(f"{label} already set (…{existing[-4:]})")
                if not ask_yn("Update it?", default=False):
                    return
            api_key = ask(f"{label}", secret=True)
            if api_key:
                _config_set({db_key: api_key})
                ok(f"{label} saved.")
            else:
                warn("No key entered — add it later in Admin → Settings.")
        elif provider_name == "ollama":
            existing_url = _config_get("ollama_base_url") or ""
            url = ask("Ollama base URL", default=existing_url or "http://localhost:11434/v1")
            _config_set({"ollama_base_url": url})
            ok(f"Ollama URL saved: {url}")


# ---------------------------------------------------------------------------
# Step 8 — defaults + summary
# ---------------------------------------------------------------------------
def step_defaults_and_summary() -> None:
    # Ensure RAG key is written if not already set by step_rag
    if not _config_get("rag_enabled"):
        _config_set({"rag_enabled": "false"})
    ok(f"RAG: {green(_config_get('rag_enabled') or 'false')}")
    print()

    print()
    hr("═")
    print(bold(cyan("  Configuration Summary")))
    hr("═")
    print()

    def check_db(key: str, label: str, sensitive: bool = False) -> None:
        val = _config_get(key) or ""
        if val:
            display = f"…{val[-4:]}" if sensitive and len(val) >= 4 else green("set")
            ok(f"{label}: {green(display)}")
        else:
            warn(f"{label}: {yellow('not set')}")

    check_db("jwt_secret", "JWT secret", sensitive=True)

    import sqlite3
    users_db = DATA_DIR / "users.db"
    if users_db.exists():
        conn = sqlite3.connect(str(users_db))
        row = conn.execute("SELECT username FROM users WHERE role='admin' LIMIT 1").fetchone()
        conn.close()
        if row:
            ok(f"Admin user: {green(row[0])}")
        else:
            warn("Admin user: not found in users.db")

    sdk = _config_get("claude_agent_sdk_enabled") or "false"
    if sdk == "true":
        ok(f"LLM provider: {green('Claude Agent SDK')}")
    else:
        info("LLM provider: configure API keys in Admin → Settings after startup.")

    siem = _config_get("siem_provider") or ""
    if siem:
        ok(f"SIEM: {green(siem)}")
    else:
        info("SIEM: not configured (add later via Admin → Settings or .env)")

    print()
    ok(f"Config written → {bold(str(DATA_DIR / 'config.db'))}")


# ---------------------------------------------------------------------------
# Port utilities
# ---------------------------------------------------------------------------
# Default port — non-standard so automated scanners targeting 8000 miss it.
# Range 49152-65535 is IANA "dynamic/private", least likely to clash with
# other dev services.
DEFAULT_PORT = 58443


def _port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """Return True if a TCP listener is already bound to host:port."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        try:
            s.bind((host, port))
            return False
        except OSError:
            return True


def _find_free_port(start: int = DEFAULT_PORT, attempts: int = 50) -> int:
    """Return the first free port at or after `start`. Falls back to a
    random free port if everything in the search range is taken."""
    for offset in range(attempts):
        candidate = start + offset
        if not _port_in_use(candidate):
            return candidate
    # Fall back: let the OS pick any free port
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _pid_on_port(port: int) -> Optional[int]:
    """Return PID listening on `port` (POSIX only via lsof). None on Windows
    or if no listener found."""
    if sys.platform == "win32":
        return None
    try:
        r = subprocess.run(
            ["lsof", "-tiTCP:" + str(port), "-sTCP:LISTEN"],
            capture_output=True, text=True, timeout=5,
        )
        out = r.stdout.strip().splitlines()
        return int(out[0]) if out else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Final instructions
# ---------------------------------------------------------------------------
def step_instructions() -> None:
    print()
    hr()
    print(bold("  Ready to launch!"))
    hr()
    print()

    # Resolve uvicorn inside the venv so we don't need activation
    venv_dir = BASE / ".venv"
    if sys.platform == "win32":
        uvicorn_bin = venv_dir / "Scripts" / "uvicorn.exe"
    else:
        uvicorn_bin = venv_dir / "bin" / "uvicorn"

    # Decide which port to use — prefer DEFAULT_PORT, handle conflicts.
    port = DEFAULT_PORT
    auto_start = False  # set True when user already took action on a conflict
    if _port_in_use(port):
        pid = _pid_on_port(port)
        warn(f"Port {port} is already in use" + (f" (PID {pid})." if pid else "."))
        choices = [
            (f"Stop the process on port {port}" + (f" (kill PID {pid})" if pid else ""),
             "Frees the default port and uses it."),
            (f"Use a different free port",
             f"Auto-pick the next available port at or above {DEFAULT_PORT}."),
            ("Cancel — I'll start it myself later", ""),
        ]
        idx = ask_choice("How do you want to handle this?", choices, default=2)
        if idx == 3:  # Cancel
            _print_manual_start(port)
            return
        elif idx == 2:  # Different port
            port = _find_free_port(port + 1)
            ok(f"Using port {port}.")
        else:  # idx == 1 — kill
            import signal as _sig, time as _t
            if pid:
                try:
                    os.kill(pid, _sig.SIGTERM)
                    for _ in range(10):
                        if not _port_in_use(port):
                            break
                        _t.sleep(0.3)
                    if _port_in_use(port):
                        warn("Process didn't release the port — using a different port.")
                        port = _find_free_port(port + 1)
                    else:
                        ok(f"Freed port {port}.")
                except ProcessLookupError:
                    ok(f"Process already gone — port {port} is free.")
                except PermissionError:
                    err(f"Cannot kill PID {pid} (permission denied) — using a different port.")
                    port = _find_free_port(port + 1)
            else:
                warn("Could not identify the process — trying port anyway.")
                if _port_in_use(port):
                    port = _find_free_port(port + 1)
                    warn(f"Still in use — using port {port} instead.")
        # User already resolved the conflict — start automatically without asking again.
        auto_start = True

    # Save port to config.db so the CLI can read it
    _config_set({"server_port": str(port)})

    if not auto_start and not ask_yn("Start the server now?", default=True):
        _print_manual_start(port)
        return

    print()
    info(f"Starting NullShift on port {bold(cyan(str(port)))} in the background …")
    print()

    # Use the CLI's start command — handles PID file, log file, daemonization
    cli_py = BASE / "cli.py"
    venv_python = (BASE / ".venv" / ("Scripts" if sys.platform == "win32" else "bin") / "python")
    python_exe = str(venv_python) if venv_python.exists() else sys.executable
    result = subprocess.run([python_exe, str(cli_py), "start"], cwd=str(BASE))

    if result.returncode == 0:
        # Open the browser shortly after startup
        _open_browser_when_ready(port)
        print()
        info("Manage the server anytime with:")
        print(f"    {bold(cyan('nullshift status'))}   — check status & URL")
        print(f"    {bold(cyan('nullshift logs'))}     — stream live logs")
        print(f"    {bold(cyan('nullshift stop'))}     — stop the server")
        print()


def _open_browser_when_ready(port: int) -> None:
    """Spawn a background thread that opens the browser once the server
    starts listening on `port`. Best-effort — silently gives up after 15s."""
    import threading, time as _t, webbrowser
    def _wait_and_open() -> None:
        url = f"http://localhost:{port}"
        for _ in range(30):
            _t.sleep(0.5)
            if _port_in_use(port):
                try:
                    webbrowser.open(url)
                except Exception:
                    pass
                return
    threading.Thread(target=_wait_and_open, daemon=True).start()


def _print_manual_start(port: int) -> None:
    """Show CLI usage after setup or Ctrl+C."""
    print()
    print(f"  {bold('To manage the server, use the CLI:')}")
    print()
    if sys.platform == "win32":
        prefix = "nullshift.bat"
    else:
        prefix = "./nullshift"
    print(f"    {bold(cyan(f'{prefix} start'))}    — start in background")
    print(f"    {bold(cyan(f'{prefix} stop'))}     — stop the server")
    print(f"    {bold(cyan(f'{prefix} status'))}   — check if running")
    print(f"    {bold(cyan(f'{prefix} logs'))}     — stream live logs")
    print(f"    {bold(cyan(f'{prefix} setup'))}    — re-run this wizard")
    print()
    info("URL: " + bold(cyan(f"http://localhost:{port}")))
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    TOTAL = 7

    banner()
    print(dim("  Re-run this wizard at any time to reconfigure or reinstall."))
    print()

    # Step 1: Venv + dependencies (bootstrap already created the venv and re-exec'd)
    step_header(1, TOTAL, "Environment")
    step_environment()

    # Step 2: JWT secret → config.db
    step_header(2, TOTAL, "JWT Secret")
    step_jwt()

    # Step 3: Admin account → users.db
    step_header(3, TOTAL, "Admin Account")
    step_admin()

    # Step 4: Claude Agent SDK
    step_header(4, TOTAL, "Claude Agent SDK")
    step_sdk()

    # Step 5: SIEM connector → config.db
    step_header(5, TOTAL, "SIEM Connector")
    step_siem()

    # Step 6: RAG / Knowledge Base
    step_header(6, TOTAL, "RAG / Knowledge Base")
    step_rag()

    # Step 7: Defaults + summary + launch
    step_header(7, TOTAL, "Complete")
    step_defaults_and_summary()
    step_instructions()

    print()
    hr("═")
    print(bold(cyan("  Setup complete. Welcome to NullShift!")))
    hr("═")
    print()


if __name__ == "__main__":
    main()
