#!/usr/bin/env python3
"""NullShift interactive setup wizard.

Run from the nullshift/ directory:
    python setup_wizard.py

Asks for every config value (with sensible defaults), then writes .env in
the current directory. Any existing .env is backed up to .env.bak.<ts>.

Stdlib-only on purpose — runs before `pip install -r requirements.txt`.
"""
from __future__ import annotations

import getpass
import os
import secrets
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# Terminal helpers
# --------------------------------------------------------------------------- #

USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if USE_COLOR else s


def bold(s: str) -> str: return _c("1", s)
def dim(s: str) -> str: return _c("2", s)
def cyan(s: str) -> str: return _c("36", s)
def green(s: str) -> str: return _c("32", s)
def yellow(s: str) -> str: return _c("33", s)
def red(s: str) -> str: return _c("31", s)


def section(title: str) -> None:
    print()
    print(cyan("─── " + title + " " + "─" * max(0, 60 - len(title))))


def header(title: str) -> None:
    line = "═" * 65
    print(cyan(line))
    print(cyan("  " + bold(title)))
    print(cyan(line))


# --------------------------------------------------------------------------- #
# Input primitives
# --------------------------------------------------------------------------- #


def ask(prompt: str, default: Optional[str] = None, required: bool = False) -> str:
    suffix = f" [{dim(default)}]" if default is not None else ""
    while True:
        try:
            raw = input(f"{prompt}{suffix}: ").strip()
        except EOFError:
            print()
            sys.exit(130)
        if raw:
            return raw
        if default is not None:
            return default
        if not required:
            return ""
        print(yellow("  Value required."))


def ask_secret(prompt: str, allow_blank: bool = False, min_len: int = 0) -> str:
    while True:
        try:
            raw = getpass.getpass(f"{prompt}: ").strip()
        except EOFError:
            print()
            sys.exit(130)
        if not raw and allow_blank:
            return ""
        if not raw:
            print(yellow("  Value required (input hidden)."))
            continue
        if min_len and len(raw) < min_len:
            print(yellow(f"  Must be at least {min_len} characters."))
            continue
        return raw


def ask_yn(prompt: str, default: bool = False) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        try:
            raw = input(f"{prompt} ({hint}): ").strip().lower()
        except EOFError:
            print()
            sys.exit(130)
        if not raw:
            return default
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        print(yellow("  Answer y or n."))


def ask_choice(prompt: str, choices: List[Tuple[str, str]], default: int = 1) -> int:
    """choices = [(label, description), ...]. 1-indexed selection."""
    print(prompt)
    for i, (label, desc) in enumerate(choices, 1):
        marker = green("●") if i == default else " "
        print(f"  {marker} {i}) {bold(label)} {dim('— ' + desc) if desc else ''}")
    while True:
        try:
            raw = input(f"Select [1-{len(choices)}] (default: {default}): ").strip()
        except EOFError:
            print()
            sys.exit(130)
        if not raw:
            return default
        try:
            n = int(raw)
            if 1 <= n <= len(choices):
                return n
        except ValueError:
            pass
        print(yellow(f"  Enter a number 1-{len(choices)}."))


# --------------------------------------------------------------------------- #
# Wizard sections
# --------------------------------------------------------------------------- #


def configure_llm(env: Dict[str, str]) -> None:
    section("LLM Provider")
    choice = ask_choice(
        "Which LLM should the assistant use?",
        [
            ("Claude Agent SDK", "uses your Claude.ai Pro/Max subscription via local `claude` CLI — home-SOC mode"),
            ("Anthropic API", "pay-as-you-go API key — recommended for team/org deployments"),
            ("OpenAI", "fallback only; less tuned for SOC reasoning"),
        ],
        default=1,
    )
    if choice == 1:
        env["USE_CLAUDE_AGENT_SDK"] = "true"
        print(dim("  → You'll need: `pip install claude-agent-sdk`, the `claude` CLI installed, and `claude login` already run."))
        if ask_yn("Also set an Anthropic API key as a fallback?", default=False):
            env["ANTHROPIC_API_KEY"] = ask_secret("  Anthropic API key")
            env["ANTHROPIC_MODEL"] = ask("  Anthropic model", default="claude-sonnet-4-6")
    elif choice == 2:
        env["USE_CLAUDE_AGENT_SDK"] = "false"
        env["ANTHROPIC_API_KEY"] = ask_secret("Anthropic API key")
        env["ANTHROPIC_MODEL"] = ask("Anthropic model", default="claude-sonnet-4-6")
    else:
        env["USE_CLAUDE_AGENT_SDK"] = "false"
        env["OPENAI_API_KEY"] = ask_secret("OpenAI API key")
        env["OPENAI_MODEL"] = ask("OpenAI model", default="gpt-4.1")


def configure_siem(env: Dict[str, str]) -> None:
    section("SIEM Provider")
    choice = ask_choice(
        "Which SIEM does this SOC query?",
        [
            ("Wazuh", "OpenSearch indexer; default in this project"),
            ("LimaCharlie", "SecOps Cloud; uses OID + secret API key"),
            ("Splunk", "Enterprise/Cloud REST API"),
            ("Elastic", "Elasticsearch / Elastic Security alerts"),
            ("Microsoft Sentinel", "Azure Log Analytics; needs App Registration"),
        ],
        default=1,
    )
    providers = {1: "wazuh", 2: "limacharlie", 3: "splunk", 4: "elastic", 5: "sentinel"}
    env["SIEM_PROVIDER"] = providers[choice]

    if choice == 1:  # Wazuh
        env["WAZUH_INDEXER_URL"] = ask("Wazuh Indexer (OpenSearch) URL", default="https://wazuh-indexer.local:9200", required=True)
        env["WAZUH_INDEXER_USER"] = ask("Wazuh Indexer username", default="admin")
        env["WAZUH_INDEXER_PASS"] = ask_secret("Wazuh Indexer password")
        if ask_yn("Also configure the Wazuh Manager API (for agent control)?", default=False):
            env["WAZUH_API_URL"] = ask("  Wazuh Manager API URL", default="https://wazuh-manager.local:55000")
            env["WAZUH_API_TOKEN"] = ask_secret("  Wazuh Manager API token", allow_blank=True)
        env["WAZUH_VERIFY_SSL"] = "true" if ask_yn("Verify Wazuh TLS certs?", default=False) else "false"
    elif choice == 2:  # LimaCharlie
        env["LIMACHARLIE_OID"] = ask("LimaCharlie Org ID (OID, UUID-shaped)", required=True)
        env["LIMACHARLIE_API_KEY"] = ask_secret("LimaCharlie secret API key")
    elif choice == 3:  # Splunk
        env["SPLUNK_URL"] = ask("Splunk REST URL (e.g. https://splunk:8089)", required=True)
        env["SPLUNK_TOKEN"] = ask_secret("Splunk bearer token", allow_blank=True)
        if not env.get("SPLUNK_TOKEN"):
            env["SPLUNK_USER"] = ask("Splunk username")
            env["SPLUNK_PASS"] = ask_secret("Splunk password")
        env["SPLUNK_INDEX"] = ask("Splunk index", default="*")
    elif choice == 4:  # Elastic
        env["ELASTIC_URL"] = ask("Elasticsearch URL (e.g. https://elastic:9200)", required=True)
        env["ELASTIC_API_KEY"] = ask_secret("Elastic API key (base64 id:api_key)", allow_blank=True)
        if not env.get("ELASTIC_API_KEY"):
            env["ELASTIC_USERNAME"] = ask("Elastic username")
            env["ELASTIC_PASSWORD"] = ask_secret("Elastic password")
        env["ELASTIC_INDEX"] = ask("Elastic index pattern", default="logs-*,.alerts-security.alerts-*")
    else:  # Sentinel
        env["SENTINEL_WORKSPACE_ID"] = ask("Sentinel Log Analytics workspace GUID", required=True)
        env["SENTINEL_TENANT_ID"] = ask("Azure AD tenant ID", required=True)
        env["SENTINEL_CLIENT_ID"] = ask("App registration client ID", required=True)
        env["SENTINEL_CLIENT_SECRET"] = ask_secret("App registration client secret")


def configure_auth(env: Dict[str, str]) -> None:
    section("Auth & JWT")
    if ask_yn("Auto-generate a JWT secret?", default=True):
        env["JWT_SECRET"] = secrets.token_urlsafe(32)
        print(dim("  → Generated 32-byte secret."))
    else:
        env["JWT_SECRET"] = ask_secret("JWT secret (>= 32 chars)", min_len=32)
    env["JWT_EXPIRE_MINUTES"] = ask("JWT lifetime (minutes)", default="480")

    env["ADMIN_USERNAME"] = ask("Bootstrap admin username", default="admin")
    env["ADMIN_PASSWORD"] = ask_secret("Bootstrap admin password (>= 16 chars)", min_len=16)


def configure_optional(env: Dict[str, str]) -> None:
    section("Optional Connectors")
    if not ask_yn("Configure any optional connectors (Suricata / pfSense / VirusTotal / TheHive)?", default=False):
        return
    if ask_yn("  Enable Suricata?", default=False):
        env["SURICATA_EVE_PATH"] = ask("    Path to local eve.json", default="./data/eve.json")
        if ask_yn("    Or read it remotely over SSH?", default=False):
            env["SURICATA_SSH_HOST"] = ask("      SSH host", required=True)
            env["SURICATA_SSH_USER"] = ask("      SSH user", required=True)
            env["SURICATA_SSH_KEY"] = ask("      Path to private key", required=True)
            env["SURICATA_REMOTE_EVE_PATH"] = ask("      Remote eve.json path", default="/var/log/suricata/eve.json")
    if ask_yn("  Enable pfSense?", default=False):
        env["PFSENSE_SYSLOG_PATH"] = ask("    Path to local syslog", default="./data/pfsense.log")
    if ask_yn("  Enable VirusTotal?", default=False):
        env["VT_API_KEY"] = ask_secret("    VirusTotal API key")
    if ask_yn("  Enable TheHive?", default=False):
        env["THEHIVE_URL"] = ask("    TheHive URL", required=True)
        env["THEHIVE_API_KEY"] = ask_secret("    TheHive API key")


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

SECRETS = {
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "JWT_SECRET", "ADMIN_PASSWORD",
    "WAZUH_INDEXER_PASS", "WAZUH_API_TOKEN", "LIMACHARLIE_API_KEY",
    "SPLUNK_TOKEN", "SPLUNK_PASS", "ELASTIC_API_KEY", "ELASTIC_PASSWORD",
    "SENTINEL_CLIENT_SECRET", "VT_API_KEY", "THEHIVE_API_KEY",
    "SURICATA_SSH_PASS", "PFSENSE_SSH_PASS",
}


def _mask(key: str, val: str) -> str:
    if not val:
        return dim("(unset)")
    if key in SECRETS:
        return dim(f"{'*' * 8} ({len(val)} chars)")
    return val


def print_summary(env: Dict[str, str]) -> None:
    section("Summary")
    for k, v in env.items():
        print(f"  {bold(k)}={_mask(k, v)}")


def write_env(env: Dict[str, str], dest: Path) -> None:
    if dest.exists():
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = dest.with_suffix(f".bak.{ts}")
        dest.rename(backup)
        print(green(f"✓ Backed up existing .env → {backup.name}"))
    lines = [
        "# Generated by setup_wizard.py on " + datetime.now().isoformat(timespec="seconds"),
        "",
    ]
    for k, v in env.items():
        # Quote values with whitespace or # so dotenv parses them correctly.
        if any(c in v for c in (" ", "\t", "#", "\"")):
            v_out = '"' + v.replace('"', '\\"') + '"'
        else:
            v_out = v
        lines.append(f"{k}={v_out}")
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    dest.chmod(0o600)
    print(green(f"✓ Wrote {dest} (mode 600)"))


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #


def main() -> int:
    print()
    header("NullShift — Interactive Setup")
    print()
    print("This wizard will create a " + bold(".env") + " file with your configuration.")
    print(dim("Press Ctrl+C at any time to abort — nothing is written until the end."))

    env: Dict[str, str] = {}
    try:
        configure_llm(env)
        configure_siem(env)
        configure_auth(env)
        configure_optional(env)
    except KeyboardInterrupt:
        print()
        print(yellow("Aborted. No .env written."))
        return 130

    print_summary(env)
    print()
    if not ask_yn("Write this to .env now?", default=True):
        print(yellow("Aborted. No .env written."))
        return 0

    dest = Path(__file__).resolve().parent / ".env"
    write_env(env, dest)

    print()
    print(green(bold("Done.")) + " Next steps:")
    print(f"  1) {bold('pip install -r requirements.txt')}")
    if env.get("USE_CLAUDE_AGENT_SDK") == "true":
        print(f"  2) Verify the {bold('claude')} CLI is on PATH and logged in: " + dim("`claude --version` && `ls ~/.claude/`"))
        print(f"  3) {bold('uvicorn app.main:app --reload --host 0.0.0.0 --port 8000')}")
    else:
        print(f"  2) {bold('uvicorn app.main:app --reload --host 0.0.0.0 --port 8000')}")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
