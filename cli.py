#!/usr/bin/env python3
"""NullShift CLI — server lifecycle management.

Usage:
    nullshift start     Start the server in the background
    nullshift stop      Stop the server
    nullshift restart   Restart the server
    nullshift status    Show server status and URL
    nullshift logs      Stream live server logs (Ctrl+C to exit)
    nullshift setup     Run the configuration wizard
    nullshift update    Move to the newest signed release: its dependencies, git merge --ff-only, restart,
                        health check (rolled back if it fails); nullshift update --check only reports;
                        nullshift update --mode off|notify|auto sets the daily check's mode (docs/UPDATES.md)
    nullshift passwd    Set a user's password (nullshift passwd [username], default admin)
"""
from __future__ import annotations
import os
import signal
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

BASE     = Path(__file__).resolve().parent
VENV     = BASE / '.venv'
DATA     = BASE / 'app' / 'data'
PID_FILE = DATA / 'nullshift.pid'
LOG_FILE = DATA / 'nullshift.log'
CONFIG_DB = DATA / 'config.db'

DEFAULT_PORT = 58443


# ── helpers ───────────────────────────────────────────────────────────────────

def _cyan(s):    return f'\033[96m{s}\033[0m'
def _green(s):   return f'\033[92m{s}\033[0m'
def _red(s):     return f'\033[91m{s}\033[0m'
def _muted(s):   return f'\033[90m{s}\033[0m'
def _bold(s):    return f'\033[1m{s}\033[0m'


def _venv_python() -> Path:
    if sys.platform == 'win32':
        return VENV / 'Scripts' / 'python.exe'
    return VENV / 'bin' / 'python'


def _venv_uvicorn() -> Path:
    if sys.platform == 'win32':
        return VENV / 'Scripts' / 'uvicorn.exe'
    return VENV / 'bin' / 'uvicorn'


def _read_pid() -> int | None:
    try:
        return int(PID_FILE.read_text().strip())
    except Exception:
        return None


def _is_running(pid: int | None) -> bool:
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError, OSError):
        return False


def _get_port() -> int:
    try:
        conn = sqlite3.connect(str(CONFIG_DB))
        row = conn.execute(
            "SELECT value FROM app_settings WHERE key='server_port' LIMIT 1"
        ).fetchone()
        conn.close()
        if row:
            return int(row[0])
    except Exception:
        pass
    return DEFAULT_PORT


def _uptime(pid: int) -> str:
    try:
        result = subprocess.run(
            ['ps', '-o', 'etime=', '-p', str(pid)],
            capture_output=True, text=True,
        )
        return result.stdout.strip() or '?'
    except Exception:
        return '?'


# ── commands ──────────────────────────────────────────────────────────────────

def cmd_start() -> None:
    pid = _read_pid()
    if _is_running(pid):
        port = _get_port()
        print(f'● NullShift is already running  '
              f'{_cyan(f"http://localhost:{port}")}  '
              f'{_muted(f"PID {pid}")}')
        return

    uvicorn = _venv_uvicorn()
    if not uvicorn.exists():
        print(_red('✗ Virtual environment not found.  Run: python setup.py'))
        sys.exit(1)

    port = _get_port()
    DATA.mkdir(parents=True, exist_ok=True)

    with open(LOG_FILE, 'a') as log:
        proc = subprocess.Popen(
            [
                str(uvicorn), 'app.main:app',
                '--host', '0.0.0.0',
                '--port', str(port),
                '--reload',
                '--reload-dir', 'app',
            ],
            cwd=BASE,
            stdout=log,
            stderr=log,
            start_new_session=True,
        )

    PID_FILE.write_text(str(proc.pid))

    # Brief pause to confirm the process is alive
    time.sleep(1.5)
    if _is_running(proc.pid):
        print(f'{_green("✓")} NullShift started')
        print(f'  {_bold("URL")}   {_cyan(f"http://localhost:{port}")}')
        print(f'  {_bold("PID")}   {proc.pid}')
        print(f'  {_bold("Logs")}  nullshift logs')
    else:
        print(_red('✗ Server failed to start — check logs:'))
        print(f'  nullshift logs')
        PID_FILE.unlink(missing_ok=True)
        sys.exit(1)


def cmd_stop() -> None:
    pid = _read_pid()
    if not _is_running(pid):
        print('○ NullShift is not running')
        PID_FILE.unlink(missing_ok=True)
        return

    try:
        os.kill(pid, signal.SIGTERM)
        for _ in range(20):
            time.sleep(0.3)
            if not _is_running(pid):
                break
        if _is_running(pid):
            os.kill(pid, signal.SIGKILL)
            time.sleep(0.3)
        PID_FILE.unlink(missing_ok=True)
        print(_green('✓ NullShift stopped'))
    except Exception as exc:
        print(_red(f'✗ Failed to stop: {exc}'))
        sys.exit(1)


def cmd_restart() -> None:
    cmd_stop()
    time.sleep(0.5)
    cmd_start()


def cmd_status() -> None:
    pid = _read_pid()
    if _is_running(pid):
        port = _get_port()
        uptime = _uptime(pid)
        print(f'{_green("●")} Running')
        print(f'  {_bold("URL")}     {_cyan(f"http://localhost:{port}")}')
        print(f'  {_bold("PID")}     {pid}')
        print(f'  {_bold("Uptime")} {uptime}')
        print(f'  {_bold("Logs")}   nullshift logs')
    else:
        print(f'{_muted("○")} Stopped')
        PID_FILE.unlink(missing_ok=True)


def cmd_logs() -> None:
    if not LOG_FILE.exists():
        print('No log file yet. Start the server first:  nullshift start')
        return
    print(_muted(f'Streaming {LOG_FILE}  (Ctrl+C to exit)\n'))
    try:
        subprocess.run(['tail', '-n', '50', '-f', str(LOG_FILE)])
    except KeyboardInterrupt:
        print()


def cmd_setup() -> None:
    python = _venv_python()
    exe = str(python) if python.exists() else sys.executable
    subprocess.run([exe, str(BASE / 'setup.py')])


def _updater():
    """app/updater.py, with the repo on the path and as the working directory (.env, the
    data folder), as the other commands that use app/ do."""
    sys.path.insert(0, str(BASE))
    os.chdir(BASE)
    from app import updater
    return updater


MODE_TEXT = {
    'off': 'nothing is checked',
    'notify': 'a daily check; admins are told in Settings › Updates (and by nullshift update --check)',
    'auto': 'a daily check, then the update by itself (when this install can update itself)',
}


def _print_check(st, updater) -> None:
    """What `nullshift update --check` says: the same as Settings › Updates."""
    print(f'  NullShift {_bold(updater.VERSION)}  {_muted("mode: " + updater.mode())}')
    if st['error']:
        print(_red(f'✗ The check failed: {st["error"]}'))
        sys.exit(1)
    if not st['latest']:
        print(f'  {_green("✓")} Up to date: no newer release')
        return
    if st['verify'] == updater.VERIFIED:
        print(f'  {_cyan("●")} Update available: {_bold(st["latest"])} (verified)')
    else:
        print(f'  {_cyan("●")} Update available: {_bold(st["latest"])} — {st["latest"]} {st["verify"]}')
    if st['reason']:
        print(_muted(f'  This install can only be notified: {st["reason"]}'))
    elif st['updatable']:
        print(f'  Install it with:  {_cyan("nullshift update")}')


def _restart_for_update() -> None:
    """cmd_restart for the updater. A start that fails exits the CLI (sys.exit); in an update
    that must become a failed health check and a rollback, not the end of the process."""
    try:
        cmd_restart()
    except SystemExit as e:
        raise RuntimeError(f'nullshift restart failed (exit {e.code}): see nullshift logs')


def cmd_update() -> None:
    """nullshift update — move this release checkout to the newest verified release: the new
    release's dependencies first, git merge --ff-only, the restart, a health check and a
    rollback to the previous commit if it fails (docs/UPDATES.md). Refused with the reason
    for anything but a clean release checkout. nullshift update --check only reports (what
    Settings › Updates shows); nullshift update --mode off|notify|auto sets the daily
    check's mode."""
    updater = _updater()
    args = sys.argv[2:]
    if args and args[0] == '--mode':
        if len(args) != 2:
            print(_red('✗ Usage: nullshift update --mode off|notify|auto'))
            sys.exit(1)
        try:
            mode = updater.set_mode(args[1])
        except ValueError as e:
            print(_red(f'✗ {e}'))
            sys.exit(1)
        print(f'{_green("✓")} Update mode: {_bold(mode)} — {MODE_TEXT[mode]}')
        return
    if args == ['--check']:
        _print_check(updater.check(), updater)
        return
    if args:
        print(_red('✗ Usage: nullshift update [--check | --mode off|notify|auto]'))
        sys.exit(1)

    ck = updater.checkout()
    if ck['dirty']:
        print(_red('✗ Uncommitted local changes detected:'))
        print()
        for line in ck['dirty'][:8]:
            print(f'    {_muted(line)}')
        if len(ck['dirty']) > 8:
            print(f'    {_muted("…")}')
        print()
        print('  Commit, stash, or revert your changes before updating.')
        print(f'  To force a clean update: {_cyan("git stash -u && nullshift update")}')
        print(f'  That also sets aside your untracked files (your own playbooks in data/kb/); '
              f'{_cyan("git stash pop")} brings everything back afterwards.')
        sys.exit(1)
    if not ck['release']:
        print(_red(f'✗ This install cannot update itself: {ck["reason"]}'))
        if not ck['docker']:  # the Docker reason already ends with the rebuild steps
            print(_muted('  Only a clean clone of the release repository updates itself; nullshift update --check still reports.'))
        sys.exit(1)

    print(f'  {_bold("Updating NullShift…")}')
    print()
    r = updater.update(restart=_restart_for_update, say=lambda step: print(f'  {_muted("◯")} {step}'))
    if r['result'] == 'current':
        print(f'  {_green("✓")} Already up to date: NullShift {updater.VERSION} is the newest release.')
        return
    if r['ok']:
        print(f'  {_green("✓")} {r["message"]}')
        return
    print(_red(f'✗ {r["message"]}'))
    sys.exit(1)


# ── entry point ───────────────────────────────────────────────────────────────

def cmd_passwd() -> None:
    """nullshift passwd [username] — set a user's password (default user: admin)."""
    import getpass
    sys.path.insert(0, str(BASE))
    os.chdir(BASE)
    from app.auth import get_password_hash
    from app.db import user_store

    username = sys.argv[2] if len(sys.argv) > 2 else 'admin'
    if not user_store.get_user_by_username(username):
        print(_red(f'✗ No user named {username!r}'))
        sys.exit(1)
    pw = getpass.getpass(f'  New password for {username} (min 16 chars): ')
    if len(pw) < 16:
        print(_red('✗ Password must be at least 16 characters'))
        sys.exit(1)
    if getpass.getpass('  Repeat it: ') != pw:
        print(_red('✗ Passwords do not match'))
        sys.exit(1)
    user_store.set_password(username, get_password_hash(pw))
    print(f'{_green("✓")} Password updated for {username}. Sessions already signed in stay valid until they expire.')


COMMANDS = {
    'start':   cmd_start,
    'stop':    cmd_stop,
    'restart': cmd_restart,
    'status':  cmd_status,
    'logs':    cmd_logs,
    'setup':   cmd_setup,
    'update':  cmd_update,
    'passwd':  cmd_passwd,
}


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print(f'\n  {_bold(_cyan("NullShift"))} — AI-Powered Security Operations Center\n')
        print('  Usage: nullshift <command>\n')
        print('  Commands:')
        print(f'    {_cyan("start")}    Start the server in the background')
        print(f'    {_cyan("stop")}     Stop the server')
        print(f'    {_cyan("restart")} Restart the server')
        print(f'    {_cyan("status")}  Show server status and URL')
        print(f'    {_cyan("logs")}    Stream live server logs  (Ctrl+C to exit)')
        print(f'    {_cyan("setup")}   Run the configuration wizard')
        print(f'    {_cyan("update")}  Move to the newest signed release (deps, git merge --ff-only, restart, health check)')
        print(f'             --check only reports; --mode off|notify|auto sets the daily check (default notify)')
        print(f'    {_cyan("passwd")}  Set a user\'s password  (nullshift passwd [username], default admin)')
        print()
        sys.exit(0 if len(sys.argv) < 2 else 1)

    COMMANDS[sys.argv[1]]()


if __name__ == '__main__':
    main()
