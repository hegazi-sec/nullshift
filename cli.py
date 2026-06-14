#!/usr/bin/env python3
"""NullShift CLI — server lifecycle management.

Usage:
    nullshift start     Start the server in the background
    nullshift stop      Stop the server
    nullshift restart   Restart the server
    nullshift status    Show server status and URL
    nullshift logs      Stream live server logs (Ctrl+C to exit)
    nullshift setup     Run the configuration wizard
    nullshift update    Pull latest from GitHub, refresh dependencies, restart
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


def cmd_update() -> None:
    """Pull the latest from origin/main, refresh dependencies, and restart."""
    if not (BASE / '.git').exists():
        print(_red('✗ Not a git repository.'))
        print(f'  This command only works when NullShift was installed via git clone.')
        sys.exit(1)

    print(f'  {_bold("Updating NullShift…")}')
    print()

    # 1) Warn about uncommitted local changes
    try:
        dirty = subprocess.run(
            ['git', '-C', str(BASE), 'status', '--porcelain'],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        if dirty:
            print(_red('✗ Uncommitted local changes detected:'))
            print()
            for line in dirty.splitlines()[:8]:
                print(f'    {_muted(line)}')
            if len(dirty.splitlines()) > 8:
                print(f'    {_muted("…")}')
            print()
            print('  Commit, stash, or revert your changes before updating.')
            print(f'  To force a clean update: {_cyan("git stash && nullshift update")}')
            sys.exit(1)
    except subprocess.CalledProcessError:
        print(_red('✗ Could not check git status. Aborting.'))
        sys.exit(1)

    # 2) Fetch
    print(f'  {_muted("◯")} Fetching from origin…')
    fetch = subprocess.run(
        ['git', '-C', str(BASE), 'fetch', 'origin', 'main'],
        capture_output=True, text=True,
    )
    if fetch.returncode != 0:
        print(_red('✗ git fetch failed:'))
        print(fetch.stderr)
        sys.exit(1)

    # 3) Determine commits behind
    behind = subprocess.run(
        ['git', '-C', str(BASE), 'rev-list', '--count', 'HEAD..origin/main'],
        capture_output=True, text=True,
    ).stdout.strip()
    try:
        behind_n = int(behind)
    except ValueError:
        behind_n = 0

    if behind_n == 0:
        print(f'  {_green("✓")} Already up to date.')
        return

    # 4) Preview the new commits
    print(f'  {_cyan("●")} {behind_n} commit{"s" if behind_n != 1 else ""} behind origin/main:')
    print()
    log = subprocess.run(
        ['git', '-C', str(BASE), 'log', '--oneline', '--no-decorate',
         f'HEAD..origin/main'],
        capture_output=True, text=True,
    ).stdout.strip()
    for line in log.splitlines()[:10]:
        print(f'    {_muted("•")} {line}')
    if behind_n > 10:
        print(f'    {_muted(f"… and {behind_n - 10} more")}')
    print()

    # 5) Snapshot requirements.txt to detect dependency changes
    req_path = BASE / 'requirements.txt'
    req_before = req_path.read_text() if req_path.exists() else ''

    # 6) Pull
    print(f'  {_muted("◯")} Pulling…')
    pull = subprocess.run(
        ['git', '-C', str(BASE), 'pull', 'origin', 'main', '--ff-only'],
        capture_output=True, text=True,
    )
    if pull.returncode != 0:
        print(_red('✗ git pull failed:'))
        print(pull.stderr)
        sys.exit(1)
    print(f'  {_green("✓")} Code updated.')

    # 7) Reinstall dependencies if requirements changed
    req_after = req_path.read_text() if req_path.exists() else ''
    if req_before != req_after:
        print(f'  {_muted("◯")} requirements.txt changed — installing updated dependencies…')
        python = _venv_python()
        if python.exists():
            subprocess.run(
                [str(python), '-m', 'pip', 'install', '-q', '-r', str(req_path)],
                cwd=str(BASE),
            )
            print(f'  {_green("✓")} Dependencies updated.')
        else:
            print(f'  {_red("⚠")}  venv missing — run {_cyan("python setup.py")} to recreate it.')

    # 8) Restart the server if it's running
    pid = _read_pid()
    if _is_running(pid):
        print(f'  {_muted("◯")} Restarting server…')
        cmd_restart()
    else:
        print()
        print(f'  Server was not running.')
        print(f'  Start it with:  {_cyan("nullshift start")}')


# ── entry point ───────────────────────────────────────────────────────────────

COMMANDS = {
    'start':   cmd_start,
    'stop':    cmd_stop,
    'restart': cmd_restart,
    'status':  cmd_status,
    'logs':    cmd_logs,
    'setup':   cmd_setup,
    'update':  cmd_update,
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
        print(f'    {_cyan("update")}  Pull latest from GitHub, refresh dependencies, restart')
        print()
        sys.exit(0 if len(sys.argv) < 2 else 1)

    COMMANDS[sys.argv[1]]()


if __name__ == '__main__':
    main()
