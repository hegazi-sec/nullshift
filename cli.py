#!/usr/bin/env python3
"""NullShift CLI — server lifecycle management.

Usage:
    nullshift start     Start the server in the background
    nullshift stop      Stop the server
    nullshift restart   Restart the server
    nullshift status    Show server status and URL
    nullshift logs      Stream live server logs (Ctrl+C to exit)
    nullshift setup     Run the configuration wizard
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


# ── entry point ───────────────────────────────────────────────────────────────

COMMANDS = {
    'start':   cmd_start,
    'stop':    cmd_stop,
    'restart': cmd_restart,
    'status':  cmd_status,
    'logs':    cmd_logs,
    'setup':   cmd_setup,
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
        print()
        sys.exit(0 if len(sys.argv) < 2 else 1)

    COMMANDS[sys.argv[1]]()


if __name__ == '__main__':
    main()
