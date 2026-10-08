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
    nullshift activate  Activate NullShift Pro with a product key (nullshift activate <KEY>)
    nullshift license   Show the license, or install a .lic file (nullshift license <file>);
                        nullshift license request-code <KEY> prints the offline activation code;
                        nullshift license reset-clock sets the rollback clock to now (logged)
    nullshift pro       The Pro code (app/pro/): nullshift pro status shows what is installed;
                        nullshift pro sync downloads or updates it from the license server;
                        nullshift pro install <file.nspro> loads the bundle sent to air-gapped installs;
                        nullshift pro free turns Pro on with Cyber-Pillar's free offer while it is open (no key)
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
    _pro_sync_before_start()

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


def _pro_sync_before_start() -> None:
    """Best effort, before the server starts: download or update the Pro package when the
    license has a Pro feature, so the server loads it at once (a short timeout; the daily
    check-in tries again). Nothing here can stop the start."""
    try:
        sys.path.insert(0, str(BASE))
        os.chdir(BASE)  # .env (NULLSHIFT_LICENSE_SERVER) is read from the repo, as the server reads it
        from app import pro_package
        r = pro_package.sync(timeout=5)
    except Exception:
        return
    if r['status'] == 'installed':
        print(f'{_green("✓")} NullShift Pro downloaded (package {r["sha256"][:12]})')
    elif r['status'] == 'error':
        print(_muted(f'  Pro package: {r["message"]}'))


def _pro_sync_line(r) -> str:
    """One line on a sync's outcome, for activate and `pro sync`."""
    if r['status'] == 'installed':
        return f'{_green("✓")} NullShift Pro downloaded (package {r["sha256"][:12]}): restart NullShift to load it'
    if r['status'] == 'current':
        return f'{_green("✓")} The Pro code is up to date'
    if r['status'] == 'source':
        return _muted('  Pro code: a source checkout, never downloaded over')
    if r['status'] == 'skipped':
        return _muted(f'  Pro code not downloaded: {r["message"]}')
    return _red(f'✗ Pro code not downloaded: {r["message"]}')


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


def _local_changes(porcelain: str) -> list[str]:
    """The `git status --porcelain` lines that are the user's own changes. A downloaded Pro
    package (app/pro/ holding .package.json) is untracked in a public clone and is not one:
    an update must not stop for it. The filter lives in app/updater.py, which uses it to
    tell a release checkout from a tree with local edits."""
    return _updater().local_changes(porcelain, BASE)


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
        print(f'  To force a clean update: {_cyan("git stash && nullshift update")}')
        sys.exit(1)
    if not ck['release']:
        print(_red(f'✗ This install cannot update itself: {ck["reason"]}'))
        if ck['docker']:
            print(f'  Rebuild the image instead:  {_cyan(updater.DOCKER_STEPS)}')
        else:
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


def _print_license(s=None) -> None:
    from app import licensing
    s = s or licensing.status()
    state = {'none': 'no license' + (' — ' + s['ended_message'] if s.get('ended_message') else ''),
             'invalid': 'saved license does not verify',
             'clock': 'clock rollback: ' + licensing.CLOCK_MESSAGE,
             'moved': 'moved: ' + licensing.MOVED_MESSAGE}.get(s['state'], s['state'])
    print(f'  Edition   {_bold(s["edition"].title())} {_muted("(" + state + ")")}')
    if s['customer']:
        print(f'  Customer  {s["customer"]}')
        if s['type'] == 'promo':  # the free Pro offer: no key, renewed at every check-in until Cyber-Pillar closes it
            kind = 'Free Pro (offer) · renews daily while the offer is open'
        else:
            kind = (s['type'] or 'paid') + (' · offline (activated with a request code)' if s['offline'] else '')
        print(f'  Type      {kind}')
        grace = _muted('(works until ' + s['grace_ends'][:10] + ')')
        print(f'  Expires   {s["expires"][:10]} {grace}')
        if s['offline']:
            checkin = _muted('not needed for an offline license')
        elif s['checked_at']:
            checkin = s['checked_at'][:16].replace('T', ' ') + ' UTC'
        else:
            checkin = _muted('never (the server was not reached yet)')
        print(f'  Check-in  {checkin}')
    print(f'  Install   {s["install_id"]}')
    if s['machine']:
        note = '' if s['bound'] or not s['customer'] else _muted(' (the license is not bound to a machine)')
        print(f'  Machine   {s["machine"]}{note}')
    else:
        print(f'  Machine   {_muted("not bound (no hardware ID found: set NULLSHIFT_MACHINE_ID)")}')
    print(f'  Seats     {s["seats_used"]} of {s["seats"]} in use')
    print(f'  Features  {", ".join(s["features"]) or _muted("Community")}')
    print(f'  Pro code  {_pro_code_line(s)}')


def _pro_code_line(s) -> str:
    """The Pro package as status() reports it: source checkout, installed package (with its
    commit and any load error), or none."""
    if s['pro_source']:
        return 'source checkout' + (_red(' — failed to load: ' + s['pro_load_error']) if s['pro_load_error'] else '')
    if s['pro_package'] is not None:
        pkg = s['pro_package']
        line = f'package {(pkg.get("sha256") or "?")[:12]} (commit {pkg.get("commit") or "unknown"}, installed {(pkg.get("installed_at") or "?")[:10]})'
        if s['pro_load_error']:
            line += _red(' — failed to load: ' + s['pro_load_error'])
        elif not s['pro_installed']:
            line += _muted(' — not loaded yet: restart NullShift')
        return line
    return _muted('not installed (downloads at activation and the daily check-in; nullshift pro sync)')


def cmd_activate() -> None:
    """nullshift activate <KEY> [--transfer] — exchange a product key for a license at the
    license server (NULLSHIFT_LICENSE_SERVER, default https://nullshift.cyber-pillar.com),
    then download the Pro code and show the edition. --transfer moves a key already on its
    maximum installs here: the other install loses Pro at its next check-in (at most 3
    moves per 30 days). The license takes effect at once, running server included (it reads
    config.db live); a downloaded Pro package needs a restart."""
    sys.path.insert(0, str(BASE))
    os.chdir(BASE)
    from app import licensing, pro_package

    args = sys.argv[2:]
    transfer = '--transfer' in args
    keys = [a for a in args if not a.startswith('--')]
    unknown = [a for a in args if a.startswith('--') and a != '--transfer']
    if len(keys) != 1 or unknown:
        print(_red('✗ Usage: nullshift activate NS-XXXXX-XXXXX-XXXXX-XXXXX [--transfer]'))
        sys.exit(1)
    try:
        lic = licensing.activate(keys[0], transfer=transfer)
    except licensing.ActivationError as e:
        print(_red(f'✗ {e}'))
        if e.status == 502:
            print(_muted('  Air-gapped? nullshift license request-code <KEY>, send the code to Cyber-Pillar, '
                         'then nullshift license <file.lic>'))
        elif e.code == 'activation_limit':
            print(_muted('  Moving from another server? nullshift activate <KEY> --transfer moves the license here; '
                         'the other install loses Pro at its next check-in (at most 3 moves per 30 days).'))
        sys.exit(1)
    _activation_outcome(f'{"Moved to this install" if transfer else "Activated"} for {lic["customer"]}')
    print(_pro_sync_line(pro_package.sync()))  # the Pro code follows the license (best effort)
    _print_license()


def _activation_outcome(what: str) -> None:
    """The outcome of an activation (a key, a move, the free offer) by the saved license's
    state: it can succeed and still leave Pro off."""
    from app import licensing
    s = licensing.status()
    if s['state'] in ('valid', 'grace'):
        print(f'{_green("✓")} {what}')
        if s['state'] == 'grace':
            print(_muted(f'  This license expired on {s["expires"][:10]} and is in its grace period until '
                         f'{s["grace_ends"][:10]}: renew it with Cyber-Pillar.'))
    else:
        why = {'moved': 'it is bound to another machine. ' + licensing.MOVED_MESSAGE,
               'expired': 'it expired on ' + s['expires'][:10] + ' and its grace period is over. Renew it with Cyber-Pillar.',
               'clock': licensing.CLOCK_MESSAGE + '. The license server\'s time is ahead of this machine\'s clock.'
               }.get(s['state'], s['state'])
        print(_red(f'✗ {what}, but Pro is still off: {why}'))


def cmd_pro() -> None:
    """nullshift pro status — the installed Pro package (app/pro/), if any.
    nullshift pro sync — download or update it from the license server (the license must
    have a Pro feature; never over a source checkout). nullshift pro install <file.nspro> —
    the bundle Cyber-Pillar sends air-gapped installs with the .lic, verified the same way.
    A new package is loaded at the next restart.
    nullshift pro free — turn Pro on with Cyber-Pillar's free offer while it is open: no key,
    a promo license for this install that renews at every daily check-in; when the offer
    ends, Pro turns off at the next check-in and NullShift continues as Community, nothing
    lost. Then the Pro code is downloaded, as after a key. Refused while this install has a
    live license of its own (a product key activated later replaces the promo license)."""
    sys.path.insert(0, str(BASE))
    os.chdir(BASE)
    from app import licensing, pro_package

    verb = sys.argv[2] if len(sys.argv) > 2 else ''
    if verb == 'status' and len(sys.argv) == 3:
        _print_license()
        return
    if verb == 'free' and len(sys.argv) == 3:
        offer = licensing.promo_status()
        if not offer.get('open'):
            print(_red('✗ ' + (offer.get('message') or 'The free Pro offer is not open right now.')))
            if not offer.get('error'):
                print(_muted('  Cyber-Pillar opens it from time to time; Settings › License shows the card while it is open. '
                             'A product key: nullshift activate <KEY>'))
            sys.exit(1)
        try:
            lic = licensing.promo_activate()
        except licensing.ActivationError as e:
            print(_red(f'✗ {e}'))
            sys.exit(1)
        _activation_outcome(f'Free Pro (offer) activated: {lic["seats"]} active users, every Pro feature, free while '
                            f'the offer lasts')
        print(_muted('  The license renews daily while the offer is open. When Cyber-Pillar closes it, Pro turns off at '
                     'the next check-in and NullShift continues as Community: nothing is lost.'))
        print(_pro_sync_line(pro_package.sync()))  # the Pro code follows the license (best effort)
        _print_license()
        return
    if verb == 'sync' and len(sys.argv) == 3:
        r = pro_package.sync()
        print(_pro_sync_line(r))
        if r['status'] == 'error':
            sys.exit(1)
        return
    if verb == 'install' and len(sys.argv) == 4:
        try:
            marker = pro_package.install_bundle(sys.argv[3])
        except (ValueError, OSError) as e:
            print(_red(f'✗ {e}'))
            sys.exit(1)
        print(f'{_green("✓")} NullShift Pro installed (package {marker["sha256"][:12]}, commit '
              f'{marker["commit"] or "unknown"}): restart NullShift to load it')
        return
    print(_red('✗ Usage: nullshift pro status | sync | install <file.nspro> | free'))
    sys.exit(1)


def cmd_license() -> None:
    """nullshift license [file] — install a NullShift Pro license from a file, then show the
    edition. Takes effect at once, running server included (it reads config.db live).
    nullshift license request-code <KEY> — the offline activation code for air-gapped installs.
    nullshift license reset-clock — set the rollback clock to now: for an install whose clock
    was set ahead by mistake and corrected, and which no license server can put right
    (an offline license). Shell access on the server is the trust; it is logged."""
    sys.path.insert(0, str(BASE))
    os.chdir(BASE)
    from app import licensing

    if len(sys.argv) > 2 and sys.argv[2] == 'reset-clock':
        if len(sys.argv) > 3:
            print(_red('✗ Usage: nullshift license reset-clock'))
            sys.exit(1)
        old, new = licensing.reset_clock()
        print(f'{_green("✓")} License clock reset: {old or "unset"} → {new}')
        _print_license()
        return
    if len(sys.argv) > 2 and sys.argv[2] == 'request-code':
        if len(sys.argv) < 4:
            print(_red('✗ Usage: nullshift license request-code NS-XXXXX-XXXXX-XXXXX-XXXXX'))
            sys.exit(1)
        try:
            code = licensing.request_code(sys.argv[3])
        except ValueError as e:
            print(_red(f'✗ {e}'))
            sys.exit(1)
        print(code)  # alone on stdout, so it can be redirected to a file
        print(_muted('Send this code to Cyber-Pillar. They answer with a .lic file: nullshift license <file.lic>'),
              file=sys.stderr)
        return
    if len(sys.argv) > 2:
        try:
            blob = Path(sys.argv[2]).read_text().strip()
            licensing.verify(blob)
        except (OSError, ValueError) as e:
            print(_red(f'✗ {e}'))
            sys.exit(1)
        licensing.save(blob)
        print(f'{_green("✓")} License installed')
    _print_license()


COMMANDS = {
    'start':   cmd_start,
    'stop':    cmd_stop,
    'restart': cmd_restart,
    'status':  cmd_status,
    'logs':    cmd_logs,
    'setup':   cmd_setup,
    'update':  cmd_update,
    'passwd':  cmd_passwd,
    'activate': cmd_activate,
    'license': cmd_license,
    'pro': cmd_pro,
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
        print(f'    {_cyan("activate")} Activate NullShift Pro with a product key  (nullshift activate <KEY> [--transfer])')
        print(f'    {_cyan("license")} Show the license, or install a .lic file  (nullshift license <file>)')
        print(f'             Offline activation code: nullshift license request-code <KEY>')
        print(f'             Clock reported as rolled back after a correction: nullshift license reset-clock')
        print(f'    {_cyan("pro")}     The Pro code: nullshift pro status | sync | install <file.nspro> | free')
        print(f'             sync downloads it from the license server (activation and start do too); install loads')
        print(f'             the bundle sent to air-gapped installs. Restart NullShift to load a new package.')
        print(f'             free turns Pro on with Cyber-Pillar\'s free offer while it is open (no key needed).')
        print()
        sys.exit(0 if len(sys.argv) < 2 else 1)

    COMMANDS[sys.argv[1]]()


if __name__ == '__main__':
    main()
