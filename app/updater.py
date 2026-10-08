"""Release updates: how an install learns about, and optionally installs, a new NullShift
release (docs/UPDATES.md). The Pro package updates itself (app/pro_package.py); this is
the core.

- A release is a signed git tag `vMAJOR.MINOR.PATCH` on the repository the install was
  cloned from. It is verified with ALLOWED_SIGNERS below, this install's own copy of the
  release key, never anything fetched with the update: a compromised repository cannot
  ship an update. While the list is empty nothing verifies, so Auto never updates and
  Notify says the release "is not signed; update manually".
- Only a release checkout updates itself: this folder is the top level of its own git
  repository, the tree is clean (the `local_changes` filter `nullshift update` uses) and
  HEAD is an ancestor of the tag. A development tree whose git root is a parent folder,
  a zip download without .git and a Docker image are told about releases (the GitHub tags
  API, nothing verified or installed) and shown why.
- check(): `git fetch --tags`, the highest release tag above VERSION, `git verify-tag`
  with gpg.format=ssh and a temp allowed-signers file. Never raises: a failure lands in
  update_state and the next tick retries. It runs in the daily thread (start_loop(), begun
  at app startup) or a "Check now" thread, never on a request.
- update(): the new release's dependencies first (`git show <tag>:requirements.txt`, so a
  --reload server never reloads onto missing packages), `git merge --ff-only`, the restart
  `nullshift restart` does, then /health within HEALTH_WAIT seconds and no traceback from
  app.main in the startup log; otherwise `git reset --hard` to the previous commit, the
  previous requirements, another restart, and "rolled back: <why>" recorded. The server
  cannot restart itself from a thread (the restart kills it), so Auto and "Update now"
  run `nullshift update` as a detached process (launch_detached()); Auto first waits for
  no investigation in flight, up to IDLE_MAX, in the daily thread.
- Everything here is injectable (BASE, the git runner, pip, the restart, the health
  check, the in-flight probe) so tests run against temporary repositories only.
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import requests

from app.version import VERSION

log = logging.getLogger("nullshift.updater")

BASE = Path(__file__).resolve().parent.parent  # the install folder (app/, cli.py, requirements.txt); tests point it at temp clones

# The release key's public half, in git's allowed-signers format, one line per key:
#   "release@cyber-pillar.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... release@cyber-pillar.com"
# (the principal, then the key as ~/.ssh/nullshift-release.pub holds it). The owner adds
# the key here in a release signed by the previous key (the first one in an ordinary
# commit): an install trusts only the keys it already has.
ALLOWED_SIGNERS: List[str] = [
    # 2026-10-08, SHA256:ct7pQmAMfMiB0Fq99y9UQnMORM08MLPE45N96+093gw
    "release@cyber-pillar.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL9KNFv8qVu112R8lTnshX7Exqi1dv0xg2c1qhtLSIBB",
]
PRINCIPAL = "release@cyber-pillar.com"

DEFAULT_REPO = "hegazi-sec/nullshift"  # the GitHub repository whose tags are read when there is no git checkout
GITHUB_API = "https://api.github.com"
MODES = ("off", "notify", "auto")
DEFAULT_MODE = "notify"
TIMEOUT = 30  # seconds, every git command and HTTP call of the check
CHECK_EVERY = 24 * 3600
FIRST_CHECK_AFTER = 5 * 60  # the first check waits this long after startup (a --reload server restarts often)
IDLE_POLL = 60  # Auto: the in-flight probe's interval and limit while waiting for a quiet moment
IDLE_MAX = 6 * 3600
HEALTH_WAIT = 90  # seconds for /health to answer 200 after the restart
HEALTH_POLL = 1
PIP_TIMEOUT = 1800
DOCKERENV = "/.dockerenv"
DOCKER_STEPS = "git pull && docker compose build --no-cache && docker compose up -d"

TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")  # releases only: a suffixed tag (v1.0.0-rc1) is not one
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")

# What the check says about the newest release, after its tag ("v0.4.0 is not signed; …")
VERIFIED = "verified"
NOT_SIGNED = "is not signed; update manually"
BAD_SIGNATURE = "has a signature that does not verify; update manually"
NOT_VERIFIABLE = "cannot be verified without a git checkout; update manually"


# ── Settings ─────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _store():
    from app.db.settings_store import settings_store
    return settings_store


def _setting(name: str) -> str:
    """A NULLSHIFT_* value: from .env through app.config's Settings, else the process
    environment; "" when neither has it (as app/licensing.py reads its own)."""
    try:
        from app.config import settings
        v = getattr(settings, name, None)
    except Exception:
        v = None
    return str(v or os.environ.get(name) or "").strip()


def mode() -> str:
    """off | notify | auto; anything else stored reads as the default (notify)."""
    m = (_store().get("update_mode") or "").strip().lower()
    return m if m in MODES else DEFAULT_MODE


def set_mode(value: str, updated_by: Optional[int] = None) -> str:
    m = str(value or "").strip().lower()
    if m not in MODES:
        raise ValueError("The update mode is off, notify or auto")
    _store().set_many({"update_mode": m}, updated_by=updated_by)
    log.info("Update mode set to %s", m)
    return m


def state() -> Dict[str, Any]:
    """update_state as stored (JSON); {} when there is none or it does not parse."""
    try:
        st = json.loads(_store().get("update_state") or "{}")
        return st if isinstance(st, dict) else {}
    except (ValueError, TypeError):
        return {}


_state_lock = threading.Lock()


def _save_state(**fields: Any) -> Dict[str, Any]:
    """Merge fields into update_state (None removes nothing: it is stored as null)."""
    with _state_lock:
        st = {**state(), **fields}
        _store().set_many({"update_state": json.dumps(st, sort_keys=True)})
    return st


# ── Versions and tags ────────────────────────────────────────────────────────

def parse_tag(tag: str) -> Optional[Tuple[int, int, int]]:
    """v1.2.3 -> (1, 2, 3); None for anything that is not a release tag."""
    m = TAG_RE.match(str(tag or "").strip())
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def current_version() -> Tuple[int, int, int]:
    return parse_tag("v" + VERSION) or (0, 0, 0)


def newest_release(tags: Iterable[str]) -> Optional[str]:
    """The highest release tag above VERSION among `tags`, or None."""
    best: Optional[Tuple[Tuple[int, int, int], str]] = None
    for tag in tags:
        v = parse_tag(tag)
        if v and v > current_version() and (best is None or v > best[0]):
            best = (v, tag.strip())
    return best[1] if best else None


def repo() -> str:
    """owner/name of the GitHub repository checked without a git checkout."""
    r = _setting("NULLSHIFT_UPDATE_REPO") or DEFAULT_REPO
    if not REPO_RE.match(r):
        raise ValueError("NULLSHIFT_UPDATE_REPO must be owner/name")
    return r


def github_tags() -> List[str]:
    """The repository's tag names from the GitHub tags API (the newest 100)."""
    r = requests.get(f"{GITHUB_API}/repos/{repo()}/tags", params={"per_page": 100}, timeout=TIMEOUT,
                     headers={"Accept": "application/vnd.github+json", "User-Agent": f"NullShift/{VERSION}"})
    r.raise_for_status()
    return [str(t.get("name") or "") for t in r.json() if isinstance(t, dict)]


# ── The checkout ─────────────────────────────────────────────────────────────

def _git(*args: str, timeout: int = TIMEOUT) -> subprocess.CompletedProcess:
    """git in the install folder; raises OSError / SubprocessError (no git, a timeout)."""
    return subprocess.run(["git", "-C", str(BASE), *args], capture_output=True, text=True, timeout=timeout)


def local_changes(porcelain: str, base: Optional[Path] = None) -> List[str]:
    """The `git status --porcelain` lines that are the user's own changes. A downloaded Pro
    package (app/pro/ holding .package.json) is untracked in a public clone and is not one:
    an update must not stop for it. `nullshift update` uses this same filter."""
    lines = [line for line in porcelain.splitlines() if line.strip()]
    if ((base or BASE) / "app" / "pro" / ".package.json").exists():
        def is_package(line: str) -> bool:
            path = line[3:].replace("\\", "/").rstrip("/")  # `XY path`
            return path == "app/pro" or path.startswith("app/pro/")
        lines = [line for line in lines if not is_package(line)]
    return lines


def in_docker() -> bool:
    return os.path.exists(DOCKERENV) or bool(_setting("NULLSHIFT_IN_DOCKER"))


def checkout() -> Dict[str, Any]:
    """What this install is. `git`: its own git checkout (the repository's top level is
    this folder; its tags are fetched and verified). `release`: a release checkout that can
    update itself (also clean). Otherwise `reason` says why it can only be notified."""
    ck: Dict[str, Any] = {"git": False, "release": False, "reason": None, "head": None, "dirty": [],
                          "docker": in_docker()}
    if ck["docker"]:
        ck["reason"] = f"a Docker image: rebuild it instead ({DOCKER_STEPS})"
        return ck
    try:
        top = _git("rev-parse", "--show-toplevel")
    except (OSError, subprocess.SubprocessError) as e:
        ck["reason"] = f"git is not available here ({e}); install the new release by hand"
        return ck
    if top.returncode != 0:
        ck["reason"] = "not a git checkout (a download without .git): install the new release by hand"
        return ck
    top_path = Path(top.stdout.strip()).resolve()
    if top_path != BASE.resolve():
        ck["reason"] = f"a development tree: the git repository's top level is {top_path}, not this folder"
        return ck
    ck["git"] = True
    try:
        porcelain = _git("status", "--porcelain")
        head = _git("rev-parse", "HEAD")
    except (OSError, subprocess.SubprocessError) as e:
        ck["reason"] = f"git status failed ({e})"
        return ck
    if porcelain.returncode != 0 or head.returncode != 0:
        ck["reason"] = "git status failed: " + (porcelain.stderr or head.stderr).strip()[:200]
        return ck
    ck["head"] = head.stdout.strip()
    ck["dirty"] = local_changes(porcelain.stdout)
    if ck["dirty"]:
        n = len(ck["dirty"])
        ck["reason"] = f"uncommitted local changes ({n} path{'s' if n != 1 else ''}): commit, stash or revert them first"
        return ck
    ck["release"] = True
    return ck


def is_ancestor(commit: str, tag: str) -> bool:
    """HEAD (or any commit) is an ancestor of the tag's commit: the update is a fast-forward."""
    return _git("merge-base", "--is-ancestor", commit, f"{tag}^{{commit}}").returncode == 0


def release_tags() -> List[str]:
    r = _git("tag", "-l", "v*")
    if r.returncode != 0:
        raise RuntimeError("git tag failed: " + r.stderr.strip()[:200])
    return [t for t in r.stdout.split() if parse_tag(t)]


def verify_tag(tag: str) -> str:
    """VERIFIED, or why not: `git verify-tag` with gpg.format=ssh against an allowed-signers
    file written from ALLOWED_SIGNERS (this install's own copy of the release key)."""
    if not ALLOWED_SIGNERS:
        return NOT_SIGNED  # nothing can verify until the release key is embedded
    fd, path = tempfile.mkstemp(prefix="nullshift-signers-", suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(line.strip() for line in ALLOWED_SIGNERS if line.strip()) + "\n")
        r = _git("-c", "gpg.format=ssh", "-c", f"gpg.ssh.allowedSignersFile={path}", "verify-tag", tag)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    if r.returncode == 0:
        # the signature covers the tag object, not the ref: a v9.9.9 ref pointed at the signed
        # v0.4.0 object verifies too, so the name signed inside it must be this one
        obj = _git("cat-file", "tag", tag)
        signed_name = next((ln[4:] for ln in obj.stdout.splitlines() if ln.startswith("tag ")), "")
        if obj.returncode == 0 and signed_name == tag:
            return VERIFIED
        log.warning("Release tag %s is a signed tag named %r: refused", tag, signed_name)
        return BAD_SIGNATURE
    err = (r.stderr or "").strip()
    log.warning("Release tag %s did not verify: %s", tag, err[:300])
    if "no signature found" in err or "non-tag object" in err:  # an unsigned annotated tag, a lightweight tag
        return NOT_SIGNED
    return BAD_SIGNATURE


# ── The check ────────────────────────────────────────────────────────────────

_check_lock = threading.Lock()


def check() -> Dict[str, Any]:
    """The daily check (and "Check now"): the newest release above VERSION, whether it
    verified and whether this install can install it. Never raises; the result (or the
    failure) is merged into update_state and returned."""
    st: Dict[str, Any] = {"checked_at": _now(), "current": VERSION, "source": None, "latest": None,
                          "verify": None, "updatable": False, "reason": None, "error": None}
    with _check_lock:
        try:
            ck = checkout()
            st["reason"] = ck["reason"]
            if ck["git"]:
                st["source"] = "git"
                r = _git("fetch", "--tags", "--quiet", "origin")
                if r.returncode != 0:
                    raise RuntimeError("git fetch failed: " + r.stderr.strip()[:200])
                latest = newest_release(release_tags())
                if latest and ck["head"] and _git("rev-parse", f"{latest}^{{commit}}").stdout.strip() == ck["head"]:
                    latest = None  # the code is already at the tag (a restart has not loaded it yet): current
                if latest:
                    st["latest"] = latest
                    st["verify"] = verify_tag(latest)
                    if ck["release"] and not is_ancestor("HEAD", latest):
                        st["reason"] = f"local commits: HEAD is not an ancestor of {latest}; update manually"
                    st["updatable"] = bool(ck["release"] and st["verify"] == VERIFIED and not st["reason"])
            else:
                st["source"] = "github"  # a zip, a Docker image, a development tree: told, nothing installed
                latest = newest_release(github_tags())
                if latest:
                    st["latest"] = latest
                    st["verify"] = NOT_VERIFIABLE
            log.info("Update check: %s", f"{st['latest']} {st['verify']}" if st["latest"] else f"{VERSION} is current")
        except Exception as e:
            st["error"] = f"{type(e).__name__}: {e}"[:300]
            log.warning("Update check failed: %s", st["error"])
    _save_state(**st)
    return st


_check_thread: Optional[threading.Thread] = None


def check_now() -> Dict[str, Any]:
    """"Check now": check() in its own daemon thread, one at a time. {"started": bool}."""
    global _check_thread
    with _state_lock:
        if _check_thread is not None and _check_thread.is_alive():
            return {"started": False, "checking": True}
        _check_thread = threading.Thread(target=check, name="update-check-now", daemon=True)
        _check_thread.start()
    return {"started": True, "checking": True}


def checking() -> bool:
    return _check_thread is not None and _check_thread.is_alive()


# ── The update ───────────────────────────────────────────────────────────────

def venv_python() -> Path:
    return BASE / ".venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")


def _data_dir() -> Path:
    return BASE / "app" / "data"


def _log_file() -> Path:
    return _data_dir() / "nullshift.log"  # the server log `nullshift logs` streams


def _alive(pid: Any) -> bool:
    try:
        os.kill(int(pid), 0)
        return True
    except (TypeError, ValueError, ProcessLookupError, PermissionError, OSError):
        return False


def server_running() -> bool:
    """The pid file `nullshift start` writes names a live process."""
    try:
        return _alive(int((_data_dir() / "nullshift.pid").read_text().strip()))
    except (OSError, ValueError):
        return False


def server_port() -> int:
    """server_port from config.db as the CLI reads it (not an app setting), else 58443."""
    import sqlite3
    try:
        conn = sqlite3.connect(str(_data_dir() / "config.db"))
        try:
            row = conn.execute("SELECT value FROM app_settings WHERE key='server_port' LIMIT 1").fetchone()
        finally:
            conn.close()
        if row:
            return int(row[0])
    except Exception:
        pass
    return 58443


def running() -> Optional[Dict[str, Any]]:
    """The update in progress ({tag, pid, started_at}) while its process is alive, else None."""
    r = state().get("running")
    return r if isinstance(r, dict) and _alive(r.get("pid")) else None


def install_requirements(text: str) -> None:
    """pip install the given requirements.txt content into the install's venv (never the
    file on disk: the new release's requirements are installed before the merge)."""
    python = venv_python()
    if not python.exists():
        raise RuntimeError("virtual environment not found: run python setup.py")
    fd, path = tempfile.mkstemp(prefix="nullshift-requirements-", suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        r = subprocess.run([str(python), "-m", "pip", "install", "-q", "-r", path], cwd=str(BASE),
                           capture_output=True, text=True, timeout=PIP_TIMEOUT)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    if r.returncode != 0:
        raise RuntimeError("pip install failed: " + (r.stderr or r.stdout).strip()[-500:])


def restart_server() -> None:
    """The restart `nullshift restart` does, as a subprocess (the CLI passes its own
    cmd_restart instead)."""
    r = subprocess.run([str(venv_python()), str(BASE / "cli.py"), "restart"], cwd=str(BASE),
                       capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        raise RuntimeError("nullshift restart failed: " + (r.stderr or r.stdout).strip()[-300:])


def log_mark() -> int:
    """Where the server log ends now: the health check reads only what the restart adds."""
    try:
        return _log_file().stat().st_size
    except OSError:
        return 0


def _log_since(mark: int) -> str:
    try:
        with open(_log_file(), "r", encoding="utf-8", errors="replace") as f:
            f.seek(mark)
            return f.read()
    except OSError:
        return ""


def has_main_traceback(text: str) -> bool:
    """A traceback from app.main in the new server's startup log. The old server's shutdown
    lines come first; only what follows uvicorn's last "Started …" line counts."""
    starts = [i for i in (text.rfind("Started reloader process"), text.rfind("Started server process")) if i >= 0]
    tail = text[max(starts):] if starts else text
    return "Traceback (most recent call last)" in tail and ("app/main.py" in tail or "app\\main.py" in tail
                                                             or "app.main" in tail)


def health_check(mark: int) -> Tuple[bool, str]:
    """(ok, why): /health answers 200 within HEALTH_WAIT seconds, and the log since `mark`
    has no traceback from app.main."""
    url = f"http://127.0.0.1:{server_port()}/health"
    deadline = time.monotonic() + HEALTH_WAIT
    while True:
        try:
            if requests.get(url, timeout=5).status_code == 200:
                break
        except requests.RequestException:
            pass
        if time.monotonic() >= deadline:
            return False, f"/health did not answer 200 within {HEALTH_WAIT} s"
        time.sleep(HEALTH_POLL)
    if has_main_traceback(_log_since(mark)):
        return False, "the startup log has a traceback from app.main"
    return True, "ok"


def update(*, automatic: bool = False, install_deps: Optional[Callable[[str], None]] = None,
           restart: Optional[Callable[[], None]] = None, health: Optional[Callable[[int], Tuple[bool, str]]] = None,
           say: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """Move this release checkout to the newest verified release: a fresh check(), the new
    requirements, `git merge --ff-only`, the restart, the health check, the rollback. The
    outcome {ok, result, tag, message} is also recorded as update_state.last_update
    (result: updated | current | refused: … | failed: … | rolled back: …). `automatic`
    (the daily thread) never retries a tag rolled back before; `say` gets each step for
    the CLI. Never raises."""
    install_deps = install_deps or install_requirements
    restart = restart or restart_server
    health = health or health_check

    def tell(msg: str) -> None:
        log.info(msg)
        if say:
            say(msg)

    claimed = False  # this process wrote update_state.running: only then does it clear it

    def done(ok: bool, result: str, tag: Optional[str], message: str, record: bool = True, **extra: Any) -> Dict[str, Any]:
        if record:
            fields = {"last_update": {"tag": tag, "result": result, "finished_at": _now(), **extra}}
            _save_state(**fields, **({"running": None} if claimed else {}))
        (log.info if ok else log.error)("Update %s: %s", result, message)
        return {"ok": ok, "result": result, "tag": tag, "message": message}

    try:
        ck = checkout()
        if not ck["release"]:
            return done(False, "refused: " + ck["reason"], None, ck["reason"])
        st = check()
        if st["error"]:
            return done(False, "refused: the check failed", None, "the check failed: " + st["error"])
        tag = st["latest"]
        if not tag:
            return done(True, "current", None, f"NullShift {VERSION} is the newest release", record=False)
        if st["verify"] != VERIFIED:
            return done(False, f"refused: {tag} {st['verify']}", tag, f"{tag} {st['verify']}")
        if not st["updatable"]:
            return done(False, "refused: " + (st["reason"] or "not updatable"), tag, st["reason"] or "not updatable")
        if automatic and tag in (state().get("rolled_back") or []):
            return done(False, "refused: rolled back before", tag, f"{tag} was rolled back before; not retried automatically")
        busy = running()
        if busy and int(busy.get("pid") or 0) != os.getpid():
            return done(False, "refused: already running", tag, f"an update is already running (pid {busy['pid']})",
                        record=False)

        prev = ck["head"]
        prev_req = (BASE / "requirements.txt").read_text(encoding="utf-8") if (BASE / "requirements.txt").exists() else ""
        started = _now()
        _save_state(running={"tag": tag, "pid": os.getpid(), "started_at": started})
        claimed = True
        base = {"from": prev, "started_at": started}
        tell(f"Updating NullShift {VERSION} to {tag} (from commit {prev[:12]})")

        shown = _git("show", f"{tag}:requirements.txt")
        if shown.returncode != 0:
            return done(False, f"failed: {tag} has no requirements.txt", tag, shown.stderr.strip()[:200], **base)
        tell(f"Installing the dependencies of {tag}")
        try:
            install_deps(shown.stdout)
        except Exception as e:
            _quietly(install_deps, prev_req)
            return done(False, f"failed: the dependencies of {tag} did not install", tag, str(e)[:300], **base)

        tell(f"git merge --ff-only {tag}")
        merged = _git("merge", "--ff-only", tag)
        if merged.returncode != 0:
            _quietly(install_deps, prev_req)
            why = merged.stderr.strip()[:200]
            return done(False, f"failed: git merge --ff-only {tag}", tag, why, **base)
        new_head = _git("rev-parse", "HEAD").stdout.strip()

        if not server_running():
            tell(f"Code updated to {tag}; the server was not running: start it with nullshift start")
            return done(True, "updated", tag, "updated; the server was not running: start it with nullshift start",
                        to=new_head, **base)
        mark = log_mark()
        tell("Restarting NullShift")
        try:
            restart()
            tell("Checking /health")
            ok, why = health(mark)
        except Exception as e:  # a restart that fails is a failed health check: rolled back below
            ok, why = False, f"the restart failed: {e}"[:300]
        if ok:
            tell(f"NullShift {tag} is up")
            return done(True, "updated", tag, f"updated to {tag}", to=new_head, **base)

        tell(f"Health check failed ({why}): rolling back to {prev[:12]}")
        reset = _git("reset", "--hard", prev)
        if reset.returncode != 0:
            return done(False, f"failed: {why}; git reset --hard {prev[:12]} failed", tag,
                        reset.stderr.strip()[:200], rolled_back_from=new_head, **base)
        tell("Reinstalling the previous dependencies")
        _quietly(install_deps, (BASE / "requirements.txt").read_text(encoding="utf-8"))
        tell("Restarting NullShift")
        _quietly(restart)
        _save_state(rolled_back=sorted(set(state().get("rolled_back") or []) | {tag}))
        return done(False, f"rolled back: {why}", tag, f"{tag} was rolled back: {why}", to=prev,
                    rolled_back_from=new_head, **base)
    except Exception as e:
        log.exception("Update failed")
        return done(False, f"failed: {type(e).__name__}", None, str(e)[:300])


def _quietly(fn: Callable[..., Any], *args: Any) -> None:
    """A best-effort step of a rollback: its failure is logged, the rollback goes on."""
    try:
        fn(*args)
    except (Exception, SystemExit):  # the CLI's restart exits on a start that fails
        log.exception("Rollback step %s failed", getattr(fn, "__name__", fn))


def launch_detached() -> Dict[str, Any]:
    """Start `nullshift update` as its own process (a new session, output to the server
    log) so it survives the restart it performs: "Update now" and Auto. {"started": True,
    "pid"} or {"started": False, "reason"}."""
    ck = checkout()
    if not ck["release"]:
        return {"started": False, "reason": ck["reason"]}
    st = state()
    if not st.get("latest") or st.get("verify") != VERIFIED or not st.get("updatable"):
        return {"started": False, "reason": "no verified update is known: check first"}
    busy = running()
    if busy:
        return {"started": False, "reason": f"an update is already running (pid {busy['pid']})"}
    python, cli = venv_python(), BASE / "cli.py"
    if not python.exists() or not cli.exists():
        return {"started": False, "reason": "the virtual environment or cli.py is missing: run nullshift update by hand"}
    _data_dir().mkdir(parents=True, exist_ok=True)
    detach: Dict[str, Any] = ({"creationflags": subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP}
                              if sys.platform == "win32" else {"start_new_session": True})
    with open(_log_file(), "a", encoding="utf-8") as out:
        p = subprocess.Popen([str(python), str(cli), "update"], cwd=str(BASE), stdin=subprocess.DEVNULL,
                             stdout=out, stderr=out, **detach)
    _save_state(running={"tag": st["latest"], "pid": p.pid, "started_at": _now()})
    log.info("Update to %s started as process %s", st["latest"], p.pid)
    return {"started": True, "pid": p.pid}


# ── The daily thread ─────────────────────────────────────────────────────────

_stop = threading.Event()


def inflight() -> bool:
    """An investigation is in flight (app.main._INFLIGHT); imported here, not above: main
    imports this module."""
    from app import main
    return bool(main._INFLIGHT)


def wait_idle() -> bool:
    """Auto: True once nothing is in flight, probed every IDLE_POLL seconds for up to
    IDLE_MAX; False when the install stayed busy (skipped until tomorrow) or is stopping."""
    waited = 0
    while inflight():
        if waited >= IDLE_MAX:
            return False
        if _stop.wait(IDLE_POLL):
            return False
        waited += IDLE_POLL
    return True


def tick() -> None:
    """One pass of the daily thread: nothing in Off; the check in Notify and Auto; in Auto,
    a verified update this release checkout can install (and did not roll back before)
    starts once the install is idle. Never raises."""
    try:
        m = mode()
        if m == "off":
            return
        st = check()
        if m != "auto" or not st.get("updatable"):
            return
        tag = st["latest"]
        if tag in (state().get("rolled_back") or []):
            log.info("Auto update: %s was rolled back before; not retried automatically", tag)
            return
        if not wait_idle():
            log.info("Auto update to %s skipped: investigations kept running for %d hours", tag, IDLE_MAX // 3600)
            _save_state(skipped={"tag": tag, "at": _now(), "why": "busy"})
            return
        r = launch_detached()
        if not r["started"]:
            log.warning("Auto update to %s not started: %s", tag, r["reason"])
    except Exception:
        log.exception("Update tick failed")


def start_loop() -> Optional[threading.Thread]:
    """A daemon thread: tick() FIRST_CHECK_AFTER seconds after startup, then every
    CHECK_EVERY seconds. Never raises."""
    try:
        def loop() -> None:
            if _stop.wait(FIRST_CHECK_AFTER):
                return
            while not _stop.is_set():
                tick()
                if _stop.wait(CHECK_EVERY):
                    return
        t = threading.Thread(target=loop, name="update-check", daemon=True)
        t.start()
        return t
    except Exception:
        log.exception("Update check loop did not start")
        return None


# ── Status ───────────────────────────────────────────────────────────────────

def notice() -> Optional[str]:
    """The verified release an admin should hear about (the dot on the Settings link): the
    tag when one is available and this install will not install it by itself (Notify, or
    Auto where only notifying is possible). None otherwise, and always in Off."""
    try:
        m, st = mode(), state()
        if m == "off" or not st.get("latest") or st.get("verify") != VERIFIED:
            return None
        if m == "auto" and st.get("updatable"):
            return None
        return st["latest"]
    except Exception:
        return None


def status() -> Dict[str, Any]:
    """What Settings › Updates shows."""
    ck = checkout()
    st = state()
    busy = running()
    return {
        "version": VERSION,
        "mode": mode(),
        "state": st,
        "release_checkout": ck["release"],
        "reason": ck["reason"],  # why this install can only be notified; None for a release checkout
        "docker": ck["docker"],
        "docker_steps": DOCKER_STEPS if ck["docker"] else None,
        "signed_releases": bool(ALLOWED_SIGNERS),  # the release key is embedded: releases can verify
        "can_update": bool(ck["release"] and st.get("updatable") and st.get("latest") and not busy),
        "checking": checking(),
        "running": busy,
        "notice": notice(),
    }
