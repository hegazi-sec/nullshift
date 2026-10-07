"""Editions. NullShift Community is free (Apache 2.0): one SIEM and COMMUNITY_SEATS active
users. A NullShift Pro license lifts the seat and SIEM limits and turns on the Pro features,
whose code (app/pro/) ships only to licensed installs.

A license is one line, `<payload>.<signature>` in base64url: the payload is JSON
{kid, id, key_id, install_id, machine, customer, type, issued, expires, seats, features,
offline}, the signature Ed25519 over the payload bytes, checked offline against
PUBLIC_KEYS[kid]. The license names the install it was issued to (install_id, created here
on first use) and the machine it was activated on (machine: the hashed hardware
fingerprint, see machine_id(); "" or absent = unbound), so one can't be copied between
servers: on another machine its state is `moved`, Pro off, until it is activated there.

Licenses come from the Cyber-Pillar license server (license_server()), the contract is
nullshift-license-server/CONTRACT.md (protocol v2):
- activate(key, transfer): a product key `NS-XXXXX-XXXXX-XXXXX-XXXXX` is exchanged for a
  license. A key on its maximum installs answers `activation_limit`; activating again with
  transfer=True moves it here and the server revokes the other install (3 moves per 30 days).
- request_code(key): for air-gapped installs; Cyber-Pillar turns the code into a .lic file,
  loaded with the paste box or `nullshift license <file>`. Such a license is `offline`.
- checkin(): at startup and every 24h an online license asks for its current terms. Only a
  SIGNED revocation naming this license and this install removes it; a network failure, an
  unsigned answer or a revocation for anything else never turns Pro off.
- license_clock: the latest time seen. A clock more than 24h behind it is a rollback
  (state `clock`): Pro off until the clock is fixed.
- The Pro code itself (app/pro/) is a signed package the server serves to a license with a
  Pro feature, built for this core's PRO_API: app/pro_package.py downloads, verifies and
  installs it after an activation and on every check-in tick (never over a source tree).
- Free Pro (promo): while Cyber-Pillar has an offer open, promo_activate() gets an install
  without a valid license of its own an ordinary signed license of type `promo` with no
  key (promo_status() asks whether the offer is open, cached PROMO_CACHE_SECONDS). It
  renews at every check-in while the offer is open; once it closes, the check-in brings a
  signed `promo_ended` revocation and the install is Community again, nothing lost. A
  product key activated later replaces it.

An expired license keeps working for GRACE_DAYS, then the install drops back to Community.
Nothing here gates logins or alert ingestion: only adding users and the Pro features.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import logging
import os
import re
import socket
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any, Callable, Dict, Optional, Tuple

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import HTTPException

log = logging.getLogger("nullshift.licensing")

# Signing keys by kid: `kms-1` is the license server's Cloud KMS key (cyber-pillar-licensing,
# us-central1, nullshift/license-signing v1). The owner's dev key `dev-1` was retired on
# 2026-10-06, once a kms-1 license verified on a real install.
PUBLIC_KEYS = {
    "kms-1": "c8dKpY7ZmVhfVQm0upgQeMq+konxyIHtZQBdSkcyxq0=",
}
DEFAULT_LICENSE_SERVER = "https://nullshift.cyber-pillar.com"  # NULLSHIFT_LICENSE_SERVER overrides: license_server()
TIMEOUT = 15  # seconds, activation and check-in
PROMO_TIMEOUT = 5  # seconds, the free Pro offer's state: informational, on Settings › License's load path
PROMO_CACHE_SECONDS = 600  # the offer's state is asked at most once in ten minutes, whatever the answer
CHECKIN_EVERY = 24 * 3600
CLOCK_TOLERANCE = timedelta(hours=24)  # NTP corrections never trip the rollback check
CLOCK_MESSAGE = "the system clock is behind; fix the clock"
MOVED_MESSAGE = ("This license is bound to another machine: NullShift was copied or the hardware changed. "
                 "Activate again here with the product key to move it.")
PROMO_ENDED_MESSAGE = "The free Pro offer has ended"
PROMO_TYPE = "promo"  # the license type of a free Pro (offer) license; its key_id is "promo", it has no product key
VERSION = ""  # NullShift has no release version yet; the promo request's optional `version` sends this
MACHINE_SALT = "nullshift-machine-v1:"  # the raw hardware id is hashed with it; only the hash ever leaves
_MACHINE_ID_FILES = ("/etc/machine-id", "/var/lib/dbus/machine-id")  # Linux (and Docker with it mounted)
FEATURES = ("multi_siem", "agents", "metrics", "reports")
PRO_FEATURES = ("agents", "metrics", "reports")  # code in app/pro/; multi_siem and seats are core limits
COMMUNITY_SEATS = 3
GRACE_DAYS = 14
PRO_INSTALLED = importlib.util.find_spec("app.pro") is not None  # app.main clears it when the package fails to import
PRO_LOAD_ERROR: Optional[str] = None  # why it failed, for status() and Settings › License
# The package interface this core offers app/pro: the license server keeps one package per
# PRO_API and an install only ever receives the one built for its own. Bump it whenever core
# changes anything app/pro relies on (a store signature, a route it hooks, a helper it calls).
PRO_API = 1

# Product keys: 20 Crockford base32 characters (no I, L, O, U), shown as NS-XXXXX-XXXXX-XXXXX-XXXXX
KEY_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
KEY_LEN = 20
_KEY_FIXUPS = str.maketrans({"O": "0", "I": "1", "L": "1"})  # humans read O as 0 and I/L as 1


class ActivationError(Exception):
    """An activation that did not produce a license, with the HTTP status the admin API
    answers, a sentence an admin can act on and the contract's error code (so the UI can
    offer the move after `activation_limit`)."""

    def __init__(self, message: str, status: int = 400, code: str = ""):
        super().__init__(message)
        self.status = status
        self.code = code


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _store():
    from app.db.settings_store import settings_store
    return settings_store


def _setting(name: str) -> str:
    """A NULLSHIFT_* value: from .env through app.config's Settings (which declares both
    keys, so a .env that sets them still loads), else the process environment. "" when
    neither has it."""
    try:
        from app.config import settings
        v = getattr(settings, name, None)
    except Exception:
        v = None
    return str(v or os.environ.get(name) or "").strip()


def license_server() -> str:
    """The license server's base URL, read at call time (never at import): the
    NULLSHIFT_LICENSE_SERVER setting, or DEFAULT_LICENSE_SERVER."""
    return (_setting("NULLSHIFT_LICENSE_SERVER") or DEFAULT_LICENSE_SERVER).rstrip("/")


_CODE = re.compile(r"[a-z_]{1,32}")


def _code(value: Any) -> str:
    """A server-supplied code (an error, a revocation reason) clamped to [a-z_]{1,32}
    before it reaches a message or a log line: "" when the server sent none, "unknown"
    for anything else (so no newline, HTML or novel ever gets in)."""
    s = "" if value is None else str(value)
    return s if not s or _CODE.fullmatch(s) else "unknown"


# ── Product keys ─────────────────────────────────────────────────────────────

def normalize_key(key: str) -> str:
    """The contract's normalization: uppercase, drop the NS prefix, spaces and dashes, then
    O→0 and I/L→1. ValueError unless exactly 20 valid characters remain."""
    s = str(key or "").strip().upper().replace(" ", "").replace("-", "")
    if s.startswith("NS"):
        s = s[2:]
    s = s.translate(_KEY_FIXUPS)
    if len(s) != KEY_LEN or any(c not in KEY_ALPHABET for c in s):
        raise ValueError("That doesn't look like a NullShift product key (NS-XXXXX-XXXXX-XXXXX-XXXXX).")
    return s


def format_key(normalized: str) -> str:
    return "NS-" + "-".join(normalized[i:i + 5] for i in range(0, KEY_LEN, 5))


def last4(key: str) -> str:
    """For logs: never the whole key."""
    try:
        return normalize_key(key)[-4:]
    except ValueError:
        return "????"


def _hostname() -> str:
    try:
        return socket.gethostname()[:64]
    except OSError:
        return ""


# ── The install ──────────────────────────────────────────────────────────────

_install_lock = threading.Lock()


def install_id() -> str:
    """This install's id: a uuid4 hex created on first use, kept in config.db for good.
    Licenses are issued to it."""
    store = _store()
    with _install_lock:
        v = store.get("install_id")
        if not v:
            v = uuid.uuid4().hex
            store.set_many({"install_id": v})
    return v


# ── The machine ──────────────────────────────────────────────────────────────

MACHINE_RAW_MIN = 32  # a machine-id (32 hex), a platform UUID or a MachineGuid (36): anything shorter is not one
_DOCKERENV = "/.dockerenv"
_CGROUP = "/proc/1/cgroup"
CONTAINER_HINT = ("set NULLSHIFT_MACHINE_ID (compose `environment:` or `docker run -e`) or, on a Linux host, "
                  "mount /etc/machine-id read-only; see README › Editions › Docker")


def _usable(raw: Any) -> str:
    """The raw id when it can stand for a machine: stripped, at least MACHINE_RAW_MIN
    characters and not systemd's placeholder `uninitialized` (a fresh image or a first
    boot, which the next boot or rebuild replaces). "" otherwise, so the next source
    is tried."""
    v = str(raw or "").strip()
    return v if len(v) >= MACHINE_RAW_MIN and v.lower() != "uninitialized" else ""


def _machine_raw() -> str:
    """The raw hardware identifier, from the first source that has a usable one (see
    _usable): the setting NULLSHIFT_MACHINE_ID (.env or the environment: Docker on
    Windows, or any override), Linux's machine-id files, macOS's IOPlatformUUID,
    Windows' MachineGuid. "" when none is found. Never leaves this process: machine_id()
    hashes it."""
    v = _setting("NULLSHIFT_MACHINE_ID")
    if v and not _usable(v):
        log.warning("NULLSHIFT_MACHINE_ID is ignored: it must be at least %d characters (a machine-id, "
                    "platform UUID or MachineGuid)", MACHINE_RAW_MIN)
    v = _usable(v)
    if v:
        return v
    for path in _MACHINE_ID_FILES:
        try:
            with open(path, encoding="utf-8") as f:
                v = _usable(f.read())
        except (OSError, UnicodeDecodeError):
            continue
        if v:
            return v
    if sys.platform == "darwin":
        try:
            out = subprocess.run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], capture_output=True,
                                 text=True, timeout=5, check=False).stdout
            m = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', out or "")
            v = _usable(m.group(1)) if m else ""
            if v:
                return v
        except (OSError, subprocess.SubprocessError, ValueError):
            pass
    if sys.platform == "win32":
        try:
            import winreg
            # the 64-bit view explicitly: a 32-bit Python on 64-bit Windows is redirected to
            # WOW6432Node otherwise, where MachineGuid may be absent or differ
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography",
                                access=winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
                v = _usable(winreg.QueryValueEx(k, "MachineGuid")[0])
            if v:
                return v
        except (ImportError, OSError, ValueError, TypeError, AttributeError):
            pass
    return ""


def _in_container() -> bool:
    """Docker or containerd: /.dockerenv exists, or PID 1's cgroup names one of them."""
    if os.path.exists(_DOCKERENV):
        return True
    try:
        with open(_CGROUP, encoding="utf-8", errors="replace") as f:
            return any(w in f.read() for w in ("docker", "containerd"))
    except OSError:
        return False


_machine_lock = threading.Lock()
_machine: Optional[str] = None


def machine_id() -> str:
    """This machine's fingerprint: sha256(MACHINE_SALT + raw id) as 64 lowercase hex,
    computed once per process; "" (unbound, one warning) when no source has an id. A
    license names the machine it was activated on; elsewhere its state is `moved`. In
    a container without NULLSHIFT_MACHINE_ID, one warning: the id found is the
    container's own unless the host's is mounted, and a rebuild changes it."""
    global _machine
    with _machine_lock:
        if _machine is None:
            raw = _machine_raw()
            if raw:
                _machine = hashlib.sha256((MACHINE_SALT + raw).encode("utf-8")).hexdigest()
            else:
                _machine = ""
                log.warning("No machine id found (NULLSHIFT_MACHINE_ID, /etc/machine-id, IOPlatformUUID or "
                            "MachineGuid): this install is not bound to its hardware")
            if not _setting("NULLSHIFT_MACHINE_ID") and _in_container():
                log.warning("Running in a container without NULLSHIFT_MACHINE_ID: the machine fingerprint may "
                            "change when the container is rebuilt, and the license would then show `moved`. "
                            "To keep it stable, %s", CONTAINER_HINT)
    return _machine


# ── The license ──────────────────────────────────────────────────────────────

def _verify_signed(blob: Any, keys: Dict[str, str]) -> Dict[str, Any]:
    """The payload of `base64url(payload).base64url(sig)`, Ed25519-signed by keys[kid]:
    the one signature check behind licenses and revocations. ValueError otherwise."""
    try:
        body, sig = str(blob).strip().split(".")
        payload = _b64d(body)
        data = json.loads(payload)
        kid = str(data.get("kid"))
    except (ValueError, AttributeError, TypeError) as e:
        raise ValueError("Not a valid NullShift license") from e
    public_key = keys.get(kid)
    if not public_key:
        raise ValueError("Not a valid NullShift license (signed with an unknown key)")
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key)).verify(_b64d(sig), payload)
    except (ValueError, InvalidSignature) as e:
        raise ValueError("Not a valid NullShift license") from e
    return data


@lru_cache(maxsize=8)
def _parse(blob: str, keys: Tuple[Tuple[str, str], ...]) -> Dict[str, Any]:
    lic = _verify_signed(blob, dict(keys))
    try:
        expires = datetime.fromisoformat(lic["expires"])
        lic["install_id"] = str(lic["install_id"])
        lic["machine"] = str(lic.get("machine") or "").strip().lower()  # absent = unbound
        lic["seats"], lic["features"] = int(lic["seats"]), list(lic["features"])
        lic["offline"] = bool(lic.get("offline", False))
    except (ValueError, KeyError, TypeError, InvalidSignature) as e:
        raise ValueError("Not a valid NullShift license") from e
    return {**lic, "_expires": expires if expires.tzinfo else expires.replace(tzinfo=timezone.utc)}


def _keys() -> Tuple[Tuple[str, str], ...]:
    return tuple(sorted(PUBLIC_KEYS.items()))


def verify(blob: str, now: Optional[datetime] = None) -> Dict[str, Any]:
    """The license with its state: 'valid', 'grace' (expired under GRACE_DAYS ago),
    'expired', or 'moved' (bound to another machine than this one: Pro off until it is
    activated here again). ValueError when the blob is malformed, not signed with a known
    key, or issued to another install."""
    lic = _parse(blob, _keys())
    mine = install_id()
    if lic["install_id"] != mine:
        raise ValueError(
            f"This license was issued to another NullShift install ({lic['install_id'][:8]}…, this one is "
            f"{mine[:8]}…). Activate here with the product key, or request an offline code from this install.")
    now = now or _now()
    exp = lic["_expires"]
    grace_ends = exp + timedelta(days=GRACE_DAYS)
    state = "valid" if now < exp else "grace" if now < grace_ends else "expired"
    if lic["machine"] and lic["machine"] != machine_id():
        state = "moved"
    return {k: v for k, v in lic.items() if k != "_expires"} | {"state": state, "grace_ends": grace_ends.isoformat()}


def save(blob: Optional[str], updated_by: Optional[int] = None, server_time: Optional[str] = None) -> None:
    """Store a license (already verified by the caller), or remove it with None. Saving
    moves license_clock forward; a license fresh from the server sets it to the server's
    signed `issued` time instead (server_time; see set_clock_from_server), so a clock
    once wrongly set ahead and then corrected is not taken for a rollback for as long as
    it had been ahead. A pasted .lic never carries server_time: an old file must not be
    able to lower the clock. Any save forgets why the previous license was removed by a
    revocation (license_revoked); checkin() records that after it removes one."""
    _store().set_many({"license": blob or None, "license_revoked": None}, updated_by=updated_by)
    if blob and not set_clock_from_server(server_time):
        touch_clock()


OFF_STATES = ("expired", "clock", "moved")  # a license in one of these turns nothing on
_clock_check_failed = False  # the clock check failed open: logged once per process


def current() -> Optional[Dict[str, Any]]:
    """The saved license, or None (none saved, or one that no longer verifies). A clock
    rolled back past license_clock gives it the state 'clock'; one bound to another
    machine has the state 'moved' (from verify()). The clock check fails OPEN: if it
    raises (a store error, anything unforeseen), the license keeps its state and the
    failure is logged once."""
    global _clock_check_failed
    blob = _store().get("license")
    try:
        lic = verify(blob) if blob else None
    except ValueError:
        return None
    if lic:
        try:
            behind = clock_behind()
        except Exception:
            behind = False
            if not _clock_check_failed:
                _clock_check_failed = True
                log.exception("The license clock check failed; the license keeps its state")
        if behind:
            lic["state"] = "clock"
    return lic


def _live() -> Optional[Dict[str, Any]]:
    lic = current()
    return lic if lic and lic["state"] not in OFF_STATES else None


def has(feature: str) -> bool:
    """The feature is licensed and, for a Pro feature, its code is installed."""
    return _has(_live(), feature)


def _has(live: Optional[Dict[str, Any]], feature: str) -> bool:
    return bool(live) and feature in live["features"] and (feature not in PRO_FEATURES or PRO_INSTALLED)


def seats() -> int:
    return _seats(_live())


def _seats(live: Optional[Dict[str, Any]]) -> int:
    return live["seats"] if live else COMMUNITY_SEATS


def seats_used() -> int:
    from app.db import user_store
    user_store.init_db()  # the CLI can ask before setup or the server ever created the table
    return sum(1 for u in user_store.list_users() if u["is_active"])


def check_seat() -> None:
    """Before a user is added or re-enabled. Users past the limit (a license that lapsed)
    keep their access; only new seats are refused."""
    n = seats()
    if seats_used() >= n:
        raise HTTPException(status_code=402, detail=(
            f"This install allows {n} active user{'s' if n != 1 else ''}. "
            "Add or upgrade a NullShift Pro license in Settings › License, or disable a user first."))


def require(feature: str) -> Callable[[], None]:
    """Route dependency: 402 unless the feature is on."""
    def dep() -> None:
        if not has(feature):
            raise HTTPException(status_code=402, detail="This is a NullShift Pro feature. Add a license in Settings › License.")
    return dep


# ── Clock rollback ───────────────────────────────────────────────────────────

def _parse_time(v: Any, naive_utc: bool) -> Optional[datetime]:
    """An ISO 8601 string as an aware datetime, or None when it is not one. A naive
    value (no offset) is taken as UTC when naive_utc, else refused."""
    try:
        t = datetime.fromisoformat(v)
    except (ValueError, TypeError):
        return None
    if t.tzinfo is None:
        return t.replace(tzinfo=timezone.utc) if naive_utc else None
    return t


def _read_clock() -> Optional[datetime]:
    """The stored license_clock as an aware datetime; None when unset, garbage or not a
    time at all (nothing stored here may ever crash licensing or startup). A stored
    naive value (older versions, a hand edit) counts as UTC."""
    return _parse_time(_store().get("license_clock"), naive_utc=True)


def touch_clock(now: Optional[datetime] = None) -> None:
    """license_clock = the latest UTC time seen (never moved back): at startup, on every
    check-in tick and when a license is saved."""
    now = now or _now()
    seen = _read_clock()
    if seen is None or now > seen:
        _store().set_many({"license_clock": now.isoformat()})


def set_clock_from_server(server_time: Optional[str]) -> bool:
    """license_clock = the license server's signed time (a license's `issued`), the one
    trusted time: this is how a clock that ran ahead recovers once the server has
    answered. Only an aware time counts (stored normalized); False, and nothing
    written, for None, a naive value or garbage, so the caller moves the clock forward
    with touch_clock() instead."""
    t = _parse_time(server_time, naive_utc=False)
    if t is None:
        return False
    _store().set_many({"license_clock": t.astimezone(timezone.utc).isoformat()})
    return True


def reset_clock(now: Optional[datetime] = None) -> Tuple[Optional[str], str]:
    """license_clock = now, whatever it was: the escape hatch for an install whose clock
    was set ahead by mistake, corrected, and is now reported as a rollback, and which
    no license server can put right (offline). Only `nullshift license reset-clock`
    calls it: shell access on the server is the trust. Returns (old, new) and logs a
    WARNING naming both."""
    old = _store().get("license_clock")
    new = (now or _now()).isoformat()
    _store().set_many({"license_clock": new})
    log.warning("license_clock reset by hand (nullshift license reset-clock): %s -> %s", old or "unset", new)
    return old, new


def clock_behind(now: Optional[datetime] = None) -> bool:
    """True when the clock is more than CLOCK_TOLERANCE behind the latest time seen."""
    seen = _read_clock()
    return seen is not None and (now or _now()) < seen - CLOCK_TOLERANCE


# ── Activation (online) ──────────────────────────────────────────────────────

# contract error code → (HTTP status NullShift answers, sentence for the admin)
_ACTIVATION_ERRORS = {
    "malformed": (400, "The license server did not accept that product key (NS-XXXXX-XXXXX-XXXXX-XXXXX). Check it and try again."),
    "unknown_key": (404, "No NullShift product key matches that one. Check the key and try again."),
    "activation_limit": (409, "This product key is already active on its maximum number of installs. "
                              "Move the license to this install (the other install loses Pro at its next "
                              "check-in), or contact Cyber-Pillar to add an activation."),
    "transfer_limit": (409, "This product key has been moved more than 3 times in 30 days, so it can't be "
                            "moved again yet. Contact Cyber-Pillar."),
    "transfer_unavailable": (409, "This product key is only active on offline (air-gapped) installs, which can't be "
                                  "moved automatically. Ask Cyber-Pillar to release one."),
    "rebind_limit": (409, "This install's hardware has changed more than 5 times in 30 days, so the license "
                          "can't follow it again yet. Contact Cyber-Pillar."),
    "revoked": (410, "This product key has been revoked. Contact Cyber-Pillar for a new one."),
    "expired": (410, "This product key has expired. Renew it with Cyber-Pillar."),
    "rate_limited": (429, "Too many activation attempts; wait a minute and try again."),
}
UNREACHABLE = ("The license server ({server}) could not be reached. If this network is air-gapped, "
               "use offline activation: get a request code below and send it to Cyber-Pillar.")


def _post(path: str, body: Dict[str, Any], timeout: Optional[float] = None) -> requests.Response:
    return requests.post(f"{license_server()}{path}", json=body, timeout=timeout or TIMEOUT,
                         headers={"User-Agent": "NullShift"})


def _get(path: str, timeout: Optional[float] = None) -> requests.Response:
    return requests.get(f"{license_server()}{path}", timeout=timeout or TIMEOUT, headers={"User-Agent": "NullShift"})


def _json_dict(r: requests.Response) -> Dict[str, Any]:
    """The server's JSON object, {} for anything else (not JSON, not an object)."""
    try:
        data = r.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _http_error(r: requests.Response, data: Dict[str, Any], known: Dict[str, Tuple[int, str]]) -> ActivationError:
    """The ActivationError for a non-200 answer: the contract code's sentence from `known`,
    or a generic one naming the HTTP status (and the code, clamped)."""
    code = _code(data.get("error"))  # clamped: it goes into the message and the log
    status, message = known.get(code, (502, f"The license server answered HTTP {r.status_code}"
                                            f"{' (' + code + ')' if code else ''}. Try again later."))
    return ActivationError(message, status, code)


def _accept(data: Dict[str, Any], about: str, updated_by: Optional[int]) -> Dict[str, Any]:
    """The license the server answered an activation with: verified (signature, this
    install, the machine) and saved with the server's time; the activation counts as a
    contact. ActivationError when it does not verify (nothing saved)."""
    blob = str(data.get("license") or "").strip()
    try:
        lic = verify(blob)
    except ValueError as e:
        log.error("%s: the server's license does not verify: %s", about, e)
        raise ActivationError(f"The license server sent a license this install can't use: {e}", 502, "bad_license")
    save(blob, updated_by=updated_by, server_time=lic.get("issued"))
    _store().set_many({"license_checked_at": _now().isoformat()})  # an activation is a contact too
    return lic


def activate(key: str, updated_by: Optional[int] = None, transfer: bool = False) -> Dict[str, Any]:
    """Exchange a product key for a license at the license server, verify it and save it.
    The request names this install and machine; with transfer=True a key on its maximum
    installs is moved here (the server revokes the other install at its next check-in).
    Returns the license (as verify()); ActivationError with a readable sentence otherwise."""
    try:
        normalized = normalize_key(key)
    except ValueError as e:
        raise ActivationError(str(e), 400, "malformed")
    body = {"key": format_key(normalized), "install_id": install_id(), "machine": machine_id(),
            "transfer": bool(transfer), "hostname": _hostname()}
    try:
        r = _post("/v1/activate", body)
    except requests.RequestException as e:
        log.warning("Activation with key …%s: license server unreachable (%s)", normalized[-4:], type(e).__name__)
        raise ActivationError(UNREACHABLE.format(server=license_server()), 502, "unreachable")
    data = _json_dict(r)
    if r.status_code != 200:
        err = _http_error(r, data, _ACTIVATION_ERRORS)
        log.info("Activation with key …%s%s refused: %s", normalized[-4:], " (transfer)" if transfer else "",
                 err.code or r.status_code)
        raise err
    lic = _accept(data, f"Activation with key …{normalized[-4:]}", updated_by)
    log.info("License %s (%s) activated with key …%s%s", lic.get("id"), lic.get("customer"), normalized[-4:],
             " (moved to this install)" if transfer else "")
    return lic


# ── Free Pro (promo) ─────────────────────────────────────────────────────────

# contract error code of POST /v1/promo → (HTTP status NullShift answers, sentence for the admin)
_PROMO_ERRORS = {
    "promo_closed": (410, "The free Pro offer is not open right now."),
    "promo_full": (409, "The free Pro offer has reached its number of installs, so this install can't join it. "
                        "Try again later, or contact Cyber-Pillar for a product key."),
    "rebind_limit": _ACTIVATION_ERRORS["rebind_limit"],
    "malformed": (400, "The license server did not accept this install's details (install ID, machine or hostname)."),
    "rate_limited": (429, "Too many attempts; wait a minute and try again."),
}
PROMO_UNREACHABLE = ("The license server ({server}) could not be reached. The free Pro offer needs a route to it: "
                     "it is never offered offline.")
PROMO_LICENSED_MESSAGE = ("This install already has a NullShift Pro license of its own; the free Pro offer is for "
                          "installs without one. Remove the license first to try the offer instead.")

_promo_lock = threading.Lock()
_promo_cache: Dict[str, Any] = {"until": 0.0, "answer": None}  # the last answer of GET /v1/promo and when it goes stale


def _promo_fetch() -> Dict[str, Any]:
    """GET /v1/promo as {open, seats, days}: open only when the server said `true`, seats
    and days only as positive integers. {"open": False, "error", "message"} for anything
    else (unreachable, a non-200, an answer that is not JSON): the offer is not open for
    this install until the server says so. Never raises."""
    try:
        r = _get("/v1/promo", timeout=PROMO_TIMEOUT)
    except requests.RequestException as e:
        log.info("Free Pro offer: license server unreachable (%s)", type(e).__name__)
        return {"open": False, "error": "unreachable", "message": PROMO_UNREACHABLE.format(server=license_server())}
    except Exception:  # nothing here may stop Settings › License or the CLI
        log.exception("Free Pro offer: the request failed")
        return {"open": False, "error": "unreachable", "message": PROMO_UNREACHABLE.format(server=license_server())}
    data = _json_dict(r)
    if r.status_code != 200:
        code = _code(data.get("error"))
        log.info("Free Pro offer: license server answered HTTP %s%s", r.status_code, f" ({code})" if code else "")
        return {"open": False, "error": code or "unknown",
                "message": f"The license server answered HTTP {r.status_code}{' (' + code + ')' if code else ''}. Try again later."}
    answer: Dict[str, Any] = {"open": data.get("open") is True}
    for k in ("seats", "days"):
        v = data.get(k)
        if isinstance(v, int) and not isinstance(v, bool) and v > 0:
            answer[k] = v
    return answer


def promo_status(refresh: bool = False) -> Dict[str, Any]:
    """Whether Cyber-Pillar's free Pro offer is open: GET /v1/promo (no credentials), the
    answer cached for PROMO_CACHE_SECONDS whatever it was, so Settings › License asks the
    server at most once in ten minutes. {"open": False, ...} on any failure; never raises."""
    with _promo_lock:
        cached = _promo_cache["answer"]
        if cached is None or refresh or time.monotonic() >= _promo_cache["until"]:
            cached = _promo_fetch()
            _promo_cache.update(until=time.monotonic() + PROMO_CACHE_SECONDS, answer=cached)
        return dict(cached)


def _own_license(lic: Optional[Dict[str, Any]]) -> bool:
    """A live (valid or in grace) license that is not the promo's: the install has one of
    its own and the offer is not for it."""
    return bool(lic) and lic["state"] not in OFF_STATES and lic.get("type") != PROMO_TYPE


def promo_offer() -> Dict[str, Any]:
    """What Settings › License needs for the Try NullShift Pro free card: `offered` (show
    it) is the offer being open while this install has no valid license of its own
    (`licensed`: none, or an expired, moved or clock-rolled one). With a license of its
    own the server is not asked at all (`open` is then None). A promo license already held
    counts as none: the card goes away only because the edition is Pro."""
    lic = current()
    if lic and lic["state"] not in OFF_STATES:  # a live license: its own, or the promo's
        return {"offered": False, "open": None, "licensed": True,
                "why": "this install has a valid license" + ("" if lic.get("type") == PROMO_TYPE else " of its own")}
    st = promo_status()
    return {"offered": st["open"] is True, "licensed": False, **st}


def promo_activate(updated_by: Optional[int] = None) -> Dict[str, Any]:
    """Turn Pro on with Cyber-Pillar's free offer: POST /v1/promo names this install and
    machine (no key) and answers a signed promo license, verified and saved exactly like
    an activation (install_id checked, the Pro package follows in the caller). Refused
    here, before the server is asked, while the install holds a live license of its own:
    the offer never replaces a paid or trial license (an expired, moved or clock-rolled
    one it does; a promo license held already is renewed, same id). Returns the license
    (as verify()); ActivationError with a readable sentence otherwise."""
    if _own_license(current()):
        raise ActivationError(PROMO_LICENSED_MESSAGE, 409, "licensed")
    body = {"install_id": install_id(), "machine": machine_id(), "hostname": _hostname(), "version": VERSION}
    try:
        r = _post("/v1/promo", body)
    except requests.RequestException as e:
        log.warning("Free Pro offer: license server unreachable (%s)", type(e).__name__)
        raise ActivationError(PROMO_UNREACHABLE.format(server=license_server()), 502, "unreachable")
    data = _json_dict(r)
    if r.status_code != 200:
        err = _http_error(r, data, _PROMO_ERRORS)
        log.info("Free Pro offer refused: %s", err.code or r.status_code)
        raise err
    lic = _accept(data, "Free Pro offer", updated_by)
    log.info("License %s (%s) activated with the free Pro offer; it renews daily while the offer is open",
             lic.get("id"), lic.get("customer"))
    return lic


# ── Activation (offline) ─────────────────────────────────────────────────────

def request_code(key: str) -> str:
    """`NSREQ-` + base64url(compact JSON {key, install_id, machine, hostname}): what an
    air-gapped SOC sends Cyber-Pillar to get a .lic file. ValueError for a malformed key."""
    payload = json.dumps({"key": normalize_key(key), "install_id": install_id(), "machine": machine_id(),
                          "hostname": _hostname()}, separators=(",", ":"), sort_keys=True).encode()
    return "NSREQ-" + _b64e(payload)


# ── Check-in ─────────────────────────────────────────────────────────────────

REVOCATION_REASONS = {
    "revoked": "revoked by Cyber-Pillar",
    "moved": "moved to another machine",
    "released": "released from this install by Cyber-Pillar support (the key can be activated again)",
    "promo_ended": "ended with the free Pro offer (Cyber-Pillar closed it)",
}


def _verify_revocation(blob: Any, lic: Dict[str, Any]) -> Optional[str]:
    """The reason of a signed revocation (`base64url(payload).base64url(sig)`, the payload
    {kid, type: "revocation", license_id, install_id, reason, issued}, Ed25519 like a
    license) when it verifies against a known key AND names the saved license (a
    non-empty license_id equal to the saved license's non-empty id) AND this install AND
    was issued no earlier than the saved license (a revocation of an earlier license with
    the same id, replayed, must not remove its renewal; unparsable times count as
    earlier); None, with a warning, for anything else. Only a verified one removes the
    license: an unsigned `{"revoked": true}` or a revocation for another license or
    install is ignored."""
    try:
        rev = _verify_signed(blob, PUBLIC_KEYS)
    except ValueError as e:
        log.warning("License check-in: ignoring a revocation that does not verify (%s); keeping the license", e)
        return None
    if not isinstance(rev, dict) or rev.get("type") != "revocation":
        log.warning("License check-in: ignoring a signed answer that is not a revocation; keeping the license")
        return None
    named, mine = str(rev.get("license_id") or ""), str(lic.get("id") or "")
    if not named or not mine or named != mine:
        log.warning("License check-in: ignoring a revocation for another license (%s, this one is %s); keeping "
                    "the license", named[:8] or "none", mine[:8] or "none")
        return None
    if str(rev.get("install_id")) != install_id():
        log.warning("License check-in: ignoring a revocation for another install (%s…, this one is %s…); keeping "
                    "the license", str(rev.get("install_id"))[:8], install_id()[:8])
        return None
    rev_at, lic_at = _parse_time(rev.get("issued"), naive_utc=True), _parse_time(lic.get("issued"), naive_utc=True)
    if rev_at is None or lic_at is None or rev_at < lic_at:
        log.warning("License check-in: ignoring a stale revocation (issued %s, the license was issued %s); keeping "
                    "the license", rev_at.isoformat() if rev_at else "at an unreadable time",
                    lic_at.isoformat() if lic_at else "at an unreadable time")
        return None
    return _code(rev.get("reason")) or "revoked"


def checkin() -> str:
    """Ask the license server for the saved license's current terms. Returns what happened:
    'skipped' (no license, or an offline one), a reason in REVOCATION_REASONS ('revoked',
    'moved', 'released', 'promo_ended': removed by a signed revocation for this license
    and install, the one answer that does; the reason is kept as license_revoked, so
    Settings › License can say the free Pro offer ended), 'renewed' (a new license
    verified and saved), or 'kept' (any other answer, including no network). Records
    license_checked_at when the server answered. A license in the state `moved` checks in
    too: that is how it learns it was revoked over there. Any license the server answers
    that verifies, the same blob included, resets license_clock from its signed `issued`:
    the server's time is the trusted one, so a clock that ran ahead and was corrected
    recovers at the next check-in instead of staying `clock`."""
    store = _store()
    blob = store.get("license")
    if not blob:
        return "skipped"
    try:
        lic = _parse(blob, _keys())
    except ValueError:
        return "skipped"
    if lic["offline"]:
        return "skipped"
    try:
        r = _post("/v1/checkin", {"license": blob, "machine": machine_id()})
        data = r.json() if r.status_code == 200 else None
    except (requests.RequestException, ValueError) as e:
        log.info("License check-in skipped: %s", type(e).__name__)
        return "kept"
    if not isinstance(data, dict):
        log.info("License check-in: server answered HTTP %s; keeping the license", r.status_code)
        return "kept"
    store.set_many({"license_checked_at": _now().isoformat()})
    if data.get("revocation"):
        reason = _verify_revocation(data["revocation"], lic)
        if reason:
            save(None)
            store.set_many({"license_revoked": reason})  # after save(), which forgets the previous one
            log.warning("License %s %s; this install is now Community", lic.get("id"),
                        REVOCATION_REASONS.get(reason, f"revoked ({reason})"))
            return reason if reason in REVOCATION_REASONS else "revoked"
        return "kept"
    if data.get("revoked") is True:  # protocol v1: unsigned, no longer trusted
        log.warning("License check-in: ignoring an unsigned revocation (protocol v1); keeping the license")
        return "kept"
    new = str(data.get("license") or "").strip()
    if not new:
        return "kept"
    try:
        renewed = verify(new)
    except ValueError as e:
        log.warning("License check-in: the server's license does not verify (%s); keeping the current one", e)
        return "kept"
    if new == blob:
        set_clock_from_server(renewed.get("issued"))  # the same terms: still the server's time
        return "kept"
    save(new, server_time=renewed.get("issued"))
    log.info("License %s renewed: expires %s, %s seats", renewed.get("id"), renewed.get("expires"), renewed.get("seats"))
    return "renewed"


_stop = threading.Event()


def tick() -> None:
    """One pass of the daemon: move the clock, check in, then fetch or update the Pro
    package while the license has a Pro feature (app/pro_package.py; it skips a source
    tree and an offline license by itself). Never raises."""
    try:
        touch_clock()
    except Exception:
        log.exception("license_clock update failed")
    try:
        checkin()
    except Exception:
        log.exception("License check-in failed")
    try:
        from app import pro_package
        pro_package.sync()
    except Exception:
        log.exception("Pro package sync failed")


def start_checkin_loop() -> Optional[threading.Thread]:
    """A daemon thread: tick() now, then every CHECKIN_EVERY seconds. Never raises."""
    try:
        def loop() -> None:
            while not _stop.is_set():
                tick()
                _stop.wait(CHECKIN_EVERY)
        t = threading.Thread(target=loop, name="license-checkin", daemon=True)
        t.start()
        return t
    except Exception:
        log.exception("License check-in loop did not start")
        return None


# ── Status ───────────────────────────────────────────────────────────────────

def status() -> Dict[str, Any]:
    """What Settings › License and the UI's Pro locks show."""
    store = _store()
    lic = current()  # once: seats and features below derive from it, not from fresh reads
    state = lic["state"] if lic else "invalid" if store.get("license") else "none"
    live = lic if lic and state not in OFF_STATES else None
    # why the last license went, while none replaced it: a signed revocation's reason (clamped)
    revoked = (_code(store.get("license_revoked")) or None) if state == "none" else None
    try:
        from app import pro_package
        pkg = pro_package.state()
    except Exception:  # the marker on disk can never break the status
        log.exception("The Pro package state could not be read")
        pkg = {"package": None, "source": False, "restart_needed": False}
    return {
        "edition": "pro" if lic and state not in OFF_STATES else "community",
        "state": state,
        "clock_message": CLOCK_MESSAGE if state == "clock" else None,
        "moved_message": MOVED_MESSAGE if state == "moved" else None,
        "revoked_reason": revoked,  # the last license was removed by a signed revocation with this reason
        "ended_message": PROMO_ENDED_MESSAGE if revoked == "promo_ended" else None,
        "customer": lic.get("customer") if lic else None,
        "license_id": lic.get("id") if lic else None,
        "type": lic.get("type") if lic else None,  # trial | paid | promo (the free Pro offer: "Free Pro (offer)" in the UI/CLI)
        "offline": lic["offline"] if lic else None,
        "expires": lic["expires"] if lic else None,
        "grace_ends": lic["grace_ends"] if lic else None,
        "checked_at": store.get("license_checked_at"),
        "install_id": install_id(),
        "machine": machine_id()[:12],  # "" when this install has no hardware id
        "bound": bool(lic and lic.get("machine")),  # the saved license names a machine
        "seats": _seats(live),
        "seats_used": seats_used(),
        "features": [f for f in FEATURES if _has(live, f)],
        "licensed_features": lic["features"] if lic else [],
        "pro_installed": PRO_INSTALLED,
        "pro_load_error": PRO_LOAD_ERROR,  # the package is there but failed to import at startup
        "pro_api": PRO_API,
        "pro_package": pkg["package"],  # the installed package's marker; None for a source checkout or none at all
        "pro_source": pkg["source"],  # app/pro is a checkout without the marker: never overwritten by a download
        "pro_restart_needed": pkg["restart_needed"],  # a package was installed since this process started
    }
