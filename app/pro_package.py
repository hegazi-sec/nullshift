"""The Pro package: how app/pro/ reaches a licensed install. NullShift Pro's code is not in
the public repository; an install downloads it from the license server, the license being
the credential (CONTRACT.md, "Pro package"). This module is Community code and holds no
secret: it verifies and installs what the server (or a .nspro bundle) hands over.

- The package is a zip of app/pro/: paths relative to it, plain files and folders only.
  Its manifest is a signed blob in the license format, `base64url(payload).base64url(sig)`,
  Ed25519 by the license server's key, over {kid, type: "pro-package", pro_api, sha256,
  size, commit, issued}. It has no id and no install_id: licensing.verify() refuses it as
  a license, and /v1/checkin refuses it as malformed.
- Verify, then extract, never the other way round: the manifest's signature against
  licensing.PUBLIC_KEYS, its type and pro_api (the PRO_API this core declares, bumped when
  core changes anything app/pro relies on), then the sha256 and size of the zip bytes. Only
  then the entries go into a temporary folder next to PRO_DIR, refusing any absolute path,
  `..`, symlink or anything that is not a regular file or a plain folder; MARKER is
  written and the folder swapped into place with renames.
- Never over a source tree: PRO_DIR is written only when it is absent or holds MARKER from
  an earlier install. A checkout without it (the developer's own app/pro/) is never touched.
- sync() asks the server (POST /v1/pro, with the sha256 it has) after a successful online
  activation, at startup and on every daily check-in tick while the license has a Pro
  feature, and for `nullshift pro sync` and `nullshift start`. Any failure, from no network
  to a bad signature, changes nothing on disk. An offline license never phones home:
  air-gapped installs load a .nspro bundle with install_bundle().
- Pro is imported at startup only, so a new package needs a restart; under `nullshift
  start` uvicorn's --reload does it. state() reports `restart_needed` while the installed
  package is not LOADED_SHA, the one this process started with.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import logging
import os
import re
import shutil
import stat
import tempfile
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Optional

import requests

from app import licensing

log = logging.getLogger("nullshift.pro_package")

PRO_DIR = Path(__file__).resolve().parent / "pro"  # the install target; tests point it at a temp folder
MARKER = ".package.json"  # {pro_api, sha256, commit, issued, installed_at}, written by install(); absent in a checkout
MAX_PACKAGE = 900 * 1024  # the server stores at most this much (CONTRACT.md); a bigger manifest is refused unread
MAX_UNPACKED = 16 * 1024 * 1024  # and a zip claiming to unpack to more is not a package (today it is ~250 KB)
MAX_ENTRIES = 1000
NEW_PREFIX = ".pro-new-"  # the temporary folders next to PRO_DIR: a leading dot, never importable from app/
OLD_PREFIX = ".pro-old-"
STALE_AFTER = 3600  # seconds: a temporary folder older than this was left by an interrupted install
_HEX64 = re.compile(r"[0-9a-f]{64}")

# contract error code of /v1/pro → sentence for the admin
_SYNC_ERRORS = {
    "no_package": "No Pro package is published for this NullShift version (PRO_API {api}) yet.",
    "no_pro": "This license has no Pro feature, so there is no Pro package for it.",
    "revoked": "This license has been revoked; the Pro package is not served for it. Contact Cyber-Pillar.",
    "expired": "This license has expired and its grace period is over; renew it with Cyber-Pillar.",
    "moved": "This license is bound to another machine; activate again here with the product key.",
    "malformed": "The license server did not accept this install's license.",
    "rate_limited": "Too many requests; wait a minute and try again.",
}
UNREACHABLE = ("The license server ({server}) could not be reached; the Pro package will be tried again at the "
               "next check-in (or with `nullshift pro sync`).")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── What is installed ────────────────────────────────────────────────────────

def read_marker(target: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """The marker of the package installed in target: its dict, {} when the file is there
    but unreadable, None when there is none (target absent, or a source checkout)."""
    path = Path(target or PRO_DIR) / MARKER
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except OSError:
        return {} if path.is_file() else None
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _sha_of(marker: Optional[Dict[str, Any]]) -> str:
    return str(marker.get("sha256") or "") if marker else ""


# The package this process started with ("" = none): app.main imports this module where it
# imports app.pro, so the server's value is the package it loaded. A later install differs.
LOADED_SHA = _sha_of(read_marker())


def load_problem(target: Optional[Path] = None) -> Optional[str]:
    """Why the installed package must not be imported, before app.main imports it: its
    marker is unreadable, or names another PRO_API than this core's (a core upgrade before
    the server published the matching package). None when it may be imported (a source
    checkout included). A refused package reads as a load error, and sync() then asks for
    the package again as if none were installed."""
    marker = read_marker(target)
    if marker is None:
        return None
    api = marker.get("pro_api")
    if api != licensing.PRO_API:
        return (f"the installed Pro package is built for PRO_API {api!r}; this NullShift needs PRO_API "
                f"{licensing.PRO_API} (it downloads the matching package at the next check-in)")
    return None


def state(target: Optional[Path] = None) -> Dict[str, Any]:
    """What Settings › License and `nullshift pro status` show: `package` (the installed
    package's marker, None without one), `source` (target is a checkout without MARKER:
    never written), `restart_needed` (the installed package is not the one this process
    loaded) and `load_error` (the package failed to import at startup)."""
    target = Path(target or PRO_DIR)
    marker = read_marker(target)
    return {
        "package": marker,
        "source": marker is None and (target.exists() or target.is_symlink()),
        "restart_needed": _sha_of(marker) != LOADED_SHA,
        "load_error": licensing.PRO_LOAD_ERROR,
    }


# ── Verify ───────────────────────────────────────────────────────────────────

def verify_manifest(blob: Any) -> Dict[str, Any]:
    """The manifest's payload when it is signed by a key in licensing.PUBLIC_KEYS, is of
    type pro-package, is built for this core's PRO_API and names a sha256 (64 lowercase
    hex) and a size (bytes, at most MAX_PACKAGE). ValueError, saying why, otherwise."""
    try:
        m = licensing._verify_signed(blob, licensing.PUBLIC_KEYS)
    except ValueError as e:
        raise ValueError("The Pro package manifest does not verify (not signed by a known NullShift key)") from e
    if not isinstance(m, dict) or m.get("type") != "pro-package":
        raise ValueError("Not a Pro package manifest")
    api = m.get("pro_api")
    if isinstance(api, bool) or not isinstance(api, int) or api != licensing.PRO_API:
        raise ValueError(f"This Pro package is built for PRO_API {api!r}; this NullShift needs PRO_API {licensing.PRO_API}")
    sha, size = m.get("sha256"), m.get("size")
    if not isinstance(sha, str) or not _HEX64.fullmatch(sha):
        raise ValueError("Not a Pro package manifest (bad sha256)")
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0 or size > MAX_PACKAGE:
        raise ValueError("Not a Pro package manifest (bad size)")
    return m


def verify_package(manifest: Dict[str, Any], data: bytes) -> str:
    """The sha256 of the package bytes once their size and sha256 are the manifest's.
    ValueError otherwise."""
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("The Pro package is not a byte string")
    if len(data) != manifest["size"]:
        raise ValueError(f"The Pro package is {len(data)} bytes; its manifest says {manifest['size']}")
    sha = hashlib.sha256(data).hexdigest()
    if sha != manifest["sha256"]:
        raise ValueError("The Pro package's sha256 is not the one its manifest names")
    return sha


# ── Extract ──────────────────────────────────────────────────────────────────

def _entry_path(info: zipfile.ZipInfo) -> str:
    """The entry's relative path when it is a regular file or a plain folder inside the
    package. ValueError for an absolute path (or a drive, or a backslash), `..`, the marker's
    name, a symlink, or anything else. The unix file type in external_attr says what an
    entry is; a zip written without one (Windows, or Python's writestr) carries 0 there,
    and the entry is then what its name says: a folder with a trailing slash, else a file."""
    name = info.filename
    if not name or "\\" in name or ":" in name or "\x00" in name or PurePosixPath(name).is_absolute():
        raise ValueError(f"entry {name!r}: not a relative path")
    parts = name.rstrip("/").split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise ValueError(f"entry {name!r}: `..`, `.` or an empty path part")
    if parts[-1] == MARKER:
        raise ValueError(f"entry {name!r}: the marker is written by the installer, never shipped")
    kind = stat.S_IFMT((info.external_attr >> 16) & 0xFFFF)
    if kind == stat.S_IFLNK:
        raise ValueError(f"entry {name!r}: a symlink")
    if info.is_dir():
        if kind not in (0, stat.S_IFDIR):
            raise ValueError(f"entry {name!r}: not a plain folder")
    elif kind not in (0, stat.S_IFREG):
        raise ValueError(f"entry {name!r}: not a regular file")
    return name


def _extract(data: bytes, into: Path) -> int:
    """Every entry of the zip into `into`, an empty folder of our own. Every entry is
    checked before the first is written, so a bad one refuses the whole package. Returns
    the number of files written."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as e:
        raise ValueError(f"The Pro package is not a zip file ({e})") from e
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_ENTRIES:
            raise ValueError(f"The Pro package has {len(infos)} entries; at most {MAX_ENTRIES} are expected")
        if sum(i.file_size for i in infos) > MAX_UNPACKED:
            raise ValueError("The Pro package claims to unpack to more than the limit")
        names = [_entry_path(i) for i in infos]
        root = into.resolve()
        written = 0
        for info, name in zip(infos, names):
            dest = into / name
            if not dest.resolve().is_relative_to(root):  # belt and braces after _entry_path
                raise ValueError(f"entry {name!r}: outside the package folder")
            if info.is_dir():
                dest.mkdir(parents=True, exist_ok=True)
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(dest, "wb") as out:
                shutil.copyfileobj(src, out)
            written += 1
    return written


def _sweep(parent: Path, older_than: float = STALE_AFTER) -> None:
    """Temporary folders an interrupted earlier install left next to the target. Only old
    ones: a folder another install (the check-in thread, a CLI run) is writing right now
    has a fresh mtime and is left alone."""
    for p in parent.iterdir():
        if p.name.startswith((NEW_PREFIX, OLD_PREFIX)) and p.is_dir() and not p.is_symlink():
            try:
                stale = time.time() - p.stat().st_mtime > older_than
            except OSError:
                continue
            if stale:
                shutil.rmtree(p, ignore_errors=True)


def _swap(new: Path, target: Path) -> None:
    """`new` into target's place with renames: the current target aside, new in, the old
    one removed. If the second rename fails the old folder is put back."""
    old = None
    if target.exists() or target.is_symlink():
        old = target.with_name(OLD_PREFIX + uuid.uuid4().hex[:8])
        os.rename(target, old)
    try:
        os.rename(new, target)
    except OSError:
        if old is not None:
            os.rename(old, target)
        raise
    if old is not None:
        shutil.rmtree(old, ignore_errors=True)


# ── Install ──────────────────────────────────────────────────────────────────

def install(manifest_blob: Any, package: bytes, target: Optional[Path] = None) -> Dict[str, Any]:
    """Verify, then extract: the manifest (signature, type, pro_api), the package bytes
    (size, sha256), then the zip into a temporary folder next to target, MARKER, and the
    swap with renames. Only into a target that is absent or holds MARKER: a source
    checkout is never overwritten. Returns the marker written; ValueError or OSError,
    with nothing changed on disk, otherwise."""
    target = Path(target or PRO_DIR)
    manifest = verify_manifest(manifest_blob)
    sha = verify_package(manifest, package)
    if target.is_symlink():
        raise ValueError(f"{target} is a symlink: the Pro package is not installed over it")
    if state(target)["source"]:
        raise ValueError(f"{target} is a source checkout (no {MARKER}): it is never overwritten by a package")
    marker = {"pro_api": manifest["pro_api"], "sha256": sha, "commit": str(manifest.get("commit") or ""),
              "issued": str(manifest.get("issued") or ""), "installed_at": _now_iso()}
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True)
    _sweep(parent)
    tmp = Path(tempfile.mkdtemp(prefix=NEW_PREFIX, dir=parent))
    try:
        _extract(package, tmp)
        if not (tmp / "__init__.py").is_file():
            raise ValueError("The Pro package has no __init__.py: not a Python package")
        with open(tmp / MARKER, "w", encoding="utf-8") as f:
            json.dump(marker, f, indent=2)
            f.write("\n")
        _swap(tmp, target)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    log.info("NullShift Pro package %s (commit %s, PRO_API %s) installed in %s; restart NullShift to load it",
             sha[:12], marker["commit"] or "unknown", marker["pro_api"], target)
    return marker


def _pro_licensed(lic: Optional[Dict[str, Any]]) -> bool:
    return bool(lic) and any(f in licensing.PRO_FEATURES for f in lic.get("features") or ())


def sync(target: Optional[Path] = None, timeout: Optional[float] = None) -> Dict[str, Any]:
    """Ask the license server for the Pro package built for this PRO_API and install it
    when it is new. Returns {"status", "message", ...}: `source` (target is a checkout:
    nothing sent, never written), `skipped` (no license, an offline one, or one without a
    Pro feature: nothing sent), `current` (what is installed is the latest), `installed`
    (a package was verified and written: restart NullShift to load it), `error` (no
    network, a refusal, or a package that did not verify: nothing changed on disk).
    Never raises: nothing here may stop an activation, a check-in tick or the CLI."""
    try:
        return _sync(Path(target or PRO_DIR), timeout)
    except Exception as e:
        log.exception("Pro package sync failed")
        return {"status": "error", "message": f"The Pro package sync failed: {type(e).__name__}: {e}"}


def _sync(target: Path, timeout: Optional[float]) -> Dict[str, Any]:
    st = state(target)
    if st["source"]:
        return {"status": "source", "message": f"{target} is a source checkout; the Pro package is never downloaded over it"}
    lic = licensing.current()
    if not lic:
        return {"status": "skipped", "message": "no license"}
    if lic.get("offline"):
        return {"status": "skipped", "message": ("an offline license never phones home: load the .nspro bundle from "
                                                 "Cyber-Pillar with `nullshift pro install <file>`")}
    if not _pro_licensed(lic):
        return {"status": "skipped", "message": "the license has no Pro feature"}
    # a package that failed to import is one this install does not have: ask for it again
    have = "" if licensing.PRO_LOAD_ERROR else _sha_of(st["package"])
    body = {"license": licensing._store().get("license"), "machine": licensing.machine_id(),
            "pro_api": licensing.PRO_API, "have": have}
    try:
        r = licensing._post("/v1/pro", body, timeout=timeout)
    except requests.RequestException as e:
        log.info("Pro package sync skipped: license server unreachable (%s)", type(e).__name__)
        return {"status": "error", "code": "unreachable", "message": UNREACHABLE.format(server=licensing.license_server())}
    try:
        data = r.json()
    except ValueError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    if r.status_code != 200:
        code = licensing._code(data.get("error"))  # clamped: it goes into the message and the log
        message = _SYNC_ERRORS.get(code, f"The license server answered HTTP {r.status_code}"
                                         f"{' (' + code + ')' if code else ''}. Try again later.")
        log.info("Pro package sync refused: %s", code or r.status_code)
        return {"status": "error", "code": code, "message": message.format(api=licensing.PRO_API)}
    if data.get("current") is True:
        log.info("Pro package %s is current", have[:12] or "(none)")
        return {"status": "current", "message": "the Pro package is up to date", "sha256": have}
    manifest, package = data.get("manifest"), data.get("package")
    if not isinstance(manifest, str) or not isinstance(package, str):
        return {"status": "error", "message": "The license server answered without a package. Try again later."}
    try:
        raw = base64.b64decode(package, validate=True)
    except ValueError:
        return {"status": "error", "message": "The license server's package is not base64. Try again later."}
    try:
        marker = install(manifest, raw, target)
    except (ValueError, OSError) as e:
        log.warning("Pro package from the license server refused: %s", e)
        return {"status": "error", "message": f"The Pro package was refused: {e}"}
    return {"status": "installed", "message": "NullShift Pro downloaded; restart NullShift to load it",
            "sha256": marker["sha256"], "commit": marker["commit"], "restart_needed": True}


def install_bundle(path: Any, target: Optional[Path] = None) -> Dict[str, Any]:
    """Install a `nullshift-pro-<pro_api>.nspro` bundle, JSON {"manifest": "<blob>",
    "package": "<base64 of the zip>"}: the air-gapped way to get the Pro code, through the
    same verify-then-extract path as sync(). It needs a loaded license, valid or in its
    grace period, with a Pro feature. Returns the marker written; ValueError or OSError,
    with nothing changed on disk, otherwise."""
    lic = licensing._live()
    if not lic:
        raise ValueError("A valid NullShift Pro license must be loaded first (nullshift license <file.lic>)")
    if not _pro_licensed(lic):
        raise ValueError("The loaded license has no Pro feature; the Pro package is not for it")
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except OSError as e:
        raise ValueError(f"Cannot read {path}: {e}") from e
    except ValueError as e:
        raise ValueError(f"{path} is not a .nspro bundle (JSON with manifest and package)") from e
    if not isinstance(data, dict) or not isinstance(data.get("manifest"), str) or not isinstance(data.get("package"), str):
        raise ValueError(f"{path} is not a .nspro bundle (JSON with manifest and package)")
    try:
        raw = base64.b64decode(data["package"], validate=True)
    except ValueError as e:
        raise ValueError(f"{path}: the package is not base64") from e
    return install(data["manifest"], raw, target)
