import logging
import os
import re
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from jose import jwt, JWTError
from passlib.context import CryptContext

from app.db import user_store
from app.config import settings

router = APIRouter()

# Config
ALGORITHM = "HS256"
COOKIE_NAME = "access_token"
CSRF_COOKIE = "csrftoken"
MIN_JWT_SECRET_LEN = 32
MIN_PASSWORD_LEN = 16  # same rule as the setup wizard and `nullshift passwd`
# Usernames are shown in the Settings page and chat UI, so keep them to plain
# characters rather than trusting every renderer to escape them. Check with
# .fullmatch(): `$` alone also matches before a trailing newline ("admin\n").
USERNAME_RE = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")
_KNOWN_PLACEHOLDER_SECRETS = {
    "please-change-this-secret",
    "replace_me",
    "changeme",
    "change-me",
    "secret",
    "your-secret-here",
}


_SCRIPT_TAG = re.compile(r"<script\b", re.IGNORECASE)
_CSP = ("default-src 'self'; script-src {script}; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob:; connect-src 'self'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")


def html_page(content: str, status_code: int = 200) -> HTMLResponse:
    """Serve an HTML page under a Content-Security-Policy: only the page's own
    <script> tags run, each stamped with a nonce that is new per response, so
    injected markup cannot run script. A page without scripts gets none."""
    nonce = secrets.token_urlsafe(16)
    content, n = _SCRIPT_TAG.subn(f'<script nonce="{nonce}"', content)
    resp = HTMLResponse(content, status_code=status_code)
    resp.headers["Content-Security-Policy"] = _CSP.format(
        script=f"'self' 'nonce-{nonce}'" if n else "'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "same-origin"
    return resp


def _resolve_jwt_secret() -> str:
    """Validate and return the configured JWT secret, or refuse to start.

    Resolution order:
      1. JWT_SECRET environment variable / .env
      2. jwt_secret key in config.db (written by setup wizard or /api/setup/complete)

    Previously this fell back to `secrets.token_urlsafe(32)` when no secret was
    configured. That silently invalidated every issued token on every process
    restart (which is what uvicorn --reload does on every file save). We now
    fail fast instead so the operator notices at startup, not when sessions
    start dropping out.
    """
    raw = (settings.JWT_SECRET or os.getenv("JWT_SECRET") or "").strip()

    # Fallback: read from config.db if env var is not set
    if not raw:
        try:
            from app.db.settings_store import settings_store as _ss
            raw = (_ss.get("jwt_secret") or "").strip()
        except Exception:
            pass

    if not raw:
        raise RuntimeError(
            "JWT_SECRET is not set. Run the setup wizard (python setup.py) or set it in .env:\n"
            "  python -c \"import secrets; print(secrets.token_urlsafe(32))\"\n"
            "Refusing to start to avoid silent session-invalidation on every restart."
        )
    if raw.lower() in _KNOWN_PLACEHOLDER_SECRETS:
        raise RuntimeError(
            f"JWT_SECRET is set to a known placeholder ({raw!r}). Replace it with a strong "
            "random secret:\n"
            "  python -c \"import secrets; print(secrets.token_urlsafe(32))\""
        )
    if len(raw) < MIN_JWT_SECRET_LEN:
        raise RuntimeError(
            f"JWT_SECRET is too short ({len(raw)} chars). Use at least {MIN_JWT_SECRET_LEN} "
            "characters of entropy:\n"
            "  python -c \"import secrets; print(secrets.token_urlsafe(32))\""
        )
    return raw


SECRET_KEY = _resolve_jwt_secret()
ACCESS_TOKEN_EXPIRE_MINUTES = int(settings.JWT_EXPIRE_MINUTES or os.getenv("JWT_EXPIRE_MINUTES", 480))

# Use pbkdf2_sha256 to avoid bcrypt backend/version issues & 72B limit
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(request: Request) -> Dict[str, Any]:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None or role is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user = user_store.get_user_by_username(username)
    if not user or not user.get("is_active"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inactive user")
    return {"id": user["id"], "username": user["username"], "role": user["role"]}


def require_admin(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin only")
    return current_user


def _clear_auth_cookie(resp: RedirectResponse) -> None:
    # Best-effort: delete + overwrite with expired cookie using same attributes
    try:
        resp.delete_cookie(COOKIE_NAME, path="/")
    except Exception:
        pass
    resp.set_cookie(
        key=COOKIE_NAME,
        value="",
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=0,
        expires=0,
        path="/",
    )


def _issue_csrf_token() -> str:
    return secrets.token_urlsafe(16)


def _validate_csrf(request: Request, token: Optional[str]) -> None:
    if not token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing CSRF token")
    cookie = request.cookies.get(CSRF_COOKIE)
    if not cookie or cookie != token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed")


def is_setup_complete() -> bool:
    """True once the setup wizard has finished OR any account exists.

    Accounts live in users.db (user_store), so an admin created by setup.py or
    the ADMIN_USERNAME bootstrap counts even if config.db lost the
    setup_complete flag. /, /login, /setup and /api/setup/complete must all use
    this one predicate: when they disagreed, a logged-out visitor bounced
    / -> /login -> /setup -> / forever.

    A database error counts as complete: the wizard is unauthenticated and
    creates an admin account, so a locked or unreadable DB must show the login
    form, never the wizard.
    """
    try:
        from app.db.settings_store import settings_store as _ss
        if _ss.get("setup_complete") == "true":
            return True
        return user_store.any_users_exist()
    except Exception:
        logging.getLogger("nullshift.auth").exception("setup check failed; treating setup as complete")
        return True


def _set_user_active(user_id: int, active: bool) -> bool:
    """Set a user's is_active flag. A disable that would leave no active admin
    is refused (returns False). The admin count and the write happen in one
    UPDATE, so two admins disabling each other at the same moment cannot both
    succeed."""
    with user_store.get_conn() as conn:
        if active:
            cur = conn.execute("UPDATE users SET is_active = 1 WHERE id = ?", (user_id,))
        else:
            cur = conn.execute(
                """
                UPDATE users SET is_active = 0
                WHERE id = ? AND NOT (
                    role = 'admin' AND is_active = 1 AND
                    (SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1) <= 1
                )
                """,
                (user_id,),
            )
        return cur.rowcount > 0


@router.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    # Redirect to setup if not yet configured
    if not is_setup_complete():
        return RedirectResponse(url="/setup", status_code=303)

    # If already logged in, redirect to home
    try:
        _ = get_current_user(request)
        return RedirectResponse(url="/", status_code=303)
    except HTTPException:
        pass

    # Serve static login page if present, else inline HTML
    login_path = os.path.join(os.path.dirname(__file__), "login.html")
    if os.path.exists(login_path):
        with open(login_path, "r", encoding="utf-8") as f:
            return html_page(f.read())
    error = "<p>Invalid username or password.</p>" if "error" in request.query_params else ""
    html = f"""
    <html><head><title>Login</title></head>
    <body>
      <h2>Login</h2>
      {error}
      <form method="post" action="/login">
        <label>Username: <input type="text" name="username" required /></label><br/>
        <label>Password: <input type="password" name="password" required /></label><br/>
        <button type="submit">Login</button>
      </form>
    </body></html>
    """
    return html_page(html)


@router.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    # A browser form posts here, so a failure goes back to the form with a flag
    # it can show instead of a bare JSON body. Unknown, disabled and wrong
    # password all get the same flag so the page does not reveal which
    # usernames exist.
    failed = RedirectResponse(url="/login?error=1", status_code=303)
    user = user_store.get_user_by_username(username)
    if not user or not user.get("is_active"):
        return failed
    if not verify_password(password, user["password_hash"]):
        return failed

    token = create_access_token({"sub": user["username"], "role": user["role"]})
    user_store.update_last_login(user["username"])

    resp = RedirectResponse(url="/", status_code=303)
    resp.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,  # set True behind HTTPS
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    return resp


@router.post("/logout")
async def logout():
    resp = RedirectResponse(url="/login", status_code=303)
    _clear_auth_cookie(resp)
    return resp


@router.get("/logout")
async def logout_get():
    resp = RedirectResponse(url="/login", status_code=303)
    _clear_auth_cookie(resp)
    return resp


@router.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    # A browser opens this page directly, so send an expired session to the
    # login form and a non-admin back to the chat instead of raw JSON.
    try:
        user = get_current_user(request)
    except HTTPException:
        return RedirectResponse(url="/login", status_code=303)
    if user.get("role") != "admin":
        return RedirectResponse(url="/", status_code=303)
    html_path = os.path.join(os.path.dirname(__file__), "admin.html")
    if not os.path.exists(html_path):
        return html_page("<p>Settings page not found (app/admin.html is missing).</p>", status_code=500)
    with open(html_path, "r", encoding="utf-8") as f:
        content = f.read()
    resp = html_page(content)
    # Set CSRF cookie for admin actions
    resp.set_cookie(CSRF_COOKIE, _issue_csrf_token(), httponly=False, samesite="lax", secure=False)
    # No-cache so admin UI fixes always reach the browser without the
    # user needing to know about Cmd+Shift+R. The page is tiny so the
    # extra fetch cost is irrelevant.
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    return resp


@router.get("/admin/users")
async def admin_list_users(current: Dict[str, Any] = Depends(require_admin)):
    # `me` lets the Settings page hide the Disable button on the caller's own row
    return {"users": user_store.list_users(), "me": current["id"]}


@router.post("/admin/users")
async def admin_create_user(request: Request, payload: Dict[str, Any], _: Dict[str, Any] = Depends(require_admin)):
    _validate_csrf(request, request.headers.get('X-CSRF-Token'))
    username = payload.get("username")
    password = payload.get("password")
    role = payload.get("role")
    if not username or not password or role not in ("admin","l1","l2"):
        raise HTTPException(status_code=400, detail="username, password, role (admin|l1|l2) required")
    if not isinstance(username, str) or not USERNAME_RE.fullmatch(username):
        raise HTTPException(status_code=400, detail="username may only use letters, digits and . _ @ - (max 64)")
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LEN:
        raise HTTPException(status_code=400, detail=f"password must be at least {MIN_PASSWORD_LEN} characters")
    if user_store.get_user_by_username(username):
        raise HTTPException(status_code=409, detail="username already exists")
    uid = user_store.create_user(username, get_password_hash(password), role)
    return {"id": uid, "username": username, "role": role}


@router.patch("/admin/users/{user_id}/disable")
async def admin_disable_user(user_id: int, request: Request, current: Dict[str, Any] = Depends(require_admin)):
    _validate_csrf(request, request.headers.get('X-CSRF-Token'))
    # Disabling yourself ends your session on the next request, and disabling
    # the last admin leaves nobody able to open Settings again.
    if user_id == current["id"]:
        raise HTTPException(status_code=409, detail="You cannot disable your own account")
    target = user_store.get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="user not found")
    if target["is_active"] and not _set_user_active(user_id, False):
        raise HTTPException(status_code=409, detail="Cannot disable the last active admin")
    return {"status": "disabled", "id": user_id}


@router.patch("/admin/users/{user_id}/enable")
async def admin_enable_user(user_id: int, request: Request, _: Dict[str, Any] = Depends(require_admin)):
    _validate_csrf(request, request.headers.get('X-CSRF-Token'))
    if not user_store.get_user_by_id(user_id):
        raise HTTPException(status_code=404, detail="user not found")
    _set_user_active(user_id, True)
    return {"status": "enabled", "id": user_id}


def init_auth_startup() -> None:
    # Ensure DB schema
    user_store.init_db()
    # Bootstrap admin if no users
    if not user_store.any_users_exist():
        admin_user = settings.ADMIN_USERNAME or os.getenv("ADMIN_USERNAME")
        admin_pass = settings.ADMIN_PASSWORD or os.getenv("ADMIN_PASSWORD")
        if admin_user and admin_pass:
            user_store.create_user(admin_user, get_password_hash(admin_pass), role="admin")
            print("[auth] Bootstrapped admin user from env")
        else:
            print("[auth] No users present and ADMIN_USERNAME/ADMIN_PASSWORD not set; please create an admin user via API once logged in.")
