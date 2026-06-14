import os
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
_KNOWN_PLACEHOLDER_SECRETS = {
    "please-change-this-secret",
    "replace_me",
    "changeme",
    "change-me",
    "secret",
    "your-secret-here",
}


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


@router.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    # Redirect to setup if not yet configured
    try:
        from app.db.settings_store import settings_store as _ss
        if _ss.get("setup_complete") != "true":
            return RedirectResponse(url="/setup", status_code=303)
    except Exception:
        pass

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
            return HTMLResponse(f.read())
    html = """
    <html><head><title>Login</title></head>
    <body>
      <h2>Login</h2>
      <form method="post" action="/login">
        <label>Username: <input type="text" name="username" required /></label><br/>
        <label>Password: <input type="password" name="password" required /></label><br/>
        <button type="submit">Login</button>
      </form>
    </body></html>
    """
    return HTMLResponse(html)


@router.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    user = user_store.get_user_by_username(username)
    if not user or not user.get("is_active"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

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
async def admin_page(request: Request, _: Dict[str, Any] = Depends(require_admin)):
        # Set CSRF cookie for admin actions
        token = _issue_csrf_token()
        html_path = os.path.join(os.path.dirname(__file__), "admin.html")
        if os.path.exists(html_path):
                with open(html_path, "r", encoding="utf-8") as f:
                        content = f.read()
        else:
                content = """
                <html><head><title>Admin</title></head>
                <body>
                <h2>Admin – Users</h2>
                <div id=users></div>
                <h3>Create user</h3>
                <form id="createForm">
                    <input name="username" placeholder="username" required />
                    <input type="password" name="password" placeholder="password" required />
                    <select name="role"><option>l1</option><option>l2</option><option>admin</option></select>
                    <button type="submit">Create</button>
                </form>
                <script>
                function getCookie(n){return document.cookie.split('; ').find(r=>r.startsWith(n+'='))?.split('=')[1]}
                const csrf=getCookie('csrftoken');
                async function refresh(){
                    const r=await fetch('/admin/users'); const j=await r.json();
                    const el=document.getElementById('users');
                    el.innerHTML='<table border=1><tr><th>ID</th><th>User</th><th>Role</th><th>Active</th><th>Actions</th></tr>' +
                        j.users.map(u=>`<tr><td>${u.id}</td><td>${u.username}</td><td>${u.role}</td><td>${u.is_active}</td>`+
                        `<td>${u.is_active?`<button data-id="${u.id}" class="disable">Disable</button>`:''}</td></tr>`).join('') + '</table>';
                    el.querySelectorAll('button.disable').forEach(b=>b.onclick=async()=>{
                        await fetch(`/admin/users/${b.dataset.id}/disable`,{method:'PATCH',headers:{'X-CSRF-Token':csrf}});refresh();
                    });
                }
                document.getElementById('createForm').onsubmit=async(e)=>{
                    e.preventDefault(); const fd=new FormData(e.target);
                    const body={username:fd.get('username'),password:fd.get('password'),role:fd.get('role')};
                    await fetch('/admin/users',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify(body)});
                    e.target.reset(); refresh();
                };
                refresh();
                </script>
                </body></html>
                """
        resp = HTMLResponse(content)
        resp.set_cookie(CSRF_COOKIE, token, httponly=False, samesite="lax", secure=False)
        # No-cache so admin UI fixes always reach the browser without the
        # user needing to know about Cmd+Shift+R. The page is tiny so the
        # extra fetch cost is irrelevant.
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        return resp


@router.get("/admin/users")
async def admin_list_users(_: Dict[str, Any] = Depends(require_admin)):
    return {"users": user_store.list_users()}


@router.post("/admin/users")
async def admin_create_user(request: Request, payload: Dict[str, Any], _: Dict[str, Any] = Depends(require_admin)):
    # If CSRF header is present (browser UI), validate it; CLI tools may omit it
    csrf_hdr = request.headers.get('X-CSRF-Token')
    if csrf_hdr:
        _validate_csrf(request, csrf_hdr)
    username = payload.get("username")
    password = payload.get("password")
    role = payload.get("role")
    if not username or not password or role not in ("admin","l1","l2"):
        raise HTTPException(status_code=400, detail="username, password, role (admin|l1|l2) required")
    if user_store.get_user_by_username(username):
        raise HTTPException(status_code=409, detail="username already exists")
    uid = user_store.create_user(username, get_password_hash(password), role)
    return {"id": uid, "username": username, "role": role}


@router.patch("/admin/users/{user_id}/disable")
async def admin_disable_user(user_id: int, request: Request, _: Dict[str, Any] = Depends(require_admin)):
    csrf_hdr = request.headers.get('X-CSRF-Token')
    if csrf_hdr:
        _validate_csrf(request, csrf_hdr)
    if not user_store.get_user_by_id(user_id):
        raise HTTPException(status_code=404, detail="user not found")
    user_store.disable_user(user_id)
    return {"status": "disabled", "id": user_id}


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
