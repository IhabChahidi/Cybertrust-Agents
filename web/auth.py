"""Backend-enforced session authentication for the MCP dashboard.

*** DEVELOPMENT-ONLY AUTHENTICATION ***
This module exists because there is no production identity provider wired up
yet (no SSO/Entra ID/etc. for the pilot). It is a REAL, backend-enforced
session mechanism — not a frontend-only gate — but it is intentionally simple:
- Users are seeded in-memory from environment variables at process start.
  There is no persistent user database.
- Sessions live in an in-memory dict. Restarting the server logs everyone out.
- No HTTPS enforcement here — that is the deployer's responsibility outside
  localhost (see COOKIE_SECURE below).

None of this should be mistaken for a production authentication system. Before
any non-local deployment, replace `_USERS`/`_SESSIONS` with a real identity
provider and persistent, distributed session storage.

Security properties that ARE real, even in dev mode:
- Passwords are never stored or logged in plaintext (PBKDF2-HMAC-SHA256 with a
  per-user random salt).
- The session token lives only in an HttpOnly, SameSite=Lax cookie — never in
  a JS-readable field, never in localStorage.
- A CSRF token (separate from the session cookie) is required on every
  state-changing (POST) request, mitigating CSRF against the cookie.
- Failed login attempts are rate-limited per username to slow brute force.
- Login errors are generic ("Identifiants invalides") regardless of whether
  the username or the password was wrong, to avoid user enumeration.
"""

import hashlib
import os
import secrets
import time
from dataclasses import dataclass, field

from fastapi import Depends, HTTPException, Request, Response

DEV_AUTH_NOTICE = (
    "Mode authentification de developpement : comptes et sessions en memoire, "
    "aucune base de donnees persistante, a remplacer par un fournisseur "
    "d'identite reel avant toute mise en production."
)

SESSION_COOKIE_NAME = "mcp_session"
SESSION_TTL_SECONDS = 30 * 60  # 30 min sliding expiry
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 60

VALID_ROLES = {"CISO", "CISO_DELEGATE"}


def _hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000).hex()


def _make_user(username: str, password: str, role: str) -> dict:
    salt = secrets.token_bytes(16)
    return {"username": username, "role": role, "salt": salt, "password_hash": _hash_password(password, salt)}


def _seed_users() -> dict[str, dict]:
    """Seed dev accounts from environment variables, generating random
    passwords (printed once to the server console) if none are configured —
    never a hardcoded real credential."""
    users = {}
    seeds = [
        ("CISO_DEV_USERNAME", "CISO_DEV_PASSWORD", "ciso", "CISO"),
        ("DELEGATE_DEV_USERNAME", "DELEGATE_DEV_PASSWORD", "ciso.delegate", "CISO_DELEGATE"),
    ]
    for user_env, pass_env, default_username, role in seeds:
        username = os.environ.get(user_env, default_username)
        password = os.environ.get(pass_env)
        if not password:
            password = secrets.token_urlsafe(9)
            print(
                f"[dev-auth] No {pass_env} set — generated password for "
                f"{username!r} ({role}): {password}  (dev only, not logged again)"
            )
        users[username] = _make_user(username, password, role)
    return users


_USERS: dict[str, dict] = _seed_users()
_SESSIONS: dict[str, dict] = {}
_FAILED_ATTEMPTS: dict[str, list[float]] = {}


@dataclass
class Session:
    token: str
    username: str
    role: str
    csrf_token: str
    expires_at: float


def _is_locked_out(username: str) -> bool:
    attempts = _FAILED_ATTEMPTS.get(username, [])
    now = time.time()
    recent = [t for t in attempts if now - t < LOCKOUT_SECONDS]
    _FAILED_ATTEMPTS[username] = recent
    return len(recent) >= MAX_FAILED_ATTEMPTS


def _record_failure(username: str) -> None:
    _FAILED_ATTEMPTS.setdefault(username, []).append(time.time())


def authenticate(username: str, password: str) -> Session | None:
    if _is_locked_out(username):
        return None
    user = _USERS.get(username)
    if user is None:
        # Still hash something so response timing doesn't reveal whether the
        # username exists (best-effort constant-time-ish behavior in dev).
        _hash_password(password, secrets.token_bytes(16))
        _record_failure(username)
        return None
    if _hash_password(password, user["salt"]) != user["password_hash"]:
        _record_failure(username)
        return None

    token = secrets.token_urlsafe(32)
    session = Session(
        token=token, username=user["username"], role=user["role"],
        csrf_token=secrets.token_urlsafe(24), expires_at=time.time() + SESSION_TTL_SECONDS,
    )
    _SESSIONS[token] = session
    return session


def get_session(token: str | None) -> Session | None:
    if not token:
        return None
    session = _SESSIONS.get(token)
    if session is None:
        return None
    if session.expires_at < time.time():
        _SESSIONS.pop(token, None)
        return None
    session.expires_at = time.time() + SESSION_TTL_SECONDS  # sliding expiry
    return session


def destroy_session(token: str | None) -> None:
    if token:
        _SESSIONS.pop(token, None)


def set_session_cookie(response: Response, session: Session, *, secure: bool) -> None:
    response.set_cookie(
        SESSION_COOKIE_NAME, session.token, max_age=SESSION_TTL_SECONDS,
        httponly=True, samesite="lax", secure=secure, path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")


def require_auth(request: Request) -> Session:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    session = get_session(token)
    if session is None:
        raise HTTPException(401, "Session absente ou expiree")
    return session


def require_role(*roles: str):
    def dependency(session: Session = Depends(require_auth)) -> Session:
        if session.role not in roles:
            raise HTTPException(403, f"Role {session.role!r} non autorise pour cette action")
        return session

    return dependency


def require_csrf(request: Request, session: Session = Depends(require_auth)) -> Session:
    header_token = request.headers.get("x-csrf-token")
    if not header_token or header_token != session.csrf_token:
        raise HTTPException(403, "Jeton CSRF invalide ou absent")
    return session
