"""
Hermes Web UI -- per-user email/password authentication.

Replaces the shared-password gate with named user accounts, server-side
cookie sessions, invite-link onboarding, and a two-role (owner / admin) model.

Storage: SQLite at STATE_DIR/auth.db (separate from the shared brain).

Password hashing: bcrypt, cost factor 12.
Session tokens:   32-byte URL-safe random (secrets.token_urlsafe(32)).
Invite tokens:    32-byte URL-safe random (secrets.token_urlsafe(32)).
"""
from __future__ import annotations

import logging
import os
import re
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

SESSION_TTL_SECONDS = 86400 * 30   # 30 days (per spec AC-2)
INVITE_TTL_SECONDS = 86400 * 7    # 7 days  (per spec AC-5)
PASSWORD_MIN_LEN = 12
PASSWORD_MAX_LEN = 128

_RATE_LIMIT_WINDOW = 15 * 60   # 15 minutes
_RATE_LIMIT_MAX = 5             # attempts before delay
_RATE_LIMIT_DELAY = 5           # seconds of artificial delay

# ── DB path ───────────────────────────────────────────────────────────────────

def _db_path() -> Path:
    from api.config import STATE_DIR  # lazy import — avoids circular on module load
    return STATE_DIR / "auth.db"


# ── Schema ────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('owner','admin')),
    created_at    INTEGER NOT NULL,
    last_login_at INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS invites (
    id          TEXT PRIMARY KEY,
    email       TEXT NOT NULL,
    role        TEXT NOT NULL CHECK (role IN ('owner','admin')),
    token       TEXT NOT NULL UNIQUE,
    created_by  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used_at     INTEGER
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires  ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_invites_token    ON invites(token);
CREATE INDEX IF NOT EXISTS idx_invites_email    ON invites(email);
"""


@contextmanager
def _conn() -> Generator[sqlite3.Connection, None, None]:
    """Open auth.db with WAL mode and foreign keys enabled."""
    db = _db_path()
    db.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(db), timeout=15)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    con.execute("PRAGMA journal_mode = WAL")
    con.executescript(_SCHEMA)
    try:
        yield con
    finally:
        con.close()


# ── Password hashing (bcrypt) ─────────────────────────────────────────────────

def _get_bcrypt():
    """Import bcrypt lazily (available in the container via pip install bcrypt)."""
    try:
        import bcrypt
        return bcrypt
    except ImportError as e:
        raise RuntimeError(
            "bcrypt is required for per-user auth. "
            "Add bcrypt to requirements.txt and rebuild the image."
        ) from e


def hash_password(password: str) -> str:
    """Hash a plaintext password with bcrypt (cost 12). Returns the hash string."""
    bcrypt = _get_bcrypt()
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
    return hashed.decode()


def verify_password_hash(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    bcrypt = _get_bcrypt()
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


# ── Password validation ───────────────────────────────────────────────────────

def validate_password(password: str) -> str | None:
    """
    Validate password against policy.
    Returns None on success, or an error message string on failure.
    """
    if not password or len(password) < PASSWORD_MIN_LEN:
        return f"Password must be at least {PASSWORD_MIN_LEN} characters."
    if len(password) > PASSWORD_MAX_LEN:
        return f"Password must be at most {PASSWORD_MAX_LEN} characters."
    if not re.search(r"[A-Za-z]", password):
        return "Password must contain at least one letter."
    if not re.search(r"\d", password):
        return "Password must contain at least one digit."
    return None


# ── User management ───────────────────────────────────────────────────────────

def user_count() -> int:
    """Return the total number of user rows in the DB."""
    with _conn() as con:
        row = con.execute("SELECT COUNT(*) FROM users").fetchone()
        return row[0] if row else 0


def owner_count() -> int:
    """Return the number of owner-role users."""
    with _conn() as con:
        row = con.execute("SELECT COUNT(*) FROM users WHERE role='owner'").fetchone()
        return row[0] if row else 0


def create_user(email: str, password: str, role: str) -> dict:
    """
    Create a new user. Returns the user dict.
    Raises ValueError on validation failures.
    Raises sqlite3.IntegrityError if email already exists.
    """
    email = email.strip().lower()
    if not email or "@" not in email:
        raise ValueError("Invalid email address.")
    err = validate_password(password)
    if err:
        raise ValueError(err)
    if role not in ("owner", "admin"):
        raise ValueError("Role must be 'owner' or 'admin'.")
    pw_hash = hash_password(password)
    user_id = str(uuid.uuid4())
    now = int(time.time())
    with _conn() as con:
        con.execute(
            "INSERT INTO users (id, email, password_hash, role, created_at) VALUES (?,?,?,?,?)",
            (user_id, email, pw_hash, role, now),
        )
        con.commit()
    logger.info("userauth: created user %s role=%s", email, role)
    return {"id": user_id, "email": email, "role": role, "created_at": now}


def get_user_by_email(email: str) -> dict | None:
    """Fetch user row by email (case-insensitive). Returns dict or None."""
    email = email.strip().lower()
    with _conn() as con:
        row = con.execute(
            "SELECT id, email, password_hash, role, created_at, last_login_at FROM users WHERE email=?",
            (email,),
        ).fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id: str) -> dict | None:
    """Fetch user row by id. Returns dict or None."""
    with _conn() as con:
        row = con.execute(
            "SELECT id, email, password_hash, role, created_at, last_login_at FROM users WHERE id=?",
            (user_id,),
        ).fetchone()
        return dict(row) if row else None


def list_users() -> list[dict]:
    """Return all users (without password_hash) sorted by created_at."""
    with _conn() as con:
        rows = con.execute(
            "SELECT id, email, role, created_at, last_login_at FROM users ORDER BY created_at ASC"
        ).fetchall()
        return [dict(r) for r in rows]


def delete_user(user_id: str) -> None:
    """
    Delete a user by id.
    Raises ValueError if the user is the last owner.
    Raises KeyError if the user doesn't exist.
    """
    user = get_user_by_id(user_id)
    if not user:
        raise KeyError(f"User {user_id} not found.")
    if user["role"] == "owner" and owner_count() <= 1:
        raise ValueError(
            "Cannot delete the last Owner. Promote another user to Owner first."
        )
    with _conn() as con:
        con.execute("DELETE FROM users WHERE id=?", (user_id,))
        con.commit()
    logger.info("userauth: deleted user %s", user_id)


def update_user_last_login(user_id: str) -> None:
    with _conn() as con:
        con.execute(
            "UPDATE users SET last_login_at=? WHERE id=?",
            (int(time.time()), user_id),
        )
        con.commit()


# ── Session management ────────────────────────────────────────────────────────

def create_session(user_id: str) -> str:
    """Create a new session for user_id. Returns the session token."""
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    expires = now + SESSION_TTL_SECONDS
    with _conn() as con:
        con.execute(
            "INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?,?,?,?)",
            (token, user_id, now, expires),
        )
        con.commit()
    return token


def get_session_user(token: str) -> dict | None:
    """
    Validate a session token and return the user dict, or None if
    the session is missing, expired, or the user no longer exists.
    Lazily deletes expired session on miss.
    """
    if not token:
        return None
    now = int(time.time())
    with _conn() as con:
        row = con.execute(
            "SELECT id, user_id, expires_at FROM sessions WHERE id=?",
            (token,),
        ).fetchone()
        if not row:
            return None
        if row["expires_at"] <= now:
            # Lazy cleanup of expired session
            con.execute("DELETE FROM sessions WHERE id=?", (token,))
            con.commit()
            return None
        user_row = con.execute(
            "SELECT id, email, role, created_at, last_login_at FROM users WHERE id=?",
            (row["user_id"],),
        ).fetchone()
        return dict(user_row) if user_row else None


def delete_session(token: str) -> None:
    """Invalidate a session token."""
    with _conn() as con:
        con.execute("DELETE FROM sessions WHERE id=?", (token,))
        con.commit()


def delete_other_sessions(user_id: str, keep_token: str) -> None:
    """Invalidate all sessions for user_id except keep_token (for password change)."""
    with _conn() as con:
        con.execute(
            "DELETE FROM sessions WHERE user_id=? AND id!=?",
            (user_id, keep_token),
        )
        con.commit()


# ── Invite management ─────────────────────────────────────────────────────────

def create_invite(email: str, role: str, created_by: str) -> dict:
    """
    Generate a new invite. If a pending (unexpired, unused) invite for this
    email already exists, it is silently replaced (spec E-6).

    Raises ValueError if the email already belongs to a registered user.
    """
    email = email.strip().lower()
    if not email or "@" not in email:
        raise ValueError("Invalid email address.")
    if role not in ("owner", "admin"):
        raise ValueError("Role must be 'owner' or 'admin'.")

    # Block invite if user already exists
    existing = get_user_by_email(email)
    if existing:
        raise ValueError("A user with this email already exists.")

    token = secrets.token_urlsafe(32)
    now = int(time.time())
    expires = now + INVITE_TTL_SECONDS
    invite_id = str(uuid.uuid4())

    with _conn() as con:
        # Silently replace any existing pending invite for this email (spec E-6)
        con.execute(
            "DELETE FROM invites WHERE email=? AND used_at IS NULL AND expires_at > ?",
            (email, now),
        )
        con.execute(
            """INSERT INTO invites (id, email, role, token, created_by, created_at, expires_at)
               VALUES (?,?,?,?,?,?,?)""",
            (invite_id, email, role, token, created_by, now, expires),
        )
        con.commit()

    logger.info("userauth: invite created email=%s role=%s by=%s", email, role, created_by)
    return {
        "id": invite_id,
        "email": email,
        "role": role,
        "token": token,
        "created_by": created_by,
        "created_at": now,
        "expires_at": expires,
    }


def get_invite_by_token(token: str) -> dict | None:
    """Return the invite row for the given token, or None."""
    with _conn() as con:
        row = con.execute(
            """SELECT id, email, role, token, created_by, created_at, expires_at, used_at
               FROM invites WHERE token=?""",
            (token,),
        ).fetchone()
        return dict(row) if row else None


def redeem_invite(token: str, password: str) -> dict:
    """
    Redeem an invite: validate token, create the user, mark invite used.
    Returns the created user dict.
    Raises ValueError on any validation failure.
    """
    now = int(time.time())
    invite = get_invite_by_token(token)
    if not invite:
        raise ValueError("Invalid or unknown invite link.")
    if invite["used_at"] is not None:
        raise ValueError("This invite link has already been used.")
    if invite["expires_at"] <= now:
        raise ValueError("This invite link has expired.")

    err = validate_password(password)
    if err:
        raise ValueError(err)

    pw_hash = hash_password(password)
    user_id = str(uuid.uuid4())

    with _conn() as con:
        con.execute(
            "INSERT INTO users (id, email, password_hash, role, created_at) VALUES (?,?,?,?,?)",
            (user_id, invite["email"], pw_hash, invite["role"], now),
        )
        con.execute(
            "UPDATE invites SET used_at=? WHERE token=?",
            (now, token),
        )
        con.commit()

    logger.info(
        "userauth: invite redeemed email=%s role=%s", invite["email"], invite["role"]
    )
    return {"id": user_id, "email": invite["email"], "role": invite["role"], "created_at": now}


def list_invites(viewer_user_id: str | None = None, viewer_role: str | None = None) -> list[dict]:
    """
    List pending (unused, unexpired) invites.
    Owners see all; Admins see only their own.
    """
    now = int(time.time())
    with _conn() as con:
        if viewer_role == "owner" or viewer_user_id is None:
            rows = con.execute(
                """SELECT id, email, role, created_by, created_at, expires_at, used_at
                   FROM invites WHERE expires_at > ? ORDER BY created_at DESC""",
                (now,),
            ).fetchall()
        else:
            rows = con.execute(
                """SELECT id, email, role, created_by, created_at, expires_at, used_at
                   FROM invites WHERE expires_at > ? AND created_by=? ORDER BY created_at DESC""",
                (now, viewer_user_id),
            ).fetchall()
        return [dict(r) for r in rows]


def revoke_invite(invite_id: str, acting_user_id: str, acting_role: str) -> None:
    """
    Revoke (delete) a pending invite.
    Owners can revoke any invite; Admins can only revoke their own.
    Raises ValueError if the invite is not found or not revocable.
    """
    with _conn() as con:
        row = con.execute(
            "SELECT id, created_by, used_at FROM invites WHERE id=?",
            (invite_id,),
        ).fetchone()
        if not row:
            raise ValueError("Invite not found.")
        if row["used_at"] is not None:
            raise ValueError("Cannot revoke a used invite.")
        if acting_role != "owner" and row["created_by"] != acting_user_id:
            raise ValueError("You can only revoke your own invites.")
        con.execute("DELETE FROM invites WHERE id=?", (invite_id,))
        con.commit()
    logger.info("userauth: invite %s revoked by %s", invite_id, acting_user_id)


# ── Rate limiting (per-email, in-memory) ──────────────────────────────────────

import threading as _threading

_rate_limit_lock = _threading.Lock()
_rate_limit_attempts: dict[str, list[float]] = {}  # email → list of timestamps


def check_login_rate(email: str) -> bool:
    """Return True if the email is not rate-limited, False if it is."""
    now = time.time()
    window_start = now - _RATE_LIMIT_WINDOW
    with _rate_limit_lock:
        attempts = [t for t in _rate_limit_attempts.get(email, []) if t > window_start]
        _rate_limit_attempts[email] = attempts
        return len(attempts) < _RATE_LIMIT_MAX


def record_login_failure(email: str) -> None:
    """Record a failed login attempt for rate limiting."""
    now = time.time()
    with _rate_limit_lock:
        _rate_limit_attempts.setdefault(email, []).append(now)


def clear_login_attempts(email: str) -> None:
    """Clear login failure record (on successful login)."""
    with _rate_limit_lock:
        _rate_limit_attempts.pop(email, None)


# ── Login helper ──────────────────────────────────────────────────────────────

def attempt_login(email: str, password: str) -> dict | None:
    """
    Attempt to log in. Returns the user dict on success, None on failure.
    Handles rate limiting delay internally.
    Does NOT create a session — caller must call create_session().
    """
    email_norm = email.strip().lower()

    if not check_login_rate(email_norm):
        # Apply artificial delay to slow brute-force even when rate-limited
        time.sleep(_RATE_LIMIT_DELAY)
        return None

    user = get_user_by_email(email_norm)
    if not user or not verify_password_hash(password, user["password_hash"]):
        record_login_failure(email_norm)
        return None

    clear_login_attempts(email_norm)
    update_user_last_login(user["id"])
    return user


# ── is_userauth_active ────────────────────────────────────────────────────────

def is_userauth_active() -> bool:
    """
    Return True if the per-user auth system should be used.

    Per-user auth is active when:
    1. The HERMES_USERAUTH env var is set to '1' / 'true' / 'yes', OR
    2. The auth.db already exists (created by a prior setup), OR
    3. The legacy HERMES_WEBUI_PASSWORD is NOT set (implying we want
       the new system rather than the old shared-password gate).

    The intent: once auth.db is created, always use per-user auth.
    On a fresh system with no password configured, also use per-user auth
    (showing /setup rather than the legacy password gate).
    """
    import os
    # Explicit opt-in
    env = os.getenv("HERMES_USERAUTH", "").strip().lower()
    if env in ("1", "true", "yes"):
        return True
    # Explicit opt-out (escape hatch for local dev)
    if env in ("0", "false", "no"):
        return False
    # If auth.db already exists, always use per-user auth
    try:
        if _db_path().exists():
            return True
    except Exception:
        pass
    # If no legacy password is configured, use per-user auth
    try:
        legacy_pw = os.getenv("HERMES_WEBUI_PASSWORD", "").strip()
        if not legacy_pw:
            return True
    except Exception:
        pass
    return False
