"""
Hermes Web UI -- per-user auth route handlers.

Registers handlers for:
  GET  /setup               -- First-launch setup page
  POST /auth/setup          -- Create initial owner (0-user gate)
  POST /auth/login          -- Email+password login (sets session cookie)
  POST /auth/logout         -- Invalidate session
  GET  /auth/me             -- Return current user info
  POST /users/invite        -- Generate invite link (role matrix enforced)
  GET  /invite/<token>      -- Accept-invite page
  POST /auth/accept-invite  -- Set password from invite token
  GET  /users               -- List users (JSON)
  DELETE /users/<id>        -- Delete user (owner-only)

Called from api/routes.py handle_get / handle_post / handle_delete.
"""
from __future__ import annotations

import html as _html
import json
import logging
import time
import urllib.parse

logger = logging.getLogger(__name__)


def _get_client_ip(handler) -> str | None:
    """Extract the best-effort client IP from a request handler.

    Prefers X-Forwarded-For (set by nginx/Caddy reverse proxy) then
    X-Real-IP, then falls back to the raw TCP client_address.
    Returns None if no address can be determined.
    """
    try:
        xff = (handler.headers.get("X-Forwarded-For", "") or "").split(",")[0].strip()
        if xff:
            return xff
        xri = (handler.headers.get("X-Real-IP", "") or "").strip()
        if xri:
            return xri
        addr = getattr(handler, "client_address", None)
        if addr:
            return str(addr[0])
    except Exception:
        pass
    return None


# ── Cookie helpers ─────────────────────────────────────────────────────────────

COOKIE_NAME = "hermes_user_session"


def _set_session_cookie(handler, token: str) -> None:
    """Set the httpOnly, Secure (context-aware), SameSite=Lax session cookie."""
    from api.userauth import SESSION_TTL_SECONDS

    secure = _is_secure(handler)
    secure_flag = "; Secure" if secure else ""
    handler.send_header(
        "Set-Cookie",
        f"{COOKIE_NAME}={token}; HttpOnly{secure_flag}; SameSite=Lax; Path=/; Max-Age={SESSION_TTL_SECONDS}",
    )


def _clear_session_cookie(handler) -> None:
    """Clear the session cookie by setting Max-Age=0."""
    secure = _is_secure(handler)
    secure_flag = "; Secure" if secure else ""
    handler.send_header(
        "Set-Cookie",
        f"{COOKIE_NAME}=; HttpOnly{secure_flag}; SameSite=Lax; Path=/; Max-Age=0",
    )


def _is_secure(handler) -> bool:
    """True if the connection is HTTPS (checks env var and X-Forwarded-Proto)."""
    import os

    env = os.getenv("HERMES_WEBUI_HTTPS", "").strip().lower()
    if env in ("1", "true", "yes"):
        return True
    if env in ("0", "false", "no"):
        return False
    if handler is not None:
        if handler.headers.get("X-Forwarded-Proto", "") == "https":
            return True
    return False


def _parse_user_session_cookie(handler) -> str | None:
    """Parse COOKIE_NAME from the request Cookie header."""
    raw = handler.headers.get("Cookie", "")
    for part in raw.split(";"):
        part = part.strip()
        if part.startswith(COOKIE_NAME + "="):
            return part[len(COOKIE_NAME) + 1 :]
    return None


def _read_form_or_json(handler) -> dict:
    """
    Read POST body as either application/x-www-form-urlencoded or JSON.
    Returns a plain dict with string values.
    """
    content_type = handler.headers.get("Content-Type", "").split(";")[0].strip()
    raw_length = handler.headers.get("Content-Length", 0)
    try:
        length = int(raw_length)
    except (TypeError, ValueError):
        length = 0
    if length <= 0 or length > 1024 * 1024:  # 1 MB cap
        return {}
    raw = handler.rfile.read(length)
    if content_type == "application/x-www-form-urlencoded":
        parsed = urllib.parse.parse_qs(raw.decode(errors="replace"), keep_blank_values=True)
        return {k: v[0] if v else "" for k, v in parsed.items()}
    # Assume JSON
    try:
        return json.loads(raw)
    except Exception:
        return {}


def _get_current_user(handler) -> dict | None:
    """Return the authenticated user dict or None."""
    from api.userauth import get_session_user

    token = _parse_user_session_cookie(handler)
    if not token:
        return None
    return get_session_user(token)


# ── Response helpers ──────────────────────────────────────────────────────────

def _json_response(handler, data: dict, status: int = 200) -> bool:
    body = json.dumps(data).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)
    return True


def _html_page(handler, html: str, status: int = 200) -> bool:
    body = html.encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)
    return True


def _redirect(handler, location: str) -> bool:
    handler.send_response(302)
    handler.send_header("Location", location)
    handler.send_header("Content-Length", "0")
    handler.end_headers()
    return True


# ── Page templates ────────────────────────────────────────────────────────────

_PAGE_STYLE = """
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #0f0f12; color: #e0e0e8; min-height: 100vh;
    display: flex; align-items: center; justify-content: center;
  }
  .card {
    background: #1a1a24; border: 1px solid #2a2a3a; border-radius: 12px;
    padding: 2rem 2.5rem; width: 100%; max-width: 440px;
  }
  h1 { font-size: 1.4rem; font-weight: 600; margin-bottom: 0.4rem; color: #f0f0f8; }
  .subtitle { font-size: 0.88rem; color: #888; margin-bottom: 1.5rem; }
  label { display: block; font-size: 0.82rem; color: #aaa; margin-bottom: 0.3rem; }
  input[type=email], input[type=password], input[type=text], select {
    width: 100%; padding: 0.55rem 0.75rem; border-radius: 6px;
    border: 1px solid #333; background: #111118; color: #e0e0e8;
    font-size: 0.9rem; margin-bottom: 1rem;
  }
  input:focus, select:focus { outline: none; border-color: #6060c8; }
  .btn {
    width: 100%; padding: 0.65rem; border-radius: 6px; border: none;
    background: #5050b8; color: #fff; font-size: 0.95rem; font-weight: 500;
    cursor: pointer; transition: background 0.15s;
  }
  .btn:hover { background: #6060c8; }
  .btn:disabled { background: #333; color: #666; cursor: not-allowed; }
  .error {
    background: #2a1212; border: 1px solid #5a2020; border-radius: 6px;
    color: #e87070; padding: 0.6rem 0.8rem; font-size: 0.85rem; margin-bottom: 1rem;
  }
  .info {
    background: #121a2a; border: 1px solid #204060; border-radius: 6px;
    color: #70a8e8; padding: 0.6rem 0.8rem; font-size: 0.85rem; margin-bottom: 1rem;
    word-break: break-all;
  }
  .badge {
    display: inline-block; padding: 0.15rem 0.5rem; border-radius: 3px;
    font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em;
  }
  .badge-owner { background: #302060; color: #c090f8; }
  .badge-admin { background: #103030; color: #60d0a0; }
  table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
  th { font-size: 0.75rem; color: #666; text-align: left; padding: 0.4rem 0.6rem;
       border-bottom: 1px solid #2a2a3a; text-transform: uppercase; }
  td { padding: 0.5rem 0.6rem; border-bottom: 1px solid #1a1a24; font-size: 0.88rem; }
  .action-btn {
    padding: 0.25rem 0.6rem; border-radius: 4px; border: 1px solid #3a1a1a;
    background: #2a1212; color: #e87070; font-size: 0.8rem; cursor: pointer;
  }
  .action-btn:hover { background: #3a1818; }
  a { color: #8080d8; text-decoration: none; }
  a:hover { text-decoration: underline; }
  .wide { max-width: 720px; }
  .flex-row { display: flex; gap: 0.5rem; align-items: flex-end; margin-bottom: 1rem; }
  .flex-row input, .flex-row select { margin-bottom: 0; }
  .flex-1 { flex: 1; }
  .logout-link { float: right; font-size: 0.82rem; color: #888; }
  .invite-box { background: #0c1a0c; border: 1px solid #205020; border-radius: 6px;
    padding: 0.8rem; font-size: 0.82rem; color: #60c060; word-break: break-all;
    margin-top: 0.5rem; }
  .copy-btn { margin-top: 0.5rem; padding: 0.3rem 0.7rem; border-radius: 4px;
    border: 1px solid #205020; background: #0c1a0c; color: #60c060;
    font-size: 0.8rem; cursor: pointer; }
  .copy-btn:hover { background: #122212; }
</style>
"""


def _setup_page(error: str = "") -> str:
    err_html = f'<div class="error">{_html.escape(error)}</div>' if error else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Create Owner Account</title>{_PAGE_STYLE}</head>
<body>
<div class="card">
  <h1>Create Owner Account</h1>
  <p class="subtitle">First-time setup. This page is only available once.</p>
  {err_html}
  <form method="POST" action="/auth/setup">
    <label>Email</label>
    <input type="email" name="email" required autofocus placeholder="you@example.com">
    <label>Password</label>
    <input type="password" name="password" required placeholder="Min 12 characters">
    <label>Confirm Password</label>
    <input type="password" name="password2" required placeholder="Repeat password">
    <button type="submit" class="btn">Create Account &amp; Sign In</button>
  </form>
</div>
</body></html>"""


def _login_page(error: str = "", next_url: str = "/") -> str:
    err_html = f'<div class="error">{_html.escape(error)}</div>' if error else ""
    next_esc = _html.escape(next_url)
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Sign In</title>{_PAGE_STYLE}</head>
<body>
<div class="card">
  <h1>Sign In</h1>
  <p class="subtitle">Enter your email and password to continue.</p>
  {err_html}
  <form method="POST" action="/auth/login?next={next_esc}" id="login-form">
    <label>Email</label>
    <input type="email" name="email" required autofocus placeholder="you@example.com">
    <label>Password</label>
    <input type="password" name="password" required placeholder="Password">
    <button type="submit" class="btn" id="login-btn">Sign In</button>
  </form>
  <script>
    document.getElementById('login-form').addEventListener('submit', function() {{
      document.getElementById('login-btn').disabled = true;
      document.getElementById('login-btn').textContent = 'Signing in\u2026';
    }});
  </script>
</div>
</body></html>"""


def _accept_invite_page(email: str, token: str, error: str = "") -> str:
    err_html = f'<div class="error">{_html.escape(error)}</div>' if error else ""
    email_esc = _html.escape(email)
    token_esc = _html.escape(token)
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Set Your Password</title>{_PAGE_STYLE}</head>
<body>
<div class="card">
  <h1>Set Your Password</h1>
  <p class="subtitle">Complete your account setup for <strong>{email_esc}</strong>.</p>
  {err_html}
  <form method="POST" action="/auth/accept-invite">
    <input type="hidden" name="token" value="{token_esc}">
    <label>Email</label>
    <input type="email" value="{email_esc}" readonly style="opacity:0.6">
    <label>Password</label>
    <input type="password" name="password" required autofocus placeholder="Min 12 characters">
    <label>Confirm Password</label>
    <input type="password" name="password2" required placeholder="Repeat password">
    <button type="submit" class="btn">Activate Account</button>
  </form>
</div>
</body></html>"""


def _users_page(current_user: dict, users: list, invites: list, invite_url: str = "") -> str:
    role = current_user["role"]
    is_owner = role == "owner"

    # User rows
    user_rows = ""
    for u in users:
        login_ts = u.get("last_login_at")
        login_str = time.strftime("%Y-%m-%d", time.gmtime(login_ts)) if login_ts else "Never"
        badge = f'<span class="badge badge-{u["role"]}">{u["role"]}</span>'
        del_btn = ""
        if is_owner and u["id"] != current_user["id"]:
            del_btn = f"""<button class="action-btn" onclick="deleteUser('{_html.escape(u['id'])}','{_html.escape(u['email'])}')">Delete</button>"""
        user_rows += f"""<tr>
          <td>{_html.escape(u['email'])}</td>
          <td>{badge}</td>
          <td>{login_str}</td>
          <td>{del_btn}</td>
        </tr>"""

    # Invite rows
    invite_rows = ""
    for inv in invites:
        exp_str = time.strftime("%Y-%m-%d", time.gmtime(inv["expires_at"]))
        badge = f'<span class="badge badge-{inv["role"]}">{inv["role"]}</span>'
        revoke_btn = ""
        if is_owner or inv["created_by"] == current_user["id"]:
            revoke_btn = f"""<button class="action-btn" onclick="revokeInvite('{_html.escape(inv['id'])}','{_html.escape(inv['email'])}')">Revoke</button>"""
        invite_rows += f"""<tr>
          <td>{_html.escape(inv['email'])}</td>
          <td>{badge}</td>
          <td>{exp_str}</td>
          <td>{revoke_btn}</td>
        </tr>"""

    invite_url_html = ""
    if invite_url:
        invite_url_html = f"""
<div class="invite-box" id="invite-url-box">{_html.escape(invite_url)}</div>
<button class="copy-btn" onclick="copyInvite()">Copy invite link</button>
<script>
function copyInvite() {{
  navigator.clipboard.writeText({json.dumps(invite_url)}).then(function() {{
    document.querySelector('.copy-btn').textContent = 'Copied!';
    setTimeout(function(){{document.querySelector('.copy-btn').textContent='Copy invite link';}}, 2000);
  }});
}}
</script>"""

    role_options = '<option value="admin">Admin</option>'
    if is_owner:
        role_options = '<option value="owner">Owner</option>' + role_options

    invite_section = f"""
<h2 style="font-size:1rem;margin-top:2rem;margin-bottom:0.5rem">Invite User</h2>
<form method="POST" action="/users/invite" id="invite-form">
  <div class="flex-row">
    <div class="flex-1">
      <label>Email</label>
      <input type="email" name="email" required placeholder="invitee@example.com">
    </div>
    <div>
      <label>Role</label>
      <select name="role">{role_options}</select>
    </div>
  </div>
  <button type="submit" class="btn" style="margin-bottom:0">Generate Invite Link</button>
</form>
{invite_url_html}
"""

    invite_table = ""
    if invites:
        invite_table = f"""
<h2 style="font-size:1rem;margin-top:2rem;margin-bottom:0.5rem">Pending Invites</h2>
<table>
  <thead><tr><th>Email</th><th>Role</th><th>Expires</th><th></th></tr></thead>
  <tbody>{invite_rows}</tbody>
</table>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>User Management</title>{_PAGE_STYLE}</head>
<body>
<div class="card wide">
  <h1>User Management
    <span class="logout-link">
      <a href="/">Home</a> &middot;
      <a href="#" onclick="doLogout()">Sign out</a>
    </span>
  </h1>
  <p class="subtitle">Signed in as <strong>{_html.escape(current_user['email'])}</strong>
    <span class="badge badge-{role}">{role}</span>
  </p>

  <h2 style="font-size:1rem;margin-top:1rem;margin-bottom:0.5rem">Users</h2>
  <table>
    <thead><tr><th>Email</th><th>Role</th><th>Last Login</th><th></th></tr></thead>
    <tbody>{user_rows}</tbody>
  </table>

  {invite_section}
  {invite_table}
</div>
<script>
function doLogout() {{
  fetch('/auth/logout', {{method:'POST', headers:{{'X-Requested-With':'XMLHttpRequest'}}}})
    .then(function() {{ window.location = '/login'; }});
}}
function deleteUser(id, email) {{
  if (!confirm('Delete user ' + email + '?')) return;
  fetch('/users/' + id, {{method:'DELETE', headers:{{'X-Requested-With':'XMLHttpRequest'}}}})
    .then(function(r) {{ return r.json(); }})
    .then(function(d) {{
      if (d.ok) window.location.reload();
      else alert(d.error || 'Delete failed');
    }});
}}
function revokeInvite(id, email) {{
  if (!confirm('Revoke invite for ' + email + '?')) return;
  fetch('/users/invite/' + id, {{method:'DELETE', headers:{{'X-Requested-With':'XMLHttpRequest'}}}})
    .then(function(r) {{ return r.json(); }})
    .then(function(d) {{
      if (d.ok) window.location.reload();
      else alert(d.error || 'Revoke failed');
    }});
}}
</script>
</body></html>"""


# ── GET handlers ──────────────────────────────────────────────────────────────

def handle_get_setup(handler) -> bool:
    """GET /setup — show setup page or redirect to /login if users exist."""
    from api.userauth import user_count
    if user_count() > 0:
        return _redirect(handler, "/login")
    return _html_page(handler, _setup_page())


def handle_get_invite(handler, token: str) -> bool:
    """GET /invite/<token> — show accept-invite page."""
    from api.userauth import get_invite_by_token
    import time as _time
    now = int(_time.time())
    invite = get_invite_by_token(token)
    if not invite:
        return _html_page(handler, _error_page("Invalid or unknown invite link."), status=404)
    if invite["used_at"] is not None:
        return _html_page(handler, _error_page("This invite link has already been used."), status=410)
    if invite["expires_at"] <= now:
        return _html_page(handler, _error_page("This invite link has expired."), status=410)
    return _html_page(handler, _accept_invite_page(invite["email"], token))


def handle_get_login(handler) -> bool:
    """GET /login — show the email+password login form (new per-user auth)."""
    import urllib.parse as _up
    raw_qs = handler.path.split("?", 1)[1] if "?" in handler.path else ""
    qs = _up.parse_qs(raw_qs)
    next_url = qs.get("next", ["/"])[0]
    try:
        parsed_next = _up.urlparse(_up.unquote(next_url))
        if parsed_next.netloc:
            next_url = "/"
    except Exception:
        next_url = "/"
    if not next_url or not next_url.startswith("/"):
        next_url = "/"
    return _html_page(handler, _login_page(next_url=next_url))


def handle_get_users_page(handler) -> bool:
    """GET /users/manage — HTML user management page."""
    user = _get_current_user(handler)
    if not user:
        return _redirect(handler, "/login?next=/users/manage")
    from api.userauth import list_users, list_invites
    users = list_users()
    invites = list_invites(viewer_user_id=user["id"], viewer_role=user["role"])
    return _html_page(handler, _users_page(user, users, invites))


def handle_get_auth_me(handler) -> bool:
    """GET /auth/me — return current user info as JSON."""
    user = _get_current_user(handler)
    if not user:
        return _json_response(handler, {"error": "Not authenticated"}, status=401)
    safe = {k: v for k, v in user.items() if k != "password_hash"}
    return _json_response(handler, {"user": safe})


def handle_get_users_api(handler) -> bool:
    """GET /api/users — return user list as JSON."""
    user = _get_current_user(handler)
    if not user:
        return _json_response(handler, {"error": "Authentication required"}, status=401)
    from api.userauth import list_users, list_invites
    users = list_users()
    invites = list_invites(viewer_user_id=user["id"], viewer_role=user["role"])
    # Strip password_hash
    safe_users = [{k: v for k, v in u.items() if k != "password_hash"} for u in users]
    return _json_response(handler, {"users": safe_users, "invites": invites})


# ── POST handlers ─────────────────────────────────────────────────────────────

def handle_post_setup(handler, body: dict) -> bool:
    """POST /auth/setup — create the initial Owner account."""
    from api.userauth import user_count, create_user, create_session
    import sqlite3

    if user_count() > 0:
        return _redirect(handler, "/login")

    email = (body.get("email") or "").strip()
    password = body.get("password") or ""
    password2 = body.get("password2") or ""

    if not email:
        return _html_page(handler, _setup_page("Email is required."), status=400)
    if password != password2:
        return _html_page(handler, _setup_page("Passwords do not match."), status=400)

    try:
        user = create_user(email, password, "owner")
    except ValueError as e:
        return _html_page(handler, _setup_page(str(e)), status=400)
    except sqlite3.IntegrityError:
        return _html_page(handler, _setup_page("A user with that email already exists."), status=409)

    token = create_session(user["id"])
    handler.send_response(302)
    handler.send_header("Location", "/")
    handler.send_header("Content-Length", "0")
    _set_session_cookie(handler, token)
    handler.end_headers()
    return True


def handle_post_login(handler, body: dict, query: dict) -> bool:
    """POST /auth/login — validate credentials and set session cookie."""
    from api.userauth import RateLimitedError, attempt_login, create_session

    email = (body.get("email") or "").strip()
    password = body.get("password") or ""

    # Determine redirect target
    import urllib.parse
    next_url = query.get("next", ["/"])[0]
    # Validate next is a relative path
    try:
        parsed_next = urllib.parse.urlparse(urllib.parse.unquote(next_url))
        if parsed_next.netloc:
            next_url = "/"
    except Exception:
        next_url = "/"
    if not next_url or not next_url.startswith("/"):
        next_url = "/"

    if not email:
        return _html_page(handler, _login_page("Invalid email or password.", next_url), status=401)

    client_ip = _get_client_ip(handler)

    try:
        user = attempt_login(email, password, ip=client_ip)
    except RateLimitedError as exc:
        retry_after = exc.retry_after or 30
        msg = (
            f"Too many login attempts. Please wait {retry_after} second"
            f"{'s' if retry_after != 1 else ''} before trying again."
        )
        handler.send_header("Retry-After", str(retry_after))
        return _html_page(handler, _login_page(msg, next_url), status=429)
    except ValueError:
        return _html_page(handler, _login_page("Invalid email or password.", next_url), status=401)

    token = create_session(user["id"])
    handler.send_response(302)
    handler.send_header("Location", next_url)
    handler.send_header("Content-Length", "0")
    _set_session_cookie(handler, token)
    handler.end_headers()
    return True


def handle_post_logout(handler) -> bool:
    """POST /auth/logout — invalidate session and clear cookie."""
    from api.userauth import delete_session

    token = _parse_user_session_cookie(handler)
    if token:
        delete_session(token)

    # Check if it's an API request (XHR) or form submit
    is_xhr = handler.headers.get("X-Requested-With") == "XMLHttpRequest"
    if is_xhr:
        handler.send_response(200)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", "10")
        _clear_session_cookie(handler)
        handler.end_headers()
        handler.wfile.write(b'{"ok":true}')
        return True

    handler.send_response(302)
    handler.send_header("Location", "/login")
    handler.send_header("Content-Length", "0")
    _clear_session_cookie(handler)
    handler.end_headers()
    return True


def handle_post_invite(handler, body: dict, query: dict) -> bool:
    """POST /users/invite — generate invite link. Enforces role matrix."""
    from api.userauth import create_invite

    user = _get_current_user(handler)
    if not user:
        return _redirect(handler, "/login?next=/users/manage")

    email = (body.get("email") or "").strip()
    role = (body.get("role") or "").strip().lower()

    # Role matrix: admins cannot invite owners
    if user["role"] == "admin" and role == "owner":
        is_xhr = handler.headers.get("X-Requested-With") == "XMLHttpRequest"
        if is_xhr:
            return _json_response(handler, {"error": "Admins cannot invite Owners."}, status=403)
        from api.userauth import list_users, list_invites
        users = list_users()
        invites = list_invites(viewer_user_id=user["id"], viewer_role=user["role"])
        return _html_page(
            handler,
            _users_page(user, users, invites),
            status=403
        )

    try:
        invite = create_invite(email, role, user["id"])
    except ValueError as e:
        is_xhr = handler.headers.get("X-Requested-With") == "XMLHttpRequest"
        if is_xhr:
            return _json_response(handler, {"error": str(e)}, status=400)
        from api.userauth import list_users, list_invites
        users = list_users()
        invites = list_invites(viewer_user_id=user["id"], viewer_role=user["role"])
        return _html_page(handler, _users_page(user, users, invites), status=400)

    # Build the invite URL from the Host header
    host = handler.headers.get("Host", "localhost:8787")
    proto = "https" if _is_secure(handler) else "http"
    invite_url = f"{proto}://{host}/invite/{invite['token']}"

    is_xhr = handler.headers.get("X-Requested-With") == "XMLHttpRequest"
    if is_xhr:
        return _json_response(handler, {"ok": True, "invite_url": invite_url, "invite": invite})

    # Redirect back to users page with invite URL shown
    from api.userauth import list_users, list_invites
    users = list_users()
    invites = list_invites(viewer_user_id=user["id"], viewer_role=user["role"])
    return _html_page(handler, _users_page(user, users, invites, invite_url=invite_url))


def handle_post_accept_invite(handler, body: dict) -> bool:
    """POST /auth/accept-invite — redeem invite token and create user."""
    from api.userauth import redeem_invite, create_session, get_invite_by_token

    token = (body.get("token") or "").strip()
    password = body.get("password") or ""
    password2 = body.get("password2") or ""

    if not token:
        return _html_page(handler, _error_page("Missing invite token."), status=400)

    invite = get_invite_by_token(token)
    if not invite:
        return _html_page(handler, _error_page("Invalid or unknown invite link."), status=404)

    if password != password2:
        return _html_page(
            handler,
            _accept_invite_page(invite["email"], token, "Passwords do not match."),
            status=400,
        )

    try:
        user = redeem_invite(token, password)
    except ValueError as e:
        email = invite["email"] if invite else ""
        return _html_page(handler, _accept_invite_page(email, token, str(e)), status=400)

    session_token = create_session(user["id"])
    handler.send_response(302)
    handler.send_header("Location", "/")
    handler.send_header("Content-Length", "0")
    _set_session_cookie(handler, session_token)
    handler.end_headers()
    return True


# ── DELETE handlers ───────────────────────────────────────────────────────────

def handle_delete_user(handler, user_id: str) -> bool:
    """DELETE /users/<id> — delete user (owner-only)."""
    from api.userauth import delete_user

    current = _get_current_user(handler)
    if not current:
        return _json_response(handler, {"error": "Authentication required"}, status=401)
    if current["role"] != "owner":
        return _json_response(handler, {"error": "Owner role required."}, status=403)
    if current["id"] == user_id:
        return _json_response(handler, {"error": "Cannot delete your own account."}, status=400)

    try:
        delete_user(user_id)
    except KeyError:
        return _json_response(handler, {"error": "User not found."}, status=404)
    except ValueError as e:
        return _json_response(handler, {"error": str(e)}, status=409)

    return _json_response(handler, {"ok": True})


def handle_delete_invite(handler, invite_id: str) -> bool:
    """DELETE /users/invite/<id> — revoke a pending invite."""
    from api.userauth import revoke_invite

    current = _get_current_user(handler)
    if not current:
        return _json_response(handler, {"error": "Authentication required"}, status=401)

    try:
        revoke_invite(invite_id, current["id"], current["role"])
    except ValueError as e:
        return _json_response(handler, {"error": str(e)}, status=400)

    return _json_response(handler, {"ok": True})


def handle_post_change_password(handler, body: dict) -> bool:
    """POST /auth/change-password — change the current user's password."""
    from api.userauth import change_password

    current = _get_current_user(handler)
    if not current:
        return _json_response(handler, {"error": "Authentication required"}, status=401)

    current_password = body.get("current_password") or ""
    new_password = body.get("new_password") or ""

    if not current_password or not new_password:
        return _json_response(handler, {"error": "current_password and new_password are required."}, status=400)

    # Get the current session token to keep alive
    keep_token = _parse_user_session_cookie(handler) or ""

    try:
        change_password(current["id"], current_password, new_password, keep_token)
    except ValueError as e:
        msg = str(e)
        if msg == "current_password":
            return _json_response(handler, {"error": "Current password is incorrect."}, status=401)
        return _json_response(handler, {"error": msg}, status=400)
    except KeyError:
        return _json_response(handler, {"error": "User not found."}, status=404)

    return _json_response(handler, {"ok": True})


def handle_post_reset_password(handler, user_id: str) -> bool:
    """POST /api/users/<id>/reset-password — Owner-only: generate a temp password."""
    from api.userauth import reset_user_password

    current = _get_current_user(handler)
    if not current:
        return _json_response(handler, {"error": "Authentication required"}, status=401)

    if current["role"] != "owner":
        return _json_response(handler, {"error": "Owner role required."}, status=403)

    # Owners cannot reset their own password via this endpoint (use change-password)
    if current["id"] == user_id:
        return _json_response(handler, {"error": "Use the change-password form to update your own password."}, status=400)

    try:
        result = reset_user_password(user_id, current["role"])
    except PermissionError as e:
        return _json_response(handler, {"error": str(e)}, status=403)
    except KeyError:
        return _json_response(handler, {"error": "User not found."}, status=404)

    return _json_response(handler, {"ok": True, "temp_password": result["temp_password"], "expires_at": result["expires_at"]})


def handle_post_unlock_login(handler, user_id: str) -> bool:
    """POST /api/users/<id>/unlock-login — Owner-only: clear login rate-limit lockout."""
    from api.userauth import get_user_by_id, unlock_login_attempts

    current = _get_current_user(handler)
    if not current:
        return _json_response(handler, {"error": "Authentication required"}, status=401)

    if current["role"] != "owner":
        return _json_response(handler, {"error": "Owner role required."}, status=403)

    target = get_user_by_id(user_id)
    if not target:
        return _json_response(handler, {"error": "User not found."}, status=404)

    unlock_login_attempts(target["email"])
    return _json_response(handler, {"ok": True, "email": target["email"]})


# ── Utility ───────────────────────────────────────────────────────────────────

def _error_page(message: str) -> str:
    msg_esc = _html.escape(message)
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Error</title>{_PAGE_STYLE}</head>
<body>
<div class="card">
  <h1>Error</h1>
  <p class="subtitle">{msg_esc}</p>
  <p><a href="/login">Go to login</a></p>
</div>
</body></html>"""


# ── Auth gate (used by api/auth.py integration) ────────────────────────────────

def userauth_check_auth(handler, parsed) -> bool:
    """
    Gate for per-user auth system.
    Returns True if the request is allowed to proceed.
    On failure, sends the redirect/401 response and returns False.
    """
    from api.userauth import user_count, is_userauth_active

    path = parsed.path

    # Always public: static files, health, favicon
    if (
        path.startswith("/static/")
        or path.startswith("/session/static/")
        or path in ("/health", "/favicon.ico", "/sw.js", "/manifest.json",
                    "/manifest.webmanifest", "/session/manifest.json",
                    "/session/manifest.webmanifest")
    ):
        return True

    # Bootstrap: if zero users exist, redirect everything to /setup
    # (except /setup and /auth/setup themselves)
    if path not in ("/setup", "/auth/setup"):
        try:
            if user_count() == 0:
                # Zero users — send them to setup
                if not path.startswith("/api/"):
                    handler.send_response(302)
                    handler.send_header("Location", "/setup")
                    handler.send_header("Content-Length", "0")
                    handler.end_headers()
                    return False
                # API request with no users yet
                body = b'{"error":"Setup required"}'
                handler.send_response(503)
                handler.send_header("Content-Type", "application/json")
                handler.send_header("Content-Length", str(len(body)))
                handler.end_headers()
                handler.wfile.write(body)
                return False
        except Exception:
            pass

    # Setup page: only accessible when 0 users exist
    if path in ("/setup", "/auth/setup"):
        try:
            if user_count() > 0:
                if path == "/auth/setup":
                    handler.send_response(302)
                    handler.send_header("Location", "/login")
                    handler.send_header("Content-Length", "0")
                    handler.end_headers()
                    return False
                return True  # GET /setup handler will redirect itself
        except Exception:
            pass
        return True  # Allow setup page/endpoint

    # Login page and login endpoint are always public
    if path in ("/login", "/auth/login"):
        return True

    # Accept-invite page
    if path.startswith("/invite/") or path == "/auth/accept-invite":
        return True

    # Check session
    user = _get_current_user(handler)
    if user:
        return True

    # Not authenticated
    if path.startswith("/api/") or path.startswith("/auth/"):
        body = b'{"error":"Authentication required"}'
        handler.send_response(401)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)
        return False

    # Page redirect
    import urllib.parse as _urlparse
    _path_with_query = path or "/"
    if parsed.query:
        _path_with_query += "?" + parsed.query
    _next = _urlparse.quote(_path_with_query, safe="/")
    handler.send_response(302)
    handler.send_header("Location", "/login?next=" + _next)
    handler.send_header("Content-Length", "0")
    handler.end_headers()
    return False
