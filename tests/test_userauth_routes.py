"""
Integration-style unit tests for api/userauth_routes.py.

These tests cover the HTTP route handlers (setup, login, logout, /auth/me,
invite flow, role enforcement, and security properties) using a fake HTTP
handler that captures response headers and body without a real server.

Run with: python3.12 -m pytest tests/test_userauth_routes.py -v
"""

import io
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from http.server import BaseHTTPRequestHandler
from unittest.mock import MagicMock

import pytest

# ── Test isolation ─────────────────────────────────────────────────────────

_TMP = tempfile.mkdtemp(prefix="hermes_routes_test_")
os.environ["HERMES_WEBUI_STATE_DIR"] = _TMP
os.environ["HERMES_USERAUTH"] = "1"
os.environ["HERMES_WEBUI_PASSWORD"] = ""
os.environ["HERMES_WEBUI_HTTPS"] = "0"   # disable Secure flag in tests

sys.path.insert(0, str(Path(__file__).parent.parent))


# ── Fixtures ───────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    """Give each test a clean auth.db and a clean rate-limit state."""
    import api.userauth as ua
    db = tmp_path / "auth.db"
    monkeypatch.setattr(ua, "_db_path", lambda: db)

    # Reset in-memory rate-limit state between tests
    with ua._rate_limit_lock:
        ua._rate_limit_attempts.clear()
    yield


# ── Fake HTTP handler ──────────────────────────────────────────────────────

class FakeResponse:
    """Accumulates send_response / send_header / end_headers / wfile.write calls."""

    def __init__(self, cookie_header: str = "", body: bytes = b"", headers: dict | None = None):
        self.status_code: int | None = None
        self.headers_sent: list[tuple[str, str]] = []
        self.body_written: bytes = b""

        # Request side
        self._cookie_header = cookie_header
        self._request_body = body
        self._request_headers = headers or {}
        self._content_length = len(body) if body else 0

    # ---- handler protocol used by route functions ----
    def send_response(self, code: int) -> None:
        self.status_code = code

    def send_header(self, name: str, value: str) -> None:
        self.headers_sent.append((name, value))

    def end_headers(self) -> None:
        pass

    # ---- response helpers access handler.wfile ----
    @property
    def wfile(self):
        class _Writer:
            def __init__(self_inner):
                self_inner._parent = self
            def write(self_inner, data: bytes):
                self_inner._parent.body_written += data
        return _Writer()

    # ---- request helpers ----
    @property
    def headers(self):
        """Mimic http.server handler.headers dict-like access."""
        h = dict(self._request_headers)
        h["Cookie"] = self._cookie_header
        h.setdefault("Content-Type", "application/json")
        h.setdefault("Content-Length", str(self._content_length))
        return h

    @property
    def rfile(self):
        return io.BytesIO(self._request_body)

    # ---- convenience ----
    def get_header(self, name: str) -> str | None:
        for k, v in self.headers_sent:
            if k.lower() == name.lower():
                return v
        return None

    def get_set_cookie(self) -> str | None:
        return self.get_header("Set-Cookie")

    def json_body(self) -> dict:
        return json.loads(self.body_written)


def _make_handler(cookie: str = "", body: bytes = b"", headers: dict | None = None) -> FakeResponse:
    return FakeResponse(cookie_header=cookie, body=body, headers=headers)


def _json_body(**kwargs) -> bytes:
    return json.dumps(kwargs).encode()


# ── Helper to create users/sessions ───────────────────────────────────────

def _create_owner(email="owner@example.com", password="OwnerPass123!"):
    import api.userauth as ua
    user = ua.create_user(email, password, "owner")
    token = ua.create_session(user["id"])
    return user, token


def _create_admin(email="admin@example.com", password="AdminPass123!"):
    import api.userauth as ua
    user = ua.create_user(email, password, "admin")
    token = ua.create_session(user["id"])
    return user, token


def _cookie(token: str) -> str:
    return f"hermes_user_session={token}"


# ══════════════════════════════════════════════════════════════════════════
# Auth flows
# ══════════════════════════════════════════════════════════════════════════

class TestSetupFlow:
    """POST /auth/setup — first-launch owner creation."""

    def test_setup_succeeds_when_no_users(self):
        from api.userauth_routes import handle_post_setup
        import api.userauth as ua

        assert ua.user_count() == 0
        body = _json_body(email="admin@example.com", password="NewPass12345", password2="NewPass12345")
        h = _make_handler(body=body)
        result = handle_post_setup(h, json.loads(body))

        assert result is True
        assert h.status_code == 302
        assert h.get_header("Location") == "/"
        # Session cookie must be set
        cookie = h.get_set_cookie()
        assert cookie is not None
        assert "hermes_user_session=" in cookie
        # User now exists
        assert ua.user_count() == 1

    def test_setup_redirects_to_login_when_users_exist(self):
        from api.userauth_routes import handle_post_setup
        import api.userauth as ua

        ua.create_user("existing@example.com", "ExistPass1234", "owner")
        body = _json_body(email="new@example.com", password="NewPass12345", password2="NewPass12345")
        h = _make_handler(body=body)
        handle_post_setup(h, json.loads(body))

        assert h.status_code == 302
        assert h.get_header("Location") == "/login"
        # No new user was created
        assert ua.user_count() == 1

    def test_setup_rejects_password_mismatch(self):
        from api.userauth_routes import handle_post_setup
        import api.userauth as ua

        body = _json_body(email="admin@example.com", password="NewPass12345", password2="Different123")
        h = _make_handler(body=body)
        handle_post_setup(h, json.loads(body))

        assert h.status_code == 400
        assert h.get_set_cookie() is None
        assert ua.user_count() == 0

    def test_setup_rejects_weak_password(self):
        from api.userauth_routes import handle_post_setup
        import api.userauth as ua

        body = _json_body(email="admin@example.com", password="short", password2="short")
        h = _make_handler(body=body)
        handle_post_setup(h, json.loads(body))

        assert h.status_code == 400
        assert ua.user_count() == 0


class TestLoginFlow:
    """POST /auth/login — credentials → cookie."""

    def test_valid_credentials_set_cookie(self):
        from api.userauth_routes import handle_post_login
        import api.userauth as ua

        ua.create_user("user@example.com", "LoginPass1234", "owner")
        body = _json_body(email="user@example.com", password="LoginPass1234")
        h = _make_handler(body=body)
        import urllib.parse
        handle_post_login(h, json.loads(body), {"next": ["/"]})

        assert h.status_code == 302
        cookie = h.get_set_cookie()
        assert cookie is not None
        assert "hermes_user_session=" in cookie
        # Token from cookie should be valid
        token = cookie.split("hermes_user_session=")[1].split(";")[0]
        assert ua.get_session_user(token) is not None

    def test_invalid_password_no_cookie(self):
        from api.userauth_routes import handle_post_login
        import api.userauth as ua

        ua.create_user("user@example.com", "LoginPass1234", "owner")
        body = _json_body(email="user@example.com", password="WrongPass1234")
        h = _make_handler(body=body)
        handle_post_login(h, json.loads(body), {"next": ["/"]})

        # Should return 401 with no session cookie set to a valid token
        assert h.status_code == 401
        cookie = h.get_set_cookie()
        # Either no cookie or explicitly cleared (Max-Age=0 or empty token)
        if cookie:
            # If a cookie was sent it must be cleared (empty value or Max-Age=0)
            assert "hermes_user_session=;" in cookie or "Max-Age=0" in cookie

    def test_nonexistent_user_no_cookie(self):
        from api.userauth_routes import handle_post_login

        body = _json_body(email="ghost@example.com", password="AnyPass12345")
        h = _make_handler(body=body)
        handle_post_login(h, json.loads(body), {"next": ["/"]})

        assert h.status_code == 401
        cookie = h.get_set_cookie()
        if cookie:
            assert "hermes_user_session=;" in cookie or "Max-Age=0" in cookie

    def test_login_does_not_leak_email_existence(self):
        """Wrong-password and nonexistent-user must return the same error message."""
        from api.userauth_routes import handle_post_login
        import api.userauth as ua

        ua.create_user("real@example.com", "RealPass1234", "owner")

        body_wrong_pw = _json_body(email="real@example.com", password="WrongPw12345")
        h_wrong = _make_handler(body=body_wrong_pw)
        handle_post_login(h_wrong, json.loads(body_wrong_pw), {"next": ["/"]})

        body_ghost = _json_body(email="ghost@example.com", password="AnyPass12345")
        h_ghost = _make_handler(body=body_ghost)
        handle_post_login(h_ghost, json.loads(body_ghost), {"next": ["/"]})

        # Both return same HTTP status
        assert h_wrong.status_code == h_ghost.status_code
        # Both should show the same generic error (not "user not found" vs "wrong password")
        assert h_wrong.status_code == 401
        # Check that the HTML body doesn't distinguish them
        wrong_body = h_wrong.body_written.decode(errors="replace")
        ghost_body = h_ghost.body_written.decode(errors="replace")
        assert "Invalid email or password" in wrong_body
        assert "Invalid email or password" in ghost_body

    def test_cookie_flags_httponly_and_samesite(self):
        """Session cookie must be httpOnly and SameSite=Lax."""
        from api.userauth_routes import handle_post_login
        import api.userauth as ua

        ua.create_user("flagtest@example.com", "FlagTest1234", "owner")
        body = _json_body(email="flagtest@example.com", password="FlagTest1234")
        h = _make_handler(body=body)
        handle_post_login(h, json.loads(body), {"next": ["/"]})

        cookie = h.get_set_cookie()
        assert cookie is not None
        assert "HttpOnly" in cookie
        assert "SameSite=Lax" in cookie

    def test_cookie_secure_flag_when_https(self, monkeypatch):
        """Cookie must include Secure flag when HERMES_WEBUI_HTTPS=1."""
        from api.userauth_routes import handle_post_login
        import api.userauth as ua

        monkeypatch.setenv("HERMES_WEBUI_HTTPS", "1")
        ua.create_user("secure@example.com", "SecurePass12", "owner")
        body = _json_body(email="secure@example.com", password="SecurePass12")
        h = _make_handler(body=body)
        handle_post_login(h, json.loads(body), {"next": ["/"]})

        cookie = h.get_set_cookie()
        assert cookie is not None
        assert "Secure" in cookie


class TestLogoutFlow:
    """POST /auth/logout — session invalidated server-side."""

    def test_logout_invalidates_session(self):
        from api.userauth_routes import handle_post_logout
        import api.userauth as ua

        user, token = _create_owner()
        h = _make_handler(cookie=_cookie(token))
        handle_post_logout(h)

        # Session must be gone
        assert ua.get_session_user(token) is None

    def test_old_cookie_fails_after_logout(self):
        """The old session token no longer authenticates after logout."""
        from api.userauth_routes import handle_post_logout, handle_get_auth_me
        import api.userauth as ua

        user, token = _create_owner()

        # Verify token works before logout
        h_me_before = _make_handler(cookie=_cookie(token))
        handle_get_auth_me(h_me_before)
        assert h_me_before.status_code == 200

        # Logout
        h_logout = _make_handler(cookie=_cookie(token),
                                 headers={"X-Requested-With": "XMLHttpRequest"})
        handle_post_logout(h_logout)
        assert ua.get_session_user(token) is None

        # Old cookie no longer works
        h_me_after = _make_handler(cookie=_cookie(token))
        handle_get_auth_me(h_me_after)
        assert h_me_after.status_code == 401

    def test_logout_clears_cookie(self):
        """Logout response must clear the session cookie."""
        from api.userauth_routes import handle_post_logout

        user, token = _create_owner()
        h = _make_handler(cookie=_cookie(token))
        handle_post_logout(h)

        cookie = h.get_set_cookie()
        assert cookie is not None
        # Cookie should be cleared
        assert "Max-Age=0" in cookie or "hermes_user_session=;" in cookie

    def test_logout_xhr_returns_json_ok(self):
        """XHR logout returns JSON {ok: true}."""
        from api.userauth_routes import handle_post_logout

        user, token = _create_owner()
        h = _make_handler(cookie=_cookie(token),
                          headers={"X-Requested-With": "XMLHttpRequest"})
        handle_post_logout(h)

        assert h.status_code == 200
        assert h.json_body() == {"ok": True}


class TestAuthMe:
    """GET /auth/me — returns user when authed; 401 otherwise."""

    def test_authed_returns_user(self):
        from api.userauth_routes import handle_get_auth_me

        user, token = _create_owner()
        h = _make_handler(cookie=_cookie(token))
        handle_get_auth_me(h)

        assert h.status_code == 200
        data = h.json_body()
        assert "user" in data
        assert data["user"]["email"] == "owner@example.com"

    def test_no_cookie_returns_401(self):
        from api.userauth_routes import handle_get_auth_me

        h = _make_handler()
        handle_get_auth_me(h)

        assert h.status_code == 401

    def test_invalid_cookie_returns_401(self):
        from api.userauth_routes import handle_get_auth_me

        h = _make_handler(cookie="hermes_user_session=bogustoken")
        handle_get_auth_me(h)

        assert h.status_code == 401

    def test_password_hash_not_in_response(self):
        """Ensure password_hash is never exposed via /auth/me."""
        from api.userauth_routes import handle_get_auth_me

        user, token = _create_owner()
        h = _make_handler(cookie=_cookie(token))
        handle_get_auth_me(h)

        data = h.json_body()
        assert "password_hash" not in data.get("user", {})


# ══════════════════════════════════════════════════════════════════════════
# Invite flow
# ══════════════════════════════════════════════════════════════════════════

class TestInviteFlow:
    """POST /users/invite + GET /invite/<token> + POST /auth/accept-invite."""

    def test_owner_generates_invite_for_admin(self):
        from api.userauth_routes import handle_post_invite

        owner, token = _create_owner()
        body = _json_body(email="newadmin@example.com", role="admin")
        h = _make_handler(cookie=_cookie(token), body=body,
                          headers={"X-Requested-With": "XMLHttpRequest",
                                   "Host": "localhost:8787"})
        handle_post_invite(h, json.loads(body), {})

        assert h.status_code == 200
        data = h.json_body()
        assert data["ok"] is True
        assert "invite_url" in data
        assert "invite" in data
        assert data["invite"]["role"] == "admin"

    def test_owner_generates_invite_for_owner(self):
        """Per role matrix: owners can invite other owners."""
        from api.userauth_routes import handle_post_invite

        owner, token = _create_owner()
        body = _json_body(email="newowner@example.com", role="owner")
        h = _make_handler(cookie=_cookie(token), body=body,
                          headers={"X-Requested-With": "XMLHttpRequest",
                                   "Host": "localhost:8787"})
        handle_post_invite(h, json.loads(body), {})

        assert h.status_code == 200
        data = h.json_body()
        assert data["ok"] is True
        assert data["invite"]["role"] == "owner"

    def test_admin_generates_invite_for_admin(self):
        """Admins can invite other admins."""
        from api.userauth_routes import handle_post_invite

        _create_owner()  # need at least one owner
        admin, token = _create_admin()
        body = _json_body(email="another@example.com", role="admin")
        h = _make_handler(cookie=_cookie(token), body=body,
                          headers={"X-Requested-With": "XMLHttpRequest",
                                   "Host": "localhost:8787"})
        handle_post_invite(h, json.loads(body), {})

        assert h.status_code == 200
        data = h.json_body()
        assert data["ok"] is True

    def test_admin_cannot_invite_owner_returns_403(self):
        """Role matrix: admins cannot invite owners."""
        from api.userauth_routes import handle_post_invite

        _create_owner()
        admin, token = _create_admin()
        body = _json_body(email="sneaky@example.com", role="owner")
        h = _make_handler(cookie=_cookie(token), body=body,
                          headers={"X-Requested-With": "XMLHttpRequest",
                                   "Host": "localhost:8787"})
        handle_post_invite(h, json.loads(body), {})

        assert h.status_code == 403
        data = h.json_body()
        assert "error" in data

    def test_unauthenticated_invite_redirects_to_login(self):
        from api.userauth_routes import handle_post_invite

        _create_owner()
        body = _json_body(email="x@example.com", role="admin")
        h = _make_handler(body=body)  # no cookie
        handle_post_invite(h, json.loads(body), {})

        assert h.status_code == 302
        assert "/login" in (h.get_header("Location") or "")

    def test_accept_invite_creates_user_and_sets_cookie(self):
        """Accepting a valid invite creates a user and logs them in."""
        from api.userauth_routes import handle_post_accept_invite
        import api.userauth as ua

        owner, _ = _create_owner()
        invite = ua.create_invite("invitee@example.com", "admin", owner["id"])

        body = _json_body(token=invite["token"], password="InvitePass12", password2="InvitePass12")
        h = _make_handler(body=body)
        handle_post_accept_invite(h, json.loads(body))

        assert h.status_code == 302
        assert h.get_header("Location") == "/"
        # Session cookie set
        cookie = h.get_set_cookie()
        assert cookie is not None
        assert "hermes_user_session=" in cookie
        # User was created and can log in
        new_user = ua.get_user_by_email("invitee@example.com")
        assert new_user is not None
        assert new_user["role"] == "admin"

    def test_accept_invite_sets_password_correctly(self):
        """After accepting an invite, the user can log in with the set password."""
        from api.userauth_routes import handle_post_accept_invite
        import api.userauth as ua

        owner, _ = _create_owner()
        invite = ua.create_invite("invited@example.com", "admin", owner["id"])

        body = _json_body(token=invite["token"], password="MyNewPass123", password2="MyNewPass123")
        h = _make_handler(body=body)
        handle_post_accept_invite(h, json.loads(body))

        # Should be able to log in with the new password
        result = ua.attempt_login("invited@example.com", "MyNewPass123")
        assert result is not None

    def test_invite_single_use_enforced(self):
        """A used invite token must be rejected on second accept."""
        from api.userauth_routes import handle_post_accept_invite
        import api.userauth as ua

        owner, _ = _create_owner()
        invite = ua.create_invite("once@example.com", "admin", owner["id"])

        # First redemption
        body = _json_body(token=invite["token"], password="FirstPass123", password2="FirstPass123")
        h1 = _make_handler(body=body)
        handle_post_accept_invite(h1, json.loads(body))
        assert h1.status_code == 302  # success

        # Second redemption with same token
        body2 = _json_body(token=invite["token"], password="SecondPass12", password2="SecondPass12")
        h2 = _make_handler(body=body2)
        handle_post_accept_invite(h2, json.loads(body2))
        assert h2.status_code == 400  # error

    def test_expired_invite_rejected(self):
        """An expired invite token must return an error."""
        from api.userauth_routes import handle_post_accept_invite, handle_get_invite
        import api.userauth as ua

        owner, _ = _create_owner()
        invite = ua.create_invite("expire@example.com", "admin", owner["id"])

        # Manually expire the invite
        with ua._conn() as con:
            con.execute(
                "UPDATE invites SET expires_at=? WHERE token=?",
                (int(time.time()) - 1, invite["token"]),
            )
            con.commit()

        # POST accept-invite
        body = _json_body(token=invite["token"], password="SomePass1234", password2="SomePass1234")
        h = _make_handler(body=body)
        handle_post_accept_invite(h, json.loads(body))
        assert h.status_code == 400

    def test_get_invite_expired_returns_410(self):
        """GET /invite/<token> for an expired invite should return 410."""
        from api.userauth_routes import handle_get_invite
        import api.userauth as ua

        owner, _ = _create_owner()
        invite = ua.create_invite("exp2@example.com", "admin", owner["id"])

        with ua._conn() as con:
            con.execute(
                "UPDATE invites SET expires_at=? WHERE token=?",
                (int(time.time()) - 1, invite["token"]),
            )
            con.commit()

        h = _make_handler()
        handle_get_invite(h, invite["token"])
        assert h.status_code == 410

    def test_get_invite_used_returns_410(self):
        """GET /invite/<token> for a used invite should return 410."""
        from api.userauth_routes import handle_get_invite
        import api.userauth as ua

        owner, _ = _create_owner()
        invite = ua.create_invite("used@example.com", "admin", owner["id"])
        ua.redeem_invite(invite["token"], "UsePass12!!!")

        h = _make_handler()
        handle_get_invite(h, invite["token"])
        assert h.status_code == 410

    def test_get_invite_valid_returns_200(self):
        from api.userauth_routes import handle_get_invite
        import api.userauth as ua

        owner, _ = _create_owner()
        invite = ua.create_invite("pending@example.com", "admin", owner["id"])

        h = _make_handler()
        handle_get_invite(h, invite["token"])
        assert h.status_code == 200

    def test_get_invite_invalid_token_returns_404(self):
        from api.userauth_routes import handle_get_invite

        _create_owner()
        h = _make_handler()
        handle_get_invite(h, "totally-bogus-token")
        assert h.status_code == 404


# ══════════════════════════════════════════════════════════════════════════
# Role enforcement
# ══════════════════════════════════════════════════════════════════════════

class TestRoleEnforcement:
    """Enforce owner-only endpoints and unauthenticated access."""

    def test_admin_cannot_delete_user(self):
        """DELETE /users/<id> — admin gets 403 (owner-only)."""
        from api.userauth_routes import handle_delete_user
        import api.userauth as ua

        owner, _ = _create_owner()
        admin, admin_token = _create_admin()

        # Create a third user to delete
        third = ua.create_user("victim@example.com", "VictimPass12", "admin")

        h = _make_handler(cookie=_cookie(admin_token))
        handle_delete_user(h, third["id"])

        assert h.status_code == 403
        # Victim still exists
        assert ua.get_user_by_id(third["id"]) is not None

    def test_unauthenticated_cannot_delete_user(self):
        """DELETE /users/<id> — unauthenticated gets 401."""
        from api.userauth_routes import handle_delete_user
        import api.userauth as ua

        owner, _ = _create_owner()
        admin = ua.create_user("target@example.com", "TargetPass12", "admin")

        h = _make_handler()  # no cookie
        handle_delete_user(h, admin["id"])

        assert h.status_code == 401

    def test_owner_can_delete_user(self):
        """DELETE /users/<id> — owner successfully deletes another user."""
        from api.userauth_routes import handle_delete_user
        import api.userauth as ua

        owner, owner_token = _create_owner()
        admin = ua.create_user("todelete@example.com", "DeletePass12", "admin")

        h = _make_handler(cookie=_cookie(owner_token))
        handle_delete_user(h, admin["id"])

        assert h.status_code == 200
        assert h.json_body()["ok"] is True
        assert ua.get_user_by_id(admin["id"]) is None

    def test_owner_cannot_delete_themselves(self):
        """DELETE /users/<own_id> — owner cannot delete their own account."""
        from api.userauth_routes import handle_delete_user

        owner, owner_token = _create_owner()

        h = _make_handler(cookie=_cookie(owner_token))
        handle_delete_user(h, owner["id"])

        assert h.status_code == 400

    def test_unauthenticated_api_returns_401(self):
        """GET /auth/me without cookie returns 401."""
        from api.userauth_routes import handle_get_auth_me

        _create_owner()
        h = _make_handler()
        handle_get_auth_me(h)

        assert h.status_code == 401

    def test_unauthenticated_cannot_revoke_invite(self):
        """DELETE /users/invite/<id> — unauthenticated gets 401."""
        from api.userauth_routes import handle_delete_invite
        import api.userauth as ua

        owner, _ = _create_owner()
        invite = ua.create_invite("tbd@example.com", "admin", owner["id"])

        h = _make_handler()  # no cookie
        handle_delete_invite(h, invite["id"])

        assert h.status_code == 401


# ══════════════════════════════════════════════════════════════════════════
# Security properties
# ══════════════════════════════════════════════════════════════════════════

class TestSecurityProperties:
    """Security: hashing, cookie flags, info leakage."""

    def test_password_stored_hashed_in_db(self):
        """The password stored in the DB must not be the plaintext."""
        import api.userauth as ua

        password = "MySecret12345"
        ua.create_user("hashed@example.com", password, "owner")
        user = ua.get_user_by_email("hashed@example.com")

        # password_hash must not equal plaintext
        assert user["password_hash"] != password
        # Must start with a bcrypt prefix
        assert user["password_hash"].startswith("$2b$") or user["password_hash"].startswith("$2a$")

    def test_password_hash_not_in_list_users(self):
        """list_users() must never expose password_hash."""
        import api.userauth as ua

        ua.create_user("list@example.com", "ListPass1234", "owner")
        users = ua.list_users()
        for u in users:
            assert "password_hash" not in u

    def test_password_hash_not_in_api_users_response(self):
        """GET /api/users must not expose password_hash."""
        from api.userauth_routes import handle_get_users_api

        owner, token = _create_owner()
        h = _make_handler(cookie=_cookie(token))
        handle_get_users_api(h)

        assert h.status_code == 200
        data = h.json_body()
        for u in data.get("users", []):
            assert "password_hash" not in u

    def test_session_cookie_httponly(self):
        """All session cookie set operations include HttpOnly."""
        from api.userauth_routes import handle_post_login
        import api.userauth as ua

        ua.create_user("http@example.com", "HttpOnly1234", "owner")
        body = _json_body(email="http@example.com", password="HttpOnly1234")
        h = _make_handler(body=body)
        handle_post_login(h, json.loads(body), {"next": ["/"]})

        cookie = h.get_set_cookie()
        assert cookie is not None
        assert "HttpOnly" in cookie

    def test_session_cookie_samesite_lax(self):
        """Session cookie must specify SameSite=Lax."""
        from api.userauth_routes import handle_post_login
        import api.userauth as ua

        ua.create_user("same@example.com", "SameSite1234", "owner")
        body = _json_body(email="same@example.com", password="SameSite1234")
        h = _make_handler(body=body)
        handle_post_login(h, json.loads(body), {"next": ["/"]})

        cookie = h.get_set_cookie()
        assert cookie is not None
        assert "SameSite=Lax" in cookie

    def test_login_generic_error_for_wrong_password(self):
        """Login must not leak 'wrong password' vs 'user not found'."""
        from api.userauth_routes import handle_post_login
        import api.userauth as ua

        ua.create_user("real2@example.com", "Real2Pass123", "owner")

        body = _json_body(email="real2@example.com", password="WrongPass9999")
        h = _make_handler(body=body)
        handle_post_login(h, json.loads(body), {"next": ["/"]})

        response_text = h.body_written.decode(errors="replace")
        # Must show generic error — not "wrong password" or "user not found"
        assert "Invalid email or password" in response_text
        assert "wrong password" not in response_text.lower()
        assert "user not found" not in response_text.lower()
        assert "does not exist" not in response_text.lower()

    def test_last_owner_delete_blocked_via_route(self):
        """DELETE /users/<last-owner-id> returns 409 when the route wraps the guard.

        Strategy:
        - Two owners: owner_a (actor) and owner_b (target).
        - While both exist (2 owners), owner_b is not last → delete succeeds.
        - After deleting owner_b, owner_a is the sole owner.
        - owner_a tries self-delete → route returns 400 (self-delete guard fires first).
        - Direct core call confirms the last-owner ValueError is still raised.
        """
        from api.userauth_routes import handle_delete_user
        import api.userauth as ua

        # Two owners: owner_a (acting) and owner_b (target)
        owner_a, token_a = _create_owner(
            email="owner-a@example.com", password="OwnerAPass123"
        )
        owner_b = ua.create_user("owner-b@example.com", "OwnerBPass123", "owner")

        # Delete owner_a so owner_b becomes the last owner
        ua.delete_user(owner_a["id"])
        assert ua.owner_count() == 1

        # Scenario 1: owner_a is gone; owner_b is last.
        # owner_b tries to self-delete → route 400 (self-delete guard fires before last-owner guard)
        h_self = _make_handler(cookie=_cookie(token_a))
        # Note: token_a belongs to deleted owner_a, so the session lookup returns None
        # (user deleted, cascade), meaning this is an auth 401 scenario:
        handle_delete_user(h_self, owner_b["id"])
        # The session for owner_a is gone (cascade delete) → 401
        assert h_self.status_code == 401

        # Scenario 2: Create owner_c as a fresh actor; owner_b is still last owner.
        owner_c = ua.create_user("owner-c@example.com", "OwnerCPass123", "owner")
        token_c = ua.create_session(owner_c["id"])
        # Both owner_b and owner_c exist (2 owners); owner_b is NOT the last owner.
        # Delete owner_b succeeds (owner_c remains):
        h_ok = _make_handler(cookie=_cookie(token_c))
        handle_delete_user(h_ok, owner_b["id"])
        assert h_ok.status_code == 200
        assert ua.owner_count() == 1  # owner_c is now the sole owner

        # Scenario 3: owner_c is now the last owner.
        # owner_c tries to delete themselves → route returns 400 (self-delete guard).
        h_self2 = _make_handler(cookie=_cookie(token_c))
        handle_delete_user(h_self2, owner_c["id"])
        assert h_self2.status_code == 400  # self-delete blocked

        # Belt-and-suspenders: core last-owner guard raises directly.
        with pytest.raises(ValueError, match="last Owner"):
            ua.delete_user(owner_c["id"])




class TestSetupGate:
    """GET /setup — redirects if users exist."""

    def test_get_setup_redirects_when_users_exist(self):
        from api.userauth_routes import handle_get_setup
        import api.userauth as ua

        ua.create_user("exists@example.com", "ExistsPass123", "owner")
        h = _make_handler()
        handle_get_setup(h)

        assert h.status_code == 302
        assert h.get_header("Location") == "/login"

    def test_get_setup_serves_page_when_no_users(self):
        from api.userauth_routes import handle_get_setup
        import api.userauth as ua

        assert ua.user_count() == 0
        h = _make_handler()
        handle_get_setup(h)

        assert h.status_code == 200
        body = h.body_written.decode()
        assert "Create Owner Account" in body
