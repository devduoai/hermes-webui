"""
Integration-style tests for the password change and reset HTTP endpoints.

Tests route handler logic directly (no real HTTP server needed) using a
minimal fake handler shim.

Run with: python3 -m pytest tests/test_password_change_reset.py -v
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

# Isolate test state
_TMP = tempfile.mkdtemp(prefix="hermes_pw_change_test_")
os.environ["HERMES_WEBUI_STATE_DIR"] = _TMP
os.environ["HERMES_USERAUTH"] = "1"
os.environ["HERMES_WEBUI_PASSWORD"] = ""

sys.path.insert(0, str(Path(__file__).parent.parent))


# ── Minimal fake handler shim ─────────────────────────────────────────────────

class _FakeHandler:
    """Minimal handler shim that captures response status/headers/body."""

    def __init__(self, cookie: str = "", body: bytes = b"", content_type: str = "application/json"):
        self._status = None
        self._headers: list[tuple[str, str]] = []
        self._body_buf = io.BytesIO()
        # Simulate request headers
        self.headers = {
            "Cookie": f"hermes_user_session={cookie}" if cookie else "",
            "Content-Type": content_type,
            "Content-Length": str(len(body)),
        }
        self.path = "/"
        self.rfile = io.BytesIO(body)
        self.wfile = self._body_buf

    def send_response(self, status: int):
        self._status = status

    def send_header(self, key: str, value: str):
        self._headers.append((key, value))

    def end_headers(self):
        pass

    def response_body(self) -> bytes:
        return self._body_buf.getvalue()

    def response_json(self) -> dict:
        return json.loads(self.response_body())


def _make_handler(token: str = "", payload: dict | None = None) -> _FakeHandler:
    body = json.dumps(payload or {}).encode()
    return _FakeHandler(cookie=token, body=body, content_type="application/json")


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    import api.userauth as ua
    db = tmp_path / "auth.db"
    monkeypatch.setattr(ua, "_db_path", lambda: db)
    yield


def _ua():
    import api.userauth as ua
    return ua


def _setup_users():
    ua = _ua()
    owner = ua.create_user("owner@example.com", "ValidPassword1", "owner")
    admin = ua.create_user("admin@example.com", "ValidPassword1", "admin")
    owner_token = ua.create_session(owner["id"])
    admin_token = ua.create_session(admin["id"])
    return ua, owner, admin, owner_token, admin_token


# ── POST /auth/change-password ────────────────────────────────────────────────

class TestChangePasswordRoute:
    def test_success_200(self):
        from api.userauth_routes import handle_post_change_password
        ua, owner, admin, owner_token, admin_token = _setup_users()

        h = _make_handler(owner_token, {"current_password": "ValidPassword1", "new_password": "NewPassword99"})
        handle_post_change_password(h, json.loads(h.rfile.getvalue()))
        assert h._status == 200
        resp = h.response_json()
        assert resp.get("ok") is True

    def test_wrong_current_password_401(self):
        from api.userauth_routes import handle_post_change_password
        ua, owner, admin, owner_token, admin_token = _setup_users()

        h = _make_handler(owner_token, {"current_password": "WrongPassword1", "new_password": "NewPassword99"})
        handle_post_change_password(h, json.loads(h.rfile.getvalue()))
        assert h._status == 401
        assert "error" in h.response_json()

    def test_policy_violation_400(self):
        from api.userauth_routes import handle_post_change_password
        ua, owner, admin, owner_token, admin_token = _setup_users()

        h = _make_handler(owner_token, {"current_password": "ValidPassword1", "new_password": "short"})
        handle_post_change_password(h, json.loads(h.rfile.getvalue()))
        assert h._status == 400
        assert "error" in h.response_json()

    def test_unauthenticated_401(self):
        from api.userauth_routes import handle_post_change_password
        ua, owner, admin, owner_token, admin_token = _setup_users()

        h = _make_handler("", {"current_password": "ValidPassword1", "new_password": "NewPassword99"})
        handle_post_change_password(h, json.loads(h.rfile.getvalue()))
        assert h._status == 401

    def test_password_actually_changed(self):
        from api.userauth_routes import handle_post_change_password
        ua, owner, admin, owner_token, admin_token = _setup_users()

        h = _make_handler(owner_token, {"current_password": "ValidPassword1", "new_password": "NewPassword99"})
        handle_post_change_password(h, json.loads(h.rfile.getvalue()))
        assert h._status == 200
        # Old password must not work
        assert ua.attempt_login("owner@example.com", "ValidPassword1") is None
        # New password works
        assert ua.attempt_login("owner@example.com", "NewPassword99") is not None

    def test_other_sessions_deleted_current_kept(self):
        from api.userauth_routes import handle_post_change_password
        ua, owner, admin, owner_token, admin_token = _setup_users()
        extra_token = ua.create_session(owner["id"])

        h = _make_handler(owner_token, {"current_password": "ValidPassword1", "new_password": "NewPassword99"})
        handle_post_change_password(h, json.loads(h.rfile.getvalue()))
        assert h._status == 200
        # Current session kept
        assert ua.get_session_user(owner_token) is not None
        # Extra session wiped
        assert ua.get_session_user(extra_token) is None

    def test_missing_fields_400(self):
        from api.userauth_routes import handle_post_change_password
        ua, owner, admin, owner_token, admin_token = _setup_users()

        h = _make_handler(owner_token, {"current_password": "ValidPassword1"})
        handle_post_change_password(h, json.loads(h.rfile.getvalue()))
        assert h._status == 400


# ── POST /api/users/<id>/reset-password ──────────────────────────────────────

class TestResetPasswordRoute:
    def test_owner_resets_admin_200(self):
        from api.userauth_routes import handle_post_reset_password
        ua, owner, admin, owner_token, admin_token = _setup_users()

        h = _make_handler(owner_token, {})
        handle_post_reset_password(h, admin["id"])
        assert h._status == 200
        resp = h.response_json()
        assert resp.get("ok") is True
        assert "temp_password" in resp
        assert "expires_at" in resp
        assert len(resp["temp_password"]) == 16

    def test_admin_gets_403(self):
        from api.userauth_routes import handle_post_reset_password
        ua, owner, admin, owner_token, admin_token = _setup_users()

        h = _make_handler(admin_token, {})
        handle_post_reset_password(h, owner["id"])
        assert h._status == 403

    def test_target_can_login_with_temp_password(self):
        from api.userauth_routes import handle_post_reset_password
        ua, owner, admin, owner_token, admin_token = _setup_users()

        h = _make_handler(owner_token, {})
        handle_post_reset_password(h, admin["id"])
        assert h._status == 200
        temp_pw = h.response_json()["temp_password"]
        assert ua.attempt_login("admin@example.com", temp_pw) is not None
        # Old password no longer works
        assert ua.attempt_login("admin@example.com", "ValidPassword1") is None

    def test_target_sessions_wiped(self):
        from api.userauth_routes import handle_post_reset_password
        ua, owner, admin, owner_token, admin_token = _setup_users()

        h = _make_handler(owner_token, {})
        handle_post_reset_password(h, admin["id"])
        assert h._status == 200
        # Admin's session wiped
        assert ua.get_session_user(admin_token) is None
        # Owner's session untouched
        assert ua.get_session_user(owner_token) is not None

    def test_unauthenticated_401(self):
        from api.userauth_routes import handle_post_reset_password
        ua, owner, admin, owner_token, admin_token = _setup_users()

        h = _make_handler("", {})
        handle_post_reset_password(h, admin["id"])
        assert h._status == 401

    def test_owner_cannot_reset_own_password_400(self):
        from api.userauth_routes import handle_post_reset_password
        ua, owner, admin, owner_token, admin_token = _setup_users()

        h = _make_handler(owner_token, {})
        handle_post_reset_password(h, owner["id"])
        assert h._status == 400

    def test_nonexistent_user_404(self):
        from api.userauth_routes import handle_post_reset_password
        ua, owner, admin, owner_token, admin_token = _setup_users()

        h = _make_handler(owner_token, {})
        handle_post_reset_password(h, "nonexistent-uuid-xxxx")
        assert h._status == 404
