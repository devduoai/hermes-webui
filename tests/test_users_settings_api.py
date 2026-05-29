"""
Unit tests for the JSON user-management API endpoints added for the
Users settings panel (feat/auth-users-settings-nav).

Endpoints tested:
  GET  /api/users          -- returns {users, invites}; requires auth
  POST /users/invite       -- creates invite; enforces role matrix
  DELETE /users/<id>       -- deletes user; owner-only
  DELETE /users/invite/<id>-- revokes invite
  GET  /auth/me            -- returns current user info

Run standalone (no conftest.py, no server fixture):
  python3 tests/test_users_settings_api.py
"""
from __future__ import annotations
import io
import json
import os
import sys
import tempfile
import traceback
from pathlib import Path

# Isolate test state before any api imports
_TMP = tempfile.mkdtemp(prefix="hermes_users_api_test_")
os.environ["HERMES_WEBUI_STATE_DIR"] = _TMP
os.environ["HERMES_USERAUTH"] = "1"
os.environ["HERMES_WEBUI_PASSWORD"] = ""

sys.path.insert(0, str(Path(__file__).parent.parent))


# ── Minimal handler mock ──────────────────────────────────────────────────────

class _FakeHandler:
    """Minimal http.server.BaseHTTPRequestHandler mock for route handlers."""

    def __init__(self, session_token=None, body=None,
                 content_type="application/json", is_xhr=True):
        self._response_status = None
        self._header_list: list = []
        self._output = io.BytesIO()

        raw_cookie = f"hermes_user_session={session_token}" if session_token else ""
        self.headers: dict = {
            "Cookie": raw_cookie,
            "X-Requested-With": "XMLHttpRequest" if is_xhr else "",
            "Content-Type": content_type,
            "Content-Length": str(len(body or b"")),
        }
        self.rfile = io.BytesIO(body or b"")
        self.wfile = self._output

    def send_response(self, code: int) -> None:
        self._response_status = code

    def send_header(self, key: str, value: str) -> None:
        self._header_list.append((key, value))

    def end_headers(self) -> None:
        pass

    def response_json(self) -> dict:
        return json.loads(self._output.getvalue())

    def status(self) -> int:
        return self._response_status


# ── DB-isolation helper ───────────────────────────────────────────────────────

class _IsolatedDB:
    """Context manager that patches api.userauth._db_path to a temp file."""

    def __init__(self) -> None:
        self._tmp_dir = tempfile.mkdtemp()
        self._db_path = Path(self._tmp_dir) / "auth.db"
        self._orig = None

    def __enter__(self) -> "_IsolatedDB":
        import api.userauth as ua
        self._orig = ua._db_path
        ua._db_path = lambda: self._db_path
        return self

    def __exit__(self, *_) -> None:
        import api.userauth as ua
        ua._db_path = self._orig


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_owner_session():
    from api import userauth as ua
    user = ua.create_user("owner@example.com", "ValidPassword1", "owner")
    token = ua.create_session(user["id"])
    return user, token


def _make_admin_session():
    from api import userauth as ua
    _make_owner_session()
    user = ua.create_user("admin@example.com", "ValidPassword1", "admin")
    token = ua.create_session(user["id"])
    return user, token


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestGetApiUsers:
    """GET /api/users"""

    def test_returns_users_and_invites_for_owner(self):
        from api.userauth_routes import handle_get_users_api
        owner, token = _make_owner_session()
        h = _FakeHandler(session_token=token)
        assert handle_get_users_api(h) is True
        assert h.status() == 200
        data = h.response_json()
        assert "users" in data and "invites" in data
        assert any(u["email"] == "owner@example.com" for u in data["users"])

    def test_returns_users_and_invites_for_admin(self):
        from api.userauth_routes import handle_get_users_api
        admin, token = _make_admin_session()
        h = _FakeHandler(session_token=token)
        assert handle_get_users_api(h) is True
        assert h.status() == 200
        data = h.response_json()
        assert "users" in data and "invites" in data

    def test_requires_authentication(self):
        from api.userauth_routes import handle_get_users_api
        h = _FakeHandler(session_token=None)
        assert handle_get_users_api(h) is True
        assert h.status() == 401
        assert "error" in h.response_json()

    def test_no_password_hash_in_response(self):
        from api.userauth_routes import handle_get_users_api
        owner, token = _make_owner_session()
        h = _FakeHandler(session_token=token)
        handle_get_users_api(h)
        for user in h.response_json()["users"]:
            assert "password_hash" not in user

    def test_response_shape(self):
        from api.userauth_routes import handle_get_users_api
        owner, token = _make_owner_session()
        h = _FakeHandler(session_token=token)
        handle_get_users_api(h)
        for user in h.response_json()["users"]:
            assert "id" in user and "email" in user and "role" in user


class TestGetAuthMe:
    """GET /auth/me"""

    def test_returns_current_user(self):
        from api.userauth_routes import handle_get_auth_me
        owner, token = _make_owner_session()
        h = _FakeHandler(session_token=token)
        assert handle_get_auth_me(h) is True
        assert h.status() == 200
        data = h.response_json()
        assert data["user"]["email"] == "owner@example.com"
        assert data["user"]["role"] == "owner"
        assert "password_hash" not in data["user"]

    def test_returns_401_when_unauthenticated(self):
        from api.userauth_routes import handle_get_auth_me
        h = _FakeHandler(session_token=None)
        assert handle_get_auth_me(h) is True
        assert h.status() == 401
        assert "error" in h.response_json()


class TestPostUsersInvite:
    """POST /users/invite"""

    def _invite(self, token, email, role):
        from api.userauth_routes import handle_post_invite
        h = _FakeHandler(session_token=token)
        handle_post_invite(h, {"email": email, "role": role}, {})
        return h

    def test_owner_can_invite_admin(self):
        _, token = _make_owner_session()
        h = self._invite(token, "newadmin@example.com", "admin")
        assert h.status() == 200
        data = h.response_json()
        assert data.get("ok") is True
        assert "invite_url" in data

    def test_owner_can_invite_owner(self):
        _, token = _make_owner_session()
        h = self._invite(token, "newowner@example.com", "owner")
        assert h.status() == 200
        assert h.response_json().get("ok") is True

    def test_admin_cannot_invite_owner(self):
        from api.userauth_routes import handle_post_invite
        _, token = _make_admin_session()
        h = _FakeHandler(session_token=token)
        handle_post_invite(h, {"email": "bad@example.com", "role": "owner"}, {})
        assert h.status() == 403
        assert "error" in h.response_json()

    def test_admin_can_invite_admin(self):
        _, token = _make_admin_session()
        h = self._invite(token, "admin2@example.com", "admin")
        assert h.status() == 200
        assert h.response_json().get("ok") is True

    def test_requires_authentication(self):
        from api.userauth_routes import handle_post_invite
        h = _FakeHandler(session_token=None)
        handle_post_invite(h, {"email": "x@example.com", "role": "admin"}, {})
        assert h.status() != 200

    def test_invite_url_contains_invite_path(self):
        _, token = _make_owner_session()
        h = self._invite(token, "check@example.com", "admin")
        assert "/invite/" in h.response_json().get("invite_url", "")


class TestDeleteUser:
    """DELETE /users/<id>"""

    def test_owner_can_delete_other_user(self):
        from api.userauth_routes import handle_delete_user
        from api import userauth as ua
        owner, token = _make_owner_session()
        admin = ua.create_user("todelete@example.com", "ValidPassword1", "admin")
        h = _FakeHandler(session_token=token)
        assert handle_delete_user(h, admin["id"]) is True
        assert h.status() == 200
        assert h.response_json().get("ok") is True

    def test_owner_cannot_delete_self(self):
        from api.userauth_routes import handle_delete_user
        owner, token = _make_owner_session()
        h = _FakeHandler(session_token=token)
        assert handle_delete_user(h, owner["id"]) is True
        assert h.status() == 400
        assert "error" in h.response_json()

    def test_admin_cannot_delete_user(self):
        from api.userauth_routes import handle_delete_user
        from api import userauth as ua
        owner, _ = _make_owner_session()
        admin = ua.create_user("admin@example.com", "ValidPassword1", "admin")
        admin_token = ua.create_session(admin["id"])
        h = _FakeHandler(session_token=admin_token)
        assert handle_delete_user(h, owner["id"]) is True
        assert h.status() == 403
        assert "error" in h.response_json()

    def test_requires_authentication(self):
        from api.userauth_routes import handle_delete_user
        h = _FakeHandler(session_token=None)
        assert handle_delete_user(h, "some-id") is True
        assert h.status() == 401


class TestDeleteInvite:
    """DELETE /users/invite/<id>"""

    def test_owner_can_revoke_invite(self):
        from api.userauth_routes import handle_delete_invite
        from api import userauth as ua
        owner, token = _make_owner_session()
        invite = ua.create_invite("someone@example.com", "admin", owner["id"])
        h = _FakeHandler(session_token=token)
        assert handle_delete_invite(h, invite["id"]) is True
        assert h.status() == 200
        assert h.response_json().get("ok") is True

    def test_admin_can_revoke_own_invite(self):
        from api.userauth_routes import handle_delete_invite
        from api import userauth as ua
        _make_owner_session()
        admin = ua.create_user("admin@example.com", "ValidPassword1", "admin")
        admin_token = ua.create_session(admin["id"])
        invite = ua.create_invite("target@example.com", "admin", admin["id"])
        h = _FakeHandler(session_token=admin_token)
        assert handle_delete_invite(h, invite["id"]) is True
        assert h.status() == 200

    def test_admin_cannot_revoke_other_invite(self):
        from api.userauth_routes import handle_delete_invite
        from api import userauth as ua
        owner, _ = _make_owner_session()
        admin = ua.create_user("admin@example.com", "ValidPassword1", "admin")
        admin_token = ua.create_session(admin["id"])
        invite = ua.create_invite("target@example.com", "admin", owner["id"])
        h = _FakeHandler(session_token=admin_token)
        assert handle_delete_invite(h, invite["id"]) is True
        assert h.status() == 400
        assert "error" in h.response_json()

    def test_requires_authentication(self):
        from api.userauth_routes import handle_delete_invite
        h = _FakeHandler(session_token=None)
        assert handle_delete_invite(h, "some-id") is True
        assert h.status() == 401


# ── Standalone runner ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import api.userauth as _ua  # noqa: F401 (import to validate module loads)

    test_classes = [
        TestGetApiUsers,
        TestGetAuthMe,
        TestPostUsersInvite,
        TestDeleteUser,
        TestDeleteInvite,
    ]

    passed = 0
    failed = 0

    for cls in test_classes:
        methods = [m for m in dir(cls) if m.startswith("test_")]
        for method_name in methods:
            db_path = Path(tempfile.mkdtemp()) / "auth.db"
            import api.userauth as ua
            orig_db = ua._db_path
            ua._db_path = lambda _p=db_path: _p
            try:
                obj = cls()
                getattr(obj, method_name)()
                print(f"  PASS  {cls.__name__}::{method_name}")
                passed += 1
            except Exception as e:
                print(f"  FAIL  {cls.__name__}::{method_name}: {e}")
                traceback.print_exc()
                failed += 1
            finally:
                ua._db_path = orig_db

    total = passed + failed
    print(f"\n{passed}/{total} passed", "OK" if failed == 0 else f"({failed} failed)")
    sys.exit(0 if failed == 0 else 1)
