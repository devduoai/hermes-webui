"""
Regression test: same-origin POST /users/invite without CSRF token returns
403 (not 501) when per-user auth is active and old-style single-user auth
is NOT active (is_auth_enabled() == False).

Before the fix, _check_csrf bailed out early with `return True` when
is_auth_enabled() was False, bypassing the per-user CSRF check entirely.
This let the request reach handle_post_invite, which could raise an uncaught
exception (e.g. a DB error with an unexpected user-id) resulting in a 501
from the chat-start fallback handler instead of the expected 403.

Run: python3 -m pytest tests/test_csrf_501_on_missing_token.py -v
"""

import hmac
import io
import json
import time
from types import SimpleNamespace
from unittest.mock import patch

import api.auth as auth
import api.routes as routes
import api.userauth as userauth


class _FakeHandler:
    def __init__(self, headers=None, body=b"{}"):
        self.headers = headers or {}
        self.client_address = ("127.0.0.1", 12345)
        self.rfile = io.BytesIO(body)
        self.wfile = io.BytesIO()
        self.status = None
        self.sent_headers = {}

    def send_response(self, status):
        self.status = status

    def send_header(self, key, value):
        self.sent_headers[key.lower()] = value

    def end_headers(self):
        pass


def _json_body(handler: _FakeHandler) -> dict:
    raw = handler.wfile.getvalue()
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


def _make_userauth_session(raw_token: str) -> str:
    """Create a valid per-user session cookie string (raw token, no signing)."""
    # _parse_user_session_cookie just does string parsing; we only need the cookie
    # value to be present.  csrf_token_for_session uses api.auth._signing_key() to
    # derive the expected CSRF token from the per-user cookie value.
    return raw_token


def _userauth_csrf_token(cookie_value: str) -> str:
    """Derive the CSRF token that the browser would send for this per-user session.

    Per-user session tokens are plain urlsafe strings.  The CSRF derivation
    uses hmac(signing_key, f"csrf:{token}") directly — the same logic as
    _get_csrf_token() in userauth_routes and the verifier in _check_csrf.
    """
    import hashlib
    sig = hmac.new(auth._signing_key(), f"csrf:{cookie_value}".encode(), hashlib.sha256)
    return sig.hexdigest()


class TestCsrf501RegressionPerUserAuth:
    """
    Regression: same-origin requests under per-user auth (is_auth_enabled=False)
    must be blocked at the CSRF gate with 403, not slip through to the handler.
    """

    def _post_invite_with_userauth(
        self,
        monkeypatch,
        *,
        include_csrf: bool,
        include_session: bool,
    ):
        """
        Send POST /users/invite simulating per-user auth active,
        old-style auth disabled.

        Returns the (handler, result) tuple.
        """
        raw_token = "u" * 64
        cookie_value = _make_userauth_session(raw_token)
        csrf_token = _userauth_csrf_token(cookie_value) if include_csrf else None

        # Simulate per-user auth active, old-style auth disabled
        monkeypatch.setattr(auth, "is_auth_enabled", lambda: False)
        monkeypatch.setattr(userauth, "is_userauth_active", lambda: True)

        body = json.dumps({"email": "test@example.com", "role": "admin"}).encode()
        headers = {
            "Origin": "http://127.0.0.1:8787",
            "Host": "127.0.0.1:8787",
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "X-Requested-With": "XMLHttpRequest",
        }
        if include_session:
            headers["Cookie"] = f"hermes_user_session={cookie_value}"
        if csrf_token:
            headers[auth.CSRF_HEADER_NAME] = csrf_token

        handler = _FakeHandler(headers=headers, body=body)
        parsed = SimpleNamespace(path="/users/invite", query="")
        result = routes.handle_post(handler, parsed)
        return handler, result

    def test_same_origin_no_token_with_session_returns_403(self, monkeypatch):
        """
        Regression: same-origin POST with per-user session but no CSRF token
        must return 403, not 501 or any other code.

        This is the exact scenario that was producing 501 before the fix:
        _check_csrf returned True (bypassed) because is_auth_enabled()==False,
        then the invite handler ran and could raise an uncaught exception.
        """
        handler, _ = self._post_invite_with_userauth(
            monkeypatch, include_csrf=False, include_session=True
        )
        assert handler.status == 403, (
            f"Expected 403 but got {handler.status}. "
            f"Response body: {_json_body(handler)}"
        )
        body = _json_body(handler)
        assert "error" in body

    def test_same_origin_no_session_no_token_passes_csrf_gate(self, monkeypatch):
        """
        Same-origin POST with no session at all passes the CSRF gate
        (unauthenticated requests are handled by the auth gate, not CSRF).
        The downstream handler may redirect or return 401, but must not be
        blocked with 403 by the CSRF check itself.
        """
        handler, _ = self._post_invite_with_userauth(
            monkeypatch, include_csrf=False, include_session=False
        )
        # Must NOT be 403 from CSRF (unauthenticated = no session = no token required)
        assert handler.status != 403, (
            f"Unauthenticated request should not be CSRF-rejected; got 403. "
            f"Response body: {_json_body(handler)}"
        )

    def test_same_origin_with_valid_csrf_token_passes_gate(self, monkeypatch):
        """
        Same-origin POST with valid per-user CSRF token passes the CSRF gate.
        It may still fail auth/role checks, but must not be 403 from CSRF.
        """
        raw_token = "v" * 64
        cookie_value = _make_userauth_session(raw_token)
        csrf_token = _userauth_csrf_token(cookie_value)

        monkeypatch.setattr(auth, "is_auth_enabled", lambda: False)
        monkeypatch.setattr(userauth, "is_userauth_active", lambda: True)

        # Mock _get_current_user to return a valid admin user so the handler
        # can proceed past the auth check inside handle_post_invite.
        user_fixture = {"id": "u1", "email": "admin@example.com", "role": "admin"}

        body = json.dumps({"email": "invitee@example.com", "role": "admin"}).encode()
        headers = {
            "Origin": "http://127.0.0.1:8787",
            "Host": "127.0.0.1:8787",
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "X-Requested-With": "XMLHttpRequest",
            "Cookie": f"hermes_user_session={cookie_value}",
            auth.CSRF_HEADER_NAME: csrf_token,
        }
        handler = _FakeHandler(headers=headers, body=body)
        parsed = SimpleNamespace(path="/users/invite", query="")

        with patch("api.userauth_routes._get_current_user", return_value=user_fixture), \
             patch("api.userauth.create_invite", return_value={
                 "id": "inv1", "email": "invitee@example.com", "role": "admin",
                 "token": "tok", "created_by": "u1", "created_at": 0, "expires_at": 9999999,
             }):
            result = routes.handle_post(handler, parsed)

        # CSRF gate passed — must not be 403 due to CSRF
        assert handler.status != 403, (
            f"Valid CSRF token should pass gate, got 403. "
            f"Response body: {_json_body(handler)}"
        )
