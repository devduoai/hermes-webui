"""
CSRF protection tests for POST /users/invite and DELETE /users/invite/<id>.

B2 from code review: these endpoints must reject cross-origin requests and
require a valid session-bound CSRF token from authenticated browser clients.

Run: python3 -m pytest tests/test_issue_b2_users_invite_csrf.py -v
"""

import hmac
import io
import json
import time
from types import SimpleNamespace

import api.auth as auth
import api.routes as routes


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


def _signed_cookie(raw_token: str) -> str:
    sig = hmac.new(auth._signing_key(), raw_token.encode(), "sha256").hexdigest()
    auth._sessions[raw_token] = time.time() + 60
    return f"{raw_token}.{sig}"


def _json_body(handler: _FakeHandler) -> dict:
    return json.loads(handler.wfile.getvalue().decode("utf-8"))


# ── POST /users/invite ────────────────────────────────────────────────────────

class TestPostInviteCsrf:
    def test_cross_origin_evil_post_is_rejected(self, monkeypatch):
        """POST /users/invite from evil.com must be blocked with 403."""
        monkeypatch.setattr(auth, "is_auth_enabled", lambda: False)
        handler = _FakeHandler(
            headers={
                "Origin": "https://evil.com",
                "Host": "127.0.0.1:8787",
                "Content-Type": "application/json",
                "Content-Length": "2",
            },
            body=b"{}",
        )
        routes.handle_post(handler, SimpleNamespace(path="/users/invite", query=""))
        assert handler.status == 403

    def test_post_without_origin_is_rejected(self, monkeypatch):
        """POST /users/invite with Origin header but mismatched host must be 403."""
        monkeypatch.setattr(auth, "is_auth_enabled", lambda: False)
        handler = _FakeHandler(
            headers={
                "Origin": "https://attacker.example",
                "Host": "127.0.0.1:8787",
                "Content-Type": "application/json",
                "Content-Length": "2",
            },
            body=b"{}",
        )
        routes.handle_post(handler, SimpleNamespace(path="/users/invite", query=""))
        assert handler.status == 403

    def test_same_origin_post_without_csrf_token_is_rejected(self, monkeypatch):
        """Same-origin POST without CSRF token is rejected (token required for
        authenticated browser requests)."""
        cookie = _signed_cookie("p" * 64)
        monkeypatch.setattr(auth, "is_auth_enabled", lambda: True)
        try:
            handler = _FakeHandler(
                headers={
                    "Origin": "http://127.0.0.1:8787",
                    "Host": "127.0.0.1:8787",
                    "Cookie": f"{auth.COOKIE_NAME}={cookie}",
                    "Content-Type": "application/json",
                    "Content-Length": "2",
                },
                body=b"{}",
            )
            routes.handle_post(handler, SimpleNamespace(path="/users/invite", query=""))
            assert handler.status == 403
        finally:
            auth._sessions.pop("p" * 64, None)

    def test_same_origin_post_with_valid_csrf_token_passes_csrf_gate(self, monkeypatch):
        """Same-origin POST with valid CSRF token passes the CSRF gate (may still
        fail auth/role checks, but must not be blocked by CSRF)."""
        cookie = _signed_cookie("q" * 64)
        token = auth.csrf_token_for_session(cookie)
        monkeypatch.setattr(auth, "is_auth_enabled", lambda: True)
        try:
            handler = _FakeHandler(
                headers={
                    "Origin": "http://127.0.0.1:8787",
                    "Host": "127.0.0.1:8787",
                    "Cookie": f"{auth.COOKIE_NAME}={cookie}",
                    auth.CSRF_HEADER_NAME: token,
                    "Content-Type": "application/json",
                    "Content-Length": "2",
                },
                body=b"{}",
            )
            routes.handle_post(handler, SimpleNamespace(path="/users/invite", query=""))
            # CSRF gate passed — must not be 403 due to CSRF
            assert handler.status != 403, (
                f"Expected CSRF to pass but got 403: {_json_body(handler)}"
            )
        finally:
            auth._sessions.pop("q" * 64, None)

    def test_non_browser_post_no_origin_passes_csrf_gate(self, monkeypatch):
        """Non-browser clients (no Origin/Referer) pass the CSRF gate.
        They may still fail auth, but must not be blocked by CSRF."""
        monkeypatch.setattr(auth, "is_auth_enabled", lambda: False)
        handler = _FakeHandler(
            headers={
                "Content-Type": "application/json",
                "Content-Length": "2",
                "Host": "127.0.0.1:8787",
            },
            body=b"{}",
        )
        routes.handle_post(handler, SimpleNamespace(path="/users/invite", query=""))
        # Must not be 403 (CSRF gate passes for non-browser clients)
        assert handler.status != 403


# ── DELETE /users/invite/<id> ─────────────────────────────────────────────────

class TestDeleteInviteCsrf:
    def test_cross_origin_evil_delete_is_rejected(self, monkeypatch):
        """DELETE /users/invite/<id> from evil.com must be blocked with 403."""
        monkeypatch.setattr(auth, "is_auth_enabled", lambda: False)
        handler = _FakeHandler(
            headers={
                "Origin": "https://evil.com",
                "Host": "127.0.0.1:8787",
            },
        )
        routes.handle_delete(handler, SimpleNamespace(path="/users/invite/some-id", query=""))
        assert handler.status == 403

    def test_same_origin_delete_without_csrf_token_is_rejected(self, monkeypatch):
        """Same-origin DELETE without CSRF token is rejected."""
        cookie = _signed_cookie("r" * 64)
        monkeypatch.setattr(auth, "is_auth_enabled", lambda: True)
        try:
            handler = _FakeHandler(
                headers={
                    "Origin": "http://127.0.0.1:8787",
                    "Host": "127.0.0.1:8787",
                    "Cookie": f"{auth.COOKIE_NAME}={cookie}",
                },
            )
            routes.handle_delete(handler, SimpleNamespace(path="/users/invite/some-id", query=""))
            assert handler.status == 403
        finally:
            auth._sessions.pop("r" * 64, None)

    def test_same_origin_delete_with_valid_csrf_token_passes_csrf_gate(self, monkeypatch):
        """Same-origin DELETE with valid CSRF token passes the CSRF gate."""
        cookie = _signed_cookie("s" * 64)
        token = auth.csrf_token_for_session(cookie)
        monkeypatch.setattr(auth, "is_auth_enabled", lambda: True)
        try:
            handler = _FakeHandler(
                headers={
                    "Origin": "http://127.0.0.1:8787",
                    "Host": "127.0.0.1:8787",
                    "Cookie": f"{auth.COOKIE_NAME}={cookie}",
                    auth.CSRF_HEADER_NAME: token,
                },
            )
            routes.handle_delete(handler, SimpleNamespace(path="/users/invite/some-id", query=""))
            # CSRF gate passed
            assert handler.status != 403, (
                f"Expected CSRF to pass but got 403: {_json_body(handler)}"
            )
        finally:
            auth._sessions.pop("s" * 64, None)
