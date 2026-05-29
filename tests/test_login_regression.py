"""
Regression tests for fix/login-route-collision.

Verifies that GET /login serves the new per-user email+password form
(api/userauth_routes.handle_get_login) and NOT the legacy shared-password UI.

Acceptance criteria from task t_1f7bb0c6:
- curl -s https://teamduo.ai/login returns HTML that includes type="email" or name="email"
- curl -s https://teamduo.ai/login does NOT contain "Enter your password to continue"
"""
import urllib.request
import urllib.parse

from tests._pytest_port import BASE


def get_raw(path):
    req = urllib.request.Request(BASE + path)
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read().decode(), r.status


def test_login_page_has_email_field():
    """GET /login must return an email input field (new per-user auth form)."""
    html, status = get_raw("/login")
    assert status == 200
    assert 'type="email"' in html or 'name="email"' in html, (
        "GET /login response does not contain an email input — legacy shared-password UI may be active"
    )


def test_login_page_does_not_contain_legacy_copy():
    """GET /login must NOT contain the legacy shared-password subtitle copy."""
    html, status = get_raw("/login")
    assert status == 200
    assert "Enter your password to continue" not in html, (
        "GET /login still contains legacy 'Enter your password to continue' copy — "
        "the old shared-password UI is being served instead of the new login form"
    )


def test_login_page_has_password_field():
    """GET /login must contain a password input (sanity check — form is complete)."""
    html, status = get_raw("/login")
    assert status == 200
    assert 'type="password"' in html or 'name="password"' in html


def test_login_page_returns_200():
    """GET /login must return HTTP 200 (not redirect or error)."""
    html, status = get_raw("/login")
    assert status == 200


def test_login_page_with_next_param():
    """GET /login?next=/settings must return 200 with the email form (next param is safe)."""
    html, status = get_raw("/login?next=/settings")
    assert status == 200
    assert 'type="email"' in html or 'name="email"' in html


def test_login_page_next_param_open_redirect_blocked():
    """GET /login?next=https://evil.com must NOT embed the external URL in the form action."""
    html, status = get_raw("/login?next=https%3A%2F%2Fevil.com")
    assert status == 200
    # The action should have been reset to /auth/login?next=/ (not evil.com)
    assert "evil.com" not in html


def test_login_page_form_posts_to_auth_endpoint():
    """GET /login form action must point to a new-auth endpoint (/auth/login or /auth/setup),
    NOT the legacy /login handler itself.

    When 0 users exist, /login redirects to /setup (action='/auth/setup').
    When >=1 users exist, /login shows email+password form (action='/auth/login').
    Either way, the legacy shared-password handler is NOT served.
    """
    html, status = get_raw("/login")
    assert status == 200
    # Either the email+password login form or the first-time setup form is acceptable.
    # The critical invariant: the legacy shared-password handler is NOT served.
    assert 'action="/auth/login' in html or 'action="/auth/setup' in html, (
        "GET /login form action is not pointing to a new-auth endpoint. "
        "Legacy shared-password handler may be serving /login."
    )
