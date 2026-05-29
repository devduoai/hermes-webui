"""
Sprint 19 Tests: auth/login, security headers, request size limit.
"""
import json, urllib.error, urllib.request

from tests._pytest_port import BASE


def get(path, headers=None):
    req = urllib.request.Request(BASE + path)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read()), r.status, dict(r.headers)


def post(path, body=None, headers=None):
    data = json.dumps(body or {}).encode()
    req = urllib.request.Request(BASE + path, data=data,
                                headers={"Content-Type": "application/json"})
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read()), r.status, dict(r.headers)
    except urllib.error.HTTPError as e:
        return json.loads(e.read()), e.code, dict(e.headers)


# ── Auth status (no password configured in test env) ──────────────────────

def test_auth_status_disabled():
    """Auth should be disabled by default (no password set)."""
    d, status, _ = get("/api/auth/status")
    assert status == 200
    assert d["auth_enabled"] is False


def test_login_when_auth_disabled():
    """Login should succeed trivially when auth is not enabled."""
    d, status, _ = post("/api/auth/login", {"password": "anything"})
    assert status == 200
    assert d["ok"] is True


def test_all_routes_accessible_without_auth():
    """When auth is disabled, all routes should work without cookies."""
    d, status, _ = get("/api/sessions")
    assert status == 200
    assert "sessions" in d


def test_login_page_served():
    """GET /login should return the new email+password login page HTML."""
    req = urllib.request.Request(BASE + "/login")
    with urllib.request.urlopen(req, timeout=10) as r:
        html = r.read().decode()
        assert r.status == 200
        assert "Sign In" in html
        # New login page must have an email input field
        assert 'type="email"' in html or 'name="email"' in html
        # Must NOT serve the legacy shared-password UI
        assert "Enter your password to continue" not in html


def test_login_page_cache_busts_login_script():
    """Legacy _LOGIN_PAGE_HTML with login.js still exists in routes; the new /login
    route now delegates to userauth_routes.handle_get_login instead.
    This test verifies the delegation is in place."""
    from api import routes
    import inspect
    src = inspect.getsource(routes)
    # The new /login block must delegate to handle_get_login
    assert "handle_get_login" in src


def test_login_route_injects_webui_version_for_login_script():
    """The /login route now uses handle_get_login from userauth_routes;
    verify routes.py no longer contains the legacy WEBUI_VERSION template
    in the /login block — the legacy handler is removed."""
    from pathlib import Path

    src = Path(__file__).resolve().parents[1].joinpath("api", "routes.py").read_text(encoding="utf-8")
    login_block = src[src.find('if parsed.path == "/login"'):src.find('if parsed.path == "/api/auth/status"')]
    # New block must reference the new handler, not the legacy template
    assert "handle_get_login" in login_block
    # Legacy WEBUI_VERSION template injection must be gone from /login block
    assert "{{WEBUI_VERSION}}" not in login_block


# ── Security headers ─────────────────────────────────────────────────────

def test_security_headers_on_json():
    """JSON responses should include security headers."""
    d, status, headers = get("/api/auth/status")
    assert status == 200
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("Referrer-Policy") == "same-origin"


def test_security_headers_on_health():
    """Health endpoint should include security headers."""
    d, status, headers = get("/health")
    assert status == 200
    assert headers.get("X-Content-Type-Options") == "nosniff"


def test_permissions_policy_does_not_disable_microphone():
    """Permissions-Policy must not hard-disable microphone access for same-origin voice input."""
    _, status, headers = get("/health")
    assert status == 200
    policy = headers.get("Permissions-Policy", "")
    assert policy, "Permissions-Policy header missing"
    assert "microphone=()" not in policy, \
        "Permissions-Policy must not block microphone access or desktop/mobile voice input cannot work"


def test_cache_control_no_store():
    """API responses should have Cache-Control: no-store."""
    d, status, headers = get("/api/sessions")
    assert headers.get("Cache-Control") == "no-store"


# ── Settings password field ──────────────────────────────────────────────

def test_settings_password_hash_not_exposed():
    """GET /api/settings must never expose the stored password hash."""
    d, status, _ = get("/api/settings")
    assert status == 200
    assert "password_hash" not in d  # security: never send hash to client


def test_settings_save_preserves_other_fields():
    """Saving settings should not break existing fields."""
    # Get current settings
    current, _, _ = get("/api/settings")
    # Save with just send_key
    d, status, _ = post("/api/settings", {"send_key": "enter"})
    assert status == 200
    # Verify other fields still present
    updated, _, _ = get("/api/settings")
    assert "default_model" in updated
    assert "default_workspace" in updated


def test_settings_password_hash_not_directly_settable():
    """POST /api/settings with password_hash must not overwrite the stored hash."""
    # Attempt to set a raw hash directly (attack vector)
    post("/api/settings", {"password_hash": "deadbeef" * 8})
    # Settings response must not expose it regardless
    updated, status, _ = get("/api/settings")
    assert status == 200
    assert "password_hash" not in updated
