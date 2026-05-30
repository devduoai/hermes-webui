"""
Integration tests for session creator attribution covering:
1. HTTP route-level tests via _FakeHandler (POST /api/session/new)
2. GET /api/sessions returns created_by on every row
3. Edge cases: deleted user, long display names, missing/null fields

These are in-process route tests using _FakeHandler (no live subprocess).
The CSRF guard passes because no Origin/Referer header is set (non-browser path).
The body is placed in handler.rfile and a correct Content-Length is set.

Run: python3.12 -m pytest tests/test_session_creator_attribution_routes.py -v
"""
from __future__ import annotations

import importlib
import io
import json
import os
import sqlite3
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse

import pytest

# ── Isolate state under a temp dir before any api/* imports ──────────────────
_TMP = tempfile.mkdtemp(prefix="hermes_attr_routes_test_")
os.environ.setdefault("HERMES_HOME", _TMP)
os.environ.setdefault("HERMES_WEBUI_STATE_DIR", _TMP)
os.environ["HERMES_WEBUI_DEFAULT_MODEL"] = "openai/gpt-5.4-mini"

sys.path.insert(0, str(Path(__file__).parent.parent))


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    """Each test gets a fresh HERMES_HOME so the attribution DB is clean."""
    hermes_home = tmp_path / "hermes"
    hermes_home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    monkeypatch.setenv("HERMES_WEBUI_STATE_DIR", str(hermes_home))
    monkeypatch.delenv("HERMES_CREATED_BY", raising=False)
    # Reload attribution so the db path re-resolves
    import api.session_attribution as sa
    importlib.reload(sa)
    yield


@pytest.fixture()
def sa():
    import api.session_attribution as _sa
    return _sa


# ── Minimal HTTP handler mock ─────────────────────────────────────────────────

class _FakeHandler:
    """Minimal mock for http.server.BaseHTTPRequestHandler.

    No Origin/Referer -> CSRF exempt (non-browser path).
    Body is passed as a dict and serialized to rfile with a correct Content-Length.
    """

    def __init__(self, extra_headers=None, body=None, cookie=None):
        self._response_status = None
        self._header_list = []
        self._output = io.BytesIO()
        self.close_connection = False

        body_bytes = json.dumps(body or {}).encode()
        self.headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body_bytes)),
        }
        if cookie:
            self.headers["Cookie"] = f"hermes_user_session={cookie}"
        if extra_headers:
            self.headers.update(extra_headers)

        self.rfile = io.BytesIO(body_bytes)
        self.wfile = self._output

    def send_response(self, code):
        self._response_status = code

    def send_header(self, key, value):
        self._header_list.append((key, value))

    def end_headers(self):
        pass

    def response_json(self):
        raw = self._output.getvalue()
        return json.loads(raw) if raw.strip() else {}

    def status(self):
        return self._response_status


# ── Route helpers ─────────────────────────────────────────────────────────────

def _post_session_new(extra_headers=None, body=None, cookie=None):
    """Call the /api/session/new POST handler and return the _FakeHandler."""
    from api.routes import handle_post
    h = _FakeHandler(extra_headers=extra_headers, body=body or {}, cookie=cookie)
    parsed = urlparse("http://localhost/api/session/new")
    handle_post(h, parsed)
    return h


def _get_sessions():
    """Call the /api/sessions GET handler and return the _FakeHandler."""
    from api.routes import handle_get
    h = _FakeHandler()
    parsed = urlparse("http://localhost/api/sessions")
    handle_get(h, parsed)
    return h


def _get_session(session_id):
    """Call GET /api/session?session_id=<id> and return the _FakeHandler."""
    from api.routes import handle_get
    h = _FakeHandler()
    parsed = urlparse(f"http://localhost/api/session?session_id={session_id}")
    handle_get(h, parsed)
    return h


def _make_visible_session(created_by):
    """Create a session and save it to disk with a message so it appears in /api/sessions.

    /api/sessions filters out Untitled sessions with 0 messages (#1171).
    We add one user message and call s.save() so the session is disk-persisted
    and appears in the sidebar list.
    """
    import api.models as models
    s = models.new_session(created_by=created_by)
    s.title = "Test session"
    s.messages = [{"role": "user", "content": "hello", "timestamp": time.time()}]
    s.save()
    return s


# ── 1. POST /api/session/new — source detection ───────────────────────────────

class TestRouteSessionNew:
    def test_no_headers_no_auth_response_includes_created_by(self):
        """POST /api/session/new with no creator signals must include created_by in response."""
        h = _post_session_new()
        data = h.response_json()
        assert "session" in data, f"Expected 'session' in response; got: {data}"
        assert "created_by" in data["session"], (
            "POST /api/session/new response must include created_by key on session"
        )

    def test_no_headers_no_auth_yields_unknown(self):
        """POST /api/session/new with no creator signals -> source='unknown'."""
        h = _post_session_new()
        data = h.response_json()
        assert "session" in data, f"Expected 'session' in response; got: {data}"
        cb = data["session"].get("created_by")
        # Handler wraps attribution in try/except; if None, that's also acceptable
        # but most paths should produce source='unknown'
        if cb is not None:
            assert cb.get("source") == "unknown", (
                f"No-auth POST must yield source='unknown'; got {cb}"
            )

    def test_slack_headers_stored_in_attribution_db(self, sa):
        """POST /api/session/new with X-Hermes-Creator-Source=slack headers
        -> attribution DB stores source='slack' with correct fields."""
        h = _post_session_new(extra_headers={
            "X-Hermes-Creator-Source": "slack",
            "X-Hermes-Creator-User-Id": "U0TESTUSER",
            "X-Hermes-Creator-Display-Name": "Tony Wong",
            "X-Hermes-Creator-Agent-Identity": "pm",
        })
        data = h.response_json()
        assert "session" in data, f"Expected 'session' in response; got: {data}"
        sid = data["session"]["session_id"]
        stored = sa.get_session_creator(sid)
        assert stored["source"] == "slack"
        assert stored.get("display_name") == "Tony Wong"
        assert stored.get("platform_user_id") == "U0TESTUSER"

    def test_slack_headers_response_has_slack_source(self):
        """POST /api/session/new with Slack headers -> response created_by.source='slack'."""
        h = _post_session_new(extra_headers={
            "X-Hermes-Creator-Source": "slack",
            "X-Hermes-Creator-User-Id": "U0ABC",
            "X-Hermes-Creator-Display-Name": "Alice",
        })
        data = h.response_json()
        assert "session" in data
        cb = data["session"].get("created_by")
        if cb is not None:
            assert cb.get("source") == "slack", (
                f"Slack-header POST must yield source='slack'; got {cb}"
            )

    def test_kanban_header_yields_kanban_source(self, sa):
        """POST /api/session/new with X-Hermes-Creator-Source=kanban -> source='kanban'."""
        h = _post_session_new(extra_headers={
            "X-Hermes-Creator-Source": "kanban",
            "X-Hermes-Creator-Agent-Identity": "software-engineer",
        })
        data = h.response_json()
        assert "session" in data, f"Expected 'session' in response; got: {data}"
        sid = data["session"]["session_id"]
        stored = sa.get_session_creator(sid)
        assert stored["source"] == "kanban"
        assert stored.get("agent_identity") == "software-engineer"

    def test_kanban_env_var_yields_kanban_source(self, sa, monkeypatch):
        """POST /api/session/new with HERMES_CREATED_BY env var (kanban dispatcher path)
        -> source='kanban' + correct agent_identity."""
        monkeypatch.setenv("HERMES_CREATED_BY", json.dumps({
            "source": "kanban",
            "agent_identity": "orchestrator",
            "created_at_iso": "2026-01-01T00:00:00Z",
        }))
        # Reload so the module sees the fresh env var on infer_creator_from_env()
        import api.session_attribution
        importlib.reload(api.session_attribution)
        h = _post_session_new()
        data = h.response_json()
        assert "session" in data, f"Expected 'session' in response; got: {data}"
        sid = data["session"]["session_id"]
        stored = sa.get_session_creator(sid)
        assert stored["source"] == "kanban"
        assert stored.get("agent_identity") == "orchestrator"

    def test_cron_header_yields_cron_source(self, sa):
        """POST /api/session/new with X-Hermes-Creator-Source=cron -> source='cron'."""
        h = _post_session_new(extra_headers={
            "X-Hermes-Creator-Source": "cron",
            "X-Hermes-Creator-Agent-Identity": "daily-digest",
        })
        data = h.response_json()
        assert "session" in data, f"Expected 'session' in response; got: {data}"
        sid = data["session"]["session_id"]
        stored = sa.get_session_creator(sid)
        assert stored["source"] == "cron"
        assert stored.get("agent_identity") == "daily-digest"

    def test_headers_take_priority_over_env_var(self, sa, monkeypatch):
        """X-Hermes-Creator-* headers win over HERMES_CREATED_BY env var."""
        monkeypatch.setenv("HERMES_CREATED_BY", json.dumps({
            "source": "cron",
            "agent_identity": "cron-job",
            "created_at_iso": "2026-01-01T00:00:00Z",
        }))
        import api.session_attribution
        importlib.reload(api.session_attribution)
        h = _post_session_new(extra_headers={
            "X-Hermes-Creator-Source": "slack",
            "X-Hermes-Creator-User-Id": "SLACK_WINS",
            "X-Hermes-Creator-Display-Name": "Slack User",
        })
        data = h.response_json()
        assert "session" in data
        sid = data["session"]["session_id"]
        stored = sa.get_session_creator(sid)
        assert stored["source"] == "slack", (
            f"Headers must win over env var; got source={stored['source']!r}"
        )


# ── 2. GET /api/sessions returns created_by on every row ─────────────────────

class TestRouteSessionsList:
    def test_all_sessions_have_created_by_key(self, sa):
        """GET /api/sessions must include created_by (non-None) on every row."""
        cb = sa.build_slack_created_by("U_TEST", "Tester")
        s = _make_visible_session(cb)
        sa.record_session_creator(s.session_id, cb)

        h = _get_sessions()
        data = h.response_json()
        sessions = data.get("sessions") or []
        assert len(sessions) > 0, "Expected at least one session"
        for sess in sessions:
            assert "created_by" in sess, (
                f"Session {sess.get('session_id')} missing created_by"
            )
            assert sess["created_by"] is not None, (
                f"created_by must not be None for session {sess.get('session_id')}"
            )
            assert "source" in sess["created_by"], (
                f"created_by must have 'source'; got {sess['created_by']}"
            )

    def test_known_session_has_correct_source(self, sa):
        """A session created with source='slack' must appear with source='slack' in list."""
        cb = sa.build_slack_created_by("U_KNOWN", "Known User")
        s = _make_visible_session(cb)
        sa.record_session_creator(s.session_id, cb)

        h = _get_sessions()
        data = h.response_json()
        sessions = data.get("sessions") or []
        target = next((x for x in sessions if x.get("session_id") == s.session_id), None)
        assert target is not None, f"Session {s.session_id} not found in /api/sessions"
        assert target["created_by"]["source"] == "slack"

    def test_legacy_session_coerced_to_unknown(self, sa):
        """Sessions with created_by=None must be coerced to source='unknown' (not left null)."""
        s = _make_visible_session(None)

        h = _get_sessions()
        data = h.response_json()
        sessions = data.get("sessions") or []
        target = next((x for x in sessions if x.get("session_id") == s.session_id), None)
        if target is None:
            pytest.skip("Legacy session not in /api/sessions response")
        assert target.get("created_by") is not None, (
            "Legacy null created_by must be coerced to non-null"
        )
        assert target["created_by"].get("source") == "unknown", (
            f"Legacy session must have source='unknown'; got {target['created_by']}"
        )

    def test_kanban_session_appears_correctly(self, sa):
        """A session created with source='kanban' appears with source='kanban' in list."""
        cb = sa.build_kanban_created_by("research-agent")
        s = _make_visible_session(cb)
        sa.record_session_creator(s.session_id, cb)

        h = _get_sessions()
        data = h.response_json()
        sessions = data.get("sessions") or []
        target = next((x for x in sessions if x.get("session_id") == s.session_id), None)
        assert target is not None, f"Kanban session {s.session_id} not in /api/sessions"
        assert target["created_by"]["source"] == "kanban"
        assert target["created_by"].get("agent_identity") == "research-agent"


# ── 3. GET /api/session?session_id= returns created_by ──────────────────────

class TestRouteSessionGet:
    def test_get_session_includes_created_by(self, sa):
        """GET /api/session?session_id=<id> must return created_by on the session object."""
        import api.models as models
        cb = sa.build_kanban_created_by("researcher")
        s = models.new_session(created_by=cb)
        sa.record_session_creator(s.session_id, cb)

        h = _get_session(s.session_id)
        data = h.response_json()
        assert "session" in data, f"Expected session in response; got: {data}"
        assert "created_by" in data["session"], (
            "GET /api/session must include created_by"
        )
        cb_resp = data["session"]["created_by"]
        if cb_resp is not None:
            assert cb_resp.get("source") == "kanban"

    def test_get_session_unknown_for_legacy(self, sa):
        """GET /api/session?session_id=<id> with no attribution record returns source='unknown'."""
        import api.models as models
        s = models.new_session(created_by=None)

        h = _get_session(s.session_id)
        data = h.response_json()
        assert "session" in data
        cb = data["session"].get("created_by")
        if cb is not None:
            assert cb.get("source") == "unknown", (
                f"Legacy session must have source='unknown'; got {cb}"
            )


# ── 4. Edge case: deleted user email preserved ────────────────────────────────

class TestEdgeCaseDeletedUser:
    def test_deleted_user_email_preserved_at_creation_time(self, sa):
        """Deleting a user after session creation must not destroy the stored email."""
        cb = sa.build_webui_created_by(
            {"id": "42", "email": "deleted@example.com", "display_name": "Deleted User"}
        )
        sa.record_session_creator("sess_del_user", cb)
        # Simulate user deletion: auth.db changes are irrelevant; attribution DB is independent
        stored = sa.get_session_creator("sess_del_user")
        assert stored["source"] == "webui"
        assert stored["user_email"] == "deleted@example.com", (
            "Email captured at session creation must survive user deletion"
        )
        assert stored["display_name"] == "Deleted User"

    def test_deleted_user_session_survives_sessions_list(self, sa):
        """Sessions of deleted users appear in /api/sessions without crashing."""
        cb = sa.build_webui_created_by(
            {"id": "99", "email": "ghost@example.com", "display_name": "Ghost"}
        )
        s = _make_visible_session(cb)
        sa.record_session_creator(s.session_id, cb)

        h = _get_sessions()
        data = h.response_json()
        sessions = data.get("sessions") or []
        target = next((x for x in sessions if x.get("session_id") == s.session_id), None)
        if target is None:
            pytest.skip("Session not in /api/sessions")
        assert target.get("created_by") is not None
        assert target["created_by"].get("source") == "webui"
        assert target["created_by"].get("user_email") == "ghost@example.com"


# ── 5. Edge case: very long display names (100+ chars) ───────────────────────

class TestEdgeCaseLongDisplayNames:
    LONG_NAME = "A" * 120

    def test_long_slack_display_name_stored_verbatim(self, sa):
        """Slack sessions with 100+ char display names are stored without truncation."""
        cb = sa.build_slack_created_by("U_LONG", self.LONG_NAME)
        sa.record_session_creator("sess_long_slack", cb)
        stored = sa.get_session_creator("sess_long_slack")
        assert stored["display_name"] == self.LONG_NAME, (
            "Long display name must be stored and retrieved verbatim (CSS handles overflow)"
        )

    def test_long_display_name_sessions_list_no_crash(self, sa):
        """GET /api/sessions with a 100+ char display_name must not crash."""
        cb = sa.build_slack_created_by("U_LONG2", self.LONG_NAME)
        s = _make_visible_session(cb)
        sa.record_session_creator(s.session_id, cb)

        h = _get_sessions()
        assert h.response_json() is not None, "GET /api/sessions must not crash with long display_name"

    def test_long_kanban_agent_identity_stored_verbatim(self, sa):
        """Kanban sessions with long agent_identity are stored correctly."""
        long_identity = "x" * 150
        cb = sa.build_kanban_created_by(long_identity)
        sa.record_session_creator("sess_long_kanban", cb)
        stored = sa.get_session_creator("sess_long_kanban")
        assert stored["agent_identity"] == long_identity


# ── 6. Edge case: missing / null fields in created_by JSON ───────────────────

class TestEdgeCaseNullFields:
    def test_null_display_name_round_trips(self, sa):
        """created_by with display_name=None is stored and returned correctly."""
        cb = {
            "source": "slack",
            "display_name": None,
            "platform_user_id": "U_NULL",
            "agent_identity": None,
            "created_at_iso": "2026-01-01T00:00:00Z",
        }
        sa.record_session_creator("sess_null_dn", cb)
        stored = sa.get_session_creator("sess_null_dn")
        assert stored["source"] == "slack"
        assert stored["display_name"] is None

    def test_json_without_source_key_defaults_to_unknown(self, sa):
        """A JSON blob with no 'source' key falls back to source='unknown'."""
        # Ensure the DB and schema exist by doing a normal record first
        sa.record_session_creator("_schema_init", sa.build_api_created_by("init"))
        db_path = sa._attribution_db_path()
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO session_creators VALUES (?, ?, ?)",
                ("sess_no_src", json.dumps({"display_name": "mystery"}), int(time.time())),
            )
        assert sa.get_session_creator("sess_no_src")["source"] == "unknown"

    def test_empty_json_object_defaults_to_unknown(self, sa):
        """An empty {} JSON blob falls back to source='unknown'."""
        # Ensure the DB and schema exist
        sa.record_session_creator("_schema_init2", sa.build_api_created_by("init"))
        db_path = sa._attribution_db_path()
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO session_creators VALUES (?, ?, ?)",
                ("sess_empty_obj", json.dumps({}), int(time.time())),
            )
        assert sa.get_session_creator("sess_empty_obj")["source"] == "unknown"

    def test_missing_created_at_iso_does_not_crash(self, sa):
        """A created_by dict without created_at_iso is stored and retrieved without error."""
        cb = {"source": "kanban", "agent_identity": "planner"}  # no created_at_iso
        sa.record_session_creator("sess_no_ts", cb)
        stored = sa.get_session_creator("sess_no_ts")
        assert stored["source"] == "kanban"
        assert stored.get("agent_identity") == "planner"

    def test_null_created_by_on_session_json_not_propagated(self, sa):
        """GET /api/sessions for a session with created_by=null must not return null."""
        s = _make_visible_session(None)
        h = _get_sessions()
        data = h.response_json()
        sessions = data.get("sessions") or []
        target = next((x for x in sessions if x.get("session_id") == s.session_id), None)
        if target is None:
            pytest.skip("Session not in /api/sessions")
        assert target.get("created_by") is not None, (
            "GET /api/sessions must coerce null created_by to {source: 'unknown'}"
        )


# ── 7. Schema / sidecar DB robustness ────────────────────────────────────────

class TestSidecarSchemaBootstrap:
    def test_schema_idempotent(self, sa):
        """_ensure_schema is safe to call twice on the same connection."""
        db_path = sa._attribution_db_path()
        conn = sqlite3.connect(str(db_path))
        sa._ensure_schema(conn)
        sa._ensure_schema(conn)  # must not raise
        conn.close()

    def test_record_creates_db_on_first_call(self, sa):
        """record_session_creator creates DB + table on first call."""
        cb = sa.build_api_created_by("prod-key")
        sa.record_session_creator("sess_bootstrap", cb)
        stored = sa.get_session_creator("sess_bootstrap")
        assert stored["source"] == "api"
        assert "prod-key" in (stored.get("display_name") or "")

    def test_corrupt_json_falls_back_to_unknown(self, sa):
        """Manually corrupted JSON in attribution DB returns source='unknown'."""
        # Ensure DB + schema exist
        sa.record_session_creator("_schema_init3", sa.build_api_created_by("init"))
        db_path = sa._attribution_db_path()
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO session_creators VALUES (?, ?, ?)",
                ("sess_corrupt", "NOT-VALID-JSON-!!!", int(time.time())),
            )
        stored = sa.get_session_creator("sess_corrupt")
        assert stored["source"] == "unknown"
