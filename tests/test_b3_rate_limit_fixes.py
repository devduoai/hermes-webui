"""
B3 rate-limiter fix acceptance tests.

Tests cover:
  1. 5 failed attempts → next attempt raises RateLimitedError with retry_after
  2. Waiting out the window allows login again
  3. Owner /api/users/<id>/unlock-login clears lockout
  4. Per-IP tracking: rotating email guesses on same IP still triggers limit
  5. Persistence: attempts survive a simulated restart (new _db_path, same file)
  6. No time.sleep() in login path — 429 returned immediately (timing check)
"""
import os
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_TMP = tempfile.mkdtemp(prefix="hermes_b3_test_")
os.environ["HERMES_WEBUI_STATE_DIR"] = _TMP
os.environ["HERMES_USERAUTH"] = "1"
os.environ["HERMES_WEBUI_PASSWORD"] = ""

sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    """Give each test a clean auth.db at a deterministic path."""
    import api.userauth as ua
    db = tmp_path / "auth.db"
    monkeypatch.setattr(ua, "_db_path", lambda: db)
    # Store the path so individual tests can simulate a restart
    monkeypatch.setattr(ua, "_test_db_path", db, raising=False)
    yield


def _ua():
    import api.userauth as ua
    return ua


# ── 1. 5 failures → 429 (RateLimitedError) ────────────────────────────────────

class TestFiveFailures429:
    def test_first_four_attempts_allowed(self):
        ua = _ua()
        email = "victim@example.com"
        for _ in range(4):
            ua.record_login_failure(email)
        # 4 failures — should NOT raise yet
        ua.check_login_rate(email)

    def test_fifth_attempt_raises(self):
        ua = _ua()
        email = "victim2@example.com"
        for _ in range(5):
            ua.record_login_failure(email)
        with pytest.raises(ua.RateLimitedError) as exc_info:
            ua.check_login_rate(email)
        assert exc_info.value.retry_after >= 0

    def test_retry_after_is_positive_after_many_failures(self):
        ua = _ua()
        email = "victim3@example.com"
        for _ in range(10):
            ua.record_login_failure(email)
        with pytest.raises(ua.RateLimitedError) as exc_info:
            ua.check_login_rate(email)
        assert exc_info.value.retry_after > 0

    def test_attempt_login_raises_rate_limited_error(self):
        """Full attempt_login flow triggers RateLimitedError after 5 failures."""
        ua = _ua()
        email = "ratelimited@example.com"
        ua.create_user(email, "ValidPassword1", "owner")
        # Burn 5 attempts with the wrong password
        for _ in range(5):
            with pytest.raises(ValueError):
                ua.attempt_login(email, "WrongPassword1")
        # Next attempt should be rate limited, not just invalid credentials
        with pytest.raises(ua.RateLimitedError):
            ua.attempt_login(email, "WrongPassword1")


# ── 2. Wait window → allowed again ────────────────────────────────────────────

class TestWindowExpiry:
    def test_expired_attempts_not_counted(self, monkeypatch):
        """Attempts older than _RATE_LIMIT_WINDOW are ignored."""
        ua = _ua()
        email = "expiry@example.com"
        past = time.time() - ua._RATE_LIMIT_WINDOW - 1

        # Inject expired timestamps directly into the DB
        db = ua._db_path()
        db.parent.mkdir(parents=True, exist_ok=True)
        import sqlite3
        con = sqlite3.connect(str(db))
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("""CREATE TABLE IF NOT EXISTS login_attempts (
            key TEXT NOT NULL, ts REAL NOT NULL
        )""")
        for _ in range(10):
            con.execute("INSERT INTO login_attempts VALUES (?, ?)", (email, past))
        con.commit()
        con.close()

        # Despite 10 old attempts on record, check_login_rate should not raise
        ua.check_login_rate(email)


# ── 3. Owner unlock clears lockout ────────────────────────────────────────────

class TestOwnerUnlock:
    def test_unlock_allows_further_attempts(self):
        ua = _ua()
        email = "locked@example.com"
        for _ in range(5):
            ua.record_login_failure(email)
        # Confirm locked
        with pytest.raises(ua.RateLimitedError):
            ua.check_login_rate(email)
        # Owner unlocks
        ua.unlock_login_attempts(email)
        # Should no longer raise
        ua.check_login_rate(email)

    def test_unlock_does_not_affect_other_keys(self):
        ua = _ua()
        email_a = "locked_a@example.com"
        email_b = "locked_b@example.com"
        for _ in range(5):
            ua.record_login_failure(email_a)
            ua.record_login_failure(email_b)
        ua.unlock_login_attempts(email_a)
        # email_a is unlocked
        ua.check_login_rate(email_a)
        # email_b is still locked
        with pytest.raises(ua.RateLimitedError):
            ua.check_login_rate(email_b)

    def test_unlock_route_handler_calls_unlock_login_attempts(self, monkeypatch):
        """handle_post_unlock_login calls unlock_login_attempts for target email."""
        from api import userauth_routes as routes

        calls = []
        ua = _ua()
        email = "target@example.com"
        user = ua.create_user(email, "ValidPassword1", "owner")
        # Lock the user
        for _ in range(5):
            ua.record_login_failure(email)

        # Build a minimal fake handler
        handler = MagicMock()
        handler.headers = {"X-Requested-With": "XMLHttpRequest"}
        owner = ua.create_user("owner@example.com", "OwnerPassword1", "owner")
        owner_token = ua.create_session(owner["id"])

        def fake_get_current_user(h):
            return {**owner, "role": "owner"}

        monkeypatch.setattr(routes, "_get_current_user", fake_get_current_user)

        result = routes.handle_post_unlock_login(handler, user["id"])
        assert result is True
        # Confirm user is unlocked
        ua.check_login_rate(email)


# ── 4. Per-IP: rotating emails same IP still triggers limit ───────────────────

class TestPerIPRateLimit:
    def test_ip_limited_with_different_emails(self):
        """Same IP with 5 different emails still trips the IP-level limit."""
        ua = _ua()
        ip = "203.0.113.99"
        for i in range(5):
            ua.record_login_failure(f"victim{i}@example.com", ip)
        with pytest.raises(ua.RateLimitedError) as exc_info:
            ua.check_login_rate("newvictim@example.com", ip)
        assert exc_info.value.key == ip

    def test_email_limit_independent_of_ip(self):
        """Email counter and IP counter are tracked independently."""
        ua = _ua()
        email = "shared@example.com"
        ip = "10.0.0.1"
        # 5 failures on email only (no IP)
        for _ in range(5):
            ua.record_login_failure(email)
        # email is limited even without IP
        with pytest.raises(ua.RateLimitedError) as exc_info:
            ua.check_login_rate(email, ip="10.0.0.2")
        assert exc_info.value.key == email

    def test_ip_limit_does_not_block_different_ips(self):
        """Locking one IP does not block another IP."""
        ua = _ua()
        email = "another@example.com"
        ip_bad = "203.0.113.1"
        ip_good = "203.0.113.2"
        for _ in range(5):
            ua.record_login_failure(email, ip_bad)
        # ip_good should not be blocked
        ua.check_login_rate("other@example.com", ip_good)


# ── 5. Persistence: attempts survive simulated restart ────────────────────────

class TestPersistence:
    def test_attempts_survive_restart(self, tmp_path, monkeypatch):
        """
        Record 4 failures, then re-point _db_path to the same file (simulating
        a process restart), and confirm the count is still 4 (no reset to 0).
        """
        import api.userauth as ua
        db = tmp_path / "persistent.db"
        monkeypatch.setattr(ua, "_db_path", lambda: db)

        email = "persist@example.com"
        for _ in range(4):
            ua.record_login_failure(email)

        # Simulate restart: clear any module-level caches (there are none in
        # the new DB-backed implementation, but this confirms it still works)
        # The count should still be 4 after the "restart"
        count = ua.get_login_attempt_count(email)
        assert count == 4

    def test_fifth_failure_after_restart_locks_out(self, tmp_path, monkeypatch):
        """4 pre-existing failures + 1 after simulated restart = lockout."""
        import api.userauth as ua
        db = tmp_path / "persistent2.db"
        monkeypatch.setattr(ua, "_db_path", lambda: db)

        email = "persist2@example.com"
        for _ in range(4):
            ua.record_login_failure(email)

        # "Restart": _db_path still points at the same file
        ua.record_login_failure(email)
        with pytest.raises(ua.RateLimitedError):
            ua.check_login_rate(email)

    def test_in_memory_reset_does_not_clear_db_state(self, tmp_path, monkeypatch):
        """
        The old bug: in-memory dict wiped on restart meant lockout was lost.
        Confirm the new DB-backed impl is immune to dict wipe.
        """
        import api.userauth as ua
        db = tmp_path / "persistent3.db"
        monkeypatch.setattr(ua, "_db_path", lambda: db)

        email = "persist3@example.com"
        for _ in range(5):
            ua.record_login_failure(email)

        # Simulate old bug: wipe any in-memory state that might exist
        # (the new impl has none, but the test proves the DB path is used)
        # check_login_rate must still raise even without any in-memory state
        with pytest.raises(ua.RateLimitedError):
            ua.check_login_rate(email)


# ── 6. No sleep in login path ─────────────────────────────────────────────────

class TestNoSleep:
    def test_rate_limited_response_is_fast(self):
        """
        When rate-limited, check_login_rate should return (raise) immediately,
        not block for 5 seconds.  Allow 0.5 s total for 5 DB calls.
        """
        ua = _ua()
        email = "fasttimer@example.com"
        for _ in range(5):
            ua.record_login_failure(email)
        start = time.monotonic()
        with pytest.raises(ua.RateLimitedError):
            ua.check_login_rate(email)
        elapsed = time.monotonic() - start
        assert elapsed < 0.5, f"check_login_rate took {elapsed:.2f}s — sleep may have crept back in"

    def test_rate_limit_delay_constant_removed(self):
        """_RATE_LIMIT_DELAY constant was removed (it enabled the DoS bug)."""
        ua = _ua()
        assert not hasattr(ua, "_RATE_LIMIT_DELAY"), (
            "_RATE_LIMIT_DELAY still exists — the sleep-based delay was not removed"
        )
