"""
Tests for B4 fix: owner-setup race condition.

Verifies that concurrent POST /auth/setup requests cannot create two Owner
accounts (BEGIN EXCLUSIVE transaction fix in setup_first_owner).

Run with: python3 -m pytest tests/test_owner_setup_race_b4.py -v
"""
import os
import sys
import tempfile
import threading
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Isolate test state from any real Hermes install
# ---------------------------------------------------------------------------
_TMP = tempfile.mkdtemp(prefix="hermes_b4_race_test_")
os.environ["HERMES_WEBUI_STATE_DIR"] = _TMP
os.environ["HERMES_USERAUTH"] = "1"
os.environ["HERMES_WEBUI_PASSWORD"] = ""

sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    """Each test gets an isolated auth.db."""
    import api.userauth as ua

    db = tmp_path / "auth.db"
    monkeypatch.setattr(ua, "_db_path", lambda: db)
    yield


def _ua():
    import api.userauth as ua

    return ua


# ---------------------------------------------------------------------------
# Unit tests for setup_first_owner
# ---------------------------------------------------------------------------


class TestSetupFirstOwner:
    def test_creates_owner_on_empty_db(self):
        ua = _ua()
        user = ua.setup_first_owner("owner@example.com", "ValidPassword1")
        assert user["email"] == "owner@example.com"
        assert user["role"] == "owner"
        assert "id" in user
        assert ua.user_count() == 1

    def test_sequential_second_call_raises_already_setup(self):
        """After one Owner exists, a second call raises AlreadySetupError."""
        ua = _ua()
        ua.setup_first_owner("first@example.com", "ValidPassword1")
        with pytest.raises(ua.AlreadySetupError):
            ua.setup_first_owner("second@example.com", "AnotherPass1")
        # Still only one owner in the DB
        assert ua.user_count() == 1

    def test_invalid_email_raises_value_error(self):
        ua = _ua()
        with pytest.raises(ValueError, match="Invalid email"):
            ua.setup_first_owner("not-an-email", "ValidPassword1")

    def test_weak_password_raises_value_error(self):
        ua = _ua()
        with pytest.raises(ValueError):
            ua.setup_first_owner("owner@example.com", "short")

    def test_concurrent_setup_creates_exactly_one_owner(self):
        """
        Two threads race to call setup_first_owner at the same time.
        Exactly one should succeed; the other must raise AlreadySetupError.
        BEGIN EXCLUSIVE guarantees no duplicate Owner rows.
        """
        ua = _ua()

        results = []
        errors = []

        def attempt(email, password):
            try:
                user = ua.setup_first_owner(email, password)
                results.append(user)
            except ua.AlreadySetupError as exc:
                errors.append(exc)
            except Exception as exc:
                errors.append(exc)

        t1 = threading.Thread(target=attempt, args=("racer1@example.com", "ValidPassword1"))
        t2 = threading.Thread(target=attempt, args=("racer2@example.com", "ValidPassword1"))

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # Exactly one success, one AlreadySetupError
        assert len(results) == 1, (
            f"Expected 1 successful setup, got {len(results)}. errors={errors}"
        )
        assert len(errors) == 1, (
            f"Expected 1 AlreadySetupError, got {len(errors)}. results={results}"
        )
        assert isinstance(errors[0], ua.AlreadySetupError), (
            f"Expected AlreadySetupError, got {type(errors[0])}: {errors[0]}"
        )

        # DB must contain exactly one owner
        assert ua.user_count() == 1, (
            f"Race created {ua.user_count()} users — duplicate Owner detected!"
        )
        assert ua.owner_count() == 1, (
            f"Race created {ua.owner_count()} owners — race condition not fixed!"
        )
