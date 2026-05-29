"""
Unit tests for api/userauth.py -- per-user auth backend.

Run with: python3.12 -m pytest tests/test_userauth.py -v
"""
import os
import sys
import tempfile
import time
from pathlib import Path

import pytest

# Isolate test state
_TMP = tempfile.mkdtemp(prefix="hermes_userauth_test_")
os.environ["HERMES_WEBUI_STATE_DIR"] = _TMP
os.environ["HERMES_USERAUTH"] = "1"  # force per-user auth active
os.environ["HERMES_WEBUI_PASSWORD"] = ""

sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    """Give each test a clean auth.db."""
    import api.userauth as ua
    db = tmp_path / "auth.db"
    monkeypatch.setattr(ua, "_db_path", lambda: db)
    yield


def _ua():
    import api.userauth as ua
    return ua


class TestPasswordValidation:
    def test_too_short(self):
        ua = _ua()
        err = ua.validate_password("short1")
        assert err is not None
        assert "12" in err

    def test_no_digit(self):
        ua = _ua()
        err = ua.validate_password("passwordpassword")
        assert err is not None
        assert "digit" in err

    def test_no_letter(self):
        ua = _ua()
        err = ua.validate_password("123456789012")
        assert err is not None
        assert "letter" in err

    def test_valid(self):
        ua = _ua()
        assert ua.validate_password("ValidPassword1") is None

    def test_passphrase(self):
        ua = _ua()
        assert ua.validate_password("correct horse battery staple 1") is None


class TestUserManagement:
    def test_create_and_get_user(self):
        ua = _ua()
        user = ua.create_user("test@example.com", "ValidPassword1", "owner")
        assert user["email"] == "test@example.com"
        assert user["role"] == "owner"
        assert "id" in user

        fetched = ua.get_user_by_email("test@example.com")
        assert fetched is not None
        assert fetched["email"] == "test@example.com"
        assert "password_hash" in fetched

    def test_email_normalization(self):
        ua = _ua()
        ua.create_user("UPPER@EXAMPLE.COM", "ValidPassword1", "admin")
        user = ua.get_user_by_email("upper@example.com")
        assert user is not None

    def test_duplicate_email_raises(self):
        import sqlite3
        ua = _ua()
        ua.create_user("dup@example.com", "ValidPassword1", "owner")
        with pytest.raises(sqlite3.IntegrityError):
            ua.create_user("dup@example.com", "AnotherPass1", "admin")

    def test_user_count(self):
        ua = _ua()
        assert ua.user_count() == 0
        ua.create_user("a@example.com", "ValidPassword1", "owner")
        assert ua.user_count() == 1
        ua.create_user("b@example.com", "ValidPassword1", "admin")
        assert ua.user_count() == 2

    def test_list_users(self):
        ua = _ua()
        ua.create_user("alice@example.com", "ValidPassword1", "owner")
        ua.create_user("bob@example.com", "ValidPassword1", "admin")
        users = ua.list_users()
        assert len(users) == 2
        emails = [u["email"] for u in users]
        assert "alice@example.com" in emails
        assert "bob@example.com" in emails

    def test_delete_user(self):
        ua = _ua()
        ua.create_user("owner@example.com", "ValidPassword1", "owner")
        admin = ua.create_user("admin@example.com", "ValidPassword1", "admin")
        ua.delete_user(admin["id"])
        assert ua.get_user_by_id(admin["id"]) is None

    def test_cannot_delete_last_owner(self):
        ua = _ua()
        owner = ua.create_user("owner@example.com", "ValidPassword1", "owner")
        with pytest.raises(ValueError, match="last Owner"):
            ua.delete_user(owner["id"])

    def test_can_delete_owner_if_another_exists(self):
        ua = _ua()
        o1 = ua.create_user("owner1@example.com", "ValidPassword1", "owner")
        ua.create_user("owner2@example.com", "ValidPassword1", "owner")
        ua.delete_user(o1["id"])
        assert ua.user_count() == 1


class TestPasswordHashing:
    def test_hash_and_verify(self):
        ua = _ua()
        h = ua.hash_password("ValidPassword1")
        assert ua.verify_password_hash("ValidPassword1", h)
        assert not ua.verify_password_hash("wrongpassword", h)

    def test_different_users_different_hashes(self):
        ua = _ua()
        h1 = ua.hash_password("ValidPassword1")
        h2 = ua.hash_password("ValidPassword1")
        # bcrypt uses random salt — hashes must differ
        assert h1 != h2


class TestSessions:
    def test_create_and_verify(self):
        ua = _ua()
        user = ua.create_user("u@example.com", "ValidPassword1", "owner")
        token = ua.create_session(user["id"])
        assert token is not None
        result = ua.get_session_user(token)
        assert result is not None
        assert result["email"] == "u@example.com"

    def test_delete_session(self):
        ua = _ua()
        user = ua.create_user("u@example.com", "ValidPassword1", "owner")
        token = ua.create_session(user["id"])
        ua.delete_session(token)
        assert ua.get_session_user(token) is None

    def test_expired_session_returns_none(self, monkeypatch):
        ua = _ua()
        # Monkeypatch time to create an already-expired session
        past = int(time.time()) - 1
        user = ua.create_user("u@example.com", "ValidPassword1", "owner")
        token = ua.create_session(user["id"])
        # Manually expire the session in the DB
        with ua._conn() as con:
            con.execute("UPDATE sessions SET expires_at=? WHERE id=?", (past, token))
            con.commit()
        assert ua.get_session_user(token) is None

    def test_invalid_token_returns_none(self):
        ua = _ua()
        assert ua.get_session_user("nonexistent_token_xyz") is None


class TestLogin:
    def test_successful_login(self):
        ua = _ua()
        ua.create_user("login@example.com", "ValidPassword1", "owner")
        result = ua.attempt_login("login@example.com", "ValidPassword1")
        assert result is not None
        assert result["email"] == "login@example.com"

    def test_wrong_password(self):
        ua = _ua()
        ua.create_user("login@example.com", "ValidPassword1", "owner")
        result = ua.attempt_login("login@example.com", "WrongPassword1")
        assert result is None

    def test_nonexistent_user(self):
        ua = _ua()
        result = ua.attempt_login("noone@example.com", "ValidPassword1")
        assert result is None

    def test_case_insensitive_email(self):
        ua = _ua()
        ua.create_user("MIXED@example.com", "ValidPassword1", "owner")
        result = ua.attempt_login("mixed@EXAMPLE.COM", "ValidPassword1")
        assert result is not None


class TestInvites:
    def _make_owner(self):
        ua = _ua()
        return ua.create_user("owner@example.com", "ValidPassword1", "owner")

    def test_create_invite(self):
        ua = _ua()
        owner = self._make_owner()
        invite = ua.create_invite("new@example.com", "admin", owner["id"])
        assert invite["email"] == "new@example.com"
        assert invite["role"] == "admin"
        assert len(invite["token"]) > 20

    def test_invite_existing_user_raises(self):
        ua = _ua()
        owner = self._make_owner()
        ua.create_user("existing@example.com", "ValidPassword1", "admin")
        with pytest.raises(ValueError, match="already exists"):
            ua.create_invite("existing@example.com", "admin", owner["id"])

    def test_duplicate_invite_silently_replaced(self):
        ua = _ua()
        owner = self._make_owner()
        i1 = ua.create_invite("new@example.com", "admin", owner["id"])
        i2 = ua.create_invite("new@example.com", "admin", owner["id"])
        assert i1["token"] != i2["token"]  # new token issued
        # Old token should not be found
        assert ua.get_invite_by_token(i1["token"]) is None

    def test_redeem_invite(self):
        ua = _ua()
        owner = self._make_owner()
        invite = ua.create_invite("invitee@example.com", "admin", owner["id"])
        user = ua.redeem_invite(invite["token"], "InviteePass1")
        assert user["email"] == "invitee@example.com"
        assert user["role"] == "admin"
        # Can now log in
        result = ua.attempt_login("invitee@example.com", "InviteePass1")
        assert result is not None

    def test_redeem_twice_raises(self):
        ua = _ua()
        owner = self._make_owner()
        invite = ua.create_invite("invitee@example.com", "admin", owner["id"])
        ua.redeem_invite(invite["token"], "InviteePass1")
        with pytest.raises(ValueError, match="already been used"):
            ua.redeem_invite(invite["token"], "InviteePass2")

    def test_expired_invite_raises(self):
        ua = _ua()
        owner = self._make_owner()
        invite = ua.create_invite("new@example.com", "admin", owner["id"])
        # Manually expire
        with ua._conn() as con:
            con.execute(
                "UPDATE invites SET expires_at=? WHERE token=?",
                (int(time.time()) - 1, invite["token"]),
            )
            con.commit()
        with pytest.raises(ValueError, match="expired"):
            ua.redeem_invite(invite["token"], "ValidPass1!")

    def test_owner_sees_all_invites(self):
        ua = _ua()
        owner = self._make_owner()
        ua.create_invite("a@example.com", "admin", owner["id"])
        ua.create_invite("b@example.com", "admin", owner["id"])
        invites = ua.list_invites(viewer_user_id=owner["id"], viewer_role="owner")
        assert len(invites) == 2

    def test_admin_sees_own_invites_only(self):
        ua = _ua()
        owner = self._make_owner()
        admin = ua.create_user("admin@example.com", "ValidPassword1", "admin")
        ua.create_invite("a@example.com", "admin", owner["id"])
        ua.create_invite("b@example.com", "admin", admin["id"])
        invites = ua.list_invites(viewer_user_id=admin["id"], viewer_role="admin")
        assert len(invites) == 1
        assert invites[0]["email"] == "b@example.com"

    def test_revoke_invite(self):
        ua = _ua()
        owner = self._make_owner()
        invite = ua.create_invite("new@example.com", "admin", owner["id"])
        ua.revoke_invite(invite["id"], owner["id"], "owner")
        assert ua.get_invite_by_token(invite["token"]) is None

    def test_admin_cannot_revoke_others_invite(self):
        ua = _ua()
        owner = self._make_owner()
        admin = ua.create_user("admin@example.com", "ValidPassword1", "admin")
        invite = ua.create_invite("new@example.com", "admin", owner["id"])
        with pytest.raises(ValueError, match="own invites"):
            ua.revoke_invite(invite["id"], admin["id"], "admin")


class TestRateLimit:
    def test_initial_not_limited(self):
        ua = _ua()
        assert ua.check_login_rate("ratetest@example.com") is True

    def test_limited_after_max_attempts(self):
        ua = _ua()
        email = "ratetest2@example.com"
        for _ in range(5):
            ua.record_login_failure(email)
        assert ua.check_login_rate(email) is False

    def test_cleared_after_success(self):
        ua = _ua()
        email = "ratetest3@example.com"
        for _ in range(4):
            ua.record_login_failure(email)
        ua.clear_login_attempts(email)
        assert ua.check_login_rate(email) is True


class TestIsUserauthActive:
    def test_active_when_no_password_set(self):
        import os
        os.environ["HERMES_WEBUI_PASSWORD"] = ""
        ua = _ua()
        # Already set HERMES_USERAUTH=1 in env at top, so should be True
        assert ua.is_userauth_active() is True

    def test_opt_out_via_env(self, monkeypatch):
        monkeypatch.setenv("HERMES_USERAUTH", "0")
        # Need to reload the module-level check
        ua = _ua()
        assert ua.is_userauth_active() is False

    def test_opt_in_via_env(self, monkeypatch):
        monkeypatch.setenv("HERMES_USERAUTH", "1")
        ua = _ua()
        assert ua.is_userauth_active() is True
