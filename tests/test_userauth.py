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
        with pytest.raises(ValueError):
            ua.attempt_login("login@example.com", "WrongPassword1")

    def test_nonexistent_user(self):
        ua = _ua()
        with pytest.raises(ValueError):
            ua.attempt_login("noone@example.com", "ValidPassword1")

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
        # Should not raise — no attempts recorded
        ua.check_login_rate("ratetest@example.com")

    def test_limited_after_max_attempts(self):
        ua = _ua()
        email = "ratetest2@example.com"
        for _ in range(5):
            ua.record_login_failure(email)
        with pytest.raises(ua.RateLimitedError):
            ua.check_login_rate(email)

    def test_cleared_after_success(self):
        ua = _ua()
        email = "ratetest3@example.com"
        for _ in range(4):
            ua.record_login_failure(email)
        ua.clear_login_attempts(email)
        # Should not raise after clearing
        ua.check_login_rate(email)

    def test_rate_limited_error_has_retry_after(self):
        ua = _ua()
        email = "ratetest4@example.com"
        for _ in range(10):
            ua.record_login_failure(email)
        with pytest.raises(ua.RateLimitedError) as exc_info:
            ua.check_login_rate(email)
        assert exc_info.value.retry_after > 0

    def test_unlock_clears_lockout(self):
        ua = _ua()
        email = "ratetest5@example.com"
        for _ in range(5):
            ua.record_login_failure(email)
        ua.unlock_login_attempts(email)
        # Should not raise after unlock
        ua.check_login_rate(email)

    def test_per_ip_rate_limit(self):
        ua = _ua()
        email = "ratetest6@example.com"
        ip = "1.2.3.4"
        for _ in range(5):
            ua.record_login_failure(email, ip)
        with pytest.raises(ua.RateLimitedError):
            ua.check_login_rate(email, ip)


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


class TestChangePassword:
    def _setup(self):
        ua = _ua()
        owner = ua.create_user("owner@example.com", "ValidPassword1", "owner")
        token = ua.create_session(owner["id"])
        return ua, owner, token

    def test_change_password_success(self):
        ua, owner, token = self._setup()
        ua.change_password(owner["id"], "ValidPassword1", "NewPassword99", token)
        # Old password should no longer work
        with pytest.raises(ValueError):
            ua.attempt_login("owner@example.com", "ValidPassword1")
        # New password works
        assert ua.attempt_login("owner@example.com", "NewPassword99") is not None

    def test_change_password_keeps_current_session(self):
        ua, owner, token = self._setup()
        # Create a second session to verify it gets deleted
        token2 = ua.create_session(owner["id"])
        ua.change_password(owner["id"], "ValidPassword1", "NewPassword99", token)
        # Current session still valid
        assert ua.get_session_user(token) is not None
        # Other session wiped
        assert ua.get_session_user(token2) is None

    def test_change_password_wrong_current(self):
        ua, owner, token = self._setup()
        import pytest
        with pytest.raises(ValueError) as exc_info:
            ua.change_password(owner["id"], "WrongPassword1", "NewPassword99", token)
        assert str(exc_info.value) == "current_password"

    def test_change_password_policy_violation(self):
        ua, owner, token = self._setup()
        import pytest
        with pytest.raises(ValueError) as exc_info:
            ua.change_password(owner["id"], "ValidPassword1", "short", token)
        assert "12" in str(exc_info.value)

    def test_change_password_no_digit(self):
        ua, owner, token = self._setup()
        import pytest
        with pytest.raises(ValueError) as exc_info:
            ua.change_password(owner["id"], "ValidPassword1", "passwordpassword", token)
        assert "digit" in str(exc_info.value)

    def test_change_password_hash_actually_updated(self):
        ua, owner, token = self._setup()
        old_hash = ua.get_user_by_id(owner["id"])["password_hash"]
        ua.change_password(owner["id"], "ValidPassword1", "NewPassword99", token)
        new_hash = ua.get_user_by_id(owner["id"])["password_hash"]
        assert old_hash != new_hash
        assert ua.verify_password_hash("NewPassword99", new_hash)


class TestResetUserPassword:
    def _setup(self):
        ua = _ua()
        owner = ua.create_user("owner@example.com", "ValidPassword1", "owner")
        admin = ua.create_user("admin@example.com", "ValidPassword1", "admin")
        return ua, owner, admin

    def test_owner_can_reset(self):
        ua, owner, admin = self._setup()
        result = ua.reset_user_password(admin["id"], "owner")
        assert "temp_password" in result
        assert "expires_at" in result
        temp_pw = result["temp_password"]
        assert len(temp_pw) == 16
        # Admin can log in with temp password
        assert ua.attempt_login("admin@example.com", temp_pw) is not None
        # Old password no longer works
        with pytest.raises(ValueError):
            ua.attempt_login("admin@example.com", "ValidPassword1")

    def test_reset_wipes_target_sessions(self):
        ua, owner, admin = self._setup()
        admin_token = ua.create_session(admin["id"])
        ua.reset_user_password(admin["id"], "owner")
        # Admin's sessions wiped
        assert ua.get_session_user(admin_token) is None

    def test_admin_cannot_reset(self):
        ua, owner, admin = self._setup()
        import pytest
        with pytest.raises(PermissionError):
            ua.reset_user_password(owner["id"], "admin")

    def test_reset_nonexistent_user_raises(self):
        ua, owner, admin = self._setup()
        import pytest
        with pytest.raises(KeyError):
            ua.reset_user_password("nonexistent-uuid", "owner")

    def test_temp_password_is_unambiguous(self):
        ua, owner, admin = self._setup()
        result = ua.reset_user_password(admin["id"], "owner")
        temp_pw = result["temp_password"]
        # None of the ambiguous characters: 0, O, 1, l, I
        for ch in "0O1lI":
            assert ch not in temp_pw, f"Ambiguous char {ch!r} found in temp password"

    def test_generate_temp_password_length(self):
        ua = _ua()
        pw = ua.generate_temp_password()
        assert len(pw) == 16

    def test_expires_at_is_roughly_24h(self):
        import time
        ua, owner, admin = self._setup()
        before = int(time.time())
        result = ua.reset_user_password(admin["id"], "owner")
        after = int(time.time())
        assert result["expires_at"] >= before + 86399
        assert result["expires_at"] <= after + 86401
