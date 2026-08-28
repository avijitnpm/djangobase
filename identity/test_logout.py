import os
import uuid
from unittest.mock import AsyncMock, patch

from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model

from identity.session import SESSION_KEY, set_authenticated_user, is_authenticated, get_authenticated_user_id
from identity.views import SESSION_STATE, SESSION_VERIFIER, SESSION_NONCE


@override_settings(
    KINDE_CLIENT_ID="test_client",
    KINDE_CLIENT_SECRET="secret123",
    KINDE_HOST="https://test.kinde.com",
    KINDE_REDIRECT_URI="http://localhost:8000/auth/callback",
)
class LogoutTests(TestCase):
    def setUp(self):
        os.environ["KINDE_CLIENT_ID"] = "test_client"
        os.environ["KINDE_CLIENT_SECRET"] = "secret123"
        os.environ["KINDE_HOST"] = "https://test.kinde.com"
        os.environ["KINDE_REDIRECT_URI"] = "http://localhost:8000/auth/callback"

    def _login(self):
        User = get_user_model()
        u = User.objects.create(username="logout_user")
        s = self.client.session
        s[SESSION_KEY] = str(u.id)
        s[SESSION_STATE] = "some_state"
        s[SESSION_VERIFIER] = "some_verifier"
        s.save()
        return u

    def test_authenticated_user_can_logout(self):
        self._login()
        resp = self.client.get("/auth/logout")
        self.assertEqual(resp.status_code, 302)

    def test_local_session_no_longer_authenticates(self):
        u = self._login()
        self.client.get("/auth/logout")
        sess = self.client.session
        self.assertNotIn(SESSION_KEY, sess)
        self.assertFalse(is_authenticated(self._fake_request_from_session(sess)))

    def test_protected_state_not_available_after_logout(self):
        self._login()
        self.client.get("/auth/logout")
        sess = self.client.session
        self.assertNotIn(SESSION_STATE, sess)
        self.assertNotIn(SESSION_VERIFIER, sess)
        self.assertNotIn(SESSION_NONCE, sess)

    def test_invalid_session_fails_closed(self):
        s = self.client.session
        s[SESSION_KEY] = "not-a-uuid"
        s.save()
        req = self._fake_request_from_session(s)
        self.assertFalse(is_authenticated(req))
        self.assertIsNone(get_authenticated_user_id(req))

    def test_expired_session_fails_closed(self):
        # expired = empty session
        s = self.client.session
        s.save()
        req = self._fake_request_from_session(s)
        self.assertFalse(is_authenticated(req))

    def test_malformed_session_fails_closed(self):
        for bad in ["", "123", "null", "{}", "00000000-0000-0000-0000-000000000000-xxx"]:
            s = self.client.session
            s[SESSION_KEY] = bad
            s.save()
            req = self._fake_request_from_session(s)
            self.assertIsNone(get_authenticated_user_id(req))
            self.assertFalse(is_authenticated(req))

    def test_repeated_logout_safe(self):
        self._login()
        r1 = self.client.get("/auth/logout")
        r2 = self.client.get("/auth/logout")
        self.assertEqual(r1.status_code, 302)
        self.assertEqual(r2.status_code, 302)
        self.assertNotIn(SESSION_KEY, self.client.session)

    def test_logout_does_not_affect_other_user(self):
        u1 = self._login()
        # create second client
        from django.test import Client
        c2 = Client()
        User = get_user_model()
        u2 = User.objects.create(username="other_user")
        s2 = c2.session
        s2[SESSION_KEY] = str(u2.id)
        s2.save()
        self.client.get("/auth/logout")
        # u2 still authenticated in c2
        s2_after = c2.session
        self.assertEqual(s2_after[SESSION_KEY], str(u2.id))
        self.assertNotIn(SESSION_KEY, self.client.session)

    def test_provider_logout_destination_correct(self):
        self._login()
        mock = AsyncMock()
        mock.logout = AsyncMock(return_value="https://test.kinde.com/logout?client_id=test_client&redirect_uri=/")
        with patch("identity.views.get_kinde_oauth", return_value=mock):
            resp = self.client.get("/auth/logout")
            self.assertEqual(resp.status_code, 302)
            loc = resp["Location"]
            self.assertTrue(loc.startswith("https://test.kinde.com/logout"))
            self.assertIn("client_id=test_client", loc)
            mock.logout.assert_called_once()

    def test_no_token_values_exposed(self):
        # ensure logout doesn't leak tokens even if they were somehow in session (they shouldn't be)
        s = self.client.session
        s["access_token"] = "secret_at"
        s["refresh_token"] = "secret_rt"
        s[SESSION_KEY] = str(uuid.uuid4())
        s.save()
        # logout clears our keys but we check response doesn't contain secrets
        mock = AsyncMock()
        mock.logout = AsyncMock(return_value="https://test.kinde.com/logout?client_id=test_client&redirect_uri=/")
        with patch("identity.views.get_kinde_oauth", return_value=mock):
            resp = self.client.get("/auth/logout")
        body = resp.content.decode()
        loc = resp.get("Location", "")
        for secret in ["secret_at", "secret_rt"]:
            self.assertNotIn(secret, body)
            self.assertNotIn(secret, loc)
        # also provider logout url must not contain id_token_hint
        self.assertNotIn("id_token_hint", loc)

    def _fake_request_from_session(self, session):
        from django.test import RequestFactory
        rf = RequestFactory()
        req = rf.get("/")
        req.session = session
        return req
