import os
from unittest.mock import AsyncMock, patch

from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model

from identity.models import ExternalIdentity
from identity.session import SESSION_KEY
from identity.views import SESSION_NONCE, SESSION_STATE, SESSION_VERIFIER


@override_settings(
    KINDE_CLIENT_ID="test_client",
    KINDE_CLIENT_SECRET="secret123",
    KINDE_HOST="https://test.kinde.com",
    KINDE_REDIRECT_URI="http://localhost:8000/auth/callback",
)
class CallbackTests(TestCase):
    def setUp(self):
        os.environ["KINDE_CLIENT_ID"] = "test_client"
        os.environ["KINDE_CLIENT_SECRET"] = "secret123"
        os.environ["KINDE_HOST"] = "https://test.kinde.com"
        os.environ["KINDE_REDIRECT_URI"] = "http://localhost:8000/auth/callback"

    def _set_session(self, state="s123", verifier="v123", nonce="n123"):
        s = self.client.session
        s[SESSION_STATE] = state
        s[SESSION_VERIFIER] = verifier
        s[SESSION_NONCE] = nonce
        s.save()

    def _mock_oauth(self, token_data=None, exchange_side_effect=None):
        mock = AsyncMock()
        mock.token_url = "https://test.kinde.com/oauth2/token"
        mock.userinfo_url = "https://test.kinde.com/oauth2/userinfo"
        mock._logger = AsyncMock()
        if exchange_side_effect:
            mock.exchange_code_for_tokens = AsyncMock(side_effect=exchange_side_effect)
        else:
            mock.exchange_code_for_tokens = AsyncMock(return_value=token_data or {"access_token": "at123", "id_token": "it123"})
        return mock

    def test_valid_callback_creates_user(self):
        self._set_session(state="valid_state", verifier="verif")
        mock = self._mock_oauth(token_data={"access_token": "at", "id_token": "it"})
        with patch("identity.views.get_kinde_oauth", return_value=mock), patch("kinde_sdk.core.helpers.get_user_details", new=AsyncMock(return_value={"sub": "kp_123", "email": "a@example.com"})):
            resp = self.client.get("/auth/callback?code=authcode&state=valid_state")
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], "/")
        User = get_user_model()
        self.assertTrue(User.objects.filter(username="kinde_kp_123").exists())
        self.assertTrue(ExternalIdentity.objects.filter(provider="kinde", external_id="kp_123").exists())
        self.assertIn(SESSION_KEY, self.client.session)
        self.assertNotIn(SESSION_STATE, self.client.session)

    def test_valid_callback_reuses_existing(self):
        User = get_user_model()
        u = User.objects.create(username="kinde_kp_dup")
        ExternalIdentity.objects.create(provider="kinde", external_id="kp_dup", user=u)
        self._set_session(state="st", verifier="verif")
        mock = self._mock_oauth(token_data={"access_token": "at"})
        with patch("identity.views.get_kinde_oauth", return_value=mock), patch("kinde_sdk.core.helpers.get_user_details", new=AsyncMock(return_value={"sub": "kp_dup"})):
            resp = self.client.get("/auth/callback?code=c&state=st")
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(ExternalIdentity.objects.filter(external_id="kp_dup").count(), 1)
        self.assertEqual(self.client.session[SESSION_KEY], str(u.id))

    def test_invalid_state_denied(self):
        self._set_session(state="good", verifier="v")
        resp = self.client.get("/auth/callback?code=c&state=bad")
        self.assertEqual(resp.status_code, 400)
        self.assertNotIn(SESSION_KEY, self.client.session)
        self.assertNotIn(SESSION_STATE, self.client.session)

    def test_missing_state_denied(self):
        self._set_session(state="good", verifier="v")
        s = self.client.session
        s.pop(SESSION_STATE)
        s.save()
        resp = self.client.get("/auth/callback?code=c")
        self.assertEqual(resp.status_code, 400)

    def test_invalid_code_denied(self):
        self._set_session(state="st", verifier="v")
        mock = self._mock_oauth(exchange_side_effect=Exception("fail"))
        with patch("identity.views.get_kinde_oauth", return_value=mock):
            resp = self.client.get("/auth/callback?code=bad&state=st")
        self.assertEqual(resp.status_code, 400)
        self.assertNotIn(SESSION_STATE, self.client.session)

    def test_duplicate_callback_no_duplicate_identity(self):
        self._set_session(state="st", verifier="v")
        mock = self._mock_oauth(token_data={"access_token": "at"})
        with patch("identity.views.get_kinde_oauth", return_value=mock), patch("kinde_sdk.core.helpers.get_user_details", new=AsyncMock(return_value={"sub": "kp_once"})):
            r1 = self.client.get("/auth/callback?code=c&state=st")
        self.assertEqual(r1.status_code, 302)
        with patch("identity.views.get_kinde_oauth", return_value=mock), patch("kinde_sdk.core.helpers.get_user_details", new=AsyncMock(return_value={"sub": "kp_once"})):
            r2 = self.client.get("/auth/callback?code=c&state=st")
        self.assertEqual(r2.status_code, 400)
        self.assertEqual(ExternalIdentity.objects.filter(external_id="kp_once").count(), 1)

    def test_transaction_cleanup(self):
        self._set_session(state="st", verifier="v", nonce="n")
        mock = self._mock_oauth(token_data={"access_token": "at"})
        with patch("identity.views.get_kinde_oauth", return_value=mock), patch("kinde_sdk.core.helpers.get_user_details", new=AsyncMock(return_value={"sub": "kp_clean"})):
            self.client.get("/auth/callback?code=c&state=st")
        sess = self.client.session
        self.assertNotIn(SESSION_STATE, sess)
        self.assertNotIn(SESSION_VERIFIER, sess)
        self.assertNotIn(SESSION_NONCE, sess)

    def test_tokens_not_exposed(self):
        self._set_session(state="st", verifier="v")
        token_data = {"access_token": "secret_at_999", "refresh_token": "secret_rt", "id_token": "secret_it"}
        mock = self._mock_oauth(token_data=token_data)
        with patch("identity.views.get_kinde_oauth", return_value=mock), patch("kinde_sdk.core.helpers.get_user_details", new=AsyncMock(return_value={"sub": "kp_tok"})):
            resp = self.client.get("/auth/callback?code=c&state=st")
        body = resp.content.decode()
        loc = resp.get("Location", "")
        for secret in ["secret_at_999", "secret_rt", "secret_it"]:
            self.assertNotIn(secret, body)
            self.assertNotIn(secret, loc)
        self.assertNotIn("secret_at_999", str(dict(self.client.session)))

    def test_unknown_identity_first_login_creates(self):
        self._set_session(state="st", verifier="v")
        mock = self._mock_oauth(token_data={"access_token": "at"})
        with patch("identity.views.get_kinde_oauth", return_value=mock), patch("kinde_sdk.core.helpers.get_user_details", new=AsyncMock(return_value={"sub": "new_kp", "email": "new@example.com"})):
            resp = self.client.get("/auth/callback?code=c&state=st")
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(ExternalIdentity.objects.filter(external_id="new_kp").exists())
