import base64
import hashlib
from unittest.mock import AsyncMock, patch
from urllib.parse import urlparse, parse_qs

from django.test import TestCase, override_settings, RequestFactory
from django.contrib.sessions.backends.db import SessionStore


@override_settings(
    KINDE_CLIENT_ID="test_client",
    KINDE_CLIENT_SECRET="secret123",
    KINDE_HOST="https://test.kinde.com",
    KINDE_REDIRECT_URI="http://localhost:8000/auth/callback",
)
class LoginTests(TestCase):
    def setUp(self):
        import os

        os.environ["KINDE_CLIENT_ID"] = "test_client"
        os.environ["KINDE_CLIENT_SECRET"] = "secret123"
        os.environ["KINDE_HOST"] = "https://test.kinde.com"
        os.environ["KINDE_REDIRECT_URI"] = "http://localhost:8000/auth/callback"

    def _mock_oauth(self):
        mock = AsyncMock()
        mock.generate_auth_url = AsyncMock(
            side_effect=lambda login_options=None, **kw: {
                "url": f"https://test.kinde.com/oauth2/auth?client_id=test_client&redirect_uri=http://localhost:8000/auth/callback&response_type=code&scope=openid profile email&state={login_options.get('state')}&nonce={login_options.get('nonce')}&code_challenge={login_options.get('code_challenge')}&code_challenge_method=S256"
            }
        )
        return mock

    def test_redirects(self):
        with patch("identity.views.get_kinde_oauth", return_value=self._mock_oauth()):
            resp = self.client.get("/auth/login")
            self.assertEqual(resp.status_code, 302)

    def test_redirect_target_is_kinde(self):
        with patch("identity.views.get_kinde_oauth", return_value=self._mock_oauth()):
            resp = self.client.get("/auth/login")
            loc = resp["Location"]
            self.assertTrue(loc.startswith("https://test.kinde.com"))

    def test_state_generated_and_stored(self):
        with patch("identity.views.get_kinde_oauth", return_value=self._mock_oauth()):
            resp = self.client.get("/auth/login")
            loc = resp["Location"]
            qs = parse_qs(urlparse(loc).query)
            state = qs["state"][0]
            self.assertTrue(len(state) > 10)
            sess = self.client.session
            self.assertEqual(sess["kinde_oauth_state"], state)

    def test_verifier_stored_server_side(self):
        with patch("identity.views.get_kinde_oauth", return_value=self._mock_oauth()):
            self.client.get("/auth/login")
            sess = self.client.session
            self.assertIn("kinde_oauth_code_verifier", sess)
            self.assertTrue(len(sess["kinde_oauth_code_verifier"]) > 20)

    def test_challenge_included_correctly(self):
        with patch("identity.views.get_kinde_oauth", return_value=self._mock_oauth()):
            resp = self.client.get("/auth/login")
            loc = resp["Location"]
            qs = parse_qs(urlparse(loc).query)
            challenge = qs["code_challenge"][0]
            self.assertEqual(qs["code_challenge_method"][0], "S256")
            sess = self.client.session
            verifier = sess["kinde_oauth_code_verifier"]
            expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
            self.assertEqual(challenge, expected)

    def test_redirect_uri_from_config(self):
        with patch("identity.views.get_kinde_oauth", return_value=self._mock_oauth()):
            resp = self.client.get("/auth/login")
            qs = parse_qs(urlparse(resp["Location"]).query)
            self.assertEqual(qs["redirect_uri"][0], "http://localhost:8000/auth/callback")

    def test_client_secret_not_in_redirect(self):
        with patch("identity.views.get_kinde_oauth", return_value=self._mock_oauth()):
            resp = self.client.get("/auth/login")
            self.assertNotIn("secret123", resp["Location"])
            self.assertNotIn("secret123", str(resp.content))

    def test_repeated_creates_distinct_state(self):
        with patch("identity.views.get_kinde_oauth", return_value=self._mock_oauth()):
            r1 = self.client.get("/auth/login")
            s1 = self.client.session["kinde_oauth_state"]
            v1 = self.client.session["kinde_oauth_code_verifier"]
            r2 = self.client.get("/auth/login")
            s2 = self.client.session["kinde_oauth_state"]
            v2 = self.client.session["kinde_oauth_code_verifier"]
            self.assertNotEqual(s1, s2)
            self.assertNotEqual(v1, v2)
            self.assertNotEqual(
                parse_qs(urlparse(r1["Location"]).query)["state"][0],
                parse_qs(urlparse(r2["Location"]).query)["state"][0],
            )

    def test_no_global_mutable_oauth_state(self):
        import identity.views as v

        self.assertFalse(hasattr(v, "_state"))
        self.assertFalse(hasattr(v, "_verifier"))
        self.assertFalse(hasattr(v, "global_state"))

    def test_verifier_not_in_redirect(self):
        with patch("identity.views.get_kinde_oauth", return_value=self._mock_oauth()):
            resp = self.client.get("/auth/login")
            sess = self.client.session
            self.assertNotIn(sess["kinde_oauth_code_verifier"], resp["Location"])
