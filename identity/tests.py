from django.db import IntegrityError
from django.test import TestCase, RequestFactory
from django.contrib.sessions.backends.db import SessionStore

from accounts.models import User
from identity.models import ExternalIdentity
from identity.services import resolve_user_id
from identity.session import (
    SESSION_KEY,
    set_authenticated_user,
    get_authenticated_user_id,
    clear_authenticated_user,
    is_authenticated,
)


class ExternalIdentityTests(TestCase):
    def test_link_kinde_external_id_to_user(self):
        user = User.objects.create_user(username="alice", password="x")
        ei = ExternalIdentity.objects.create(provider="kinde", external_id="kp_alice_123", user=user)
        self.assertEqual(ei.user_id, user.id)
        self.assertEqual(ExternalIdentity.objects.get(provider="kinde", external_id="kp_alice_123").user_id, user.id)

    def test_duplicate_provider_external_id_rejected(self):
        u1 = User.objects.create_user(username="u1", password="x")
        u2 = User.objects.create_user(username="u2", password="x")
        ExternalIdentity.objects.create(provider="kinde", external_id="dup123", user=u1)
        with self.assertRaises(IntegrityError):
            ExternalIdentity.objects.create(provider="kinde", external_id="dup123", user=u2)

    def test_resolve_correct_local_user_uuid(self):
        user = User.objects.create_user(username="bob", password="x")
        ExternalIdentity.objects.create(provider="kinde", external_id="kp_bob", user=user)
        self.assertEqual(resolve_user_id("kinde", "kp_bob"), user.id)

    def test_unknown_external_id_does_not_resolve(self):
        user = User.objects.create_user(username="carol", password="x")
        ExternalIdentity.objects.create(provider="kinde", external_id="kp_carol", user=user)
        self.assertIsNone(resolve_user_id("kinde", "unknown_id"))
        other = User.objects.create_user(username="dave", password="x")
        self.assertNotEqual(resolve_user_id("kinde", "kp_carol"), other.id)

    def test_user_independent_of_provider_objects(self):
        user = User.objects.create_user(username="eve", password="x")
        ExternalIdentity.objects.create(provider="kinde", external_id="kp_eve", user=user)
        fetched = User.objects.get(id=user.id)
        self.assertEqual(fetched.id, user.id)
        self.assertFalse(hasattr(fetched, "kinde_token"))
        self.assertFalse(hasattr(fetched, "kinde_sdk"))


class SessionTests(TestCase):
    def _request(self):
        factory = RequestFactory()
        request = factory.get("/")
        request.session = SessionStore()
        request.session.create()
        return request

    def test_session_retains_local_user_identity(self):
        user = User.objects.create_user(username="sess1", password="x")
        req = self._request()
        set_authenticated_user(req, user.id)
        self.assertTrue(is_authenticated(req))
        self.assertEqual(get_authenticated_user_id(req), user.id)
        self.assertEqual(req.session[SESSION_KEY], str(user.id))

    def test_session_does_not_contain_sdk_objects(self):
        user = User.objects.create_user(username="sess2", password="x")
        req = self._request()
        set_authenticated_user(req, user.id)
        for v in req.session.values():
            self.assertNotIn("kinde_sdk", str(type(v)).lower())
            self.assertNotIn("oauth", str(type(v)).lower())
        self.assertIsInstance(req.session[SESSION_KEY], str)

    def test_sensitive_tokens_not_exposed(self):
        user = User.objects.create_user(username="sess3", password="x")
        req = self._request()
        set_authenticated_user(req, user.id)
        keys = set(req.session.keys())
        self.assertNotIn("access_token", keys)
        self.assertNotIn("refresh_token", keys)
        self.assertNotIn("id_token", keys)
        self.assertIn(SESSION_KEY, keys)

    def test_clear_session(self):
        user = User.objects.create_user(username="sess4", password="x")
        req = self._request()
        set_authenticated_user(req, user.id)
        clear_authenticated_user(req)
        self.assertFalse(is_authenticated(req))
        self.assertIsNone(get_authenticated_user_id(req))
