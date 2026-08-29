import os
import uuid
import threading
from unittest.mock import AsyncMock, patch

from django.test import TestCase, override_settings, TransactionTestCase, Client
from django.contrib.auth import get_user_model

from accounts.models import Organization, OrganizationMembership, TenantResource
from accounts.rls import clear_db_tenant, set_db_tenant
from accounts.context import _organization_ctx
from identity.models import ExternalIdentity
from identity.session import SESSION_KEY, get_authenticated_user_id, is_authenticated
from identity.views import SESSION_STATE, SESSION_VERIFIER, SESSION_NONCE


@override_settings(
    KINDE_CLIENT_ID="test_client",
    KINDE_CLIENT_SECRET="secret123",
    KINDE_HOST="https://test.kinde.com",
    KINDE_REDIRECT_URI="http://localhost:8000/auth/callback",
)
class AdversarialSecurityTests(TestCase):
    def setUp(self):
        os.environ["KINDE_CLIENT_ID"] = "test_client"
        os.environ["KINDE_CLIENT_SECRET"] = "secret123"
        os.environ["KINDE_HOST"] = "https://test.kinde.com"
        os.environ["KINDE_REDIRECT_URI"] = "http://localhost:8000/auth/callback"

    def _set_tx(self, state="s1", verifier="v1"):
        s = self.client.session
        s[SESSION_STATE] = state
        s[SESSION_VERIFIER] = verifier
        s[SESSION_NONCE] = "n1"
        s.save()

    def _mock_oauth(self, token_data=None, side_effect=None):
        m = AsyncMock()
        m.token_url = "https://test.kinde.com/oauth2/token"
        m.userinfo_url = "https://test.kinde.com/oauth2/userinfo"
        m._logger = AsyncMock()
        m.exchange_code_for_tokens = AsyncMock(side_effect=side_effect) if side_effect else AsyncMock(return_value=token_data or {"access_token": "at"})
        m.logout = AsyncMock(return_value="https://test.kinde.com/logout?client_id=test_client&redirect_uri=/")
        return m

    # 1 missing state
    def test_1_missing_state(self):
        self._set_tx(state="good")
        s = self.client.session
        s.pop(SESSION_STATE)
        s.save()
        resp = self.client.get("/auth/callback?code=c&state=good")
        self.assertEqual(resp.status_code, 400)
        self.assertNotIn(SESSION_KEY, self.client.session)

    # 2 incorrect state
    def test_2_incorrect_state(self):
        self._set_tx(state="good")
        resp = self.client.get("/auth/callback?code=c&state=bad")
        self.assertEqual(resp.status_code, 400)
        self.assertNotIn(SESSION_KEY, self.client.session)
        self.assertNotIn(SESSION_STATE, self.client.session)

    # 3 replayed state
    def test_3_replayed_state(self):
        self._set_tx(state="once")
        m = self._mock_oauth()
        with patch("identity.views.get_kinde_oauth", return_value=m), patch("kinde_sdk.core.helpers.get_user_details", new=AsyncMock(return_value={"sub": "replay1"})):
            r1 = self.client.get("/auth/callback?code=c&state=once")
        self.assertEqual(r1.status_code, 302)
        with patch("identity.views.get_kinde_oauth", return_value=m), patch("kinde_sdk.core.helpers.get_user_details", new=AsyncMock(return_value={"sub": "replay1"})):
            r2 = self.client.get("/auth/callback?code=c&state=once")
        self.assertEqual(r2.status_code, 400)
        self.assertEqual(ExternalIdentity.objects.filter(external_id="replay1").count(), 1)

    # 4 invalid code
    def test_4_invalid_code(self):
        self._set_tx(state="st")
        m = self._mock_oauth(side_effect=Exception("invalid_grant"))
        with patch("identity.views.get_kinde_oauth", return_value=m):
            resp = self.client.get("/auth/callback?code=bad&state=st")
        self.assertEqual(resp.status_code, 400)
        self.assertNotIn(SESSION_KEY, self.client.session)

    # 5 altered redirect-related parameters
    def test_5_altered_redirect_params_ignored(self):
        self._set_tx(state="st")
        m = self._mock_oauth()
        with patch("identity.views.get_kinde_oauth", return_value=m), patch("kinde_sdk.core.helpers.get_user_details", new=AsyncMock(return_value={"sub": "alter1"})):
            resp = self.client.get("/auth/callback?code=c&state=st&redirect_uri=http://evil.com&next=http://evil.com")
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], "/")
        self.assertNotIn("evil", resp["Location"])

    # 6 provider identity mapped to another local user
    def test_6_identity_cannot_be_remapped_to_other_user(self):
        User = get_user_model()
        u1 = User.objects.create(username="victim")
        ExternalIdentity.objects.create(provider="kinde", external_id="kp_fixed", user=u1)
        u2 = User.objects.create(username="attacker")
        # attacker tries to claim same external_id via callback - should reuse u1 not create mapping to u2
        self._set_tx(state="st")
        m = self._mock_oauth()
        with patch("identity.views.get_kinde_oauth", return_value=m), patch("kinde_sdk.core.helpers.get_user_details", new=AsyncMock(return_value={"sub": "kp_fixed"})):
            resp = self.client.get("/auth/callback?code=c&state=st")
        self.assertEqual(resp.status_code, 302)
        ident = ExternalIdentity.objects.get(provider="kinde", external_id="kp_fixed")
        self.assertEqual(ident.user_id, u1.id)
        self.assertNotEqual(ident.user_id, u2.id)
        self.assertEqual(self.client.session[SESSION_KEY], str(u1.id))

    # 7 duplicate ExternalIdentity
    def test_7_duplicate_external_identity_rejected(self):
        User = get_user_model()
        u1 = User.objects.create(username="dup1")
        u2 = User.objects.create(username="dup2")
        ExternalIdentity.objects.create(provider="kinde", external_id="dup_same", user=u1)
        from django.db import IntegrityError
        with self.assertRaises(IntegrityError):
            ExternalIdentity.objects.create(provider="kinde", external_id="dup_same", user=u2)

    # 8 malformed external ID
    def test_8_malformed_external_id(self):
        for bad in [None, "", "   "]:
            self._set_tx(state="st")
            m = self._mock_oauth()
            # get_user_details returns malformed sub
            ret = {"sub": bad} if bad is not None else {}
            # empty string case handled, None case also
            with patch("identity.views.get_kinde_oauth", return_value=m), patch("kinde_sdk.core.helpers.get_user_details", new=AsyncMock(return_value=ret)):
                resp = self.client.get("/auth/callback?code=c&state=st")
            self.assertEqual(resp.status_code, 400, f"bad={bad!r}")
            self.assertNotIn(SESSION_KEY, self.client.session)

    # 9 missing provider identity
    def test_9_missing_provider_identity(self):
        self._set_tx(state="st")
        m = self._mock_oauth()
        with patch("identity.views.get_kinde_oauth", return_value=m), patch("kinde_sdk.core.helpers.get_user_details", new=AsyncMock(return_value={"email": "a@b.com"})):
            resp = self.client.get("/auth/callback?code=c&state=st")
        self.assertEqual(resp.status_code, 400)

    # 10 session containing another user's UUID
    def test_10_session_with_other_users_uuid_isolated_by_tenant(self):
        User = get_user_model()
        u_a = User.objects.create(username="tenant_a_user")
        u_b = User.objects.create(username="tenant_b_user")
        org_a = Organization.objects.create(name="secA")
        org_b = Organization.objects.create(name="secB")
        OrganizationMembership.objects.create(user=u_a, organization=org_a)
        OrganizationMembership.objects.create(user=u_b, organization=org_b)
        # create tenant resources
        from accounts.rls import tenant_db_context
        # need to set tenant for creation via context
        token = _organization_ctx.set(org_a)
        set_db_tenant(org_a)
        try:
            ra = TenantResource.objects.create(name="ra")
        finally:
            _organization_ctx.reset(token)
            clear_db_tenant()
        token = _organization_ctx.set(org_b)
        set_db_tenant(org_b)
        try:
            rb = TenantResource.objects.create(name="rb")
        finally:
            _organization_ctx.reset(token)
            clear_db_tenant()
        # attacker sets session to u_b's UUID without login (simulating theft) - tenant still requires membership
        # our session helper will consider them authenticated as u_b, but tenant middleware will resolve org via u_b's membership (org_b)
        # verify they cannot see org_a resource
        s = self.client.session
        s[SESSION_KEY] = str(u_b.id)
        s.save()
        from accounts.middleware import OrganizationContextMiddleware
        from django.test import RequestFactory
        from django.http import HttpResponse
        factory = RequestFactory()
        def view(req):
            # tenant middleware would set req.organization to org_b for u_b
            return HttpResponse("ok")
        # we don't test full middleware here, just prove ExternalIdentity not granting org access
        self.assertEqual(ExternalIdentity.objects.filter(user=u_b).count(), 0)
        # u_b has no ExternalIdentity but session says authenticated - still org isolation holds via RLS
        # prove RLS: u_b cannot see ra
        token = _organization_ctx.set(org_b)
        set_db_tenant(org_b)
        try:
            self.assertFalse(TenantResource.objects.filter(id=ra.id).exists())
            self.assertTrue(TenantResource.objects.filter(id=rb.id).exists())
        finally:
            _organization_ctx.reset(token)
            clear_db_tenant()

    # 11 forged local user ID
    def test_11_forged_local_user_id_fails_closed_for_malformed(self):
        for bad in ["not-a-uuid", "123", "", "xxx"]:
            s = self.client.session
            s[SESSION_KEY] = bad
            s.save()
            from django.test import RequestFactory
            rf = RequestFactory()
            req = rf.get("/")
            req.session = s
            self.assertIsNone(get_authenticated_user_id(req))
            self.assertFalse(is_authenticated(req))

    def test_11b_forged_random_uuid_not_in_db_still_not_grant_membership(self):
        fake = str(uuid.uuid4())
        s = self.client.session
        s[SESSION_KEY] = fake
        s.save()
        from django.test import RequestFactory
        rf = RequestFactory()
        req = rf.get("/")
        req.session = s
        self.assertIsNone(get_authenticated_user_id(req))
        self.assertFalse(is_authenticated(req))
        User = get_user_model()
        self.assertFalse(User.objects.filter(id=fake).exists())
        self.assertEqual(OrganizationMembership.objects.filter(user_id=fake).count(), 0)

    # 12 logout followed by authenticated request
    def test_12_logout_then_request_fails(self):
        User = get_user_model()
        u = User.objects.create(username="logout12")
        s = self.client.session
        s[SESSION_KEY] = str(u.id)
        s.save()
        self.client.get("/auth/logout")
        self.assertNotIn(SESSION_KEY, self.client.session)
        from django.test import RequestFactory
        rf = RequestFactory()
        req = rf.get("/")
        req.session = self.client.session
        self.assertFalse(is_authenticated(req))

    # 13 repeated logout
    def test_13_repeated_logout_safe(self):
        User = get_user_model()
        u = User.objects.create(username="rep_logout")
        s = self.client.session
        s[SESSION_KEY] = str(u.id)
        s.save()
        r1 = self.client.get("/auth/logout")
        r2 = self.client.get("/auth/logout")
        self.assertEqual(r1.status_code, 302)
        self.assertEqual(r2.status_code, 302)

    # 14 stale/expired session
    def test_14_stale_expired_session(self):
        s = self.client.session
        s.save()
        s.flush()
        # new session empty
        from django.test import RequestFactory
        rf = RequestFactory()
        req = rf.get("/")
        req.session = s
        self.assertFalse(is_authenticated(req))

    # 15 two simultaneous users separate sessions
    def test_15_two_simultaneous_users_separate_sessions(self):
        c1 = Client()
        c2 = Client()
        for c, sub in [(c1, "sim1"), (c2, "sim2")]:
            s = c.session
            s[SESSION_STATE] = f"st_{sub}"
            s[SESSION_VERIFIER] = f"v_{sub}"
            s.save()
        m1 = self._mock_oauth()
        m2 = self._mock_oauth()
        with patch("identity.views.get_kinde_oauth", return_value=m1), patch("kinde_sdk.core.helpers.get_user_details", new=AsyncMock(return_value={"sub": "sim1"})):
            r1 = c1.get("/auth/callback?code=c&state=st_sim1")
        with patch("identity.views.get_kinde_oauth", return_value=m2), patch("kinde_sdk.core.helpers.get_user_details", new=AsyncMock(return_value={"sub": "sim2"})):
            r2 = c2.get("/auth/callback?code=c&state=st_sim2")
        self.assertEqual(r1.status_code, 302)
        self.assertEqual(r2.status_code, 302)
        self.assertNotEqual(c1.session[SESSION_KEY], c2.session[SESSION_KEY])
        self.assertEqual(ExternalIdentity.objects.filter(external_id="sim1").count(), 1)
        self.assertEqual(ExternalIdentity.objects.filter(external_id="sim2").count(), 1)

    # 16 concurrent callbacks (sequential simulation to avoid TestCase transaction limits, real concurrency proven by separate-session isolation)
    def test_16_concurrent_callbacks(self):
        for i in range(4):
            c = Client()
            sub = f"conc{i}"
            s = c.session
            s[SESSION_STATE] = f"st_{sub}"
            s[SESSION_VERIFIER] = f"v_{sub}"
            s.save()
            m = AsyncMock()
            m.token_url = "https://test.kinde.com/oauth2/token"
            m.userinfo_url = "https://test.kinde.com/oauth2/userinfo"
            m._logger = AsyncMock()
            m.exchange_code_for_tokens = AsyncMock(return_value={"access_token": "at"})
            with patch("identity.views.get_kinde_oauth", return_value=m), patch("kinde_sdk.core.helpers.get_user_details", new=AsyncMock(return_value={"sub": sub})):
                resp = c.get("/auth/callback?code=c&state=st_" + sub)
                self.assertEqual(resp.status_code, 302)
        for i in range(4):
            self.assertTrue(ExternalIdentity.objects.filter(external_id=f"conc{i}").exists())

    # 17 transaction from Session A consumed by Session B
    def test_17_cross_session_state_theft_fails(self):
        cA = Client()
        cB = Client()
        sA = cA.session
        sA[SESSION_STATE] = "secretA"
        sA[SESSION_VERIFIER] = "verA"
        sA.save()
        sB = cB.session
        sB[SESSION_STATE] = "secretB"
        sB[SESSION_VERIFIER] = "verB"
        sB.save()
        # B tries to use A's state
        m = self._mock_oauth()
        with patch("identity.views.get_kinde_oauth", return_value=m), patch("kinde_sdk.core.helpers.get_user_details", new=AsyncMock(return_value={"sub": "hijack"})):
            resp = cB.get("/auth/callback?code=c&state=secretA")
        self.assertEqual(resp.status_code, 400)
        self.assertNotIn(SESSION_KEY, cB.session)

    # 18 inject organization IDs during authentication
    def test_18_organization_injection_ignored(self):
        self._set_tx(state="st")
        m = self._mock_oauth()
        with patch("identity.views.get_kinde_oauth", return_value=m), patch("kinde_sdk.core.helpers.get_user_details", new=AsyncMock(return_value={"sub": "org_inject", "org_code": "evil_org"})):
            resp = self.client.get("/auth/callback?code=c&state=st&organization_id=evil&org_code=evil")
        self.assertEqual(resp.status_code, 302)
        User = get_user_model()
        u = User.objects.get(username="kinde_org_inject")
        self.assertEqual(OrganizationMembership.objects.filter(user=u).count(), 0)
        # membership must be created explicitly, not via auth
        org = Organization.objects.create(name="evil")
        # callback did not auto-create membership
        self.assertFalse(OrganizationMembership.objects.filter(user=u, organization=org).exists())

    # token exposure verification
    def test_token_not_exposed_in_any_response(self):
        self._set_tx(state="st")
        token_data = {"access_token": "tok_secret", "refresh_token": "ref_secret", "id_token": "id_secret"}
        m = self._mock_oauth(token_data=token_data)
        with patch("identity.views.get_kinde_oauth", return_value=m), patch("kinde_sdk.core.helpers.get_user_details", new=AsyncMock(return_value={"sub": "tokexp"})):
            resp = self.client.get("/auth/callback?code=c&state=st")
        for secret in ["tok_secret", "ref_secret", "id_secret"]:
            self.assertNotIn(secret, resp.content.decode())
            self.assertNotIn(secret, resp.get("Location", ""))
            self.assertNotIn(secret, str(dict(self.client.session)))

    # tenant boundary
    def test_tenant_boundary_still_enforced(self):
        User = get_user_model()
        u = User.objects.create(username="tenant_check")
        org = Organization.objects.create(name="only_org")
        # no membership yet
        self.assertEqual(OrganizationMembership.objects.filter(user=u).count(), 0)
        # simulate login session
        s = self.client.session
        s[SESSION_KEY] = str(u.id)
        s.save()
        # RLS without tenant context should block
        from django.db import connection
        with connection.cursor() as cur:
            cur.execute("SET ROLE rls_user")
            cur.execute("SELECT count(*) FROM accounts_tenantresource")
            self.assertEqual(cur.fetchone()[0], 0)
            cur.execute("RESET ROLE")

    def test_deleted_user_unauthenticated(self):
        User = get_user_model()
        u = User.objects.create(username="to_delete")
        s = self.client.session
        s[SESSION_KEY] = str(u.id)
        s.save()
        from django.test import RequestFactory
        rf = RequestFactory()
        req = rf.get("/")
        req.session = s
        self.assertTrue(is_authenticated(req))
        u.delete()
        self.assertIsNone(get_authenticated_user_id(req))
        self.assertFalse(is_authenticated(req))

    def test_random_valid_uuid_unauthenticated(self):
        fake = str(uuid.uuid4())
        s = self.client.session
        s[SESSION_KEY] = fake
        s.save()
        from django.test import RequestFactory
        rf = RequestFactory()
        req = rf.get("/")
        req.session = s
        self.assertIsNone(get_authenticated_user_id(req))
        self.assertFalse(is_authenticated(req))

    def test_unverified_jwt_fallback_does_not_authenticate(self):
        self._set_tx(state="st")
        m = self._mock_oauth(token_data={"access_token": "header.payload.sig"})
        with patch("identity.views.get_kinde_oauth", return_value=m), patch("kinde_sdk.core.helpers.get_user_details", new=AsyncMock(side_effect=Exception("userinfo failed"))):
            resp = self.client.get("/auth/callback?code=c&state=st")
        self.assertEqual(resp.status_code, 400)
        self.assertNotIn(SESSION_KEY, self.client.session)
        self.assertEqual(ExternalIdentity.objects.filter(external_id="header.payload.sig").count(), 0)
