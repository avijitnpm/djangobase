import uuid

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase

from accounts.context import (
    SESSION_KEY,
    activate_organization,
    get_current_organization,
    get_current_organization_id,
    resolve_organization,
)
from accounts.middleware import OrganizationContextMiddleware
from accounts.models import Organization, OrganizationMembership


def _req(user=None, session_data=None):
    factory = RequestFactory()
    request = factory.get("/")
    request.user = user
    request.session = dict(session_data or {})
    return request


class TenantContextTests(TestCase):
    def setUp(self):
        from accounts.context import _organization_ctx

        _organization_ctx.set(None)
        User = get_user_model()
        self.user = User.objects.create_user(username="alice", password="testpass123")
        self.other = User.objects.create_user(username="bob", password="testpass123")
        self.org = Organization.objects.create(name="OrgA")
        self.org2 = Organization.objects.create(name="OrgB")
        self.org_other = Organization.objects.create(name="OrgOther")

    def tearDown(self):
        from accounts.context import _organization_ctx

        _organization_ctx.set(None)

    def test_valid_membership_establishes_context_single_org(self):
        OrganizationMembership.objects.create(user=self.user, organization=self.org)
        request = _req(user=self.user)
        org = resolve_organization(request)
        self.assertEqual(org, self.org)

    def test_valid_membership_via_session(self):
        OrganizationMembership.objects.create(user=self.user, organization=self.org)
        OrganizationMembership.objects.create(user=self.user, organization=self.org2)
        request = _req(user=self.user, session_data={SESSION_KEY: str(self.org2.id)})
        org = resolve_organization(request)
        self.assertEqual(org, self.org2)

    def test_non_member_cannot_establish_context(self):
        OrganizationMembership.objects.create(user=self.other, organization=self.org)
        request = _req(user=self.user, session_data={SESSION_KEY: str(self.org.id)})
        org = resolve_organization(request)
        self.assertIsNone(org)

    def test_missing_context_remains_missing(self):
        request = _req(user=self.user)
        org = resolve_organization(request)
        self.assertIsNone(org)
        self.assertIsNone(get_current_organization())

    def test_missing_context_not_fallback(self):
        OrganizationMembership.objects.create(user=self.user, organization=self.org)
        OrganizationMembership.objects.create(user=self.user, organization=self.org2)
        request = _req(user=self.user)
        org = resolve_organization(request)
        self.assertIsNone(org)

    def test_invalid_organization_selection_fails_closed(self):
        OrganizationMembership.objects.create(user=self.user, organization=self.org)
        for bad in [str(uuid.uuid4()), "not-a-uuid", str(self.org_other.id)]:
            request = _req(user=self.user, session_data={SESSION_KEY: bad})
            org = resolve_organization(request)
            self.assertIsNone(org, msg=f"bad {bad} should be None")

    def test_invalid_selection_does_not_fallback_to_member_org(self):
        OrganizationMembership.objects.create(user=self.user, organization=self.org)
        request = _req(user=self.user, session_data={SESSION_KEY: str(self.org_other.id)})
        org = resolve_organization(request)
        self.assertIsNone(org)

    def test_middleware_sets_request_and_contextvar(self):
        OrganizationMembership.objects.create(user=self.user, organization=self.org)

        def view(req):
            self.assertEqual(req.organization, self.org)
            self.assertEqual(get_current_organization(), self.org)
            self.assertEqual(get_current_organization_id(), self.org.id)
            from django.http import HttpResponse

            return HttpResponse("ok")

        middleware = OrganizationContextMiddleware(view)
        request = _req(user=self.user)
        request.session = {SESSION_KEY: str(self.org.id)} if False else {}
        # single membership auto-resolves
        middleware(request)
        self.assertIsNone(get_current_organization())

    def test_one_request_cannot_leak_context_into_another(self):
        OrganizationMembership.objects.create(user=self.user, organization=self.org)
        OrganizationMembership.objects.create(user=self.other, organization=self.org2)

        def view_user(req):
            from django.http import HttpResponse

            self.assertEqual(req.organization, self.org)
            self.assertEqual(get_current_organization(), self.org)
            return HttpResponse("ok")

        def view_other(req):
            from django.http import HttpResponse

            self.assertEqual(req.organization, self.org2)
            self.assertEqual(get_current_organization(), self.org2)
            return HttpResponse("ok")

        def view_anon(req):
            from django.http import HttpResponse

            self.assertIsNone(req.organization)
            self.assertIsNone(get_current_organization())
            return HttpResponse("ok")

        from django.contrib.auth.models import AnonymousUser

        m1 = OrganizationContextMiddleware(view_user)
        m1(_req(user=self.user))
        self.assertIsNone(get_current_organization())

        m2 = OrganizationContextMiddleware(view_other)
        m2(_req(user=self.other))
        self.assertIsNone(get_current_organization())

        m3 = OrganizationContextMiddleware(view_anon)
        m3(_req(user=AnonymousUser(), session_data={}))
        self.assertIsNone(get_current_organization())

    def test_activate_organization_validates_membership(self):
        OrganizationMembership.objects.create(user=self.user, organization=self.org)
        request = _req(user=self.user)
        request.session = {}
        self.assertTrue(activate_organization(request, self.org))
        self.assertEqual(request.session[SESSION_KEY], str(self.org.id))
        self.assertFalse(activate_organization(request, self.org_other))
        self.assertEqual(request.session[SESSION_KEY], str(self.org.id))

    def test_trust_not_arbitrary_header(self):
        factory = RequestFactory()
        request = factory.get("/", HTTP_X_ORGANIZATION_ID=str(self.org.id))
        request.user = self.user
        request.session = {}
        org = resolve_organization(request)
        self.assertIsNone(org)
        OrganizationMembership.objects.create(user=self.user, organization=self.org2)
        OrganizationMembership.objects.create(user=self.user, organization=self.org)
        request2 = factory.get("/", HTTP_X_ORGANIZATION_ID=str(self.org_other.id))
        request2.user = self.user
        request2.session = {}
        self.assertIsNone(resolve_organization(request2))

    def test_unauthenticated_has_no_context(self):
        from django.contrib.auth.models import AnonymousUser

        OrganizationMembership.objects.create(user=self.user, organization=self.org)
        request = _req(user=AnonymousUser(), session_data={SESSION_KEY: str(self.org.id)})
        self.assertIsNone(resolve_organization(request))
