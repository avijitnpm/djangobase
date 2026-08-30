import uuid

from django.contrib.auth.models import AnonymousUser
from django.test import TestCase

from accounts.models import Organization, OrganizationMembership
from accounts.rls import tenant_db_context
from authorization.bootstrap import bootstrap_permissions, bootstrap_roles
from authorization.demo import protected_read_scoped_resource
from authorization.models import MembershipRole, Permission, Role, ScopedResource
from authorization.service import AuthorizationDenied, authorize, is_authorized


def _user_org(username="user", org_name="Org"):
    from django.contrib.auth import get_user_model

    User = get_user_model()
    user = User.objects.create_user(username=username, password="testpass123")
    org = Organization.objects.create(name=org_name)
    membership = OrganizationMembership.objects.create(user=user, organization=org)
    return user, org, membership


class AuthenticationTests(TestCase):
    def test_unauthenticated_denied(self):
        org = Organization.objects.create(name="Org")
        with self.assertRaises(AuthorizationDenied) as cm:
            authorize(None, org, "platform.organization:read")
        self.assertEqual(cm.exception.to_http_status(), 403)

    def test_anonymous_user_denied(self):
        org = Organization.objects.create(name="Org")
        anon = AnonymousUser()
        with self.assertRaises(AuthorizationDenied):
            authorize(anon, org, "platform.organization:read")
        self.assertFalse(is_authorized(anon, org, "platform.organization:read"))

    def test_nonexistent_local_user_denied(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        org = Organization.objects.create(name="Org")
        user = User.objects.create_user(username="ghost", password="testpass123")
        OrganizationMembership.objects.create(user=user, organization=org)
        user.delete()
        with self.assertRaises(AuthorizationDenied) as cm:
            authorize(user, org, "platform.organization:read")
        self.assertIn("unknown_user", str(cm.exception.reason))
        self.assertFalse(is_authorized(user, org, "platform.organization:read"))

    def test_malformed_user_denied(self):
        org = Organization.objects.create(name="Org")
        fake = type("Fake", (), {"is_authenticated": True, "pk": "not-a-uuid"})()
        with self.assertRaises(AuthorizationDenied):
            authorize(fake, org, "platform.organization:read")


class MembershipTests(TestCase):
    def test_no_membership_denied(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        user = User.objects.create_user(username="nomem", password="testpass123")
        org = Organization.objects.create(name="Org")
        with self.assertRaises(AuthorizationDenied) as cm:
            authorize(user, org, "platform.organization:read")
        self.assertEqual(cm.exception.reason, "no_membership")
        self.assertFalse(is_authorized(user, org, "platform.organization:read"))

    def test_wrong_organization_membership_denied(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        user = User.objects.create_user(username="u", password="testpass123")
        org1 = Organization.objects.create(name="Org1")
        org2 = Organization.objects.create(name="Org2")
        OrganizationMembership.objects.create(user=user, organization=org1)
        with self.assertRaises(AuthorizationDenied):
            authorize(user, org2, "platform.organization:read")


class RoleTests(TestCase):
    def test_membership_without_role_denied(self):
        bootstrap_permissions()
        user, org, _ = _user_org("r1", "OrgR1")
        with self.assertRaises(AuthorizationDenied) as cm:
            authorize(user, org, "platform.organization:read")
        self.assertEqual(cm.exception.reason, "no_role")

    def test_membership_with_unrelated_role_denied(self):
        bootstrap_permissions()
        user, org, mem = _user_org("r2", "OrgR2")
        role = Role.objects.create(key="empty_role", name="Empty")
        MembershipRole.objects.create(membership=mem, role=role)
        with self.assertRaises(AuthorizationDenied) as cm:
            authorize(user, org, "platform.organization:read")
        self.assertEqual(cm.exception.reason, "no_permission")


class PermissionTests(TestCase):
    def test_role_without_permission_denied(self):
        user, org, mem = _user_org("p1", "OrgP1")
        role = Role.objects.create(key="noperm", name="NoPerm")
        perm = Permission.objects.create(code="platform.membership:read", name="Other")
        Permission.objects.create(code="platform.organization:read", name="Target")
        role.permissions.add(perm)
        MembershipRole.objects.create(membership=mem, role=role)
        with self.assertRaises(AuthorizationDenied) as cm:
            authorize(user, org, "platform.organization:read")
        self.assertEqual(cm.exception.reason, "no_permission")
        self.assertFalse(is_authorized(user, org, "platform.organization:read"))

    def test_role_with_permission_allowed(self):
        user, org, mem = _user_org("p2", "OrgP2")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role = Role.objects.create(key="hasperm", name="Has")
        role.permissions.add(perm)
        MembershipRole.objects.create(membership=mem, role=role)
        self.assertTrue(is_authorized(user, org, "platform.organization:read"))
        self.assertTrue(authorize(user, org, "platform.organization:read"))

    def test_unknown_permission_denied(self):
        user, org, mem = _user_org("p3", "OrgP3")
        role = Role.objects.create(key="any_role", name="Any")
        MembershipRole.objects.create(membership=mem, role=role)
        with self.assertRaises(AuthorizationDenied) as cm:
            authorize(user, org, "nonexistent:perm")
        self.assertEqual(cm.exception.reason, "unknown_permission")

    def test_malformed_permission_denied(self):
        user, org, mem = _user_org("p4", "OrgP4")
        MembershipRole.objects.create(membership=mem, role=Role.objects.create(key="r", name="R"))
        with self.assertRaises(AuthorizationDenied):
            authorize(user, org, "")
        with self.assertRaises(AuthorizationDenied):
            authorize(user, org, None)


class OrganizationTests(TestCase):
    def test_correct_organization_allowed(self):
        user, org, mem = _user_org("o1", "OrgO1")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role = Role.objects.create(key="org_role", name="R")
        role.permissions.add(perm)
        MembershipRole.objects.create(membership=mem, role=role)
        self.assertTrue(is_authorized(user, org, "platform.organization:read"))

    def test_wrong_organization_denied(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        org1 = Organization.objects.create(name="Org1")
        org2 = Organization.objects.create(name="Org2")
        user = User.objects.create_user(username="cross_org", password="testpass123")
        m1 = OrganizationMembership.objects.create(user=user, organization=org1)
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role = Role.objects.create(key="cross_role", name="R")
        role.permissions.add(perm)
        MembershipRole.objects.create(membership=m1, role=role)
        with self.assertRaises(AuthorizationDenied):
            authorize(user, org2, "platform.organization:read")
        self.assertFalse(is_authorized(user, org2, "platform.organization:read"))

    def test_no_organization_context_denied(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        user = User.objects.create_user(username="noorg", password="testpass123")
        with self.assertRaises(AuthorizationDenied) as cm:
            authorize(user, None, "platform.organization:read")
        self.assertEqual(cm.exception.reason, "no_organization")

    def test_invalid_organization_denied(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        user = User.objects.create_user(username="invorg", password="testpass123")
        with self.assertRaises(AuthorizationDenied):
            authorize(user, "not-a-uuid", "platform.organization:read")


class ScopeTests(TestCase):
    def test_matching_scope_allowed(self):
        user, org, mem = _user_org("s1", "OrgS1")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role = Role.objects.create(key="scope_role", name="R")
        role.permissions.add(perm)
        MembershipRole.objects.create(membership=mem, role=role, scope_type="region", scope_value="north")
        with tenant_db_context(org):
            res = ScopedResource.objects.create(organization=org, name="r", region="north")
            self.assertTrue(is_authorized(user, org, "platform.organization:read", res))
            self.assertTrue(authorize(user, org, "platform.organization:read", res))

    def test_non_matching_scope_denied(self):
        user, org, mem = _user_org("s2", "OrgS2")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role = Role.objects.create(key="scope_role2", name="R")
        role.permissions.add(perm)
        MembershipRole.objects.create(membership=mem, role=role, scope_type="region", scope_value="north")
        with tenant_db_context(org):
            res = ScopedResource.objects.create(organization=org, name="r", region="south")
            with self.assertRaises(AuthorizationDenied) as cm:
                authorize(user, org, "platform.organization:read", res)
            self.assertEqual(cm.exception.reason, "scope_mismatch")
            self.assertFalse(is_authorized(user, org, "platform.organization:read", res))

    def test_org_wide_allows_any_scope(self):
        user, org, mem = _user_org("s3", "OrgS3")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role = Role.objects.create(key="wide_role", name="R")
        role.permissions.add(perm)
        MembershipRole.objects.create(membership=mem, role=role)
        with tenant_db_context(org):
            north = ScopedResource.objects.create(organization=org, name="n", region="north")
            south = ScopedResource.objects.create(organization=org, name="s", region="south")
            self.assertTrue(is_authorized(user, org, "platform.organization:read", north))
            self.assertTrue(is_authorized(user, org, "platform.organization:read", south))

    def test_resource_scope_matching(self):
        user, org, mem = _user_org("s4", "OrgS4")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role = Role.objects.create(key="res_scope", name="R")
        role.permissions.add(perm)
        with tenant_db_context(org):
            res = ScopedResource.objects.create(organization=org, name="specific", region="north")
            MembershipRole.objects.create(membership=mem, role=role, scope_type="resource", scope_value=str(res.id))
            self.assertTrue(is_authorized(user, org, "platform.organization:read", res))
            other = ScopedResource.objects.create(organization=org, name="other", region="north")
            self.assertFalse(is_authorized(user, org, "platform.organization:read", other))


class ResourceTests(TestCase):
    def test_authorized_resource_allowed(self):
        user, org, mem = _user_org("res1", "OrgRes1")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role = Role.objects.create(key="res_role", name="R")
        role.permissions.add(perm)
        MembershipRole.objects.create(membership=mem, role=role)
        with tenant_db_context(org):
            res = ScopedResource.objects.create(organization=org, name="ok", region="north")
            self.assertTrue(is_authorized(user, org, "platform.organization:read", res))

    def test_unauthorized_resource_denied(self):
        user, org, mem = _user_org("res2", "OrgRes2")
        role = Role.objects.create(key="no_perm_res", name="R")
        MembershipRole.objects.create(membership=mem, role=role)
        with tenant_db_context(org):
            res = ScopedResource.objects.create(organization=org, name="ok", region="north")
            with self.assertRaises(AuthorizationDenied):
                authorize(user, org, "platform.organization:read", res)

    def test_invalid_resource_denied(self):
        user, org, mem = _user_org("res3", "OrgRes3")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role = Role.objects.create(key="inv_res_role", name="R")
        role.permissions.add(perm)
        MembershipRole.objects.create(membership=mem, role=role)
        bad = {"name": "bad"}
        with self.assertRaises(AuthorizationDenied) as cm:
            authorize(user, org, "platform.organization:read", bad)
        self.assertEqual(cm.exception.reason, "invalid_resource")

    def test_malformed_resource_denied(self):
        user, org, mem = _user_org("res4", "OrgRes4")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role = Role.objects.create(key="mal_role", name="R")
        role.permissions.add(perm)
        MembershipRole.objects.create(membership=mem, role=role)
        with tenant_db_context(org):
            res = ScopedResource.objects.create(organization=org, name="ok", region="north")
            res.organization_id = uuid.uuid4()
            with self.assertRaises(AuthorizationDenied):
                authorize(user, org, "platform.organization:read", res)

    def test_demo_protected_operation_enforces(self):
        user, org, mem = _user_org("demo", "OrgDemo")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role = Role.objects.create(key="demo_role", name="R")
        role.permissions.add(perm)
        MembershipRole.objects.create(membership=mem, role=role)
        with tenant_db_context(org):
            res = ScopedResource.objects.create(organization=org, name="demo_res", region="north")
            data = protected_read_scoped_resource(user, org, res)
            self.assertEqual(data["name"], "demo_res")
        from django.contrib.auth import get_user_model

        User = get_user_model()
        bad_user = User.objects.create_user(username="bad_demo", password="testpass123")
        with self.assertRaises(AuthorizationDenied):
            protected_read_scoped_resource(bad_user, org, res)

    def test_denied_does_not_leak_internal(self):
        user, org, _ = _user_org("leak", "OrgLeak")
        with self.assertRaises(AuthorizationDenied) as cm:
            authorize(user, org, "platform.organization:read")
        self.assertNotIn("role", str(cm.exception.internal_detail).lower() or "")
        self.assertEqual(str(cm.exception), cm.exception.reason)


class RLSIntegrationTests(TestCase):
    def test_allow_never_grants_cross_tenant_db_access(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        org_a = Organization.objects.create(name="OrgA")
        org_b = Organization.objects.create(name="OrgB")
        user_a = User.objects.create_user(username="a_rsl", password="testpass123")
        OrganizationMembership.objects.create(user=user_a, organization=org_a)
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role = Role.objects.create(key="rls_role", name="R")
        role.permissions.add(perm)
        mem_a = OrganizationMembership.objects.get(user=user_a, organization=org_a)
        MembershipRole.objects.create(membership=mem_a, role=role)
        with tenant_db_context(org_a):
            ScopedResource.objects.create(organization=org_a, name="a_res", region="north")
        with tenant_db_context(org_b):
            res_b = ScopedResource.objects.create(organization=org_b, name="b_res", region="north")
        self.assertFalse(is_authorized(user_a, org_a, "platform.organization:read", res_b))
        with self.assertRaises(AuthorizationDenied):
            authorize(user_a, org_a, "platform.organization:read", res_b)
        with tenant_db_context(org_a):
            self.assertEqual(ScopedResource.objects.filter(organization=org_a).count(), 1)
            self.assertTrue(ScopedResource.objects.filter(organization=org_b).exists())
            all_visible = list(ScopedResource.objects.all())
            self.assertGreaterEqual(len(all_visible), 1)
            self.assertTrue(any(r.organization_id == org_a.id for r in all_visible))

    def test_scope_with_rls_both_enforced(self):
        user, org_a, mem = _user_org("both", "OrgBoth")
        org_b = Organization.objects.create(name="OrgB_Both")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role = Role.objects.create(key="both_role", name="R")
        role.permissions.add(perm)
        MembershipRole.objects.create(membership=mem, role=role, scope_type="region", scope_value="north")
        with tenant_db_context(org_a):
            north_a = ScopedResource.objects.create(organization=org_a, name="north_a", region="north")
            south_a = ScopedResource.objects.create(organization=org_a, name="south_a", region="south")
        with tenant_db_context(org_b):
            north_b = ScopedResource.objects.create(organization=org_b, name="north_b", region="north")
        self.assertTrue(is_authorized(user, org_a, "platform.organization:read", north_a))
        self.assertFalse(is_authorized(user, org_a, "platform.organization:read", south_a))
        self.assertFalse(is_authorized(user, org_a, "platform.organization:read", north_b))


class FailClosedTests(TestCase):
    def test_all_fail_closed_cases(self):
        user, org, mem = _user_org("fail", "OrgFail")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role = Role.objects.create(key="fail_role", name="R")
        role.permissions.add(perm)
        MembershipRole.objects.create(membership=mem, role=role)
        cases = [
            (None, org, "platform.organization:read", None),
            (user, None, "platform.organization:read", None),
            (user, org, "", None),
            (user, org, None, None),
            (user, org, "platform.organization:read", {"bad": "resource"}),
        ]
        for u, o, p, r in cases:
            with self.subTest(u=u, o=o, p=p, r=r):
                self.assertFalse(is_authorized(u, o, p, r))
                with self.assertRaises(AuthorizationDenied):
                    authorize(u, o, p, r)

    def test_no_matching_role_binding_denied(self):
        user, org, mem = _user_org("nomatch", "OrgNoMatch")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        other_perm = Permission.objects.create(code="platform.membership:read", name="O")
        role = Role.objects.create(key="other_role", name="R")
        role.permissions.add(other_perm)
        MembershipRole.objects.create(membership=mem, role=role)
        with self.assertRaises(AuthorizationDenied) as cm:
            authorize(user, org, "platform.organization:read")
        self.assertEqual(cm.exception.reason, "no_permission")


class BootstrapIntegrationTests(TestCase):
    def test_bootstrap_roles_authorize(self):
        bootstrap_roles()
        from django.contrib.auth import get_user_model

        User = get_user_model()
        user = User.objects.create_user(username="boot", password="testpass123")
        org = Organization.objects.create(name="OrgBoot")
        mem = OrganizationMembership.objects.create(user=user, organization=org)
        admin_role = Role.objects.get(key="organization_admin")
        mem.roles.add(admin_role)
        with tenant_db_context(org):
            res = ScopedResource.objects.create(organization=org, name="x", region="north")
            self.assertTrue(is_authorized(user, org, "platform.organization:update", res))
            self.assertTrue(is_authorized(user, org, "platform.organization:read", res))
