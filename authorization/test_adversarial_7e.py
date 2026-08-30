import concurrent.futures
import uuid

from django.contrib.auth.models import AnonymousUser
from django.test import TransactionTestCase

from accounts.models import Organization, OrganizationMembership
from accounts.rls import tenant_db_context
from authorization.models import MembershipRole, Permission, Role, ScopedResource
from authorization.service import AuthorizationDenied, authorize, is_authorized


def _uorg(username, org_name):
    from django.contrib.auth import get_user_model

    User = get_user_model()
    u = User.objects.create_user(username=username, password="testpass123")
    o = Organization.objects.create(name=org_name)
    m = OrganizationMembership.objects.create(user=u, organization=o)
    return u, o, m


class AttackForgedUserTests(TransactionTestCase):
    def test_forged_user_uuid_denied(self):
        _, org, _ = _uorg("victim", "OrgVictim")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role = Role.objects.create(key="forged_r", name="R")
        role.permissions.add(perm)
        from django.contrib.auth import get_user_model

        User = get_user_model()
        fake = User(pk=uuid.uuid4(), username="fake")
        self.assertFalse(is_authorized(fake, org, "platform.organization:read"))
        with self.assertRaises(AuthorizationDenied) as cm:
            authorize(fake, org, "platform.organization:read")
        self.assertEqual(cm.exception.reason, "unknown_user")

    def test_missing_user_denied(self):
        org = Organization.objects.create(name="Org")
        with self.assertRaises(AuthorizationDenied) as cm:
            authorize(None, org, "platform.organization:read")
        self.assertEqual(cm.exception.reason, "unauthenticated")
        anon = AnonymousUser()
        self.assertFalse(is_authorized(anon, org, "platform.organization:read"))


class AttackWrongOrganizationTests(TransactionTestCase):
    def test_wrong_organization_denied(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        u = User.objects.create_user(username="u1", password="x")
        o1 = Organization.objects.create(name="O1")
        o2 = Organization.objects.create(name="O2")
        OrganizationMembership.objects.create(user=u, organization=o1)
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role = Role.objects.create(key="r1", name="R")
        role.permissions.add(perm)
        mem = OrganizationMembership.objects.get(user=u, organization=o1)
        MembershipRole.objects.create(membership=mem, role=role)
        self.assertFalse(is_authorized(u, o2, "platform.organization:read"))
        with self.assertRaises(AuthorizationDenied) as cm:
            authorize(u, o2, "platform.organization:read")
        self.assertEqual(cm.exception.reason, "no_membership")

    def test_valid_user_without_membership_denied(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        u = User.objects.create_user(username="nomem", password="x")
        org = Organization.objects.create(name="Org")
        self.assertFalse(is_authorized(u, org, "platform.organization:read"))
        with self.assertRaises(AuthorizationDenied):
            authorize(u, org, "platform.organization:read")

    def test_client_supplied_organization_id_denied(self):
        u, org, mem = _uorg("client_org", "OrgClient")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role = Role.objects.create(key="cr1", name="R")
        role.permissions.add(perm)
        MembershipRole.objects.create(membership=mem, role=role)
        target = Organization.objects.create(name="Target")
        self.assertFalse(is_authorized(u, target, "platform.organization:read"))
        with self.assertRaises(AuthorizationDenied):
            authorize(u, str(target.id), "platform.organization:read")
        with self.assertRaises(AuthorizationDenied):
            authorize(u, target, "platform.organization:read")


class AttackRolePermissionTests(TransactionTestCase):
    def test_membership_without_role_denied(self):
        u, org, _ = _uorg("norole", "OrgNoRole")
        Permission.objects.create(code="platform.organization:read", name="R")
        self.assertFalse(is_authorized(u, org, "platform.organization:read"))

    def test_role_without_permission_denied(self):
        u, org, mem = _uorg("noperm", "OrgNoPerm")
        perm_other = Permission.objects.create(code="platform.membership:read", name="O")
        Permission.objects.create(code="platform.organization:read", name="R")
        role = Role.objects.create(key="other_role", name="R")
        role.permissions.add(perm_other)
        MembershipRole.objects.create(membership=mem, role=role)
        self.assertFalse(is_authorized(u, org, "platform.organization:read"))
        with self.assertRaises(AuthorizationDenied) as cm:
            authorize(u, org, "platform.organization:read")
        self.assertEqual(cm.exception.reason, "no_permission")

    def test_client_supplied_role_denied(self):
        u, org, mem = _uorg("client_role", "OrgClientRole")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role = Role.objects.create(key="real_role", name="R")
        role.permissions.add(perm)
        MembershipRole.objects.create(membership=mem, role=role)
        fake_resource = {"organization_id": org.id, "role": "admin", "permission": "platform.organization:read"}
        self.assertTrue(is_authorized(u, org, "platform.organization:read", {"organization_id": org.id}))
        self.assertFalse(is_authorized(u, org, "platform.organization:update", {"organization_id": org.id, "role": "admin"}))

    def test_client_supplied_permission_denied(self):
        u, org, mem = _uorg("client_perm", "OrgClientPerm")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role = Role.objects.create(key="cp_role", name="R")
        role.permissions.add(perm)
        MembershipRole.objects.create(membership=mem, role=role)
        self.assertFalse(is_authorized(u, org, "platform.organization:update"))
        with self.assertRaises(AuthorizationDenied):
            authorize(u, org, "platform.organization:update", {"organization_id": org.id, "permission": "platform.organization:read"})

    def test_kinde_permission_injection_denied(self):
        u, org, mem = _uorg("kinde", "OrgKinde")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role = Role.objects.create(key="kinde_role", name="R")
        role.permissions.add(perm)
        MembershipRole.objects.create(membership=mem, role=role)
        kinde_claims = {"permissions": ["platform.organization:update"], "roles": ["admin"]}
        self.assertFalse(is_authorized(u, org, "platform.organization:update", {"organization_id": org.id, "kinde": kinde_claims}))
        self.assertFalse(is_authorized(u, org, "platform.organization:update"))


class AttackScopeTests(TransactionTestCase):
    def test_permission_without_matching_scope_denied(self):
        u, org, mem = _uorg("scope", "OrgScope")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role = Role.objects.create(key="scope_r", name="R")
        role.permissions.add(perm)
        MembershipRole.objects.create(membership=mem, role=role, scope_type="region", scope_value="north")
        with tenant_db_context(org):
            south = ScopedResource.objects.create(organization=org, name="south", region="south")
            self.assertFalse(is_authorized(u, org, "platform.organization:read", south))

    def test_matching_scope_wrong_tenant_denied(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        org_a = Organization.objects.create(name="OrgA")
        org_b = Organization.objects.create(name="OrgB")
        u = User.objects.create_user(username="scope_tenant", password="x")
        OrganizationMembership.objects.create(user=u, organization=org_a)
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role = Role.objects.create(key="scope_tenant_r", name="R")
        role.permissions.add(perm)
        mem_a = OrganizationMembership.objects.get(user=u, organization=org_a)
        MembershipRole.objects.create(membership=mem_a, role=role, scope_type="region", scope_value="north")
        with tenant_db_context(org_b):
            res_b = ScopedResource.objects.create(organization=org_b, name="b_north", region="north")
        self.assertFalse(is_authorized(u, org_a, "platform.organization:read", res_b))
        with self.assertRaises(AuthorizationDenied) as cm:
            authorize(u, org_a, "platform.organization:read", res_b)
        self.assertEqual(cm.exception.reason, "scope_mismatch")

    def test_resource_id_another_tenant_denied(self):
        u, org_a, mem_a = _uorg("res_tenant", "OrgResA")
        org_b = Organization.objects.create(name="OrgResB")
        from django.contrib.auth import get_user_model

        User = get_user_model()
        User.objects.create_user(username="other", password="x")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role = Role.objects.create(key="res_tenant_r", name="R")
        role.permissions.add(perm)
        with tenant_db_context(org_b):
            res_b = ScopedResource.objects.create(organization=org_b, name="b_res", region="north")
        MembershipRole.objects.create(membership=mem_a, role=role, scope_type="resource", scope_value=str(res_b.id))
        self.assertFalse(is_authorized(u, org_a, "platform.organization:read", res_b))

    def test_malformed_scope_denied(self):
        u, org, mem = _uorg("mal_scope", "OrgMal")
        role = Role.objects.create(key="mal_r", name="R")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role.permissions.add(perm)
        br = MembershipRole(membership=mem, role=role, scope_type="region", scope_value="")
        with self.assertRaises(Exception):
            br.full_clean()
        MembershipRole.objects.create(membership=mem, role=role, scope_type="region", scope_value="north")
        with tenant_db_context(org):
            bad = {"organization_id": org.id, "region": None}
            self.assertFalse(is_authorized(u, org, "platform.organization:read", bad))

    def test_stale_role_assignment_denied(self):
        u, org, mem = _uorg("stale", "OrgStale")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role = Role.objects.create(key="stale_r", name="R")
        role.permissions.add(perm)
        br = MembershipRole.objects.create(membership=mem, role=role)
        self.assertTrue(is_authorized(u, org, "platform.organization:read"))
        br.delete()
        self.assertFalse(is_authorized(u, org, "platform.organization:read"))
        with self.assertRaises(AuthorizationDenied):
            authorize(u, org, "platform.organization:read")

    def test_removed_role_denied(self):
        u, org, mem = _uorg("rem_role", "OrgRemRole")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role = Role.objects.create(key="rem_r", name="R")
        role.permissions.add(perm)
        MembershipRole.objects.create(membership=mem, role=role)
        self.assertTrue(is_authorized(u, org, "platform.organization:read"))
        role.delete()
        self.assertFalse(is_authorized(u, org, "platform.organization:read"))

    def test_removed_permission_denied(self):
        u, org, mem = _uorg("rem_perm", "OrgRemPerm")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role = Role.objects.create(key="rem_perm_r", name="R")
        role.permissions.add(perm)
        MembershipRole.objects.create(membership=mem, role=role)
        self.assertTrue(is_authorized(u, org, "platform.organization:read"))
        role.permissions.remove(perm)
        self.assertFalse(is_authorized(u, org, "platform.organization:read"))
        with self.assertRaises(AuthorizationDenied) as cm:
            authorize(u, org, "platform.organization:read")
        self.assertEqual(cm.exception.reason, "no_permission")

    def test_manipulated_organization_context_denied(self):
        u, org_a, mem = _uorg("manip", "OrgManipA")
        org_b = Organization.objects.create(name="OrgManipB")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role = Role.objects.create(key="manip_r", name="R")
        role.permissions.add(perm)
        MembershipRole.objects.create(membership=mem, role=role)
        with tenant_db_context(org_b):
            res_b = ScopedResource.objects.create(organization=org_b, name="b", region="north")
        self.assertFalse(is_authorized(u, org_a, "platform.organization:read", res_b))
        fake_org_resource = {"organization_id": org_a.id, "id": res_b.id, "region": "north"}
        self.assertFalse(is_authorized(u, org_b, "platform.organization:read", fake_org_resource))


class AttackDirectORMAndConcurrencyTests(TransactionTestCase):
    def test_direct_orm_retrieval_still_denied_by_authz(self):
        u, org_a, mem = _uorg("direct", "OrgDirectA")
        org_b = Organization.objects.create(name="OrgDirectB")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role = Role.objects.create(key="direct_r", name="R")
        role.permissions.add(perm)
        MembershipRole.objects.create(membership=mem, role=role)
        with tenant_db_context(org_b):
            res_b = ScopedResource.objects.create(organization=org_b, name="b_secret", region="north")
        fetched = ScopedResource.objects.get(id=res_b.id)
        self.assertEqual(fetched.id, res_b.id)
        self.assertFalse(is_authorized(u, org_a, "platform.organization:read", fetched))

    def test_concurrent_authorization_isolation(self):
        org_a = Organization.objects.create(name="ConcA")
        org_b = Organization.objects.create(name="ConcB")
        from django.contrib.auth import get_user_model

        User = get_user_model()
        u_a = User.objects.create_user(username="conc_a", password="x")
        u_b = User.objects.create_user(username="conc_b", password="x")
        OrganizationMembership.objects.create(user=u_a, organization=org_a)
        OrganizationMembership.objects.create(user=u_b, organization=org_b)
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        for u, org in [(u_a, org_a), (u_b, org_b)]:
            role = Role.objects.create(key=f"conc_{org.name}", name="R")
            role.permissions.add(perm)
            mem = OrganizationMembership.objects.get(user=u, organization=org)
            MembershipRole.objects.create(membership=mem, role=role)
        with tenant_db_context(org_a):
            ra = ScopedResource.objects.create(organization=org_a, name="ra", region="north")
        with tenant_db_context(org_b):
            rb = ScopedResource.objects.create(organization=org_b, name="rb", region="north")

        def check(u, org, res, expect):
            from django.db import connection

            connection.close()
            return is_authorized(u, org, "platform.organization:read", res) == expect

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            futs = []
            for _ in range(5):
                futs.append(ex.submit(check, u_a, org_a, ra, True))
                futs.append(ex.submit(check, u_a, org_a, rb, False))
                futs.append(ex.submit(check, u_b, org_b, rb, True))
                futs.append(ex.submit(check, u_b, org_b, ra, False))
            for f in futs:
                self.assertTrue(f.result())

    def test_authorization_immediately_after_change(self):
        u, org, mem = _uorg("immediate", "OrgImm")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role = Role.objects.create(key="imm_r", name="R")
        role.permissions.add(perm)
        self.assertFalse(is_authorized(u, org, "platform.organization:read"))
        br = MembershipRole.objects.create(membership=mem, role=role)
        self.assertTrue(is_authorized(u, org, "platform.organization:read"))
        br.delete()
        self.assertFalse(is_authorized(u, org, "platform.organization:read"))
        MembershipRole.objects.create(membership=mem, role=role)
        self.assertTrue(is_authorized(u, org, "platform.organization:read"))
        role.permissions.remove(perm)
        self.assertFalse(is_authorized(u, org, "platform.organization:read"))
        role.permissions.add(perm)
        self.assertTrue(is_authorized(u, org, "platform.organization:read"))

    def test_superuser_without_rbac_denied(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        su = User.objects.create_superuser(username="su_adv", password="x", email="a@b.com")
        org = Organization.objects.create(name="OrgSU")
        OrganizationMembership.objects.create(user=su, organization=org)
        self.assertFalse(is_authorized(su, org, "platform.organization:read"))
        with self.assertRaises(AuthorizationDenied):
            authorize(su, org, "platform.organization:read")
        self.assertTrue(su.is_superuser)

    def test_tenant_resource_rls_still_enforced(self):
        from accounts.models import TenantResource

        org_a = Organization.objects.create(name="RLSA")
        org_b = Organization.objects.create(name="RLSB")
        from accounts.rls import tenant_db_context as tdc

        with tdc(org_a):
            ra = TenantResource.objects.create(name="ra")
        with tdc(org_b):
            rb = TenantResource.objects.create(name="rb")
        u, _, _ = _uorg("rls_user", "OrgRLSUser")
        with tdc(org_a):
            self.assertTrue(TenantResource.objects.filter(id=ra.id).exists())
            self.assertFalse(TenantResource.objects.filter(id=rb.id).exists())
            all_ids = set(TenantResource.objects.values_list("id", flat=True))
            self.assertIn(ra.id, all_ids)
            self.assertNotIn(rb.id, all_ids)
