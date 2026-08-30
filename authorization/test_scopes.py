import uuid

from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.test import TestCase

from accounts.models import Organization, OrganizationMembership
from accounts.rls import tenant_db_context
from authorization.bootstrap import bootstrap_permissions, bootstrap_roles
from authorization.models import MembershipRole, Permission, Role, ScopedResource
from authorization.scopes import membership_has_permission, scope_allows


def _create_user_org(username, org_name):
    from django.contrib.auth import get_user_model

    User = get_user_model()
    user = User.objects.create_user(username=username, password="testpass123")
    org = Organization.objects.create(name=org_name)
    membership = OrganizationMembership.objects.create(user=user, organization=org)
    return user, org, membership


class OrganizationWideScopeTests(TestCase):
    def test_organization_wide_role_allows_organization_resources(self):
        bootstrap_permissions()
        _, org, membership = _create_user_org("alice_wide", "OrgWide")
        role = Role.objects.create(key="wide_role", name="Wide")
        perm = Permission.objects.get(code="platform.organization:read")
        role.permissions.add(perm)
        MembershipRole.objects.create(membership=membership, role=role, scope_type="", scope_value="")
        with tenant_db_context(org):
            res = ScopedResource.objects.create(organization=org, name="res1", region="north")
            self.assertTrue(membership_has_permission(membership, "platform.organization:read", res))
            self.assertTrue(scope_allows(membership.membership_roles.first(), res))

    def test_organization_wide_allows_any_region(self):
        _, org, membership = _create_user_org("alice_any", "OrgAny")
        role = Role.objects.create(key="wide_any", name="Wide")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role.permissions.add(perm)
        br = MembershipRole.objects.create(membership=membership, role=role)
        with tenant_db_context(org):
            r1 = ScopedResource.objects.create(organization=org, name="a", region="north")
            r2 = ScopedResource.objects.create(organization=org, name="b", region="south")
            self.assertTrue(scope_allows(br, r1))
            self.assertTrue(scope_allows(br, r2))


class ScopedRoleTests(TestCase):
    def test_scoped_role_allows_within_scope(self):
        _, org, membership = _create_user_org("bob_north", "OrgNorth")
        role = Role.objects.create(key="region_role", name="Region")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role.permissions.add(perm)
        br = MembershipRole.objects.create(membership=membership, role=role, scope_type="region", scope_value="north")
        with tenant_db_context(org):
            north = ScopedResource.objects.create(organization=org, name="north_res", region="north")
            self.assertTrue(scope_allows(br, north))
            self.assertTrue(membership_has_permission(membership, "platform.organization:read", north))

    def test_scoped_role_denies_outside_scope(self):
        _, org, membership = _create_user_org("bob_south", "OrgSouth")
        role = Role.objects.create(key="region_deny", name="Region")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role.permissions.add(perm)
        br = MembershipRole.objects.create(membership=membership, role=role, scope_type="region", scope_value="north")
        with tenant_db_context(org):
            south = ScopedResource.objects.create(organization=org, name="south_res", region="south")
            self.assertFalse(scope_allows(br, south))
            self.assertFalse(membership_has_permission(membership, "platform.organization:read", south))

    def test_resource_scope_allows_specific_id(self):
        _, org, membership = _create_user_org("carol_res", "OrgRes")
        role = Role.objects.create(key="res_role", name="Res")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role.permissions.add(perm)
        with tenant_db_context(org):
            res = ScopedResource.objects.create(organization=org, name="specific", region="north")
            br = MembershipRole.objects.create(membership=membership, role=role, scope_type="resource", scope_value=str(res.id))
            self.assertTrue(scope_allows(br, res))
            other = ScopedResource.objects.create(organization=org, name="other", region="north")
            self.assertFalse(scope_allows(br, other))

    def test_future_dimension_extensible(self):
        _, org, membership = _create_user_org("dave_future", "OrgFuture")
        role = Role.objects.create(key="future_role", name="Future")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role.permissions.add(perm)
        br = MembershipRole.objects.create(membership=membership, role=role, scope_type="cost_center", scope_value="cc123")
        self.assertTrue(scope_allows(br, {"cost_center": "cc123", "organization_id": org.id}))
        self.assertFalse(scope_allows(br, {"cost_center": "cc999", "organization_id": org.id}))


class ScopeBoundaryTests(TestCase):
    def test_scope_cannot_reference_another_organization(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        _, org_a, mem_a = _create_user_org("alice_a", "OrgA")
        org_b = Organization.objects.create(name="OrgB")
        user_b = User.objects.create_user(username="bob_b", password="testpass123")
        OrganizationMembership.objects.create(user=user_b, organization=org_b)
        role = Role.objects.create(key="cross_role", name="Cross")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role.permissions.add(perm)
        with tenant_db_context(org_b):
            res_b = ScopedResource.objects.create(organization=org_b, name="b_res", region="north")
        br = MembershipRole.objects.create(membership=mem_a, role=role, scope_type="resource", scope_value=str(res_b.id))
        self.assertFalse(scope_allows(br, res_b))
        self.assertFalse(membership_has_permission(mem_a, "platform.organization:read", res_b))

    def test_scope_evaluation_never_broadens_tenant(self):
        _, org_a, mem_a = _create_user_org("alice_tenant", "OrgA2")
        org_b = Organization.objects.create(name="OrgB2")
        role = Role.objects.create(key="tenant_role", name="Tenant")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role.permissions.add(perm)
        MembershipRole.objects.create(membership=mem_a, role=role, scope_type="region", scope_value="north")
        with tenant_db_context(org_b):
            res_b = ScopedResource.objects.create(organization=org_b, name="b_north", region="north")
        self.assertFalse(scope_allows(mem_a.membership_roles.first(), res_b))

    def test_scope_validation_rejects_organization_value(self):
        _, _, mem = _create_user_org("val_org", "OrgVal")
        role = Role.objects.create(key="val_role", name="Val")
        br = MembershipRole(membership=mem, role=role, scope_type="organization", scope_value="notempty")
        with self.assertRaises(ValidationError):
            br.full_clean()

    def test_scope_validation_rejects_invalid_region(self):
        _, _, mem = _create_user_org("val_reg", "OrgVal2")
        role = Role.objects.create(key="val_reg_role", name="Val")
        br = MembershipRole(membership=mem, role=role, scope_type="region", scope_value="")
        with self.assertRaises(ValidationError):
            br.full_clean()

    def test_scope_validation_rejects_invalid_resource_uuid(self):
        _, _, mem = _create_user_org("val_res", "OrgVal3")
        role = Role.objects.create(key="val_res_role", name="Val")
        br = MembershipRole(membership=mem, role=role, scope_type="resource", scope_value="not-a-uuid")
        with self.assertRaises(ValidationError):
            br.full_clean()

    def test_duplicate_scope_rejected(self):
        _, _, mem = _create_user_org("dup_scope", "OrgDup")
        role = Role.objects.create(key="dup_role", name="Dup")
        MembershipRole.objects.create(membership=mem, role=role, scope_type="region", scope_value="north")
        with self.assertRaises(IntegrityError):
            MembershipRole.objects.create(membership=mem, role=role, scope_type="region", scope_value="north")

    def test_same_role_different_scopes_allowed(self):
        _, _, mem = _create_user_org("multi_scope", "OrgMulti")
        role = Role.objects.create(key="multi_role", name="Multi")
        MembershipRole.objects.create(membership=mem, role=role, scope_type="region", scope_value="north")
        MembershipRole.objects.create(membership=mem, role=role, scope_type="region", scope_value="south")
        self.assertEqual(mem.membership_roles.filter(role=role).count(), 2)


class MissingScopeTests(TestCase):
    def test_missing_scope_defaults_to_organization_wide(self):
        _, org, mem = _create_user_org("missing_scope", "OrgMissing")
        role = Role.objects.create(key="missing_role", name="Missing")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role.permissions.add(perm)
        br = MembershipRole.objects.create(membership=mem, role=role)
        self.assertTrue(br.is_organization_wide)
        with tenant_db_context(org):
            res = ScopedResource.objects.create(organization=org, name="any", region="south")
            self.assertTrue(scope_allows(br, res))
            self.assertTrue(membership_has_permission(mem, "platform.organization:read", res))

    def test_missing_permission_denied_even_with_scope(self):
        _, org, mem = _create_user_org("no_perm", "OrgNoPerm")
        role = Role.objects.create(key="no_perm_role", name="NoPerm")
        MembershipRole.objects.create(membership=mem, role=role, scope_type="region", scope_value="north")
        with tenant_db_context(org):
            res = ScopedResource.objects.create(organization=org, name="res", region="north")
            self.assertFalse(membership_has_permission(mem, "platform.organization:read", res))

    def test_resource_missing_region_denied_for_region_scope(self):
        _, org, mem = _create_user_org("missing_region", "OrgMissingReg")
        role = Role.objects.create(key="missing_reg_role", name="MissingReg")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role.permissions.add(perm)
        br = MembershipRole.objects.create(membership=mem, role=role, scope_type="region", scope_value="north")
        with tenant_db_context(org):
            res_no_region = ScopedResource.objects.create(organization=org, name="no_region", region="")
            self.assertFalse(scope_allows(br, res_no_region))


class RLSCompatibilityTests(TestCase):
    def test_scope_remains_compatible_with_rls(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        _, org_a, mem_a = _create_user_org("rls_a", "OrgRLS_A")
        org_b = Organization.objects.create(name="OrgRLS_B")
        user_b = User.objects.create_user(username="rls_b", password="testpass123")
        OrganizationMembership.objects.create(user=user_b, organization=org_b)
        role = Role.objects.create(key="rls_role", name="RLS")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role.permissions.add(perm)
        MembershipRole.objects.create(membership=mem_a, role=role)
        with tenant_db_context(org_a):
            ScopedResource.objects.create(organization=org_a, name="a_res", region="north")
        with tenant_db_context(org_b):
            ScopedResource.objects.create(organization=org_b, name="b_res", region="north")
            count_b = ScopedResource.objects.filter(organization=org_b).count()
            self.assertEqual(count_b, 1)
        with tenant_db_context(org_a):
            visible = list(ScopedResource.objects.filter(organization=org_a))
            self.assertEqual(len(visible), 1)
            self.assertEqual(visible[0].name, "a_res")
            b_via_rls = ScopedResource.objects.filter(organization=org_b).count()
            self.assertEqual(b_via_rls, 1)

    def test_tenant_isolation_enforced_on_scoped_resource(self):
        _, org_a, _ = _create_user_org("iso_a", "OrgIsoA")
        _, org_b, _ = _create_user_org("iso_b", "OrgIsoB")
        with tenant_db_context(org_a):
            r = ScopedResource.objects.create(organization=org_a, name="a", region="north")
            r_id = r.id
        with tenant_db_context(org_b):
            res = ScopedResource.objects.get(id=r_id)
            self.assertEqual(res.organization_id, org_a.id)

    def test_cross_tenant_save_denied(self):
        _, org_a, _ = _create_user_org("save_a", "OrgSaveA")
        org_b = Organization.objects.create(name="OrgSaveB")
        from accounts.tenancy import MissingTenantError

        with tenant_db_context(org_b):
            with self.assertRaises(MissingTenantError):
                ScopedResource.objects.create(organization=org_a, name="cross", region="north")


class DifferentUsersScopesTests(TestCase):
    def test_different_users_different_scopes_same_organization(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        org = Organization.objects.create(name="SharedOrg")
        u1 = User.objects.create_user(username="user_north", password="testpass123")
        u2 = User.objects.create_user(username="user_south", password="testpass123")
        m1 = OrganizationMembership.objects.create(user=u1, organization=org)
        m2 = OrganizationMembership.objects.create(user=u2, organization=org)
        role = Role.objects.create(key="shared_role", name="Shared")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role.permissions.add(perm)
        MembershipRole.objects.create(membership=m1, role=role, scope_type="region", scope_value="north")
        MembershipRole.objects.create(membership=m2, role=role, scope_type="region", scope_value="south")
        with tenant_db_context(org):
            north = ScopedResource.objects.create(organization=org, name="north_res", region="north")
            south = ScopedResource.objects.create(organization=org, name="south_res", region="south")
            self.assertTrue(membership_has_permission(m1, "platform.organization:read", north))
            self.assertFalse(membership_has_permission(m1, "platform.organization:read", south))
            self.assertTrue(membership_has_permission(m2, "platform.organization:read", south))
            self.assertFalse(membership_has_permission(m2, "platform.organization:read", north))

    def test_same_user_different_orgs_different_scopes(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        user = User.objects.create_user(username="multi_org", password="testpass123")
        org1 = Organization.objects.create(name="Org1")
        org2 = Organization.objects.create(name="Org2")
        m1 = OrganizationMembership.objects.create(user=user, organization=org1)
        m2 = OrganizationMembership.objects.create(user=user, organization=org2)
        role = Role.objects.create(key="multi_org_role", name="Multi")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role.permissions.add(perm)
        MembershipRole.objects.create(membership=m1, role=role, scope_type="region", scope_value="north")
        MembershipRole.objects.create(membership=m2, role=role, scope_type="region", scope_value="south")
        with tenant_db_context(org1):
            north = ScopedResource.objects.create(organization=org1, name="n", region="north")
        with tenant_db_context(org2):
            south = ScopedResource.objects.create(organization=org2, name="s", region="south")
        self.assertTrue(membership_has_permission(m1, "platform.organization:read", north))
        self.assertFalse(membership_has_permission(m2, "platform.organization:read", north))
        self.assertTrue(membership_has_permission(m2, "platform.organization:read", south))
