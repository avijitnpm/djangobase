import uuid

from django.contrib import admin
from django.contrib.auth.models import Group, Permission as DjangoPermission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.test import TestCase

from accounts.models import Organization, OrganizationMembership
from authorization.bootstrap import PLATFORM_PERMISSIONS, PLATFORM_ROLES, bootstrap_permissions, bootstrap_roles
from authorization.models import MembershipRole, Permission, Role


class PermissionCreationTests(TestCase):
    def test_permission_creation_works(self):
        perm = Permission.objects.create(
            code="platform.organization:read",
            name="View organization",
            description="Can view organization",
        )
        self.assertIsNotNone(perm.pk)
        self.assertIsInstance(perm.id, uuid.UUID)
        self.assertEqual(perm.code, "platform.organization:read")

    def test_permission_has_metadata(self):
        perm = Permission.objects.create(
            code="platform.membership:read",
            name="View memberships",
            description="Can view memberships",
        )
        self.assertEqual(perm.name, "View memberships")
        self.assertEqual(perm.description, "Can view memberships")
        self.assertIsNotNone(perm.created_at)
        self.assertIsNotNone(perm.updated_at)

    def test_permission_str_is_code(self):
        perm = Permission.objects.create(code="platform.test:read", name="Test")
        self.assertEqual(str(perm), "platform.test:read")


class PermissionUniqueTests(TestCase):
    def test_permission_codes_are_unique(self):
        Permission.objects.create(code="platform.organization:read", name="A")
        with self.assertRaises(IntegrityError):
            Permission.objects.create(code="platform.organization:read", name="B")

    def test_duplicate_codes_are_rejected(self):
        Permission.objects.create(code="platform.membership:update", name="A")
        perm = Permission(code="platform.membership:update", name="B")
        with self.assertRaises(IntegrityError):
            perm.save()

    def test_code_unique_constraint_enforced_at_db(self):
        Permission.objects.create(code="platform.organization:update", name="A")
        from django.db import connection

        with self.assertRaises(IntegrityError):
            with connection.cursor() as cur:
                cur.execute(
                    "INSERT INTO authorization_permission (id, code, name, description, created_at, updated_at) VALUES (%s, %s, %s, %s, NOW(), NOW())",
                    [str(uuid.uuid4()), "platform.organization:update", "dup", ""],
                )


class PermissionLookupTests(TestCase):
    def test_stable_lookup_by_code(self):
        Permission.objects.create(code="platform.organization:read", name="View org")
        fetched = Permission.objects.get(code="platform.organization:read")
        self.assertEqual(fetched.code, "platform.organization:read")

    def test_lookup_nonexistent_returns_does_not_exist(self):
        with self.assertRaises(Permission.DoesNotExist):
            Permission.objects.get(code="platform.nonexistent:read")

    def test_filter_by_code(self):
        Permission.objects.create(code="platform.organization:read", name="A")
        Permission.objects.create(code="platform.membership:read", name="B")
        self.assertEqual(Permission.objects.filter(code__startswith="platform.").count(), 2)


class BootstrapPermissionTests(TestCase):
    def test_bootstrap_creates_platform_permissions(self):
        bootstrap_permissions()
        codes = set(Permission.objects.values_list("code", flat=True))
        expected = {p["code"] for p in PLATFORM_PERMISSIONS}
        self.assertEqual(codes, expected)

    def test_bootstrap_is_deterministic(self):
        bootstrap_permissions()
        first_ids = {p.code: str(p.id) for p in Permission.objects.all()}
        bootstrap_permissions()
        second_ids = {p.code: str(p.id) for p in Permission.objects.all()}
        self.assertEqual(first_ids, second_ids)
        self.assertEqual(Permission.objects.count(), len(PLATFORM_PERMISSIONS))

    def test_bootstrap_is_idempotent(self):
        bootstrap_permissions()
        bootstrap_permissions()
        bootstrap_permissions()
        self.assertEqual(Permission.objects.count(), len(PLATFORM_PERMISSIONS))

    def test_bootstrap_updates_metadata(self):
        bootstrap_permissions()
        Permission.objects.filter(code="platform.organization:read").update(name="Old")
        bootstrap_permissions()
        perm = Permission.objects.get(code="platform.organization:read")
        self.assertEqual(perm.name, "View organization")

    def test_bootstrap_does_not_create_duplicate(self):
        bootstrap_permissions()
        count_before = Permission.objects.count()
        bootstrap_permissions()
        self.assertEqual(Permission.objects.count(), count_before)

    def test_bootstrap_permissions_have_expected_codes(self):
        bootstrap_permissions()
        for code in [
            "platform.organization:read",
            "platform.organization:update",
            "platform.membership:read",
            "platform.membership:update",
        ]:
            self.assertTrue(Permission.objects.filter(code=code).exists(), f"missing {code}")


class DjangoBuiltInPermissionTests(TestCase):
    def test_django_auth_permission_still_works(self):
        ct = ContentType.objects.get_for_model(Organization)
        perm, created = DjangoPermission.objects.get_or_create(
            codename="can_test_legacy",
            content_type=ct,
            defaults={"name": "Can test legacy"},
        )
        self.assertIsNotNone(perm.pk)
        self.assertIn("can_test_legacy", perm.codename)

    def test_django_group_permissions_intact(self):
        group = Group.objects.create(name="test-group")
        ct = ContentType.objects.get_for_model(Organization)
        perm = DjangoPermission.objects.create(
            codename="custom_perm_for_group_test",
            name="Custom perm",
            content_type=ct,
        )
        group.permissions.add(perm)
        self.assertIn(perm, group.permissions.all())

    def test_platform_permissions_do_not_interfere_with_auth_permissions(self):
        bootstrap_permissions()
        ct = ContentType.objects.get_for_model(Organization)
        DjangoPermission.objects.get_or_create(
            codename="another_legacy_perm",
            content_type=ct,
            defaults={"name": "Another"},
        )
        self.assertEqual(Permission.objects.count(), len(PLATFORM_PERMISSIONS))
        self.assertTrue(DjangoPermission.objects.filter(codename="another_legacy_perm").exists())

    def test_django_user_has_perm_mechanism_still_available(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        user = User.objects.create_user(username="permtestuser", password="testpass123")
        self.assertTrue(hasattr(user, "has_perm"))
        self.assertTrue(hasattr(user, "get_all_permissions"))


class PermissionValidationTests(TestCase):
    def test_invalid_code_format_rejected(self):
        perm = Permission(code="invalid-code", name="Bad")
        with self.assertRaises(ValidationError):
            perm.full_clean()

    def test_code_requires_namespace_dot_resource_colon_action(self):
        for bad in ["platform:read", "platform.organization.read", "PLATFORM.organization:read", "platform.organization:READ"]:
            with self.subTest(bad=bad):
                perm = Permission(code=bad, name="Bad")
                with self.assertRaises(ValidationError):
                    perm.full_clean()

    def test_no_tenant_id_in_code(self):
        perm = Permission(code="platform.organization:read", name="Good")
        perm.full_clean()
        self.assertNotIn(str(uuid.uuid4()), perm.code)


class RoleCreationTests(TestCase):
    def test_role_creation_works(self):
        role = Role.objects.create(key="organization_admin", name="Organization Admin")
        self.assertIsNotNone(role.pk)
        self.assertIsInstance(role.id, uuid.UUID)
        self.assertEqual(role.key, "organization_admin")

    def test_role_has_metadata(self):
        role = Role.objects.create(key="organization_member", name="Member", description="Read only")
        self.assertEqual(role.name, "Member")
        self.assertEqual(role.description, "Read only")
        self.assertIsNotNone(role.created_at)

    def test_role_str_is_key(self):
        role = Role.objects.create(key="test_role", name="Test")
        self.assertEqual(str(role), "test_role")

    def test_role_keys_are_unique(self):
        Role.objects.create(key="organization_admin", name="A")
        with self.assertRaises(IntegrityError):
            Role.objects.create(key="organization_admin", name="B")

    def test_duplicate_role_rejected(self):
        Role.objects.create(key="organization_member", name="A")
        with self.assertRaises(IntegrityError):
            Role.objects.create(key="organization_member", name="Dup")

    def test_role_key_validation(self):
        role = Role(key="Invalid-Key", name="Bad")
        with self.assertRaises(ValidationError):
            role.full_clean()

    def test_role_with_no_permissions(self):
        role = Role.objects.create(key="empty_role", name="Empty")
        self.assertEqual(role.permissions.count(), 0)


class RolePermissionTests(TestCase):
    def test_role_to_permission_association(self):
        bootstrap_permissions()
        role = Role.objects.create(key="organization_admin", name="Admin")
        perms = Permission.objects.all()
        role.permissions.set(perms)
        self.assertEqual(role.permissions.count(), len(PLATFORM_PERMISSIONS))

    def test_role_permissions_are_correct(self):
        bootstrap_permissions()
        role = Role.objects.create(key="test_role", name="Test")
        perm = Permission.objects.get(code="platform.organization:read")
        role.permissions.add(perm)
        self.assertIn(perm, role.permissions.all())

    def test_role_permissions_removal(self):
        bootstrap_permissions()
        role = Role.objects.create(key="test_role", name="Test")
        perm = Permission.objects.get(code="platform.organization:read")
        role.permissions.add(perm)
        role.permissions.remove(perm)
        self.assertNotIn(perm, role.permissions.all())

    def test_multiple_roles_share_permission(self):
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        r1 = Role.objects.create(key="role_one", name="One")
        r2 = Role.objects.create(key="role_two", name="Two")
        r1.permissions.add(perm)
        r2.permissions.add(perm)
        self.assertIn(perm, r1.permissions.all())
        self.assertIn(perm, r2.permissions.all())


class MembershipRoleTests(TestCase):
    def _create_membership(self, username="alice", org_name="Acme"):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        user = User.objects.create_user(username=username, password="testpass123")
        org = Organization.objects.create(name=org_name)
        membership = OrganizationMembership.objects.create(user=user, organization=org)
        return user, org, membership

    def test_membership_to_role_assignment_via_through(self):
        _, _, membership = self._create_membership()
        role = Role.objects.create(key="organization_admin", name="Admin")
        MembershipRole.objects.create(membership=membership, role=role)
        self.assertIn(role, membership.roles.all())

    def test_membership_to_role_via_m2m_add(self):
        _, _, membership = self._create_membership()
        role = Role.objects.create(key="organization_member", name="Member")
        membership.roles.add(role)
        self.assertIn(role, membership.roles.all())

    def test_membership_has_multiple_roles(self):
        _, _, membership = self._create_membership()
        r1 = Role.objects.create(key="organization_admin", name="Admin")
        r2 = Role.objects.create(key="organization_member", name="Member")
        membership.roles.add(r1, r2)
        self.assertEqual(membership.roles.count(), 2)

    def test_duplicate_membership_role_rejected(self):
        _, _, membership = self._create_membership()
        role = Role.objects.create(key="organization_admin", name="Admin")
        MembershipRole.objects.create(membership=membership, role=role)
        with self.assertRaises(IntegrityError):
            MembershipRole.objects.create(membership=membership, role=role)

    def test_removing_role_removes_granted_permissions(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        bootstrap_permissions()
        user = User.objects.create_user(username="bob", password="testpass123")
        org = Organization.objects.create(name="Org1")
        membership = OrganizationMembership.objects.create(user=user, organization=org)
        role = Role.objects.create(key="organization_admin", name="Admin")
        role.permissions.set(Permission.objects.all())
        membership.roles.add(role)
        effective_before = set(Permission.objects.filter(roles__membership_roles__membership=membership).values_list("code", flat=True))
        self.assertEqual(len(effective_before), len(PLATFORM_PERMISSIONS))
        membership.roles.remove(role)
        effective_after = set(Permission.objects.filter(roles__membership_roles__membership=membership).values_list("code", flat=True))
        self.assertEqual(len(effective_after), 0)

    def test_role_deletion_cascades_membership_role(self):
        _, _, membership = self._create_membership()
        role = Role.objects.create(key="temp_role", name="Temp")
        MembershipRole.objects.create(membership=membership, role=role)
        role.delete()
        self.assertEqual(MembershipRole.objects.filter(membership=membership).count(), 0)

    def test_membership_deletion_cascades(self):
        _, _, membership = self._create_membership()
        role = Role.objects.create(key="temp_role", name="Temp")
        MembershipRole.objects.create(membership=membership, role=role)
        membership.delete()
        self.assertEqual(MembershipRole.objects.filter(role=role).count(), 0)


class OrganizationScopingTests(TestCase):
    def test_same_user_different_roles_in_different_organizations(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        bootstrap_permissions()
        user = User.objects.create_user(username="charlie", password="testpass123")
        org1 = Organization.objects.create(name="Org1")
        org2 = Organization.objects.create(name="Org2")
        m1 = OrganizationMembership.objects.create(user=user, organization=org1)
        m2 = OrganizationMembership.objects.create(user=user, organization=org2)
        admin_role = Role.objects.create(key="organization_admin", name="Admin")
        member_role = Role.objects.create(key="organization_member", name="Member")
        admin_role.permissions.set(Permission.objects.filter(code__in=["platform.organization:read", "platform.organization:update"]))
        member_role.permissions.set(Permission.objects.filter(code="platform.organization:read"))
        m1.roles.add(admin_role)
        m2.roles.add(member_role)
        self.assertIn(admin_role, m1.roles.all())
        self.assertNotIn(member_role, m1.roles.all())
        self.assertIn(member_role, m2.roles.all())
        self.assertNotIn(admin_role, m2.roles.all())
        perms_m1 = set(Permission.objects.filter(roles__membership_roles__membership=m1).values_list("code", flat=True))
        perms_m2 = set(Permission.objects.filter(roles__membership_roles__membership=m2).values_list("code", flat=True))
        self.assertIn("platform.organization:update", perms_m1)
        self.assertNotIn("platform.organization:update", perms_m2)

    def test_role_is_not_global_user_privilege(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        u1 = User.objects.create_user(username="u1", password="testpass123")
        u2 = User.objects.create_user(username="u2", password="testpass123")
        org = Organization.objects.create(name="Org")
        m1 = OrganizationMembership.objects.create(user=u1, organization=org)
        OrganizationMembership.objects.create(user=u2, organization=org)
        role = Role.objects.create(key="organization_admin", name="Admin")
        m1.roles.add(role)
        self.assertIn(role, m1.roles.all())
        m2 = OrganizationMembership.objects.get(user=u2, organization=org)
        self.assertNotIn(role, m2.roles.all())

    def test_membership_scoped_role_query(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        user = User.objects.create_user(username="scoped", password="testpass123")
        org = Organization.objects.create(name="Org")
        membership = OrganizationMembership.objects.create(user=user, organization=org)
        role = Role.objects.create(key="organization_admin", name="Admin")
        perm = Permission.objects.create(code="platform.organization:read", name="R")
        role.permissions.add(perm)
        membership.roles.add(role)
        self.assertTrue(Permission.objects.filter(roles__membership_roles__membership=membership).exists())
        other_org = Organization.objects.create(name="Other")
        other_m = OrganizationMembership.objects.create(user=user, organization=other_org)
        self.assertFalse(Permission.objects.filter(roles__membership_roles__membership=other_m).exists())


class BootstrapRoleTests(TestCase):
    def test_bootstrap_roles_creates_expected_roles(self):
        bootstrap_roles()
        keys = set(Role.objects.values_list("key", flat=True))
        self.assertEqual(keys, {"organization_admin", "organization_member"})

    def test_bootstrap_roles_are_deterministic(self):
        bootstrap_roles()
        first = {r.key: str(r.id) for r in Role.objects.all()}
        bootstrap_roles()
        second = {r.key: str(r.id) for r in Role.objects.all()}
        self.assertEqual(first, second)

    def test_bootstrap_roles_idempotent(self):
        bootstrap_roles()
        bootstrap_roles()
        self.assertEqual(Role.objects.count(), len(PLATFORM_ROLES))

    def test_bootstrap_admin_has_all_permissions(self):
        bootstrap_roles()
        admin_role = Role.objects.get(key="organization_admin")
        self.assertEqual(admin_role.permissions.count(), len(PLATFORM_PERMISSIONS))

    def test_bootstrap_member_has_read_only(self):
        bootstrap_roles()
        member = Role.objects.get(key="organization_member")
        codes = set(member.permissions.values_list("code", flat=True))
        self.assertEqual(codes, {"platform.organization:read", "platform.membership:read"})

    def test_bootstrap_roles_updates_permissions(self):
        bootstrap_roles()
        admin_role = Role.objects.get(key="organization_admin")
        admin_role.permissions.clear()
        self.assertEqual(admin_role.permissions.count(), 0)
        bootstrap_roles()
        admin_role.refresh_from_db()
        self.assertEqual(admin_role.permissions.count(), len(PLATFORM_PERMISSIONS))

    def test_bootstrap_does_not_duplicate_roles(self):
        bootstrap_roles()
        count = Role.objects.count()
        bootstrap_roles()
        self.assertEqual(Role.objects.count(), count)


class DjangoAdminTests(TestCase):
    def test_django_admin_still_functions(self):
        self.assertTrue(admin.site.is_registered(Permission))
        self.assertTrue(admin.site.is_registered(Role))
        self.assertTrue(admin.site.is_registered(MembershipRole))

    def test_django_auth_still_usable(self):
        ct = ContentType.objects.get_for_model(Organization)
        perm, _ = DjangoPermission.objects.get_or_create(
            codename="admin_test_perm_7b", content_type=ct, defaults={"name": "Test"}
        )
        group = Group.objects.create(name="admin-test-group-7b")
        group.permissions.add(perm)
        self.assertIn(perm, group.permissions.all())

    def test_is_superuser_independent(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        superuser = User.objects.create_superuser(username="super7b", password="testpass123", email="s@s.com")
        self.assertTrue(superuser.is_superuser)
        self.assertEqual(MembershipRole.objects.filter(membership__user=superuser).count(), 0)
        self.assertFalse(Permission.objects.filter(roles__membership_roles__membership__user=superuser).exists())
