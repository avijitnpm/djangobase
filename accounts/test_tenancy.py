from contextlib import contextmanager

from django.test import TestCase

from accounts.context import _organization_ctx
from accounts.models import Organization, TenantResource
from accounts.tenancy import MissingTenantError


@contextmanager
def tenant_context(org):
    from accounts.rls import clear_db_tenant, set_db_tenant

    token = _organization_ctx.set(org)
    set_db_tenant(org)
    try:
        yield
    finally:
        _organization_ctx.reset(token)
        clear_db_tenant()


class TenantQueryTests(TestCase):
    def setUp(self):
        _organization_ctx.set(None)
        self.org_a = Organization.objects.create(name="A")
        self.org_b = Organization.objects.create(name="B")
        with tenant_context(self.org_a):
            self.res_a = TenantResource.objects.create(name="Resource A")
        with tenant_context(self.org_b):
            self.res_b = TenantResource.objects.create(name="Resource B")

    def tearDown(self):
        _organization_ctx.set(None)

    def test_a_context_sees_a_not_b(self):
        with tenant_context(self.org_a):
            ids = set(TenantResource.objects.values_list("id", flat=True))
            self.assertIn(self.res_a.id, ids)
            self.assertNotIn(self.res_b.id, ids)

    def test_b_context_sees_b_not_a(self):
        with tenant_context(self.org_b):
            ids = set(TenantResource.objects.values_list("id", flat=True))
            self.assertIn(self.res_b.id, ids)
            self.assertNotIn(self.res_a.id, ids)

    def test_missing_context_fails(self):
        with self.assertRaises(MissingTenantError):
            list(TenantResource.objects.all())
        with self.assertRaises(MissingTenantError):
            TenantResource.objects.create(name="no tenant")

    def test_cross_tenant_get_fails(self):
        with tenant_context(self.org_a):
            with self.assertRaises(TenantResource.DoesNotExist):
                TenantResource.objects.get(id=self.res_b.id)

    def test_cross_tenant_update_fails(self):
        with tenant_context(self.org_a):
            obj = TenantResource.objects.get(id=self.res_a.id)
            obj.name = "changed"
            obj.save()
            self.assertEqual(TenantResource.all_objects.get(id=self.res_a.id).name, "changed")
        with tenant_context(self.org_b):
            with self.assertRaises(MissingTenantError):
                obj = TenantResource.all_objects.get(id=self.res_a.id)
                obj.name = "hijack"
                obj.save()
        with tenant_context(self.org_a):
            count = TenantResource.objects.filter(id=self.res_b.id).update(name="hijack")
            self.assertEqual(count, 0)
        with tenant_context(self.org_b):
            self.assertEqual(TenantResource.all_objects.get(id=self.res_b.id).name, "Resource B")

    def test_cross_tenant_delete_fails(self):
        with tenant_context(self.org_a):
            with self.assertRaises(Exception):
                obj = TenantResource.all_objects.get(id=self.res_b.id)
                obj.delete()
        with tenant_context(self.org_b):
            with self.assertRaises(TenantResource.DoesNotExist):
                TenantResource.objects.get(id=self.res_a.id).delete()
        with tenant_context(self.org_a):
            self.assertTrue(TenantResource.all_objects.filter(id=self.res_a.id).exists())

    def test_ownership_cannot_be_changed(self):
        with tenant_context(self.org_a):
            obj = TenantResource.objects.get(id=self.res_a.id)
            obj.organization = self.org_b
            with self.assertRaises(MissingTenantError):
                obj.save()
        with tenant_context(self.org_a):
            obj = TenantResource.objects.get(id=self.res_a.id)
            obj.organization_id = self.org_b.id
            with self.assertRaises(MissingTenantError):
                obj.save()

    def test_create_requires_matching_tenant(self):
        with tenant_context(self.org_a):
            with self.assertRaises(MissingTenantError):
                TenantResource.objects.create(name="bad", organization=self.org_b)
            with self.assertRaises(MissingTenantError):
                TenantResource.objects.create(name="bad", organization_id=self.org_b.id)

    def test_queryset_update_scoped(self):
        with tenant_context(self.org_a):
            TenantResource.objects.filter(id=self.res_a.id).update(name="updated A")
        with tenant_context(self.org_a):
            self.assertEqual(TenantResource.all_objects.get(id=self.res_a.id).name, "updated A")
        with tenant_context(self.org_b):
            self.assertEqual(TenantResource.all_objects.get(id=self.res_b.id).name, "Resource B")
        with tenant_context(self.org_a):
            count = TenantResource.objects.filter(id=self.res_b.id).update(name="should not")
            self.assertEqual(count, 0)
