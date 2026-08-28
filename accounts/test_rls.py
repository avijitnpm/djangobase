from contextlib import contextmanager

from django.db import connection
from django.test import TransactionTestCase

from accounts.context import _organization_ctx
from accounts.models import Organization, TenantResource
from accounts.rls import clear_db_tenant, set_db_tenant


@contextmanager
def rls_role():
    with connection.cursor() as cur:
        cur.execute("SET ROLE rls_user")
    try:
        yield
    finally:
        with connection.cursor() as cur:
            cur.execute("RESET ROLE")


def rls_count(org):
    set_db_tenant(org)
    with rls_role():
        with connection.cursor() as cur:
            cur.execute("SELECT count(*) FROM accounts_tenantresource")
            return cur.fetchone()[0]


class RLSTests(TransactionTestCase):
    def setUp(self):
        _organization_ctx.set(None)
        clear_db_tenant()
        self.org_a = Organization.objects.create(name="RLS A")
        self.org_b = Organization.objects.create(name="RLS B")
        set_db_tenant(self.org_a)
        _organization_ctx.set(self.org_a)
        self.res_a = TenantResource.all_objects.create(name="RA", organization=self.org_a)
        set_db_tenant(self.org_b)
        _organization_ctx.set(self.org_b)
        self.res_b = TenantResource.all_objects.create(name="RB", organization=self.org_b)
        _organization_ctx.set(None)
        clear_db_tenant()

    def test_read_isolation(self):
        set_db_tenant(self.org_a)
        with rls_role():
            with connection.cursor() as cur:
                cur.execute("SELECT id FROM accounts_tenantresource")
                ids = {r[0] for r in cur.fetchall()}
        self.assertIn(self.res_a.id, ids)
        self.assertNotIn(self.res_b.id, ids)
        set_db_tenant(self.org_b)
        with rls_role():
            with connection.cursor() as cur:
                cur.execute("SELECT id FROM accounts_tenantresource")
                ids = {r[0] for r in cur.fetchall()}
        self.assertIn(self.res_b.id, ids)
        self.assertNotIn(self.res_a.id, ids)
        clear_db_tenant()

    def test_insert_isolation(self):
        set_db_tenant(self.org_a)
        with rls_role():
            with connection.cursor() as cur:
                try:
                    cur.execute(
                        "INSERT INTO accounts_tenantresource (id, organization_id, name, created_at) VALUES (gen_random_uuid(), %s, 'hijack', now())",
                        [str(self.org_b.id)],
                    )
                    self.fail("INSERT should be blocked by RLS WITH CHECK")
                except Exception as e:
                    self.assertIn("policy", str(e).lower())
        clear_db_tenant()

    def test_update_isolation(self):
        set_db_tenant(self.org_a)
        with rls_role():
            with connection.cursor() as cur:
                cur.execute("UPDATE accounts_tenantresource SET name='hijack' WHERE id=%s", [str(self.res_b.id)])
                self.assertEqual(cur.rowcount, 0)
        set_db_tenant(self.org_b)
        with rls_role():
            with connection.cursor() as cur:
                cur.execute("SELECT name FROM accounts_tenantresource WHERE id=%s", [str(self.res_b.id)])
                self.assertEqual(cur.fetchone()[0], "RB")
        clear_db_tenant()

    def test_delete_isolation(self):
        set_db_tenant(self.org_a)
        with rls_role():
            with connection.cursor() as cur:
                cur.execute("DELETE FROM accounts_tenantresource WHERE id=%s", [str(self.res_b.id)])
                self.assertEqual(cur.rowcount, 0)
        clear_db_tenant()
        set_db_tenant(self.org_b)
        with rls_role():
            with connection.cursor() as cur:
                cur.execute("SELECT count(*) FROM accounts_tenantresource WHERE id=%s", [str(self.res_b.id)])
                self.assertEqual(cur.fetchone()[0], 1)
        clear_db_tenant()

    def test_missing_context_fail_closed(self):
        clear_db_tenant()
        with rls_role():
            with connection.cursor() as cur:
                cur.execute("SELECT count(*) FROM accounts_tenantresource")
                self.assertEqual(cur.fetchone()[0], 0)
            with connection.cursor() as cur:
                try:
                    cur.execute(
                        "INSERT INTO accounts_tenantresource (id, organization_id, name, created_at) VALUES (gen_random_uuid(), %s, 'noctx', now())",
                        [str(self.org_a.id)],
                    )
                    self.fail("INSERT without tenant should fail")
                except Exception as e:
                    self.assertIn("policy", str(e).lower())
        clear_db_tenant()

    def test_context_leak_sequential(self):
        set_db_tenant(self.org_a)
        with rls_role():
            with connection.cursor() as cur:
                cur.execute("SELECT count(*) FROM accounts_tenantresource")
                self.assertEqual(cur.fetchone()[0], 1)
        clear_db_tenant()
        with rls_role():
            with connection.cursor() as cur:
                cur.execute("SELECT count(*) FROM accounts_tenantresource")
                self.assertEqual(cur.fetchone()[0], 0)
        set_db_tenant(self.org_b)
        with rls_role():
            with connection.cursor() as cur:
                cur.execute("SELECT count(*) FROM accounts_tenantresource")
                self.assertEqual(cur.fetchone()[0], 1)
        clear_db_tenant()

    def test_middleware_clears_after_request(self):
        from django.contrib.auth import get_user_model
        from django.test import RequestFactory

        from accounts.middleware import OrganizationContextMiddleware

        User = get_user_model()
        user = User.objects.create_user(username="rlsuser", password="test123")
        from accounts.models import OrganizationMembership

        OrganizationMembership.objects.create(user=user, organization=self.org_a)
        factory = RequestFactory()
        req = factory.get("/")
        req.user = user
        req.session = {}

        def view(r):
            with connection.cursor() as cur:
                cur.execute("SELECT current_setting('app.current_organization_id', true)")
                val = cur.fetchone()[0]
                self.assertEqual(val, str(self.org_a.id))
            with rls_role():
                with connection.cursor() as cur:
                    cur.execute("SELECT count(*) FROM accounts_tenantresource")
                    self.assertEqual(cur.fetchone()[0], 1)
            from django.http import HttpResponse

            return HttpResponse("ok")

        OrganizationContextMiddleware(view)(req)
        with connection.cursor() as cur:
            cur.execute("SELECT current_setting('app.current_organization_id', true)")
            val = cur.fetchone()[0]
            self.assertEqual(val, "")
