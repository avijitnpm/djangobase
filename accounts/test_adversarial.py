import concurrent.futures
import uuid

from django.db import connection, transaction
from django.test import RequestFactory, TransactionTestCase

from accounts.context import _organization_ctx
from accounts.models import Organization, TenantResource
from accounts.rls import clear_db_tenant, set_db_tenant, tenant_db_context
from accounts.tenancy import MissingTenantError


def set_tenant(org):
    from accounts.rls import set_db_tenant

    token = _organization_ctx.set(org)
    set_db_tenant(org)
    return token


def clear_tenant(token):
    from accounts.rls import clear_db_tenant

    _organization_ctx.reset(token)
    clear_db_tenant()


class AdversarialTests(TransactionTestCase):
    def setUp(self):
        _organization_ctx.set(None)
        clear_db_tenant()
        with connection.cursor() as cur:
            cur.execute("RESET ROLE")
        self.org_a = Organization.objects.create(name="Adv A")
        self.org_b = Organization.objects.create(name="Adv B")
        t = set_tenant(self.org_a)
        self.res_a = TenantResource.objects.create(name="Res A")
        clear_tenant(t)
        t = set_tenant(self.org_b)
        self.res_b = TenantResource.objects.create(name="Res B")
        clear_tenant(t)

    def tearDown(self):
        _organization_ctx.set(None)
        clear_db_tenant()
        with connection.cursor() as cur:
            cur.execute("RESET ROLE")

    def test_01_normal_cross_tenant_retrieval(self):
        t = set_tenant(self.org_a)
        try:
            ids = set(TenantResource.objects.values_list("id", flat=True))
            assert self.res_a.id in ids, "A should see A"
            assert self.res_b.id not in ids, "A must not see B"
        finally:
            clear_tenant(t)
        t = set_tenant(self.org_b)
        try:
            ids = set(TenantResource.objects.values_list("id", flat=True))
            assert self.res_b.id in ids
            assert self.res_a.id not in ids
        finally:
            clear_tenant(t)

    def test_02_retrieval_by_pk(self):
        t = set_tenant(self.org_a)
        try:
            with self.assertRaises(TenantResource.DoesNotExist):
                TenantResource.objects.get(id=self.res_b.id)
            obj = TenantResource.objects.get(id=self.res_a.id)
            self.assertEqual(obj.id, self.res_a.id)
        finally:
            clear_tenant(t)

    def test_03_forged_organization_id(self):
        t = set_tenant(self.org_a)
        try:
            with self.assertRaises(MissingTenantError):
                TenantResource.objects.create(name="forged", organization=self.org_b)
            with self.assertRaises(MissingTenantError):
                TenantResource.objects.create(name="forged2", organization_id=self.org_b.id)
            obj = TenantResource.objects.get(id=self.res_a.id)
            obj.organization = self.org_b
            with self.assertRaises(MissingTenantError):
                obj.save()
        finally:
            clear_tenant(t)

    def test_04_update_another_tenant(self):
        t = set_tenant(self.org_a)
        try:
            c = TenantResource.objects.filter(id=self.res_b.id).update(name="hijack")
            self.assertEqual(c, 0)
            obj = TenantResource.all_objects.get(id=self.res_a.id)
            orig_name = obj.name
            obj.name = "ok"
            obj.save()
            self.assertEqual(TenantResource.all_objects.get(id=self.res_a.id).name, "ok")
            # try cross via all_objects + save
            obj2 = TenantResource.all_objects.get(id=self.res_b.id)
            obj2.name = "hijack"
            with self.assertRaises(MissingTenantError):
                obj2.save()
        finally:
            clear_tenant(t)
        # raw SQL update under RLS
        set_db_tenant(self.org_a)
        try:
            with connection.cursor() as cur:
                cur.execute("SET ROLE rls_user")
                cur.execute("UPDATE accounts_tenantresource SET name='hijack2' WHERE id=%s", [str(self.res_b.id)])
                self.assertEqual(cur.rowcount, 0)
                cur.execute("RESET ROLE")
        finally:
            clear_db_tenant()

    def test_05_deletion_another_tenant(self):
        t = set_tenant(self.org_a)
        try:
            with self.assertRaises(TenantResource.DoesNotExist):
                TenantResource.objects.get(id=self.res_b.id).delete()
            obj = TenantResource.all_objects.get(id=self.res_b.id)
            with self.assertRaises(MissingTenantError):
                obj.delete()
        finally:
            clear_tenant(t)
        set_db_tenant(self.org_a)
        try:
            with connection.cursor() as cur:
                cur.execute("SET ROLE rls_user")
                cur.execute("DELETE FROM accounts_tenantresource WHERE id=%s", [str(self.res_b.id)])
                self.assertEqual(cur.rowcount, 0)
                cur.execute("RESET ROLE")
        finally:
            clear_db_tenant()

    def test_06_creation_owned_by_another_tenant(self):
        t = set_tenant(self.org_a)
        try:
            with self.assertRaises(MissingTenantError):
                TenantResource.all_objects.create(name="bad", organization=self.org_b)
        finally:
            clear_tenant(t)
        set_db_tenant(self.org_a)
        try:
            with connection.cursor() as cur:
                cur.execute("SET ROLE rls_user")
                try:
                    cur.execute(
                        "INSERT INTO accounts_tenantresource (id, organization_id, name, created_at) VALUES (gen_random_uuid(), %s, 'bad', now())",
                        [str(self.org_b.id)],
                    )
                    self.fail("RLS should block cross-tenant insert")
                except Exception as e:
                    self.assertIn("policy", str(e).lower())
                finally:
                    cur.execute("RESET ROLE")
        finally:
            clear_db_tenant()

    def test_07_request_without_tenant_context(self):
        _organization_ctx.set(None)
        clear_db_tenant()
        with self.assertRaises(MissingTenantError):
            list(TenantResource.objects.all())
        with self.assertRaises(MissingTenantError):
            TenantResource.objects.create(name="noctx")
        with connection.cursor() as cur:
            cur.execute("SET ROLE rls_user")
            cur.execute("SELECT count(*) FROM accounts_tenantresource")
            self.assertEqual(cur.fetchone()[0], 0)
            cur.execute("RESET ROLE")

    def test_08_sequential_requests_different_tenants(self):
        from accounts.middleware import OrganizationContextMiddleware
        from django.contrib.auth import get_user_model
        from accounts.models import OrganizationMembership

        User = get_user_model()
        u_a = User.objects.create_user(username="seq_a", password="x")
        u_b = User.objects.create_user(username="seq_b", password="x")
        OrganizationMembership.objects.create(user=u_a, organization=self.org_a)
        OrganizationMembership.objects.create(user=u_b, organization=self.org_b)
        factory = RequestFactory()

        def make_req(user):
            r = factory.get("/")
            r.user = user
            r.session = {}
            return r

        from django.http import HttpResponse

        def view_a(r):
            self.assertEqual(r.organization, self.org_a)
            ids = set(TenantResource.objects.values_list("id", flat=True))
            self.assertIn(self.res_a.id, ids)
            self.assertNotIn(self.res_b.id, ids)
            with connection.cursor() as cur:
                cur.execute("SELECT current_setting('app.current_organization_id', true)")
                self.assertEqual(cur.fetchone()[0], str(self.org_a.id))
            return HttpResponse("ok")

        def view_b(r):
            self.assertEqual(r.organization, self.org_b)
            ids = set(TenantResource.objects.values_list("id", flat=True))
            self.assertIn(self.res_b.id, ids)
            self.assertNotIn(self.res_a.id, ids)
            with connection.cursor() as cur:
                cur.execute("SELECT current_setting('app.current_organization_id', true)")
                self.assertEqual(cur.fetchone()[0], str(self.org_b.id))
            return HttpResponse("ok")

        OrganizationContextMiddleware(view_a)(make_req(u_a))
        with connection.cursor() as cur:
            cur.execute("SELECT current_setting('app.current_organization_id', true)")
            self.assertEqual(cur.fetchone()[0], "")
        OrganizationContextMiddleware(view_b)(make_req(u_b))
        with connection.cursor() as cur:
            cur.execute("SELECT current_setting('app.current_organization_id', true)")
            self.assertEqual(cur.fetchone()[0], "")

    def test_09_concurrent_requests_different_tenants(self):
        def task(org, expected_id, unexpected_id):
            from django.db import connection as conn

            conn.close()
            t = set_tenant(org)
            try:
                ids = set(TenantResource.objects.values_list("id", flat=True))
                ok = expected_id in ids and unexpected_id not in ids
                with conn.cursor() as cur:
                    cur.execute("SET ROLE rls_user")
                    cur.execute("SELECT count(*) FROM accounts_tenantresource")
                    cnt = cur.fetchone()[0]
                    cur.execute("RESET ROLE")
                    ok = ok and cnt == 1
                return ok
            finally:
                clear_tenant(t)
                conn.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            futs = []
            for _ in range(8):
                futs.append(ex.submit(task, self.org_a, self.res_a.id, self.res_b.id))
                futs.append(ex.submit(task, self.org_b, self.res_b.id, self.res_a.id))
            for f in futs:
                self.assertTrue(f.result())

    def test_10_direct_orm_without_helper(self):
        # all_objects without tenant should be blocked by RLS via rls_user
        with connection.cursor() as cur:
            cur.execute("SET ROLE rls_user")
            cur.execute("SELECT count(*) FROM accounts_tenantresource")
            self.assertEqual(cur.fetchone()[0], 0)
            cur.execute("RESET ROLE")
        # with tenant, all_objects sees only tenant via RLS
        set_db_tenant(self.org_a)
        try:
            with connection.cursor() as cur:
                cur.execute("SET ROLE rls_user")
                cur.execute("SELECT count(*) FROM accounts_tenantresource")
                self.assertEqual(cur.fetchone()[0], 1)
                cur.execute("RESET ROLE")
        finally:
            clear_db_tenant()

    def test_11_transaction_boundaries_change_tenant(self):
        # SET LOCAL inside atomic should be scoped to transaction
        from accounts.rls import tenant_atomic_context

        with tenant_atomic_context(self.org_a):
            with connection.cursor() as cur:
                cur.execute("SET ROLE rls_user")
                cur.execute("SELECT count(*) FROM accounts_tenantresource")
                self.assertEqual(cur.fetchone()[0], 1)
                cur.execute("RESET ROLE")
        # after atomic, GUC should be empty
        with connection.cursor() as cur:
            cur.execute("SELECT current_setting('app.current_organization_id', true)")
            self.assertEqual(cur.fetchone()[0], "")
            cur.execute("SET ROLE rls_user")
            cur.execute("SELECT count(*) FROM accounts_tenantresource")
            self.assertEqual(cur.fetchone()[0], 0)
            cur.execute("RESET ROLE")

    def test_12_reused_database_connections(self):
        from accounts.middleware import OrganizationContextMiddleware
        from django.contrib.auth import get_user_model
        from accounts.models import OrganizationMembership

        User = get_user_model()
        u = User.objects.create_user(username="reuse", password="x")
        OrganizationMembership.objects.create(user=u, organization=self.org_a)
        factory = RequestFactory()
        from django.http import HttpResponse

        def view(r):
            return HttpResponse("ok")

        req = factory.get("/")
        req.user = u
        req.session = {}
        OrganizationContextMiddleware(view)(req)
        # simulate reused connection handling next request without tenant
        from django.contrib.auth.models import AnonymousUser

        req2 = factory.get("/")
        req2.user = AnonymousUser()
        req2.session = {}
        OrganizationContextMiddleware(view)(req2)
        with connection.cursor() as cur:
            cur.execute("SELECT current_setting('app.current_organization_id', true)")
            self.assertEqual(cur.fetchone()[0], "")
            cur.execute("SET ROLE rls_user")
            cur.execute("SELECT count(*) FROM accounts_tenantresource")
            self.assertEqual(cur.fetchone()[0], 0)
            cur.execute("RESET ROLE")

    def test_forged_header_ignored(self):
        factory = RequestFactory()
        from django.contrib.auth import get_user_model
        from accounts.middleware import OrganizationContextMiddleware
        from accounts.models import OrganizationMembership

        User = get_user_model()
        u = User.objects.create_user(username="hdr", password="x")
        OrganizationMembership.objects.create(user=u, organization=self.org_a)
        req = factory.get("/", HTTP_X_ORGANIZATION_ID=str(self.org_b.id), HTTP_ORGANIZATION_ID=str(self.org_b.id))
        req.user = u
        req.session = {}

        from django.http import HttpResponse

        def view(r):
            self.assertEqual(r.organization, self.org_a)
            self.assertNotEqual(r.organization, self.org_b)
            return HttpResponse("ok")

        OrganizationContextMiddleware(view)(req)
