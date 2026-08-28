from django.db import migrations

RLS_ENABLE = """
ALTER TABLE accounts_tenantresource ENABLE ROW LEVEL SECURITY;
ALTER TABLE accounts_tenantresource FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON accounts_tenantresource;
CREATE POLICY tenant_isolation ON accounts_tenantresource
    USING (organization_id = nullif(current_setting('app.current_organization_id', true), '')::uuid)
    WITH CHECK (organization_id = nullif(current_setting('app.current_organization_id', true), '')::uuid);
"""

RLS_DISABLE = """
DROP POLICY IF EXISTS tenant_isolation ON accounts_tenantresource;
ALTER TABLE accounts_tenantresource NO FORCE ROW LEVEL SECURITY;
ALTER TABLE accounts_tenantresource DISABLE ROW LEVEL SECURITY;
"""


class Migration(migrations.Migration):
    dependencies = [("accounts", "0002_tenantresource")]
    operations = [migrations.RunSQL(RLS_ENABLE, RLS_DISABLE)]
