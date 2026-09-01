from django.db import migrations

RLS_ENABLE = """
ALTER TABLE audit_auditevent ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_auditevent FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON audit_auditevent;
CREATE POLICY tenant_isolation ON audit_auditevent
    USING (organization_id = nullif(current_setting('app.current_organization_id', true), '')::uuid)
    WITH CHECK (organization_id = nullif(current_setting('app.current_organization_id', true), '')::uuid);
"""

RLS_DISABLE = """
DROP POLICY IF EXISTS tenant_isolation ON audit_auditevent;
ALTER TABLE audit_auditevent NO FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_auditevent DISABLE ROW LEVEL SECURITY;
"""


class Migration(migrations.Migration):
    dependencies = [("audit", "0001_auditevent")]
    operations = [migrations.RunSQL(RLS_ENABLE, RLS_DISABLE)]
