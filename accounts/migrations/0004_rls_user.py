from django.db import migrations

SQL = """
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='rls_user') THEN
    CREATE ROLE rls_user WITH NOLOGIN NOBYPASSRLS NOSUPERUSER;
  END IF;
END $$;
GRANT USAGE ON SCHEMA public TO rls_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO rls_user;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO rls_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO rls_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE ON SEQUENCES TO rls_user;
"""

REVERSE = """
REASSIGN OWNED BY rls_user TO postgres;
DROP OWNED BY rls_user;
DROP ROLE IF EXISTS rls_user;
"""

class Migration(migrations.Migration):
    dependencies = [("accounts", "0003_enable_rls")]
    operations = [migrations.RunSQL(SQL, REVERSE)]
