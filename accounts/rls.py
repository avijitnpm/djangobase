from contextlib import contextmanager

from django.db import connection, transaction


def set_db_tenant(organization):
    org_id = None
    if organization is not None:
        org_id = getattr(organization, "id", organization)
        org_id = str(org_id) if org_id is not None else None
    with connection.cursor() as cur:
        if org_id is None:
            cur.execute("RESET app.current_organization_id")
            cur.execute("SELECT set_config('app.current_organization_id', '', false)")
        else:
            cur.execute("SELECT set_config('app.current_organization_id', %s, false)", [org_id])


def clear_db_tenant():
    with connection.cursor() as cur:
        cur.execute("RESET app.current_organization_id")
        cur.execute("SELECT set_config('app.current_organization_id', '', false)")


@contextmanager
def tenant_db_context(organization):
    from accounts.context import _set_current_organization, _reset_current_organization

    token = _set_current_organization(organization)
    set_db_tenant(organization)
    try:
        yield
    finally:
        _reset_current_organization(token)
        clear_db_tenant()


@contextmanager
def tenant_atomic_context(organization):
    from accounts.context import _set_current_organization, _reset_current_organization

    with transaction.atomic():
        token = _set_current_organization(organization)
        org_id = str(getattr(organization, "id", organization)) if organization else ""
        with connection.cursor() as cur:
            cur.execute("SELECT set_config('app.current_organization_id', %s, true)", [org_id if organization else ""])
        try:
            yield
        finally:
            _reset_current_organization(token)
