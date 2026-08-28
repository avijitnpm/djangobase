from accounts.context import _reset_current_organization, _set_current_organization, resolve_organization
from accounts.rls import clear_db_tenant, set_db_tenant


class OrganizationContextMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        org = resolve_organization(request)
        request.organization = org
        token = _set_current_organization(org)
        set_db_tenant(org)
        try:
            response = self.get_response(request)
        finally:
            _reset_current_organization(token)
            clear_db_tenant()
        return response
