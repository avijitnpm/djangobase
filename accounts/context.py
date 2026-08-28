import uuid
from contextvars import ContextVar

from django.conf import settings

_organization_ctx: ContextVar[object] = ContextVar("current_organization", default=None)

SESSION_KEY = "active_organization_id"


def get_current_organization():
    return _organization_ctx.get()


def get_current_organization_id():
    org = _organization_ctx.get()
    return getattr(org, "id", None) if org is not None else None


def _set_current_organization(org):
    return _organization_ctx.set(org)


def _reset_current_organization(token):
    _organization_ctx.reset(token)


def activate_organization(request, organization):
    from accounts.models import OrganizationMembership

    org_id = organization.id if hasattr(organization, "id") else organization
    try:
        org_uuid = uuid.UUID(str(org_id))
    except (ValueError, AttributeError, TypeError):
        return False
    if not hasattr(request, "user") or not request.user.is_authenticated:
        return False
    if not OrganizationMembership.objects.filter(user=request.user, organization_id=org_uuid).exists():
        return False
    request.session[SESSION_KEY] = str(org_uuid)
    request.organization = _resolve_organization_from_id(request.user, org_uuid)
    _organization_ctx.set(request.organization)
    return True


def clear_active_organization(request):
    request.session.pop(SESSION_KEY, None)
    request.organization = None
    _organization_ctx.set(None)


def _resolve_organization_from_id(user, org_uuid):
    from accounts.models import Organization

    try:
        return Organization.objects.get(id=org_uuid)
    except Organization.DoesNotExist:
        return None


def resolve_organization(request):
    from accounts.models import Organization, OrganizationMembership

    if not hasattr(request, "user") or not getattr(request.user, "is_authenticated", False):
        return None

    user = request.user
    raw = None
    if hasattr(request, "session"):
        raw = request.session.get(SESSION_KEY)

    if raw is not None:
        try:
            org_uuid = uuid.UUID(str(raw))
        except (ValueError, AttributeError, TypeError):
            return None
        if not OrganizationMembership.objects.filter(user=user, organization_id=org_uuid).exists():
            return None
        try:
            return Organization.objects.get(id=org_uuid)
        except Organization.DoesNotExist:
            return None

    memberships = list(OrganizationMembership.objects.filter(user=user).select_related("organization"))
    if len(memberships) == 1:
        return memberships[0].organization
    return None
