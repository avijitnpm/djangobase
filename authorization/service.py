import uuid

from django.core.exceptions import ValidationError


class AuthorizationDenied(PermissionError):
    def __init__(self, reason="denied", internal_detail=""):
        super().__init__(reason)
        self.reason = reason
        self.internal_detail = internal_detail

    def to_http_status(self):
        return 403


def _deny(reason, internal=""):
    raise AuthorizationDenied(reason, internal)


def _get_org_id(obj):
    if obj is None:
        return None
    if hasattr(obj, "organization_id"):
        return getattr(obj, "organization_id")
    if hasattr(obj, "id"):
        return getattr(obj, "id")
    return None


def _resource_org_id(resource):
    if resource is None:
        return None
    if isinstance(resource, dict):
        return resource.get("organization_id") or resource.get("organization")
    return getattr(resource, "organization_id", None)


def authorize(user, organization, permission_code, resource=None):
    from accounts.models import Organization, OrganizationMembership

    from authorization.models import Permission
    from authorization.scopes import scope_allows

    if user is None or not getattr(user, "is_authenticated", False):
        _deny("unauthenticated", "no authenticated user")
    try:
        uuid.UUID(str(getattr(user, "pk", "")))
    except Exception:
        _deny("unknown_user", "invalid user pk")

    if organization is None:
        _deny("no_organization", "no organization context")
    org_id = getattr(organization, "id", None)
    if org_id is None:
        try:
            org_id = uuid.UUID(str(organization))
            organization = Organization.objects.get(id=org_id)
        except Exception:
            _deny("no_organization", "invalid organization")
    else:
        try:
            uuid.UUID(str(org_id))
        except Exception:
            _deny("no_organization", "invalid organization id")

    if not Organization.objects.filter(id=org_id).exists():
        _deny("no_organization", "organization does not exist")

    if not user.__class__.objects.filter(pk=user.pk).exists():
        _deny("unknown_user", "local user does not exist")

    if not permission_code or not isinstance(permission_code, str):
        _deny("invalid_permission", "malformed permission_code")

    try:
        membership = OrganizationMembership.objects.select_related("organization").get(
            user=user, organization_id=org_id
        )
    except OrganizationMembership.DoesNotExist:
        _deny("no_membership", "user has no membership in organization")
    except Exception:
        _deny("no_membership", "membership lookup failed")

    from authorization.models import Permission

    if not Permission.objects.filter(code=permission_code).exists():
        _deny("unknown_permission", f"permission {permission_code} does not exist")

    if resource is not None:
        res_org = _resource_org_id(resource)
        if res_org is None:
            if isinstance(resource, dict):
                _deny("invalid_resource", "resource missing organization")
            elif not hasattr(resource, "organization_id"):
                _deny("invalid_resource", "resource missing organization_id")
            else:
                _deny("invalid_resource", "resource organization missing")
        try:
            res_org_uuid = uuid.UUID(str(res_org))
        except Exception:
            _deny("invalid_resource", "resource organization invalid")
        if res_org_uuid != org_id:
            _deny("scope_mismatch", "resource organization does not match active organization")
        rid = getattr(resource, "id", None) if not isinstance(resource, dict) else resource.get("id")
        if rid is not None:
            try:
                uuid.UUID(str(rid))
            except Exception:
                _deny("invalid_resource", "resource id invalid")

    bindings = membership.membership_roles.select_related("role", "membership__organization").prefetch_related(
        "role__permissions"
    )
    if not bindings.exists():
        _deny("no_role", "membership has no role bindings")

    allowed = False
    has_permission_binding = False
    for br in bindings:
        if not br.role.permissions.filter(code=permission_code).exists():
            continue
        has_permission_binding = True
        if resource is None:
            if br.is_organization_wide:
                allowed = True
                break
            continue
        if scope_allows(br, resource):
            allowed = True
            break

    if not has_permission_binding:
        _deny("no_permission", f"no role grants {permission_code}")
    if not allowed:
        _deny("scope_mismatch", "no binding with matching permission and scope")

    return True


def is_authorized(user, organization, permission_code, resource=None):
    try:
        authorize(user, organization, permission_code, resource)
        return True
    except AuthorizationDenied:
        return False


def check_permission(user, organization, permission_code, resource=None):
    return authorize(user, organization, permission_code, resource)
