import uuid


def _get_org_id(obj):
    if obj is None:
        return None
    if hasattr(obj, "organization_id"):
        return getattr(obj, "organization_id")
    if hasattr(obj, "organization"):
        org = getattr(obj, "organization")
        if hasattr(org, "id"):
            return org.id
        return org
    return None


def scope_allows(binding, resource):
    mr_org_id = getattr(binding.membership, "organization_id", None)
    res_org_id = _get_org_id(resource)
    if res_org_id is not None and mr_org_id is not None and res_org_id != mr_org_id:
        return False
    if binding.is_organization_wide:
        return True
    st = binding.scope_type
    sv = binding.scope_value
    if st == "region":
        region = getattr(resource, "region", None)
        if region is None and isinstance(resource, dict):
            region = resource.get("region")
        return str(region) == sv
    if st == "resource":
        rid = getattr(resource, "id", None)
        if rid is None and isinstance(resource, dict):
            rid = resource.get("id") or resource.get("resource_id")
        return str(rid) == sv
    if isinstance(resource, dict):
        return str(resource.get(st)) == sv
    return str(getattr(resource, st, None)) == sv


def membership_has_permission(membership, permission_code, resource=None):
    qs = membership.membership_roles.select_related("role").prefetch_related("role__permissions")
    for br in qs:
        if not br.role.permissions.filter(code=permission_code).exists():
            continue
        if resource is None:
            if br.is_organization_wide:
                return True
            continue
        if scope_allows(br, resource):
            return True
    return False


def validate_scope_not_cross_tenant(binding):
    from django.core.exceptions import ValidationError

    if binding.scope_type == "resource" and binding.scope_value:
        try:
            rid = uuid.UUID(str(binding.scope_value))
        except Exception:
            return
        from authorization.models import ScopedResource

        try:
            res = ScopedResource.objects.get(id=rid)
        except ScopedResource.DoesNotExist:
            return
        if res.organization_id != binding.membership.organization_id:
            raise ValidationError("Scope cannot reference another organization")
