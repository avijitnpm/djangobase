import uuid

from django.db import transaction

from accounts.context import get_current_organization
from accounts.tenancy import MissingTenantError


def _ensure_tenant(organization):
    org = organization or get_current_organization()
    if org is None:
        raise MissingTenantError("Tenant context required")
    active = get_current_organization()
    org_id = getattr(org, "id", org)
    try:
        org_uuid = uuid.UUID(str(org_id))
    except Exception:
        raise MissingTenantError("Invalid organization")
    if active is None or active.id != org_uuid:
        raise MissingTenantError("Cross-tenant operation denied")
    return org


def assign_role(*, actor, membership, role, scope_type="", scope_value="", reason=None):
    from audit.services import record_audit_event
    from authorization.models import MembershipRole
    from authorization.service import authorize

    org = _ensure_tenant(membership.organization if hasattr(membership, "organization") else None)
    if membership.organization_id != org.id:
        raise MissingTenantError("Cross-tenant role assignment denied")

    authorize(actor, org, "platform.membership:update", resource=membership)

    before_roles = list(
        MembershipRole.objects.filter(membership=membership).values_list("role__key", flat=True)
    )

    with transaction.atomic():
        mr = MembershipRole.objects.create(
            membership=membership, role=role, scope_type=scope_type, scope_value=scope_value
        )
        after_roles = before_roles + [role.key]
        record_audit_event(
            actor=actor,
            organization=org,
            action="role_assigned",
            resource_type="membership_role",
            resource_id=mr.id,
            metadata={"role": role.key, "scope_type": scope_type, "scope_value": scope_value, "membership_id": str(membership.id)},
            before={"roles": before_roles},
            after={"roles": after_roles},
            reason=reason,
        )
        return mr


def revoke_role(*, actor, membership_role, reason=None):
    from audit.services import record_audit_event
    from authorization.models import MembershipRole
    from authorization.service import authorize

    membership = membership_role.membership
    org = _ensure_tenant(membership.organization if hasattr(membership, "organization") else membership.organization_id)
    if hasattr(org, "id") and membership.organization_id != org.id:
        raise MissingTenantError("Cross-tenant role revocation denied")

    authorize(actor, org, "platform.membership:update", resource=membership)

    before_roles = list(
        MembershipRole.objects.filter(membership=membership).values_list("role__key", flat=True)
    )
    role_key = membership_role.role.key if hasattr(membership_role.role, "key") else str(membership_role.role_id)

    with transaction.atomic():
        rid = membership_role.id
        membership_role.delete()
        after_roles = [r for r in before_roles if r != role_key]
        # handle duplicate keys: remove one occurrence only
        if role_key in before_roles:
            idx = before_roles.index(role_key)
            after_roles = before_roles[:idx] + before_roles[idx + 1 :]
        record_audit_event(
            actor=actor,
            organization=org,
            action="role_revoked",
            resource_type="membership_role",
            resource_id=rid,
            metadata={"role": role_key, "membership_id": str(membership.id)},
            before={"roles": before_roles},
            after={"roles": after_roles},
            reason=reason,
        )


def grant_permission(*, actor, role, permission, reason=None):
    from audit.services import record_audit_event
    from authorization.service import authorize

    org = get_current_organization()
    if org is None:
        raise MissingTenantError("Tenant context required for permission change")

    authorize(actor, org, "platform.membership:update")

    before_perms = list(role.permissions.values_list("code", flat=True))
    if permission.code in before_perms:
        return

    with transaction.atomic():
        role.permissions.add(permission)
        after_perms = before_perms + [permission.code]
        record_audit_event(
            actor=actor,
            organization=org,
            action="permission_changed",
            resource_type="role",
            resource_id=role.id,
            metadata={"permission": permission.code, "role": role.key},
            before={"permissions": before_perms},
            after={"permissions": after_perms},
            reason=reason,
        )


def revoke_permission(*, actor, role, permission, reason=None):
    from audit.services import record_audit_event
    from authorization.service import authorize

    org = get_current_organization()
    if org is None:
        raise MissingTenantError("Tenant context required for permission change")

    authorize(actor, org, "platform.membership:update")

    before_perms = list(role.permissions.values_list("code", flat=True))
    if permission.code not in before_perms:
        return

    with transaction.atomic():
        role.permissions.remove(permission)
        after_perms = [c for c in before_perms if c != permission.code]
        record_audit_event(
            actor=actor,
            organization=org,
            action="permission_changed",
            resource_type="role",
            resource_id=role.id,
            metadata={"permission": permission.code, "role": role.key},
            before={"permissions": before_perms},
            after={"permissions": after_perms},
            reason=reason,
        )
