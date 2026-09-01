import uuid

from django.db import transaction

from accounts.context import get_current_organization
from accounts.tenancy import MissingTenantError


def create_membership(*, actor, target_user, organization=None, reason=None):
    from accounts.models import OrganizationMembership
    from audit.services import record_audit_event
    from authorization.service import authorize

    org = organization or get_current_organization()
    if org is None:
        raise MissingTenantError("Tenant context required")
    org_id = getattr(org, "id", org)
    try:
        org_uuid = uuid.UUID(str(org_id))
    except Exception:
        raise MissingTenantError("Invalid organization")
    active = get_current_organization()
    if active is None or active.id != org_uuid:
        raise MissingTenantError("Cross-tenant membership creation denied")

    authorize(actor, org, "platform.membership:update")

    before = None
    after = {"user_id": str(getattr(target_user, "id", target_user)), "organization_id": str(org_uuid)}

    with transaction.atomic():
        membership = OrganizationMembership.objects.create(user=target_user, organization=org)
        record_audit_event(
            actor=actor,
            organization=org,
            action="membership.created",
            resource_type="organization_membership",
            resource_id=membership.id,
            metadata={"target_user_id": str(membership.user_id)},
            before=before,
            after=after,
            reason=reason,
        )
        return membership
