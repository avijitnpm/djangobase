import uuid

from django.conf import settings
from django.core.exceptions import ValidationError


class AuditValidationError(ValueError):
    pass


def _coerce_uuid(value, field_name="resource_id"):
    if value is None:
        return None
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except Exception:
        raise AuditValidationError(f"Invalid {field_name}: must be UUID")


def _validate_action(action):
    if not isinstance(action, str) or not action.strip():
        raise AuditValidationError("action is required and must be non-empty string")
    action = action.strip()
    if len(action) > 64:
        raise AuditValidationError("action must be <= 64 characters")
    return action


def _validate_resource_type(value):
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise AuditValidationError("resource_type must be non-empty string if provided")
    value = value.strip()
    if len(value) > 100:
        raise AuditValidationError("resource_type must be <= 100 characters")
    return value


def _validate_request_id(value):
    if value is None:
        return None
    if not isinstance(value, str):
        raise AuditValidationError("request_id must be string")
    value = value.strip()
    if not value:
        return None
    if len(value) > 64:
        raise AuditValidationError("request_id must be <= 64 characters")
    return value


def _validate_metadata(value, field_name="metadata"):
    if value is None:
        return {} if field_name == "metadata" else None
    if not isinstance(value, dict):
        raise AuditValidationError(f"{field_name} must be dict or None")
    return value


def _validate_reason(value):
    if value is None:
        return None
    if not isinstance(value, str):
        raise AuditValidationError("reason must be string")
    value = value.strip()
    if not value:
        return None
    return value


def record_audit_event(
    *,
    actor=None,
    organization=None,
    action,
    resource_type=None,
    resource_id=None,
    request_id=None,
    metadata=None,
    before=None,
    after=None,
    reason=None,
):
    from accounts.context import get_current_organization
    from accounts.models import OrganizationMembership
    from accounts.tenancy import MissingTenantError
    from audit.models import AuditEvent

    if request_id is None:
        try:
            from audit.request_context import get_current_request_id

            request_id = get_current_request_id()
        except Exception:
            request_id = None

    active_org = get_current_organization()
    if active_org is None:
        raise MissingTenantError("Cannot record audit event without tenant context")

    if organization is not None:
        org_id = getattr(organization, "id", organization)
        try:
            org_uuid = uuid.UUID(str(org_id))
        except Exception:
            raise AuditValidationError("Invalid organization")
        if org_uuid != active_org.id:
            raise MissingTenantError("Cannot record audit event for different organization than active tenant")
        org_obj = active_org
    else:
        org_obj = active_org

    action = _validate_action(action)
    resource_type = _validate_resource_type(resource_type)
    resource_id = _coerce_uuid(resource_id, "resource_id")
    request_id = _validate_request_id(request_id)
    metadata = _validate_metadata(metadata, "metadata")
    before = _validate_metadata(before, "before")
    after = _validate_metadata(after, "after")
    reason = _validate_reason(reason)

    actor_obj = None
    if actor is not None:
        from django.contrib.auth import get_user_model

        User = get_user_model()
        if isinstance(actor, User):
            actor_obj = actor
        else:
            actor_id = getattr(actor, "id", actor)
            try:
                actor_uuid = uuid.UUID(str(actor_id))
            except Exception:
                raise AuditValidationError("Invalid actor: must be User or UUID")
            try:
                actor_obj = User.objects.get(id=actor_uuid)
            except User.DoesNotExist:
                raise AuditValidationError("Invalid actor: user does not exist")
        if not OrganizationMembership.objects.filter(user=actor_obj, organization=org_obj).exists():
            raise AuditValidationError("Invalid actor: user is not a member of the organization")

    return AuditEvent.objects.create(
        organization=org_obj,
        actor=actor_obj,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        request_id=request_id,
        metadata=metadata,
        before=before,
        after=after,
        reason=reason,
    )


record_event = record_audit_event
