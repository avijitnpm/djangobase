import uuid

from django.conf import settings
from django.db import models

from accounts.tenancy import MissingTenantError, TenantManager, TenantQuerySet


class AuditQuerySet(TenantQuerySet):
    def update(self, **kwargs):
        raise MissingTenantError("AuditEvent is immutable: bulk update not allowed")

    def bulk_update(self, *args, **kwargs):
        raise MissingTenantError("AuditEvent is immutable: bulk update not allowed")

    def delete(self):
        raise MissingTenantError("AuditEvent is immutable: bulk delete not allowed")


class AuditManager(TenantManager):
    def get_queryset(self):
        from accounts.context import get_current_organization

        org = get_current_organization()
        if org is None:
            raise MissingTenantError("Tenant context required: no active organization")
        qs = AuditQuerySet(self.model, using=self._db)
        return qs.filter(organization_id=org.id)


class AuditEvent(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        "accounts.Organization",
        on_delete=models.CASCADE,
        related_name="audit_events",
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_events",
    )
    action = models.CharField(max_length=64, db_index=True)
    resource_type = models.CharField(max_length=100, null=True, blank=True)
    resource_id = models.UUIDField(null=True, blank=True)
    request_id = models.CharField(max_length=64, null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    before = models.JSONField(null=True, blank=True)
    after = models.JSONField(null=True, blank=True)
    reason = models.TextField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    objects = AuditManager()
    all_objects = models.Manager()

    class Meta:
        db_table = "audit_auditevent"
        ordering = ["-timestamp"]

    def save(self, *args, **kwargs):
        from accounts.context import get_current_organization
        from accounts.tenancy import MissingTenantError

        org = get_current_organization()
        if org is None:
            raise MissingTenantError("Cannot save audit event without tenant context")
        if self.organization_id is None:
            self.organization_id = org.id
        if self.organization_id != org.id:
            raise MissingTenantError("Cannot save audit event for different organization than active tenant")
        if self.pk is not None and type(self).all_objects.filter(pk=self.pk).exists():
            raise MissingTenantError("AuditEvent is immutable: updates are not allowed")
        if kwargs.get("update_fields") is not None:
            raise MissingTenantError("AuditEvent is immutable: updates are not allowed")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        from accounts.tenancy import MissingTenantError

        raise MissingTenantError("AuditEvent is immutable: deletes are not allowed")
