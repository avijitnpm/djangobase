import uuid

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models

from accounts.tenancy import TenantManager


class User(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class Meta:
        db_table = "accounts_user"


class Organization(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "accounts_organization"


class OrganizationMembership(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="memberships")
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="memberships")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "accounts_organizationmembership"
        constraints = [
            models.UniqueConstraint(fields=["user", "organization"], name="unique_user_organization"),
        ]


class TenantResource(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="resources")
    name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = TenantManager()
    all_objects = models.Manager()

    class Meta:
        db_table = "accounts_tenantresource"

    def save(self, *args, **kwargs):
        from accounts.tenancy import MissingTenantError
        from accounts.context import get_current_organization

        org = get_current_organization()
        if org is None:
            raise MissingTenantError("Cannot save tenant-owned row without tenant context")
        if self.organization_id is None:
            self.organization_id = org.id
        if self.organization_id != org.id:
            raise MissingTenantError("Cannot save row for different organization than active tenant")
        if self.pk is not None and type(self).all_objects.filter(pk=self.pk).exists():
            orig = type(self).all_objects.filter(pk=self.pk).values_list("organization_id", flat=True).first()
            if orig is not None and orig != org.id:
                raise MissingTenantError("Cross-tenant update denied")
            if orig is not None and self.organization_id != orig:
                raise MissingTenantError("Tenant ownership cannot be changed")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        from accounts.tenancy import MissingTenantError
        from accounts.context import get_current_organization

        org = get_current_organization()
        if org is None:
            raise MissingTenantError("Cannot delete tenant-owned row without tenant context")
        if self.organization_id != org.id:
            raise MissingTenantError("Cross-tenant delete denied")
        return super().delete(*args, **kwargs)
