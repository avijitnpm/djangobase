import uuid

from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.db import models


class Permission(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    code = models.CharField(
        max_length=255,
        unique=True,
        db_index=True,
        validators=[
            RegexValidator(
                regex=r"^[a-z0-9_]+\.[a-z0-9_]+:[a-z0-9_]+$",
                message="Code must be <namespace>.<resource>:<action> lowercase, e.g. platform.organization:read",
            )
        ],
        help_text="Stable identifier e.g. platform.organization:read",
    )
    name = models.CharField(max_length=255, help_text="Human-readable name")
    description = models.TextField(blank=True, default="", help_text="Human-readable description")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "authorization_permission"
        ordering = ["code"]
        verbose_name = "Permission"
        verbose_name_plural = "Permissions"

    def __str__(self):  # type: ignore[override]
        return str(self.code)


class Role(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    key = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
        validators=[
            RegexValidator(
                regex=r"^[a-z][a-z0-9_]*$",
                message="Key must be lowercase alphanumeric with underscores, e.g. organization_admin",
            )
        ],
        help_text="Stable key e.g. organization_admin",
    )
    name = models.CharField(max_length=255, help_text="Human-readable name")
    description = models.TextField(blank=True, default="", help_text="Human-readable description")
    permissions = models.ManyToManyField(
        Permission,
        related_name="roles",
        blank=True,
        help_text="Permissions granted by this role",
    )
    memberships = models.ManyToManyField(
        "accounts.OrganizationMembership",
        through="authorization.MembershipRole",
        related_name="roles",
        blank=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "authorization_role"
        ordering = ["key"]
        verbose_name = "Role"
        verbose_name_plural = "Roles"

    def __str__(self):  # type: ignore[override]
        return str(self.key)


class MembershipRole(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    membership = models.ForeignKey(
        "accounts.OrganizationMembership",
        on_delete=models.CASCADE,
        related_name="membership_roles",
    )
    role = models.ForeignKey(
        Role,
        on_delete=models.CASCADE,
        related_name="membership_roles",
    )
    scope_type = models.CharField(
        max_length=64,
        blank=True,
        default="",
        validators=[
            RegexValidator(
                regex=r"^[a-z][a-z0-9_]*$",
                message="scope_type must be lowercase alphanumeric with underscores",
            )
        ],
        help_text="Dimension e.g. '', 'organization', 'region', 'resource'",
    )
    scope_value = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="Value for dimension, e.g. north or resource UUID",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "authorization_membershiprole"
        constraints = [
            models.UniqueConstraint(
                fields=["membership", "role", "scope_type", "scope_value"],
                name="unique_membership_role_scope",
            ),
        ]
        verbose_name = "Membership Role"
        verbose_name_plural = "Membership Roles"

    def __str__(self):  # type: ignore[override]
        return f"{self.membership_id} -> {self.role_id} [{self.scope_type}:{self.scope_value}]"

    @property
    def is_organization_wide(self):
        return not self.scope_type or self.scope_type == "organization"

    def clean(self):
        super().clean()
        st = (self.scope_type or "").strip()
        sv = (self.scope_value or "").strip()
        if not st or st == "organization":
            if sv:
                raise ValidationError({"scope_value": "organization scope must not have a value"})
            self.scope_type = "organization" if st == "organization" else ""
            self.scope_value = ""
            return
        if st == "region":
            if not sv:
                raise ValidationError({"scope_value": "region scope requires a value"})
            if not sv.replace("-", "").replace("_", "").isalnum() or not sv[0].isalpha():
                raise ValidationError({"scope_value": "region value must be alphanumeric starting with letter"})
            return
        if st == "resource":
            if not sv:
                raise ValidationError({"scope_value": "resource scope requires a value"})
            try:
                uuid.UUID(str(sv))
            except Exception:
                raise ValidationError({"scope_value": "resource scope must be a UUID"})
            return
        if not sv:
            raise ValidationError({"scope_value": f"{st} scope requires a value"})


class ScopedResource(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        "accounts.Organization",
        on_delete=models.CASCADE,
        related_name="scoped_resources",
    )
    name = models.CharField(max_length=255)
    region = models.CharField(max_length=64, blank=True, default="", db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "authorization_scopedresource"
        ordering = ["name"]
        verbose_name = "Scoped Resource"
        verbose_name_plural = "Scoped Resources"

    def __str__(self):  # type: ignore[override]
        return f"{self.name} [{self.region}]"

    def save(self, *args, **kwargs):
        from accounts.context import get_current_organization
        from accounts.tenancy import MissingTenantError

        org = get_current_organization()
        if org is None:
            raise MissingTenantError("Cannot save tenant-owned row without tenant context")
        if self.organization_id is None:
            self.organization_id = org.id
        if self.organization_id != org.id:
            raise MissingTenantError("Cannot save row for different organization than active tenant")
        if self.pk is not None and type(self).objects.filter(pk=self.pk).exists():
            orig_org = type(self).objects.filter(pk=self.pk).values_list("organization_id", flat=True).first()
            if orig_org is not None and orig_org != org.id:
                raise MissingTenantError("Cross-tenant update denied")
            if orig_org is not None and self.organization_id != orig_org:
                raise MissingTenantError("Tenant ownership cannot be changed")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        from accounts.context import get_current_organization
        from accounts.tenancy import MissingTenantError

        org = get_current_organization()
        if org is None:
            raise MissingTenantError("Cannot delete tenant-owned row without tenant context")
        if self.organization_id != org.id:
            raise MissingTenantError("Cross-tenant delete denied")
        return super().delete(*args, **kwargs)
