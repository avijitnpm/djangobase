import uuid

from django.db import models


class MissingTenantError(RuntimeError):
    pass


class TenantQuerySet(models.QuerySet):
    def for_tenant(self, organization=None):
        from accounts.context import get_current_organization

        if organization is None:
            organization = get_current_organization()
        if organization is None:
            raise MissingTenantError("Tenant context required")
        org_id = organization.id if hasattr(organization, "id") else organization
        return self.filter(organization_id=org_id)


class TenantManager(models.Manager):
    def get_queryset(self):
        from accounts.context import get_current_organization

        org = get_current_organization()
        if org is None:
            raise MissingTenantError("Tenant context required: no active organization")
        qs = TenantQuerySet(self.model, using=self._db)
        return qs.filter(organization_id=org.id)

    def for_tenant(self, organization=None):
        from accounts.context import get_current_organization

        if organization is None:
            organization = get_current_organization()
        if organization is None:
            raise MissingTenantError("Tenant context required")
        org_id = organization.id if hasattr(organization, "id") else organization
        return TenantQuerySet(self.model, using=self._db).filter(organization_id=org_id)

    def create(self, **kwargs):
        from accounts.context import get_current_organization

        org = get_current_organization()
        if org is None:
            raise MissingTenantError("Cannot create tenant-owned row without tenant context")
        if "organization" in kwargs and "organization_id" in kwargs:
            raise ValueError("Provide only one of organization or organization_id")
        if "organization" in kwargs:
            val = kwargs["organization"]
            val_id = val.id if hasattr(val, "id") else val
            if val_id != org.id:
                raise MissingTenantError("Cannot create row for different organization than active tenant")
        elif "organization_id" in kwargs:
            try:
                q = uuid.UUID(str(kwargs["organization_id"]))
            except Exception:
                raise MissingTenantError("Invalid organization_id")
            if q != org.id:
                raise MissingTenantError("Cannot create row for different organization than active tenant")
        else:
            kwargs["organization"] = org
        return super().create(**kwargs)

    def get_or_create(self, **kwargs):
        from accounts.context import get_current_organization

        org = get_current_organization()
        if org is None:
            raise MissingTenantError("Tenant context required")
        kwargs.setdefault("organization", org)
        if kwargs.get("organization") is not org and kwargs.get("organization_id") is not org.id:
            if "organization" in kwargs:
                val = kwargs["organization"]
                val_id = val.id if hasattr(val, "id") else val
                if val_id != org.id:
                    raise MissingTenantError("Cross-tenant get_or_create denied")
        return super().get_or_create(**kwargs)

    def update_or_create(self, **kwargs):
        from accounts.context import get_current_organization

        org = get_current_organization()
        if org is None:
            raise MissingTenantError("Tenant context required")
        kwargs.setdefault("organization", org)
        return super().update_or_create(**kwargs)


class TenantModel(models.Model):
    organization = models.ForeignKey("accounts.Organization", on_delete=models.CASCADE, related_name="%(class)s_set")

    objects = TenantManager()
    all_objects = models.Manager()

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        from accounts.context import get_current_organization

        org = get_current_organization()
        if org is None:
            raise MissingTenantError("Cannot save tenant-owned row without tenant context")
        if self.organization_id is None:
            self.organization_id = org.id
        if self.organization_id != org.id:
            raise MissingTenantError("Cannot save row for different organization than active tenant")
        if self.pk is not None:
            orig = type(self).all_objects.filter(pk=self.pk).values_list("organization_id", flat=True).first()
            if orig is not None and orig != org.id:
                raise MissingTenantError("Cross-tenant update denied")
            if orig is not None and self.organization_id != orig:
                raise MissingTenantError("Tenant ownership cannot be changed")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        from accounts.context import get_current_organization

        org = get_current_organization()
        if org is None:
            raise MissingTenantError("Cannot delete tenant-owned row without tenant context")
        if self.organization_id != org.id:
            raise MissingTenantError("Cross-tenant delete denied")
        return super().delete(*args, **kwargs)
