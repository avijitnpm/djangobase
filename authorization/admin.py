from django.contrib import admin

from .models import MembershipRole, Permission, Role, ScopedResource


@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    list_display = ("code", "name", "created_at")
    search_fields = ("code", "name")
    readonly_fields = ("id", "created_at", "updated_at")
    ordering = ("code",)


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ("key", "name", "created_at")
    search_fields = ("key", "name")
    readonly_fields = ("id", "created_at", "updated_at")
    ordering = ("key",)
    filter_horizontal = ("permissions",)


@admin.register(MembershipRole)
class MembershipRoleAdmin(admin.ModelAdmin):
    list_display = ("id", "membership", "role", "scope_type", "scope_value", "created_at")
    list_filter = ("scope_type",)
    search_fields = ("role__key", "membership__user__username")
    readonly_fields = ("id", "created_at")
    list_select_related = ("membership", "role")


@admin.register(ScopedResource)
class ScopedResourceAdmin(admin.ModelAdmin):
    list_display = ("id", "organization", "name", "region", "created_at")
    list_filter = ("region",)
    readonly_fields = ("id", "created_at")
