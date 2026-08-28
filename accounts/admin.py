from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import Organization, OrganizationMembership, User


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    pass


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "created_at")
    readonly_fields = ("id",)


@admin.register(OrganizationMembership)
class OrganizationMembershipAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "organization", "created_at")
    readonly_fields = ("id",)
