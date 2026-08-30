PLATFORM_PERMISSIONS = [
    {
        "code": "platform.organization:read",
        "name": "View organization",
        "description": "Can view organization details",
    },
    {
        "code": "platform.organization:update",
        "name": "Update organization",
        "description": "Can update organization details",
    },
    {
        "code": "platform.membership:read",
        "name": "View memberships",
        "description": "Can view organization memberships",
    },
    {
        "code": "platform.membership:update",
        "name": "Update memberships",
        "description": "Can update organization memberships",
    },
]

PLATFORM_ROLES = [
    {
        "key": "organization_admin",
        "name": "Organization Admin",
        "description": "Full access to organization and memberships",
        "permissions": [
            "platform.organization:read",
            "platform.organization:update",
            "platform.membership:read",
            "platform.membership:update",
        ],
    },
    {
        "key": "organization_member",
        "name": "Organization Member",
        "description": "Read-only access to organization and memberships",
        "permissions": [
            "platform.organization:read",
            "platform.membership:read",
        ],
    },
]


def bootstrap_permissions():
    from authorization.models import Permission

    for perm in PLATFORM_PERMISSIONS:
        Permission.objects.update_or_create(
            code=perm["code"],
            defaults={
                "name": perm["name"],
                "description": perm["description"],
            },
        )


def bootstrap_roles():
    from authorization.models import Permission, Role

    bootstrap_permissions()
    for role_def in PLATFORM_ROLES:
        role, _ = Role.objects.update_or_create(
            key=role_def["key"],
            defaults={
                "name": role_def["name"],
                "description": role_def["description"],
            },
        )
        perms = Permission.objects.filter(code__in=role_def["permissions"])
        role.permissions.set(perms)


def bootstrap_all():
    bootstrap_roles()
