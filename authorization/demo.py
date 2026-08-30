from authorization.service import AuthorizationDenied, authorize


def protected_read_scoped_resource(user, organization, resource):
    authorize(user, organization, "platform.organization:read", resource)
    return {"id": str(resource.id), "name": resource.name, "region": resource.region}


def protected_update_scoped_resource(user, organization, resource, new_name):
    authorize(user, organization, "platform.organization:update", resource)
    resource.name = new_name
    resource.save()
    return resource
