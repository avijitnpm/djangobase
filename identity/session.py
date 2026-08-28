SESSION_KEY = "_identity_user_id"


def set_authenticated_user(request, user_id) -> None:
    request.session[SESSION_KEY] = str(user_id)


def get_authenticated_user_id(request):
    value = request.session.get(SESSION_KEY)
    if value is None:
        return None
    import uuid

    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError):
        return None


def clear_authenticated_user(request) -> None:
    request.session.pop(SESSION_KEY, None)


def is_authenticated(request) -> bool:
    return get_authenticated_user_id(request) is not None
