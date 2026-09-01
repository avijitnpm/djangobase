import re
import uuid
from contextvars import ContextVar

_request_id_ctx: ContextVar[str | None] = ContextVar("current_request_id", default=None)

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")


def _generate_request_id() -> str:
    return uuid.uuid4().hex


def _is_valid_request_id(value: str) -> bool:
    if not isinstance(value, str):
        return False
    value = value.strip()
    if not value:
        return False
    if len(value) > 64:
        return False
    return bool(_REQUEST_ID_RE.match(value))


def get_current_request_id() -> str | None:
    return _request_id_ctx.get()


def _set_current_request_id(request_id: str | None):
    return _request_id_ctx.set(request_id)


def _reset_current_request_id(token):
    _request_id_ctx.reset(token)
