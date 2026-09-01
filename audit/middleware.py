import asyncio

from audit.request_context import (
    _generate_request_id,
    _is_valid_request_id,
    _reset_current_request_id,
    _set_current_request_id,
)


class RequestIDMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self._is_async = asyncio.iscoroutinefunction(get_response)

    def __call__(self, request):
        if self._is_async:
            return self.__acall__(request)
        return self._sync_call(request)

    def _resolve_request_id(self, request):
        raw = request.META.get("HTTP_X_REQUEST_ID", "")
        if isinstance(raw, str):
            cand = raw.strip()
            if cand and _is_valid_request_id(cand):
                return cand
        return _generate_request_id()

    def _sync_call(self, request):
        request_id = self._resolve_request_id(request)
        request.request_id = request_id
        token = _set_current_request_id(request_id)
        self._set_telemetry(request_id)
        try:
            response = self.get_response(request)
            response["X-Request-ID"] = request_id
            return response
        finally:
            _reset_current_request_id(token)

    async def __acall__(self, request):
        request_id = self._resolve_request_id(request)
        request.request_id = request_id
        token = _set_current_request_id(request_id)
        self._set_telemetry(request_id)
        try:
            response = await self.get_response(request)
            response["X-Request-ID"] = request_id
            return response
        finally:
            _reset_current_request_id(token)

    def _set_telemetry(self, request_id):
        try:
            from opentelemetry import trace

            span = trace.get_current_span()
            if span is not None and hasattr(span, "set_attribute"):
                try:
                    span.set_attribute("request.id", request_id)
                except Exception:
                    pass
        except Exception:
            pass
        try:
            import sentry_sdk

            try:
                sentry_sdk.set_tag("request_id", request_id)
            except Exception:
                pass
        except Exception:
            pass
