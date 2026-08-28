import os


def init_observability():
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider

        try:
            trace.get_tracer_provider()
            if isinstance(trace.get_tracer_provider(), trace.NoOpTracerProvider):
                raise Exception("noop")
        except Exception:
            try:
                trace.set_tracer_provider(TracerProvider())
            except Exception:
                pass
        try:
            from opentelemetry.instrumentation.django import DjangoInstrumentor

            instr = DjangoInstrumentor()
            if not instr.is_instrumented_by_opentelemetry:
                instr.instrument()
        except Exception:
            pass
        try:
            from opentelemetry.instrumentation.psycopg import PsycopgInstrumentor

            instr2 = PsycopgInstrumentor()
            if not instr2.is_instrumented_by_opentelemetry:
                instr2.instrument()
        except Exception:
            pass
    except Exception:
        pass

    dsn = os.environ.get("SENTRY_DSN", "").strip()
    if not dsn:
        return
    try:
        import sentry_sdk
        from sentry_sdk.integrations.django import DjangoIntegration

        traces_rate = float(os.environ.get("SENTRY_TRACES_SAMPLE_RATE", "0.1"))
        sentry_sdk.init(
            dsn=dsn,
            integrations=[DjangoIntegration()],
            traces_sample_rate=traces_rate,
            environment=os.environ.get("SENTRY_ENVIRONMENT", "development"),
            send_default_pii=False,
        )
    except Exception:
        pass
