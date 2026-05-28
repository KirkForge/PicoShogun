"""OpenTelemetry tracing & metrics integration for Shogun."""
import os
import logging
from typing import Optional

logger = logging.getLogger("SecdevKimi.Observability")

# ── Tracer setup ─────────────────────────────────────────────────────

_tracer_provider = None
_meter_provider = None
_tracer = None
_meter = None

def init_telemetry(service_name: str = "shogun", endpoint: Optional[str] = None) -> bool:
    """Initialize OpenTelemetry tracing and metrics.
    
    Returns True if OTEL is available and configured, False otherwise.
    Gracefully degrades — if opentelemetry packages aren't installed, no-op.
    """
    global _tracer_provider, _meter_provider, _tracer, _meter
    
    endpoint = endpoint or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        logger.info("No OTEL endpoint configured — tracing disabled")
        return False

    try:
        from opentelemetry import trace, metrics
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.resources import Resource
        
        # OTLP exporters
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
            from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
            use_grpc = True
        except ImportError:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
            from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
            use_grpc = False

        resource = Resource.create({
            "service.name": service_name,
            "service.version": "2.13.0",
            "deployment.environment": os.environ.get("SECDEV_ENV", "development"),
        })

        # Tracing
        _tracer_provider = TracerProvider(resource=resource)
        if use_grpc:
            span_exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True)
        else:
            span_exporter = OTLPSpanExporter(endpoint=endpoint)
        _tracer_provider.add_span_processor(BatchSpanProcessor(span_exporter))
        trace.set_tracer_provider(_tracer_provider)
        _tracer = trace.get_tracer(service_name, "2.13.0")

        # Metrics
        if use_grpc:
            _metric_exporter = OTLPMetricExporter(endpoint=endpoint, insecure=True)
        else:
            _metric_exporter = OTLPMetricExporter(endpoint=endpoint)
        # TODO: wire _metric_exporter into PeriodicExportingMetricReader for production
        _meter_provider = MeterProvider(resource=resource)
        # Note: PeriodicExportingMetricReader requires additional setup in production
        metrics.set_meter_provider(_meter_provider)
        _meter = metrics.get_meter(service_name, "2.13.0")

        logger.info(f"OpenTelemetry initialized — endpoint={endpoint}, grpc={use_grpc}")
        return True

    except ImportError:
        logger.info("opentelemetry packages not installed — tracing disabled")
        return False
    except Exception as e:
        logger.warning(f"Failed to initialize OTEL: {e}")
        return False


def get_tracer():
    """Get the OTEL tracer (or a no-op proxy)."""
    if _tracer is None:
        return NoOpTracer()
    return _tracer


def get_meter():
    """Get the OTEL meter (or a no-op proxy)."""
    if _meter is None:
        return NoOpMeter()
    return _meter


class NoOpTracer:
    """No-op tracer when OTEL is not configured."""
    def start_as_current_span(self, name, **kwargs):
        from contextlib import nullcontext
        return nullcontext(NoOpSpan())
    
    def start_span(self, name, **kwargs):
        return NoOpSpan()


class NoOpSpan:
    """No-op span."""
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def set_attribute(self, key, value):
        pass
    def add_event(self, name, attributes=None):
        pass
    def set_status(self, status, description=""):
        pass
    def record_exception(self, exception, attributes=None):
        pass
    def end(self):
        pass


class NoOpMeter:
    """No-op meter when OTEL is not configured."""
    def create_counter(self, name, **kwargs):
        return NoOpInstrument()
    
    def create_histogram(self, name, **kwargs):
        return NoOpInstrument()
    
    def create_gauge(self, name, **kwargs):
        return NoOpInstrument()
    
    def create_up_down_counter(self, name, **kwargs):
        return NoOpInstrument()


class NoOpInstrument:
    """No-op instrument."""
    def add(self, amount, attributes=None):
        pass
    def record(self, amount, attributes=None):
        pass
    def set(self, amount, attributes=None):
        pass


# ── FastAPI middleware ────────────────────────────────────────────────

def setup_fastapi_instrumentation(app):
    """Add OTEL instrumentation to a FastAPI app. Gracefully no-ops if not configured."""
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        FastAPIInstrumentor().instrument_app(app)
        logger.info("FastAPI OTEL instrumentation enabled")
        return True
    except ImportError:
        logger.info("FastAPIInstrumentor not available — skipping auto-instrumentation")
        return False
    except Exception as e:
        logger.warning(f"FastAPI instrumentation failed: {e}")
        return False


# ── Convenience decorators ────────────────────────────────────────────

def trace_span(name: str, attributes: dict = None):
    """Decorator to trace a function call as an OTEL span."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            tracer = get_tracer()
            with tracer.start_as_current_span(name) as span:
                if attributes:
                    for k, v in attributes.items():
                        span.set_attribute(k, v)
                try:
                    result = func(*args, **kwargs)
                    span.set_attribute("result", "success")
                    return result
                except Exception as e:
                    span.set_attribute("result", "error")
                    span.set_attribute("error.type", type(e).__name__)
                    span.set_attribute("error.message", str(e))
                    raise
        return wrapper
    return decorator


def trace_async_span(name: str, attributes: dict = None):
    """Decorator to trace an async function call as an OTEL span."""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            tracer = get_tracer()
            with tracer.start_as_current_span(name) as span:
                if attributes:
                    for k, v in attributes.items():
                        span.set_attribute(k, v)
                try:
                    result = await func(*args, **kwargs)
                    span.set_attribute("result", "success")
                    return result
                except Exception as e:
                    span.set_attribute("result", "error")
                    span.set_attribute("error.type", type(e).__name__)
                    span.set_attribute("error.message", str(e))
                    raise
        return wrapper
    return decorator
