import contextlib
import functools
import inspect
import json
import logging
import logging.config
import os
import time
from urllib.parse import urlsplit

from opentelemetry import context, trace
from opentelemetry.baggage.propagation import W3CBaggagePropagator
from opentelemetry.propagators.composite import CompositePropagator
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator


EVENTS = frozenset((
    "http.request", "database.query", "http.client", "job.run", "oidc.login",
    "mdm.scep.challenge", "mdm.scep.authorize", "mdm.scep.proxy",
    "family_setup.page", "family_setup.activate", "family_setup.status", "family_setup.step",
    "family_setup.forget", "family_setup.provision", "family_setup.revoke",
))
OUTCOMES = frozenset(("success", "failure", "denied"))
METHODS = frozenset(("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE"))
SQL_OPERATIONS = frozenset(("SELECT", "INSERT", "UPDATE", "DELETE", "BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT"))
ERROR_TYPES = frozenset((
    "AccessRefused", "AttributeError", "ConnectionError", "DataError", "DatabaseError", "ImportError",
    "IntegrityError", "InternalError", "KeyError", "ModuleNotFoundError", "NotFound", "NotImplementedError",
    "OperationalError", "PermissionError", "PreconditionFailed", "RequestError", "RestartFreqExceeded", "RuntimeError",
    "TimeoutError", "TypeError", "ValueError",
))
propagator = CompositePropagator((TraceContextTextMapPropagator(), W3CBaggagePropagator()))
logger = logging.getLogger("zentral.telemetry")
_provider = None
_log_provider = None
_pid = None
_http_patched = False


def enabled():
    return bool(os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"))


def resource_attributes():
    attrs = {"service.name": os.environ.get("OTEL_SERVICE_NAME", "zentral")}
    for entry in os.environ.get("OTEL_RESOURCE_ATTRIBUTES", "").split(","):
        key, _, value = entry.partition("=")
        if key in ("service.version", "deployment.environment.name") and value:
            attrs[key] = value
    return attrs


def configure(**kwargs):
    global _provider, _log_provider, _pid
    if not enabled() or _pid == os.getpid():
        return
    from django.db import connections
    from django.db.backends.signals import connection_created
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
    from opentelemetry.sdk._logs import LoggerProvider
    from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    if _pid is not None and _pid != os.getpid():
        for inherited in (_provider, _log_provider):
            if inherited is not None:
                inherited.shutdown()
    # A private provider prevents third-party SDKs from exporting their raw URLs and attributes.
    _provider = TracerProvider(resource=Resource(resource_attributes()))
    _provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(timeout=5)))
    _log_provider = LoggerProvider(resource=Resource(resource_attributes()))
    _log_provider.add_log_record_processor(BatchLogRecordProcessor(OTLPLogExporter(timeout=5)))
    _pid = os.getpid()
    connection_created.connect(instrument_connection, dispatch_uid="zentral.telemetry.database", weak=False)
    for connection in connections.all(initialized_only=True):
        instrument_connection(connection=connection)
    instrument_http()
    instrument_queue()


def shutdown(**kwargs):
    if _provider is not None and _pid == os.getpid():
        _provider.shutdown()
    if _log_provider is not None and _pid == os.getpid():
        _log_provider.shutdown()


def tracer():
    if _provider is not None and _pid == os.getpid():
        return _provider.get_tracer("zentral.telemetry")
    return trace.NoOpTracer()


def error_type(error):
    name = type(error).__name__
    return name if name in ERROR_TYPES else "Exception"


def event(name, outcome="success", error=None):
    if name not in EVENTS or outcome not in OUTCOMES:
        raise ValueError("Unknown telemetry event or outcome")
    if not enabled():
        return
    span = trace.get_current_span()
    span.add_event(name, {"outcome": outcome})
    if outcome == "failure":
        span.set_status(trace.StatusCode.ERROR)
    extra = {"telemetry_event": name, "telemetry_outcome": outcome}
    if error is not None:
        extra["telemetry_error_type"] = error_type(error)
        span.set_attribute("error.type", extra["telemetry_error_type"])
    logger.log(logging.ERROR if outcome == "failure" else logging.INFO, name,
               extra=extra)


class SafeJsonFormatter(logging.Formatter):
    def format(self, record):
        name = getattr(record, "telemetry_event", None)
        outcome = getattr(record, "telemetry_outcome", None)
        if name not in EVENTS or outcome not in OUTCOMES:
            name = "application.log"
            outcome = "failure" if record.levelno >= logging.ERROR else "success"
        span = trace.get_current_span().get_span_context()
        result = {
            "event": name,
            "outcome": outcome,
            "level": record.levelname,
            **resource_attributes(),
        }
        prefix = record.name.split(".", 1)[0]
        result["source"] = prefix if prefix in ("opentelemetry", "django", "celery", "gunicorn", "zentral") else "app"
        if record.exc_info and record.exc_info[1] is not None:
            result["error.type"] = error_type(record.exc_info[1])
        elif getattr(record, "telemetry_error_type", None):
            supplied = record.telemetry_error_type
            result["error.type"] = supplied if supplied in ERROR_TYPES else "Exception"
        if span.is_valid:
            result.update(trace_id=f"{span.trace_id:032x}", span_id=f"{span.span_id:016x}")
        # Never format arbitrary messages, exception details, args, or extras from upstream.
        return json.dumps(result, separators=(",", ":"))


class SafeOTLPHandler(logging.Handler):
    def emit(self, record):
        if _log_provider is None or _pid != os.getpid() or record.name.startswith("opentelemetry"):
            return
        from opentelemetry._logs import LogRecord, SeverityNumber
        safe = json.loads(SafeJsonFormatter().format(record))
        if record.levelno >= logging.ERROR:
            trace.get_current_span().set_status(trace.StatusCode.ERROR)
        attributes = {"outcome": safe["outcome"], "source": safe["source"]}
        if "error.type" in safe:
            attributes["error.type"] = safe["error.type"]
            trace.get_current_span().set_attribute("error.type", safe["error.type"])
        severity = (SeverityNumber.ERROR if record.levelno >= logging.ERROR else
                    SeverityNumber.WARN if record.levelno >= logging.WARNING else SeverityNumber.INFO)
        _log_provider.get_logger("zentral.telemetry").emit(LogRecord(
            timestamp=int(record.created * 1_000_000_000),
            context=context.get_current(),
            severity_number=severity,
            severity_text=severity.name,
            body=safe["event"],
            attributes=attributes,
        ))


@contextlib.contextmanager
def operation(name, kind=trace.SpanKind.INTERNAL, attributes=None, parent=None):
    with tracer().start_as_current_span(
        name, kind=kind, attributes=attributes, context=parent,
        record_exception=False, set_status_on_exception=False,
    ) as span:
        try:
            yield span
        except Exception as error:
            span.set_status(trace.StatusCode.ERROR)
            event(name, "failure", error=error)
            raise


def database_query(execute, sql, params, many, db_context):
    if not trace.get_current_span().is_recording():
        return execute(sql, params, many, db_context)
    token = sql.split(None, 1)[0].upper() if isinstance(sql, str) and sql.strip() else ""
    operation_name = token if token in SQL_OPERATIONS else "OTHER"
    with operation("database.query", trace.SpanKind.CLIENT,
                   {"db.system.name": "postgresql", "db.operation.name": operation_name}):
        return execute(sql, params, many, db_context)


def instrument_connection(sender=None, connection=None, **kwargs):
    if database_query not in connection.execute_wrappers:
        connection.execute_wrappers.append(database_query)


def _http_headers(request):
    hosts = os.environ.get("OTEL_PROPAGATION_HOSTS", "").split(",")
    if urlsplit(str(request.url)).hostname in hosts:
        propagator.inject(request.headers)


def _http_span(request):
    method = request.method.upper()
    return operation("http.client", trace.SpanKind.CLIENT,
                     {"http.request.method": method if method in METHODS else "OTHER"})


def _http_result(span, response):
    span.set_attribute("http.response.status_code", response.status_code)
    if response.status_code >= 500:
        span.set_status(trace.StatusCode.ERROR)
        event("http.client", "failure")


def instrument_http():
    global _http_patched
    if _http_patched:
        return
    import httpx
    import requests

    def wrap(original):
        @functools.wraps(original)
        def send(client, request, *args, **kwargs):
            if not trace.get_current_span().is_recording():
                return original(client, request, *args, **kwargs)
            with _http_span(request) as span:
                _http_headers(request)
                response = original(client, request, *args, **kwargs)
                _http_result(span, response)
                return response
        return send

    original_async_send = httpx.AsyncClient.send

    @functools.wraps(original_async_send)
    async def async_send(client, request, *args, **kwargs):
        if not trace.get_current_span().is_recording():
            return await original_async_send(client, request, *args, **kwargs)
        with _http_span(request) as span:
            _http_headers(request)
            response = await original_async_send(client, request, *args, **kwargs)
            _http_result(span, response)
            return response

    requests.Session.send = wrap(requests.Session.send)
    httpx.Client.send = wrap(httpx.Client.send)
    httpx.AsyncClient.send = async_send
    _http_patched = True


class TelemetryMiddleware:
    def __init__(self, get_response):
        configure()
        self.get_response = get_response

    def __call__(self, request):
        if not enabled():
            return self.get_response(request)
        method = request.method if request.method in METHODS else "OTHER"
        parent = propagator.extract({
            "traceparent": request.META.get("HTTP_TRACEPARENT", ""),
            "baggage": request.META.get("HTTP_BAGGAGE", ""),
        })
        started = time.monotonic()
        with operation("http.request", trace.SpanKind.SERVER,
                       {"http.request.method": method}, parent) as span:
            response = self.get_response(request)
            match = getattr(request, "resolver_match", None)
            route = getattr(match, "route", None) or "/{unmatched}"
            span.update_name(f"{method} {route}")
            span.set_attributes({
                "http.route": route,
                "http.response.status_code": response.status_code,
                "http.server.duration_ms": round((time.monotonic() - started) * 1000),
            })
            event("http.request", "failure" if response.status_code >= 500 else "success")
            return response


def context_processor(request):
    url = os.environ.get("FARO_COLLECTOR_URL", "")
    parsed = urlsplit(url)
    attrs = resource_attributes()
    if not url or parsed.scheme != "https" or not parsed.netloc:
        return {}
    return {"telemetry_config": {
        "url": url,
        "version": attrs.get("service.version", ""),
        "environment": attrs.get("deployment.environment.name", ""),
    }}


def event_worker(callback):
    @functools.wraps(callback)
    def consume(worker, body, message):
        if not enabled():
            return callback(worker, body, message)
        headers = message.headers or {}
        parent = propagator.extract({key: headers.get(key, "") for key in ("traceparent", "baggage")})
        with operation("job.run", trace.SpanKind.CONSUMER, {"messaging.system": "rabbitmq"}, parent) as span:
            result = callback(worker, body, message)
            failed = span.is_recording() and span.status.status_code == trace.StatusCode.ERROR
            event("job.run", "failure" if failed else "success")
            return result
    return consume


def instrument_queue():
    from kombu import Producer
    if getattr(Producer.publish, "_zentral_telemetry", False):
        return
    original = Producer.publish
    signature = inspect.signature(original)

    @functools.wraps(original)
    def publish(*args, **kwargs):
        if not trace.get_current_span().is_recording():
            return original(*args, **kwargs)
        bound = signature.bind(*args, **kwargs)
        headers = dict(bound.arguments.get("headers") or {})
        propagator.inject(headers)
        bound.arguments["headers"] = headers
        return original(*bound.args, **bound.kwargs)

    publish._zentral_telemetry = True
    Producer.publish = publish


def celery_publish(headers=None, **kwargs):
    if enabled() and isinstance(headers, dict):
        propagator.inject(headers)


def celery_start(task=None, **kwargs):
    if not enabled() or task is None:
        return
    configure()
    headers = task.request.headers or {}
    parent = propagator.extract({key: headers.get(key, "") for key in ("traceparent", "baggage")})
    span = tracer().start_span("job.run", context=parent, kind=trace.SpanKind.CONSUMER,
                               attributes={"messaging.system": "celery"})
    token = context.attach(trace.set_span_in_context(span, parent))
    task.request._zentral_telemetry = (span, token)


def celery_end(task=None, state=None, **kwargs):
    saved = getattr(getattr(task, "request", None), "_zentral_telemetry", None)
    if saved is None:
        return
    span, token = saved
    try:
        event("job.run", "success" if state == "SUCCESS" else "failure")
    finally:
        span.end()
        context.detach(token)
        del task.request._zentral_telemetry


def connect_celery():
    from celery import signals
    for signal, receiver in (
        (signals.before_task_publish, celery_publish),
        (signals.task_prerun, celery_start),
        (signals.task_postrun, celery_end),
        (signals.worker_init, configure),
        (signals.worker_process_init, configure),
        (signals.worker_process_shutdown, shutdown),
        (signals.worker_shutdown, shutdown),
    ):
        signal.connect(receiver, weak=False, dispatch_uid=f"zentral.telemetry.{signal.name}")
    if enabled():
        signals.setup_logging.connect(configure_logging, weak=False, dispatch_uid="zentral.telemetry.logging")


def configure_logging(**kwargs):
    from django.conf import settings
    logging.config.dictConfig(settings.LOGGING)
