import json
import logging
import os
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from zentral import telemetry


class TelemetryTests(TestCase):
    def setUp(self):
        self.exporter = InMemorySpanExporter()
        self.provider = TracerProvider()
        self.provider.add_span_processor(SimpleSpanProcessor(self.exporter))
        self.patchers = [
            patch.object(telemetry, "_provider", self.provider),
            patch.object(telemetry, "_log_provider", None),
            patch.object(telemetry, "_pid", os.getpid()),
            patch.dict(os.environ, {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector.invalid:4318"}),
        ]
        for patcher in self.patchers:
            patcher.start()

    def tearDown(self):
        for patcher in reversed(self.patchers):
            patcher.stop()
        self.provider.shutdown()

    def exported(self):
        return [
            {
                "name": span.name,
                "attrs": dict(span.attributes),
                "status": span.status.description,
                "events": [(event.name, dict(event.attributes)) for event in span.events],
            }
            for span in self.exporter.get_finished_spans()
        ]

    def test_exception_details_never_export_and_logs_correlate(self):
        formatter = telemetry.SafeJsonFormatter()
        with self.assertRaisesRegex(ValueError, "private"):
            with telemetry.operation("oidc.login") as span:
                record = logging.LogRecord("private@example.com", logging.ERROR, "/private/file", 1,
                                           "secret %s", ("credential",), None)
                record.exc_info = (ValueError, ValueError("private"), None)
                rendered = json.loads(formatter.format(record))
                self.assertEqual(rendered["trace_id"], f"{span.get_span_context().trace_id:032x}")
                self.assertEqual(rendered["span_id"], f"{span.get_span_context().span_id:016x}")
                self.assertEqual(rendered["event"], "application.log")
                raise ValueError("private@example.com password=private")
        output = json.dumps(self.exported()) + json.dumps(rendered)
        for secret in ("private", "credential", "password"):
            self.assertNotIn(secret, output)
        self.assertEqual(self.exporter.get_finished_spans()[0].status.status_code, trace.StatusCode.ERROR)

    def test_database_span_omits_sql_and_parameters(self):
        execute = Mock(return_value="result")
        with telemetry.operation("http.request"):
            result = telemetry.database_query(execute, "SELECT email FROM users WHERE id=%s",
                                               ["private-identity"], False, {})
        self.assertEqual(result, "result")
        self.assertEqual(self.exported()[0]["attrs"],
                         {"db.system.name": "postgresql", "db.operation.name": "SELECT"})
        self.assertNotIn("email", json.dumps(self.exported()))
        self.assertNotIn("private", json.dumps(self.exported()))

    def test_request_uses_route_template_and_w3c_parent(self):
        incoming_trace = "1234567890abcdef1234567890abcdef"
        request = SimpleNamespace(
            method="GET", path="/accounts/private@example.com/", GET={"code": "private"},
            resolver_match=SimpleNamespace(route="accounts/<str:identity>/"),
            META={"HTTP_TRACEPARENT": f"00-{incoming_trace}-1234567890abcdef-01"},
        )
        response = SimpleNamespace(status_code=500)
        with patch.object(telemetry, "configure"):
            middleware = telemetry.TelemetryMiddleware(lambda request: response)
            self.assertIs(middleware(request), response)
        span = self.exporter.get_finished_spans()[0]
        self.assertEqual(f"{span.context.trace_id:032x}", incoming_trace)
        self.assertEqual(span.name, "GET accounts/<str:identity>/")
        self.assertEqual(span.status.status_code, trace.StatusCode.ERROR)
        self.assertNotIn("private", json.dumps(self.exported()))

    def test_client_captures_only_method_status_and_trusted_propagation(self):
        request = SimpleNamespace(method="GET", url="https://auth.example.test/token?code=secret", headers={})
        with telemetry.operation("http.request"):
            with telemetry._http_span(request) as span:
                with patch.dict(os.environ, {"OTEL_PROPAGATION_HOSTS": "auth.example.test"}):
                    telemetry._http_headers(request)
                telemetry._http_result(span, SimpleNamespace(status_code=503))
        self.assertIn("traceparent", request.headers)
        self.assertEqual(self.exported()[0]["attrs"],
                         {"http.request.method": "GET", "http.response.status_code": 503})
        self.assertNotIn("secret", json.dumps(self.exported()))
        request.url = "https://untrusted.test/"
        request.headers = {}
        telemetry._http_headers(request)
        self.assertEqual(request.headers, {})

    def test_jobs_propagate_context_without_arguments_or_identity(self):
        headers = {}
        task = SimpleNamespace(request=SimpleNamespace(headers=headers, id="private", args=["secret"]))
        with telemetry.operation("http.request") as parent:
            telemetry.celery_publish(headers=headers)
            with patch.object(telemetry, "configure"):
                telemetry.celery_start(task=task)
            telemetry.celery_end(task=task, state="FAILURE")
            self.assertEqual(trace.get_current_span(), parent)
        child, parent = self.exporter.get_finished_spans()
        self.assertEqual(child.context.trace_id, parent.context.trace_id)
        self.assertEqual(child.parent.span_id, parent.context.span_id)
        self.assertEqual(child.status.status_code, trace.StatusCode.ERROR)
        self.assertNotIn("private", json.dumps(self.exported()))
        self.assertNotIn("secret", json.dumps(self.exported()))

    def test_real_http_clients_emit_sanitized_child_spans(self):
        import httpx
        import requests
        from requests.adapters import BaseAdapter

        class Adapter(BaseAdapter):
            def close(self):
                pass

            def send(self, request, **kwargs):
                response = requests.Response()
                response.status_code = 200
                response._content = b"private body"
                return response

        with (
            patch.object(requests.Session, "send", requests.Session.send),
            patch.object(httpx.Client, "send", httpx.Client.send),
            patch.object(httpx.AsyncClient, "send", httpx.AsyncClient.send),
            patch.object(telemetry, "_http_patched", False),
        ):
            telemetry.instrument_http()
            with telemetry.operation("http.request") as parent:
                with requests.Session() as client:
                    client.mount("https://", Adapter())
                    client.get("https://example.test/private?password=secret")
                with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200))) as client:
                    client.get("https://example.test/private?password=secret")
                self.assertEqual(trace.get_current_span(), parent)
        spans = self.exporter.get_finished_spans()
        self.assertEqual([s.name for s in spans], ["http.client", "http.client", "http.request"])
        self.assertEqual(spans[0].parent.span_id, spans[-1].context.span_id)
        self.assertNotIn("private", json.dumps(self.exported()))
        self.assertNotIn("secret", json.dumps(self.exported()))

    def test_configure_keeps_third_party_provider_unmodified(self):
        from django import db
        from opentelemetry.exporter.otlp.proto.http import trace_exporter
        public_provider = trace.get_tracer_provider()
        with (
            patch.object(telemetry, "_pid", None),
            patch.object(telemetry, "_provider", None),
            patch.object(telemetry, "instrument_http"),
            patch.object(telemetry, "instrument_queue"),
            patch.object(db, "connections") as connections,
            patch.object(trace_exporter, "OTLPSpanExporter") as exporter,
        ):
            connections.all.return_value = []
            telemetry.configure()
            telemetry.configure()
            self.assertEqual(exporter.call_count, 1)
            self.assertIs(trace.get_tracer_provider(), public_provider)
            telemetry.shutdown()

    def test_event_worker_and_publish_propagate_without_message_content(self):
        from kombu import Producer
        captured = {}

        def publish(producer, body, headers=None):
            captured.update(headers)

        @telemetry.event_worker
        def consume(worker, body, message):
            Producer.publish(None, body)
            return "processed"

        incoming_trace = "1234567890abcdef1234567890abcdef"
        message = SimpleNamespace(headers={"traceparent": f"00-{incoming_trace}-1234567890abcdef-01"})
        with patch.object(Producer, "publish", publish):
            telemetry.instrument_queue()
            self.assertEqual(consume(None, {"secret": "private"}, message), "processed")
        self.assertIn(incoming_trace, captured["traceparent"])
        span = self.exporter.get_finished_spans()[0]
        self.assertEqual(span.name, "job.run")
        self.assertNotIn("secret", json.dumps(self.exported()))
        self.assertNotIn("private", json.dumps(self.exported()))

    def test_unknown_events_cannot_leak_values(self):
        with self.assertRaises(ValueError):
            telemetry.event("user@example.com")
        with self.assertRaises(ValueError):
            telemetry.event("oidc.login", "private")

    def test_otlp_logs_are_rebuilt_without_exception_or_arbitrary_extras(self):
        from opentelemetry.sdk._logs import LoggerProvider
        from opentelemetry.sdk._logs.export import InMemoryLogRecordExporter, SimpleLogRecordProcessor
        exporter = InMemoryLogRecordExporter()
        provider = LoggerProvider()
        provider.add_log_record_processor(SimpleLogRecordProcessor(exporter))
        with patch.object(telemetry, "_log_provider", provider):
            with telemetry.operation("http.request") as span:
                record = logging.LogRecord("celery.private", logging.ERROR, "/secret", 4,
                                           "private %s", ("secret",), (ValueError, ValueError("secret"), None))
                record.user = "private@example.com"
                telemetry.SafeOTLPHandler().emit(record)
                telemetry.SafeOTLPHandler().emit(logging.LogRecord(
                    "opentelemetry.exporter", logging.ERROR, "/secret", 4, "secret", (), None))
                log = exporter.get_finished_logs()[0].log_record
                self.assertEqual(log.trace_id, span.get_span_context().trace_id)
                self.assertEqual(log.span_id, span.get_span_context().span_id)
        self.assertEqual(len(exporter.get_finished_logs()), 1)
        self.assertEqual(log.body, "application.log")
        self.assertEqual(dict(log.attributes), {"source": "celery", "outcome": "failure"})
        provider.shutdown()

    def test_no_endpoint_disables_events(self):
        with patch.dict(os.environ, {"OTEL_EXPORTER_OTLP_ENDPOINT": ""}):
            with patch.object(telemetry.logger, "log") as log:
                telemetry.event("oidc.login")
                log.assert_not_called()

    def test_celery_signals_register(self):
        from celery import signals
        telemetry.connect_celery()
        self.assertIn(telemetry.celery_start, signals.task_prerun._live_receivers(None))
