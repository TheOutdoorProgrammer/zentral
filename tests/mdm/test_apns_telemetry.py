import io
import json
import logging
import os
import signal
from datetime import datetime
from unittest.mock import Mock, patch

import httpx
import requests
from django.test import SimpleTestCase
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from zentral import telemetry
from zentral.contrib.mdm.apns import APNSClient
from zentral.contrib.mdm.workers import DevicesAPNSWorker, UsersAPNSWorker


class APNSTelemetryTests(SimpleTestCase):
    def setUp(self):
        self.exporter = InMemorySpanExporter()
        self.provider = TracerProvider()
        self.provider.add_span_processor(SimpleSpanProcessor(self.exporter))
        self.patchers = [
            patch.object(telemetry, "_provider", self.provider),
            patch.object(telemetry, "_log_provider", None),
            patch.object(telemetry, "_pid", os.getpid()),
            patch.dict(os.environ, {
                "OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector.invalid:4318",
                "OTEL_PROPAGATION_HOSTS": "",
            }),
            patch.object(requests.Session, "send", requests.Session.send),
            patch.object(httpx.Client, "send", httpx.Client.send),
            patch.object(httpx.AsyncClient, "send", httpx.AsyncClient.send),
            patch.object(telemetry, "_http_patched", False),
            patch("zentral.contrib.mdm.apns.time.sleep"),
        ]
        for patcher in self.patchers:
            patcher.start()
        telemetry.instrument_http()
        self.log_output = io.StringIO()
        self.handler = logging.StreamHandler(self.log_output)
        self.handler.setFormatter(telemetry.SafeJsonFormatter())
        self.logger = logging.getLogger("zentral")
        self.old_level = self.logger.level
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(self.handler)
        self.addCleanup(self.restore)
        self.target = (
            98472, "private-identifier", "private-serial", "private-udid",
            "private-token", "private-magic", "private-topic", datetime(2030, 1, 1),
        )

    def restore(self):
        self.logger.removeHandler(self.handler)
        self.logger.setLevel(self.old_level)
        for patcher in reversed(self.patchers):
            patcher.stop()
        self.provider.shutdown()

    def apns_client(self, responses):
        responses = iter(responses)
        self.requests = []

        def respond(request):
            self.requests.append(request)
            response = next(responses)
            if isinstance(response, Exception):
                raise response
            return httpx.Response(response, json={"reason": "private-server-response"})

        client = object.__new__(APNSClient)
        client.topic = "private-topic"
        client.client = httpx.Client(base_url=APNSClient.apns_production_base_url,
                                     transport=httpx.MockTransport(respond))
        self.addCleanup(client.client.close)
        return client

    def run_batch(self, client, worker_class=DevicesAPNSWorker):
        worker = worker_class()

        def update(updates):
            telemetry.database_query(Mock(), "UPDATE private_table SET private_column=%s",
                                     ["private-secret"], False, {})

        with patch.object(worker, "acquire_next_targets", return_value=[self.target]), \
                patch.object(worker, "process_target_updates", side_effect=update) as updated, \
                patch("zentral.contrib.mdm.workers.apns_client_cache.get_or_create", return_value=client):
            worker.run_once()
        return updated

    def spans(self, name):
        return [span for span in self.exporter.get_finished_spans() if span.name == name]

    def assert_private(self):
        exported = [
            {"name": span.name, "attributes": dict(span.attributes), "description": span.status.description,
             "events": [(event.name, dict(event.attributes)) for event in span.events]}
            for span in self.exporter.get_finished_spans()
        ]
        rendered = json.dumps(exported) + self.log_output.getvalue()
        self.assertNotIn("private", rendered)
        self.assertNotIn(str(self.target[0]), rendered)
        self.assertNotIn("/3/device/", rendered)
        for record in self.log_output.getvalue().splitlines():
            self.assertIn("trace_id", json.loads(record))
            self.assertIn("span_id", json.loads(record))

    def test_success_preserves_push_and_records_correlated_boundaries(self):
        client = self.apns_client([200])
        updated = self.run_batch(client)
        self.assertIsNotNone(updated.call_args.args[0][0][-1])
        self.assertEqual(self.requests[0].url.path, "/3/device/private-token")
        self.assertEqual(json.loads(self.requests[0].content), {"mdm": "private-magic"})
        self.assertEqual(self.requests[0].headers["apns-topic"], "private-topic")
        self.assertNotIn("traceparent", self.requests[0].headers)
        self.assertNotIn("baggage", self.requests[0].headers)
        batch = self.spans("mdm.apns.batch")[0]
        notification = self.spans("mdm.apns.notification")[0]
        external = self.spans("http.client")[0]
        self.assertEqual(notification.parent.span_id, batch.context.span_id)
        self.assertEqual(external.parent.span_id, notification.context.span_id)
        self.assertEqual(dict(external.attributes),
                         {"http.request.method": "POST", "http.response.status_code": 200})
        self.assertEqual(len(self.spans("database.query")), 2)
        acquisition = self.spans("database.query")[0]
        self.assertEqual(acquisition.start_time, batch.start_time)
        self.assertLessEqual(acquisition.end_time, notification.start_time)
        self.assertEqual(batch.attributes["mdm.apns.target"], "device")
        self.assertTrue(all(s.status.status_code != trace.StatusCode.ERROR
                            for s in self.exporter.get_finished_spans()))
        self.assert_private()

    def test_rejected_notification_marks_batch_failed_without_retry(self):
        updated = self.run_batch(self.apns_client([400]), UsersAPNSWorker)
        self.assertIsNone(updated.call_args.args[0][0][-1])
        self.assertEqual(len(self.requests), 1)
        for name in ("mdm.apns.batch", "mdm.apns.notification"):
            self.assertEqual(self.spans(name)[0].status.status_code, trace.StatusCode.ERROR)
        self.assertEqual(self.spans("mdm.apns.batch")[0].attributes["mdm.apns.target"], "user")
        self.assert_private()

    def test_recovered_retry_keeps_failed_attempt_and_successful_batch(self):
        self.run_batch(self.apns_client([503, 200]))
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(self.spans("http.client")[0].status.status_code, trace.StatusCode.ERROR)
        self.assertNotEqual(self.spans("mdm.apns.batch")[0].status.status_code, trace.StatusCode.ERROR)
        self.assertNotEqual(self.spans("mdm.apns.notification")[0].status.status_code, trace.StatusCode.ERROR)
        self.assert_private()

    def test_transport_errors_never_export_exception_messages_or_tokens(self):
        errors = [httpx.ConnectError("private-url private-token private-certificate")] * 3
        self.run_batch(self.apns_client(errors))
        self.assertEqual(len(self.requests), 3)
        self.assertEqual(self.spans("mdm.apns.notification")[0].attributes["error.type"], "ConnectionError")
        self.assertEqual(self.spans("mdm.apns.batch")[0].status.status_code, trace.StatusCode.ERROR)
        self.assert_private()

    def test_timeout_is_a_bounded_error_type(self):
        self.run_batch(self.apns_client([httpx.ReadTimeout("private-response")] * 3))
        self.assertEqual(self.spans("mdm.apns.notification")[0].attributes["error.type"], "TimeoutError")
        self.assert_private()

    def test_missing_client_is_a_failed_batch_without_identifiers(self):
        updated = self.run_batch(None)
        self.assertIsNone(updated.call_args.args[0][0][-1])
        self.assertEqual(self.spans("mdm.apns.batch")[0].status.status_code, trace.StatusCode.ERROR)
        self.assertFalse(self.spans("http.client"))
        self.assert_private()

    def test_idle_polls_do_not_export_or_update_targets(self):
        worker = DevicesAPNSWorker()
        with patch.object(worker, "acquire_next_targets", return_value=[]), \
                patch.object(worker, "process_target_updates") as update:
            for _ in range(4):
                worker.run_once()
        update.assert_not_called()
        self.assertFalse(self.exporter.get_finished_spans())
        self.assertEqual(self.log_output.getvalue(), "")

    def test_acquisition_failure_is_correlated_and_sanitized(self):
        worker = DevicesAPNSWorker()
        with patch.object(worker, "acquire_next_targets", side_effect=ValueError("private-sql private-token")):
            with self.assertRaises(ValueError):
                worker.run_once()
        self.assertEqual(len(self.spans("database.query")), 1)
        for span in self.exporter.get_finished_spans():
            self.assertEqual(span.status.status_code, trace.StatusCode.ERROR)
            self.assertEqual(span.attributes["error.type"], "ValueError")
        self.assert_private()

    def test_update_failure_is_correlated_and_sanitized(self):
        worker = DevicesAPNSWorker()
        client = self.apns_client([200])
        with patch.object(worker, "acquire_next_targets", return_value=[self.target]), \
                patch.object(worker, "process_target_updates", side_effect=ValueError("private-sql")), \
                patch("zentral.contrib.mdm.workers.apns_client_cache.get_or_create", return_value=client):
            with self.assertRaises(ValueError):
                worker.run_once()
        self.assertEqual(self.spans("mdm.apns.batch")[0].attributes["error.type"], "ValueError")
        self.assert_private()

    def test_worker_initializes_and_flushes_on_normal_or_failed_exit(self):
        for error in (None, RuntimeError("private-state")):
            with self.subTest(failure=error is not None):
                worker = DevicesAPNSWorker()
                with patch.object(telemetry, "configure") as configure, \
                        patch.object(telemetry, "shutdown") as shutdown, \
                        patch.object(worker, "run_once", side_effect=error) as run_once, \
                        patch("zentral.contrib.mdm.workers.queues.stop") as stop:
                    self.assertEqual(worker.run(only_once=True), 1 if error else 0)
                configure.assert_called_once_with()
                run_once.assert_called_once_with()
                stop.assert_called_once_with()
                shutdown.assert_called_once_with()

    def test_sigterm_flushes_and_restores_previous_handler(self):
        previous = signal.getsignal(signal.SIGTERM)
        worker = DevicesAPNSWorker()

        def stop_now():
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)

        with patch.object(telemetry, "configure"), patch.object(telemetry, "shutdown") as shutdown, \
                patch.object(worker, "run_once", side_effect=stop_now), \
                patch("zentral.contrib.mdm.workers.queues.stop") as stop:
            with self.assertRaises(SystemExit) as result:
                worker.run()
        self.assertEqual(result.exception.code, 0)
        stop.assert_called_once_with()
        shutdown.assert_called_once_with()
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous)
