import json
import os
from unittest.mock import patch

from django.test import RequestFactory, SimpleTestCase
import httpx
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
import requests
from requests.adapters import BaseAdapter

from zentral import telemetry
from zentral.contrib.mdm import scep_views


class Adapter(BaseAdapter):
    def __init__(self, status=200, content_type="application/x-pki-message", body=b"response", error=None):
        self.status = status
        self.content_type = content_type
        self.body = body
        self.error = error
        self.calls = []

    def close(self):
        pass

    def send(self, request, **kwargs):
        self.calls.append((request, kwargs))
        if self.error:
            raise self.error
        response = requests.Response()
        response.status_code = self.status
        response.headers = {"Content-Type": self.content_type, "Set-Cookie": "must-not-forward",
                            "Location": "https://untrusted.example"}
        response._content = self.body
        response._content_consumed = True
        return response


class SCEPProxyTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def call(self, request, adapter):
        with requests.Session() as session:
            session.mount("https://", adapter)
            with patch.object(scep_views.requests, "Session", return_value=session):
                return scep_views.proxy(request)

    def test_fixed_destination_tls_and_no_forwarded_credentials(self):
        adapter = Adapter()
        request = self.factory.post("/public/mdm/scep/?operation=PKIOperation", b"private-csr",
                                    content_type="application/x-pki-message",
                                    HTTP_AUTHORIZATION="Bearer private-token", HTTP_COOKIE="sessionid=private-session",
                                    HTTP_HOST="attacker.example", HTTP_X_FORWARDED_HOST="attacker.example")
        response = self.call(request, adapter)
        self.assertEqual(response.status_code, 200)
        outgoing, kwargs = adapter.calls[0]
        self.assertEqual(outgoing.url, scep_views.SCEP_URL + "?operation=PKIOperation")
        self.assertNotIn("Authorization", outgoing.headers)
        self.assertNotIn("Cookie", outgoing.headers)
        self.assertNotIn("X-Forwarded-Host", outgoing.headers)
        self.assertEqual(outgoing.body, b"private-csr")
        self.assertEqual(kwargs["verify"], scep_views.SCEP_ROOT)
        self.assertEqual(kwargs["timeout"], (3, 20))
        self.assertEqual(kwargs["proxies"], {})
        self.assertNotIn("Set-Cookie", response)
        self.assertNotIn("Location", response)
        self.assertEqual(response["Cache-Control"], "no-store")

    def test_redirect_and_network_failures_are_generic(self):
        for adapter in (Adapter(status=302), Adapter(status=500),
                        Adapter(error=requests.exceptions.SSLError("private-key-details")),
                        Adapter(error=requests.exceptions.Timeout("private-message"))):
            with self.subTest(status=adapter.status):
                response = self.call(self.factory.get("/?operation=GetCACert"), adapter)
                self.assertEqual(response.status_code, 502)
                self.assertNotIn(b"private", response.content)
                self.assertEqual(len(adapter.calls), 1)

    def test_oversized_and_unexpected_upstream_response_rejected(self):
        for adapter in (Adapter(body=b"x" * (scep_views.MAX_RESPONSE + 1)),
                        Adapter(content_type="text/html")):
            response = self.call(self.factory.get("/?operation=GetCACert"), adapter)
            self.assertEqual(response.status_code, 502)

    def test_invalid_operations_and_duplicate_parameters_never_reach_ca(self):
        for query in ("operation=GetNextCACert", "operation=GetCACert&url=https://attacker.example",
                      "operation=GetCACert&operation=PKIOperation",
                      "operation=GetCACert&message=x&message=y",
                      "operation=PKIOperation&message=" + "x" * scep_views.MAX_MESSAGE):
            with self.subTest(query_length=len(query)):
                adapter = Adapter()
                response = self.call(self.factory.get("/?" + query), adapter)
                self.assertEqual(response.status_code, 400)
                self.assertEqual(adapter.calls, [])

    def test_post_requires_pki_operation_content_type_and_bounded_body(self):
        for operation, content_type, body in (
            ("GetCACert", "application/x-pki-message", b"message"),
            ("PKIOperation", "text/plain", b"message"),
            ("PKIOperation", "application/x-pki-message", b""),
            ("PKIOperation", "application/x-pki-message", b"x" * (scep_views.MAX_MESSAGE + 1)),
        ):
            adapter = Adapter()
            request = self.factory.post("/?operation=" + operation, body, content_type=content_type)
            self.assertEqual(self.call(request, adapter).status_code, 400)
            self.assertEqual(adapter.calls, [])

    def test_get_capabilities_and_ca_cert(self):
        for operation, content_type in (("GetCACaps", "text/plain"),
                                        ("GetCACert", "application/x-x509-ca-ra-cert")):
            adapter = Adapter(content_type=content_type)
            response = self.call(self.factory.get("/?operation=" + operation), adapter)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response["Content-Type"], content_type)

    def test_scep_query_body_and_headers_never_export(self):
        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        self.addCleanup(provider.shutdown)
        request = self.factory.get("/?operation=PKIOperation&message=private-csr",
                                   HTTP_AUTHORIZATION="Bearer private-token", HTTP_COOKIE="private-cookie")
        with (
            patch.object(telemetry, "_provider", provider),
            patch.object(telemetry, "_pid", os.getpid()),
            patch.dict(os.environ, {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector.invalid:4318"}),
            patch.object(requests.Session, "send", requests.Session.send),
            patch.object(httpx.Client, "send", httpx.Client.send),
            patch.object(httpx.AsyncClient, "send", httpx.AsyncClient.send),
            patch.object(telemetry, "_http_patched", False),
        ):
            telemetry.instrument_http()
            with self.assertLogs("zentral.telemetry", level="INFO") as logs:
                self.assertEqual(self.call(request, Adapter(body=b"private-certificate")).status_code, 200)
        spans = exporter.get_finished_spans()
        self.assertEqual([span.name for span in spans], ["http.client", "mdm.scep.proxy"])
        self.assertEqual(spans[0].parent.span_id, spans[1].context.span_id)
        exported = json.dumps([
            {"name": span.name, "attributes": dict(span.attributes),
             "events": [(event.name, dict(event.attributes)) for event in span.events]}
            for span in spans
        ])
        rendered = "".join(telemetry.SafeJsonFormatter().format(record) for record in logs.records)
        self.assertNotIn("private", exported + rendered)
        self.assertNotIn("message=", exported + rendered)
