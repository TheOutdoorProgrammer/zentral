import base64
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timedelta, timezone as dt_timezone
import hashlib
import hmac
import json
from io import StringIO
import os
from pathlib import Path
import subprocess
import sys
from threading import Barrier
from unittest.mock import patch

from asn1crypto.core import UTF8String
from asn1crypto.csr import CertificationRequest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier
from django.core.management import call_command
from django.db import connections
from django.test import RequestFactory, SimpleTestCase, TestCase, TransactionTestCase, override_settings
from django.utils import timezone

from zentral.core.secret_engines import secret_engines
from zentral.contrib.mdm.models import SCEPChallenge
from zentral.contrib.mdm.scep_broker import (
    authorize_challenge, BrokerUnavailable, decode_json, InvalidChallenge, mint_challenge, verify_webhook,
)
from zentral.contrib.mdm.scep_views import authorize, challenge


CONFIG = {
    "subject": {"common_name": "MDM$enrollment-secret", "organization": ["Example"], "serial_number": "serial"},
    "subject_alternative_names": {"dns_names": ["device.example.test"]},
    "key_usage": 5,
}
ENV = {
    "ZENTRAL_SCEP_BROKER_TOKEN": "test-broker-token-not-for-production-000",
    "ZENTRAL_SCEP_WEBHOOK_ID": "test-webhook",
    "ZENTRAL_SCEP_WEBHOOK_SECRET": base64.b64encode(b"test-webhook-secret" * 4).decode(),
}


def make_csr(key, common_name=None, sans=None, usage=True, extra=()):
    subject = [
        x509.NameAttribute(NameOID.COMMON_NAME, common_name or CONFIG["subject"]["common_name"]),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example"),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, "serial"),
    ]
    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(subject))
    builder = builder.add_extension(
        x509.SubjectAlternativeName(sans if sans is not None else [x509.DNSName("device.example.test")]),
        critical=False,
    )
    if usage is not None:
        builder = builder.add_extension(
            x509.KeyUsage(True, False, usage, False, False, False, False, False, False), critical=True,
        )
    for extension in extra:
        builder = builder.add_extension(extension, critical=False)
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def payload(challenge, raw, transaction_id="transaction-one"):
    return {
        "timestamp": datetime.now(dt_timezone.utc).isoformat(),
        "provisionerName": "zentral",
        "scepChallenge": challenge,
        "scepTransactionID": transaction_id,
        "x509CertificateRequest": {"raw": base64.b64encode(raw).decode()},
    }


def signature(body):
    return hmac.new(base64.b64decode(ENV["ZENTRAL_SCEP_WEBHOOK_SECRET"]), body, hashlib.sha256).hexdigest()


class SecretEngineMixin:
    def setUp(self):
        super().setUp()
        self.old_engines = secret_engines.secret_engines
        self.old_default = secret_engines.default_secret_engine
        secret_engines.load_config({
            "fernet": {"backend": "zentral.core.secret_engines.backends.fernet", "passwords": ["tests-only"]},
        })
        self.addCleanup(self.restore_engines)

    def restore_engines(self):
        secret_engines.secret_engines = self.old_engines
        secret_engines.default_secret_engine = self.old_default


class SCEPChallengeTests(SecretEngineMixin, TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        super().setUp()
        self.token = mint_challenge(deepcopy(CONFIG))
        self.raw = make_csr(self.key)

    def assert_denied(self, value):
        with self.assertRaises(InvalidChallenge):
            authorize_challenge(value)

    def test_encrypted_configuration_and_only_challenge_digest_persist(self):
        row = SCEPChallenge.objects.get()
        self.assertNotIn(self.token, row.csr_config)
        self.assertNotIn("enrollment-secret", row.csr_config)
        self.assertEqual(json.loads(row.get_csr_config()), CONFIG)
        self.assertEqual(row.challenge_sha256, hashlib.sha256(self.token.encode()).hexdigest())
        self.assertIsNone(row.csr_sha256)
        row.rewrap_secrets()
        self.assertEqual(json.loads(row.get_csr_config()), CONFIG)

    def test_noop_engine_fails_closed(self):
        secret_engines.load_config({})
        with self.assertRaises(BrokerUnavailable):
            mint_challenge(CONFIG)

    def test_renamed_noop_engine_fails_closed(self):
        secret_engines.load_config({"looks_encrypted": {"backend": secret_engines.noop_engine_backend}})
        with self.assertRaises(BrokerUnavailable):
            mint_challenge(CONFIG)

    def test_exact_retry_allowed_and_altered_transaction_denied(self):
        value = payload(self.token, self.raw)
        authorize_challenge(value)
        authorize_challenge(value)
        self.assert_denied(payload(self.token, self.raw, "transaction-two"))
        row = SCEPChallenge.objects.get()
        self.assertEqual(row.csr_sha256, hashlib.sha256(self.raw).hexdigest())
        self.assertNotEqual(row.transaction_sha256, "transaction-one")

    def test_same_subject_different_public_key_cannot_reuse_challenge(self):
        authorize_challenge(payload(self.token, self.raw))
        another_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.assert_denied(payload(self.token, make_csr(another_key)))

    def test_expired_challenge_denied_including_exact_retry(self):
        authorize_challenge(payload(self.token, self.raw))
        SCEPChallenge.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
        self.assert_denied(payload(self.token, self.raw))

    def test_unknown_challenge_denied(self):
        self.assert_denied(payload("x" * 43, self.raw))

    def test_cleanup_removes_expired_records_only(self):
        expired = SCEPChallenge.objects.get()
        expired.expires_at = timezone.now() - timedelta(seconds=1)
        expired.save(update_fields=["expires_at"])
        mint_challenge(CONFIG)
        output = StringIO()
        with patch("zentral.telemetry.configure"), patch("zentral.telemetry.shutdown"):
            call_command("cleanup_scep_challenges", stdout=output)
        self.assertFalse(SCEPChallenge.objects.filter(pk=expired.pk).exists())
        self.assertEqual(SCEPChallenge.objects.count(), 1)
        self.assertNotIn(self.token, output.getvalue())
        self.assertIn("Deleted 1", output.getvalue())

    def test_mismatched_subject_does_not_consume_challenge(self):
        self.assert_denied(payload(self.token, make_csr(self.key, common_name="another-enrollment")))
        self.assertIsNone(SCEPChallenge.objects.get().csr_sha256)
        authorize_challenge(payload(self.token, self.raw))

    def test_mismatched_or_additional_san_denied(self):
        for sans in ([x509.DNSName("other.example.test")],
                     [x509.DNSName("device.example.test"), x509.DNSName("extra.example.test")],
                     [x509.DNSName("device.example.test"), x509.RFC822Name("private@example.test")],
                     []):
            with self.subTest(sans=len(sans)):
                self.assert_denied(payload(self.token, make_csr(self.key, sans=sans)))

    def test_email_and_upn_match(self):
        config = deepcopy(CONFIG)
        config["subject_alternative_names"] = {
            "email_addresses": ["user@example.test"], "nt_principal_names": ["user@example.test"],
        }
        token = mint_challenge(config)
        raw = make_csr(self.key, sans=[
            x509.RFC822Name("user@example.test"),
            x509.OtherName(ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"), UTF8String("user@example.test").dump()),
        ])
        authorize_challenge(payload(token, raw))

    def test_optional_key_usage_must_match_if_present(self):
        self.assert_denied(payload(self.token, make_csr(self.key, usage=False)))
        authorize_challenge(payload(self.token, make_csr(self.key, usage=None)))

    def test_ca_server_auth_and_unknown_extension_denied(self):
        for extension in (
            x509.BasicConstraints(ca=True, path_length=None),
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            x509.UnrecognizedExtension(ObjectIdentifier("1.2.3.4"), b"private"),
        ):
            with self.subTest(extension=type(extension).__name__):
                self.assert_denied(payload(self.token, make_csr(self.key, extra=[extension])))

    def test_invalid_csr_signature_denied(self):
        altered = self.raw[:-1] + bytes([self.raw[-1] ^ 1])
        self.assert_denied(payload(self.token, altered))

    def test_validly_signed_duplicate_extension_denied(self):
        csr = CertificationRequest.load(self.raw)
        info = csr["certification_request_info"]
        for attribute in info["attributes"]:
            if attribute["type"].native == "extension_request":
                extensions = attribute["values"][0]
                extensions.append(extensions[0])
        csr["signature"] = self.key.sign(info.dump(), padding.PKCS1v15(), hashes.SHA256())
        raw = csr.dump()
        self.assertTrue(x509.load_der_x509_csr(raw).is_signature_valid)
        self.assert_denied(payload(self.token, raw))

    def test_weak_and_non_rsa_keys_denied(self):
        for key in (rsa.generate_private_key(public_exponent=65537, key_size=1024),
                    ec.generate_private_key(ec.SECP256R1())):
            self.assert_denied(payload(self.token, make_csr(key)))

    def test_invalid_csr_encoding_and_oversized_csr_denied(self):
        for raw in ("not-base64", base64.b64encode(b"not-der").decode(), base64.b64encode(b"x" * 16385).decode()):
            value = payload(self.token, self.raw)
            value["x509CertificateRequest"]["raw"] = raw
            self.assert_denied(value)

    def test_invalid_policy_cannot_mint(self):
        for update in ({"key_usage": 1}, {"key_usage": True}, {"subject": {"common_name": ""}},
                       {"subject": {"common_name": "x", "unknown": ["x"]}},
                       {"subject_alternative_names": {"ip_addresses": ["127.0.0.1"]}}):
            config = deepcopy(CONFIG)
            config.update(update)
            with self.assertRaises(InvalidChallenge):
                mint_challenge(config)

    @patch.dict(os.environ, ENV)
    def test_end_to_end_mint_and_signed_callback(self):
        factory = RequestFactory()
        mint = challenge(factory.post("/", json.dumps(CONFIG), content_type="application/json",
                                      HTTP_AUTHORIZATION=f"Bearer {ENV['ZENTRAL_SCEP_BROKER_TOKEN']}"))
        self.assertEqual(mint.status_code, 200)
        token = json.loads(mint.content)["challenge"]
        body = json.dumps(payload(token, self.raw)).encode()
        response = authorize(factory.post("/", body, content_type="application/json",
                                           HTTP_X_SMALLSTEP_SIGNATURE=signature(body),
                                           HTTP_X_SMALLSTEP_WEBHOOK_ID=ENV["ZENTRAL_SCEP_WEBHOOK_ID"]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.content), {"allow": True})
        self.assertEqual(response["Cache-Control"], "no-store")


class SCEPWebhookTests(SimpleTestCase):
    def test_internal_wsgi_starts_with_complete_settings_in_fresh_process(self):
        repository = Path(__file__).resolve().parents[2]
        script = """
import sys
sys.path.insert(0, "server")
import server.scep_wsgi
from django.conf import settings
from django.test import Client
from server import settings as base_settings
assert settings.INSTALLED_APPS == base_settings.INSTALLED_APPS
assert settings.DATABASES == base_settings.DATABASES
assert settings.SECRET_KEY == base_settings.SECRET_KEY
assert settings.ROOT_URLCONF == "server.scep_urls"
assert "django.contrib.auth.middleware.AuthenticationMiddleware" not in settings.MIDDLEWARE
assert Client().get("/healthz/", HTTP_HOST="testserver").status_code == 200
"""
        result = subprocess.run(
            [sys.executable, "-c", script], cwd=repository, capture_output=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    @patch.dict(os.environ, ENV)
    def test_signature_id_and_body_are_bound(self):
        body = json.dumps(payload("x" * 43, b"csr")).encode()
        self.assertEqual(verify_webhook(body, signature(body), ENV["ZENTRAL_SCEP_WEBHOOK_ID"])["provisionerName"],
                         "zentral")
        for raw, sig, webhook_id in (
            (body + b" ", signature(body), ENV["ZENTRAL_SCEP_WEBHOOK_ID"]),
            (body, "bad", ENV["ZENTRAL_SCEP_WEBHOOK_ID"]),
            (body, signature(body), "different"),
            (body, "é", ENV["ZENTRAL_SCEP_WEBHOOK_ID"]),
        ):
            with self.assertRaises(InvalidChallenge):
                verify_webhook(raw, sig, webhook_id)

    @patch.dict(os.environ, ENV)
    def test_timestamp_and_provisioner_validation(self):
        for update in (
            {"timestamp": (datetime.now(dt_timezone.utc) - timedelta(minutes=6)).isoformat()},
            {"timestamp": (datetime.now(dt_timezone.utc) + timedelta(minutes=6)).isoformat()},
            {"timestamp": "2026-10-20T12:00:00"}, {"timestamp": None},
            {"provisionerName": "other"},
        ):
            value = payload("x" * 43, b"csr")
            value.update(update)
            body = json.dumps(value).encode()
            with self.assertRaises(InvalidChallenge):
                verify_webhook(body, signature(body), ENV["ZENTRAL_SCEP_WEBHOOK_ID"])

    def test_missing_webhook_configuration_fails_closed(self):
        with patch.dict(os.environ, {"ZENTRAL_SCEP_WEBHOOK_SECRET": "", "ZENTRAL_SCEP_WEBHOOK_ID": ""}):
            with self.assertRaises(BrokerUnavailable):
                verify_webhook(b"{}", "", "")

    def test_duplicate_json_fields_denied(self):
        with self.assertRaises(InvalidChallenge):
            decode_json(b'{"key_usage":5,"key_usage":1}')

    @patch.dict(os.environ, ENV)
    def test_missing_bearer_and_oversized_payload_denied(self):
        factory = RequestFactory()
        self.assertEqual(challenge(factory.post("/", "{}",
                                               content_type="application/json")).status_code, 403)
        request = factory.post("/", b"x" * 8193, content_type="application/json",
                               HTTP_AUTHORIZATION=f"Bearer {ENV['ZENTRAL_SCEP_BROKER_TOKEN']}")
        self.assertEqual(challenge(request).status_code, 400)
        request = factory.post("/", b"x" * 65537, content_type="application/json")
        self.assertEqual(authorize(request).status_code, 403)

    @override_settings(ROOT_URLCONF="server.scep_urls")
    def test_internal_listener_has_only_health_and_broker_routes(self):
        self.assertEqual(self.client.get("/healthz/").status_code, 200)
        for path in ("/", "/accounts/login/", "/api/mdm/blueprints/", "/public/mdm/scep/"):
            self.assertEqual(self.client.get(path).status_code, 404)

    @override_settings(ROOT_URLCONF="server.urls")
    def test_public_listener_has_no_internal_routes(self):
        for path in ("/internal/mdm/scep/challenges/", "/internal/mdm/scep/authorize/"):
            self.assertEqual(self.client.post(path, "{}",
                                              content_type="application/json").status_code, 404)


class SCEPChallengeConcurrencyTests(SecretEngineMixin, TransactionTestCase):
    def test_only_one_distinct_csr_can_bind_concurrently(self):
        key_one = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_two = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        token = mint_challenge(CONFIG)
        requests = [payload(token, make_csr(key_one)), payload(token, make_csr(key_two))]
        barrier = Barrier(2)

        def submit(value):
            try:
                barrier.wait(timeout=10)
                authorize_challenge(value)
                return True
            except InvalidChallenge:
                return False
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(submit, requests))
        self.assertEqual(sorted(results), [False, True])
        authorize_challenge(requests[results.index(True)])
        with self.assertRaises(InvalidChallenge):
            authorize_challenge(requests[results.index(False)])
