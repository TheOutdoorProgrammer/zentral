import io
import json
from datetime import timedelta, timezone as datetime_timezone
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.utils import timezone

from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit
from zentral.contrib.mdm.management.commands.provision_ota_enrollment import parse_spec, reconcile
from zentral.contrib.mdm.models import Blueprint, OTAEnrollment
from .utils import force_push_certificate, force_scep_issuer


class ProvisionOTAEnrollmentTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name="Pilot test")
        cls.blueprint = Blueprint.objects.create(name="Pilot test")
        cls.push = force_push_certificate()
        cls.issuer = force_scep_issuer()

    def setUp(self):
        expiry = timezone.now().replace(tzinfo=datetime_timezone.utc) + timedelta(hours=2)
        self.raw = {
            "name": "One-time pilot",
            "display_name": "Pilot",
            "blueprint_id": self.blueprint.pk,
            "push_certificate_id": self.push.pk,
            "scep_issuer_id": str(self.issuer.pk),
            "meta_business_unit_id": self.mbu.pk,
            "quota": 1,
            "expires_at": expiry.isoformat(),
        }

    def spec(self):
        return parse_spec(io.StringIO(json.dumps(self.raw)))

    def test_check_creates_nothing(self):
        self.assertEqual(reconcile(self.spec(), False), "would_create")
        self.assertFalse(OTAEnrollment.objects.exists())
        self.assertFalse(EnrollmentSecret.objects.exists())

    def test_create_and_replay_preserve_secret_and_references(self):
        self.assertEqual(reconcile(self.spec(), True), "created")
        enrollment = OTAEnrollment.objects.get()
        secret = enrollment.enrollment_secret
        self.assertEqual(enrollment.blueprint_id, self.blueprint.pk)
        self.assertEqual(enrollment.push_certificate_id, self.push.pk)
        self.assertEqual(enrollment.scep_issuer_id, self.issuer.pk)
        self.assertIsNone(enrollment.realm_id)
        self.assertIsNone(enrollment.acme_issuer_id)
        self.assertEqual(secret.quota, 1)
        self.assertEqual(secret.expired_at, self.spec()["expired_at"])
        self.assertTrue(secret.secret)
        self.assertEqual(reconcile(self.spec(), True), "unchanged")
        self.assertEqual(EnrollmentSecret.objects.get().secret, secret.secret)

    def test_used_revoked_and_expired_are_never_reactivated(self):
        reconcile(self.spec(), True)
        secret = EnrollmentSecret.objects.get()
        for field, value in (
            ("request_count", 1), ("revoked_at", timezone.now()),
        ):
            with self.subTest(field=field):
                setattr(secret, field, value)
                secret.save()
                self.assertEqual(reconcile(self.spec(), True), "unchanged_inactive")
                secret.refresh_from_db()
                self.assertEqual(getattr(secret, field), value)
                setattr(secret, field, 0 if field == "request_count" else None)
                secret.save()
        future = self.spec()["expired_at"] + timedelta(seconds=1)
        with patch("django.utils.timezone.now", return_value=future):
            self.assertEqual(reconcile(self.spec(), True), "unchanged_inactive")

    def test_drift_fails_without_mutation(self):
        reconcile(self.spec(), True)
        self.raw["display_name"] = "Changed"
        with self.assertRaisesMessage(CommandError, "Enrollment drift"):
            reconcile(self.spec(), True)
        self.assertEqual(OTAEnrollment.objects.get().display_name, "Pilot")

    def test_expiry_cannot_be_renewed(self):
        reconcile(self.spec(), True)
        self.raw["expires_at"] = (
            timezone.now().replace(tzinfo=datetime_timezone.utc) + timedelta(hours=3)
        ).isoformat()
        with self.assertRaisesMessage(CommandError, "Enrollment drift"):
            reconcile(self.spec(), True)

    def test_new_expiry_must_be_finite_and_within_24_hours(self):
        for hours in (-1, 25):
            self.raw["expires_at"] = (
                timezone.now().replace(tzinfo=datetime_timezone.utc) + timedelta(hours=hours)
            ).isoformat()
            with self.assertRaisesMessage(CommandError, "within the next 24 hours"):
                reconcile(self.spec(), True)
        self.assertFalse(EnrollmentSecret.objects.exists())

    def test_invalid_spec_does_not_echo_input(self):
        for key, value in (
            ("quota", 0), ("quota", True), ("quota", 2), ("secret", "private-sentinel"),
            ("scep_issuer_id", "private-sentinel"), ("expires_at", "private-sentinel"),
            ("expires_at", "2026-10-20T12:00:00"), ("blueprint_id", True),
        ):
            with self.subTest(key=key, value=value):
                raw = {**self.raw, key: value}
                with self.assertRaisesRegex(CommandError, r"^Invalid nonsecret enrollment specification\.$"):
                    parse_spec(io.StringIO(json.dumps(raw)))
        with self.assertRaises(CommandError):
            parse_spec(io.StringIO('{"quota":1,"quota":1}'))

    def test_create_failure_rolls_back_secret(self):
        with patch.object(OTAEnrollment.objects, "create", side_effect=RuntimeError("private-sentinel")):
            with self.assertRaises(RuntimeError):
                reconcile(self.spec(), True)
        self.assertFalse(EnrollmentSecret.objects.exists())

    def test_command_default_output_and_shutdown(self):
        output = io.StringIO()
        with patch("builtins.open", return_value=io.StringIO(json.dumps(self.raw))), \
                patch("zentral.telemetry.configure"), patch("zentral.telemetry.shutdown") as shutdown:
            call_command("provision_ota_enrollment", "not-a-real-path", stdout=output)
        self.assertEqual(json.loads(output.getvalue()), {"outcome": "would_create"})
        shutdown.assert_called_once()
        self.assertFalse(OTAEnrollment.objects.exists())

    def test_command_failure_is_sanitized_and_flushes(self):
        with patch("builtins.open", side_effect=RuntimeError("private-sentinel")), \
                patch("zentral.telemetry.configure"), patch("zentral.telemetry.shutdown") as shutdown:
            with self.assertRaisesMessage(CommandError, "Enrollment provisioning failed"):
                call_command("provision_ota_enrollment", "private-path")
        shutdown.assert_called_once()

    def test_command_apply_never_prints_secret(self):
        output = io.StringIO()
        with patch("builtins.open", return_value=io.StringIO(json.dumps(self.raw))), \
                patch("zentral.telemetry.configure"), patch("zentral.telemetry.shutdown"):
            call_command("provision_ota_enrollment", "not-a-real-path", apply=True, stdout=output)
        self.assertEqual(json.loads(output.getvalue()), {"outcome": "created"})
        self.assertNotIn(EnrollmentSecret.objects.get().secret, output.getvalue())

    def test_missing_dependency_creates_nothing(self):
        self.raw["blueprint_id"] = self.blueprint.pk + 100
        with patch("builtins.open", return_value=io.StringIO(json.dumps(self.raw))), \
                patch("zentral.telemetry.configure"), patch("zentral.telemetry.shutdown"):
            with self.assertRaisesMessage(CommandError, "An enrollment dependency does not exist."):
                call_command("provision_ota_enrollment", "not-a-real-path", apply=True)
        self.assertFalse(EnrollmentSecret.objects.exists())
