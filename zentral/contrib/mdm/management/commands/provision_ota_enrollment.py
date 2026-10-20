import json
from datetime import datetime, timedelta
from uuid import UUID

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from zentral import telemetry
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit
from zentral.contrib.mdm.models import Blueprint, OTAEnrollment, PushCertificate, SCEPIssuer


FIELDS = frozenset((
    "name", "display_name", "blueprint_id", "push_certificate_id",
    "scep_issuer_id", "meta_business_unit_id", "quota", "expires_at",
))


def parse_spec(stream):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    try:
        spec = json.load(stream, object_pairs_hook=unique_pairs)
        if not isinstance(spec, dict) or set(spec) != FIELDS:
            raise ValueError
        for key, maximum in (("name", 256), ("display_name", 128)):
            if not isinstance(spec[key], str) or not spec[key].strip() or len(spec[key]) > maximum:
                raise ValueError
        for key in ("blueprint_id", "push_certificate_id", "meta_business_unit_id"):
            if type(spec[key]) is not int or spec[key] <= 0:
                raise ValueError
        if type(spec["quota"]) is not int or spec["quota"] != 1:
            raise ValueError
        spec["scep_issuer_id"] = UUID(spec["scep_issuer_id"])
        expiry = datetime.fromisoformat(spec.pop("expires_at").replace("Z", "+00:00"))
        if expiry.utcoffset() != timedelta(0):
            raise ValueError
        spec["expired_at"] = expiry if settings.USE_TZ else timezone.make_naive(expiry)
    except (ValueError, TypeError, AttributeError, OverflowError):
        raise CommandError("Invalid nonsecret enrollment specification.") from None
    return spec


def reconcile(spec, apply):
    with transaction.atomic():
        # Serialize creations against an existing row, including concurrent first runs.
        Blueprint.objects.select_for_update().get(pk=spec["blueprint_id"])
        PushCertificate.objects.get(pk=spec["push_certificate_id"])
        SCEPIssuer.objects.get(pk=spec["scep_issuer_id"])
        MetaBusinessUnit.objects.get(pk=spec["meta_business_unit_id"])
        enrollment = OTAEnrollment.objects.select_for_update().filter(name=spec["name"]).first()
        enrollment_fields = {key: spec[key] for key in (
            "name", "display_name", "blueprint_id", "push_certificate_id", "scep_issuer_id",
        )}
        secret_fields = {key: spec[key] for key in ("meta_business_unit_id", "quota", "expired_at")}
        if enrollment:
            secret = EnrollmentSecret.objects.select_for_update().get(pk=enrollment.enrollment_secret_id)
            matches = all(getattr(enrollment, key) == value for key, value in enrollment_fields.items())
            matches &= all(getattr(secret, key) == value for key, value in secret_fields.items())
            matches &= not (enrollment.realm_id or enrollment.acme_issuer_id
                            or secret.serial_numbers or secret.udids or secret.tags.exists())
            if not matches:
                raise CommandError("Enrollment drift detected; existing enrollment was not changed.")
            return "unchanged" if secret.is_valid()[0] else "unchanged_inactive"
        now = timezone.now()
        if not now < spec["expired_at"] <= now + timedelta(hours=24):
            raise CommandError("New enrollment expiry must be within the next 24 hours.")
        if not apply:
            return "would_create"
        secret = EnrollmentSecret.objects.create(**secret_fields)
        OTAEnrollment.objects.create(enrollment_secret=secret, **enrollment_fields)
        return "created"


class Command(BaseCommand):
    help = "Check or create one finite, single-use OTA enrollment from a nonsecret JSON specification."

    def add_arguments(self, parser):
        parser.add_argument("specification")
        parser.add_argument("--apply", action="store_true")

    def handle(self, *args, **options):
        telemetry.configure()
        try:
            with telemetry.operation("job.run") as span:
                span.update_name("mdm.ota.provision")
                try:
                    with open(options["specification"]) as stream:
                        spec = parse_spec(stream)
                    outcome = reconcile(spec, options["apply"])
                except (Blueprint.DoesNotExist, PushCertificate.DoesNotExist,
                        SCEPIssuer.DoesNotExist, MetaBusinessUnit.DoesNotExist):
                    raise CommandError("An enrollment dependency does not exist.") from None
                except OSError:
                    raise CommandError("Cannot read enrollment specification.") from None
                telemetry.event("job.run")
                self.stdout.write(json.dumps({"outcome": outcome}))
        except CommandError:
            raise
        except Exception:
            raise CommandError("Enrollment provisioning failed; no changes were committed.") from None
        finally:
            telemetry.shutdown()
