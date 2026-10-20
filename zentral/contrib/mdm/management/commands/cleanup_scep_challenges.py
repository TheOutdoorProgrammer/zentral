from django.core.management.base import BaseCommand
from django.utils import timezone

from zentral import telemetry
from zentral.contrib.mdm.models import SCEPChallenge


class Command(BaseCommand):
    help = "Delete expired SCEP challenge metadata. Run hourly."

    def handle(self, *args, **options):
        telemetry.configure()
        try:
            with telemetry.operation("job.run"):
                expired = SCEPChallenge.objects.filter(expires_at__lte=timezone.now())
                count = 0
                while True:
                    ids = list(expired.values_list("pk", flat=True)[:1000])
                    if not ids:
                        break
                    deleted, _ = SCEPChallenge.objects.filter(pk__in=ids).delete()
                    count += deleted
                telemetry.event("job.run", "success")
                self.stdout.write(f"Deleted {count} expired SCEP challenges.")
        finally:
            telemetry.shutdown()
