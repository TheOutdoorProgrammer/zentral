import uuid

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("mdm", "0110_deviceartifact_force_install_requested_at_and_more")]

    operations = [
        migrations.CreateModel(
            name="SCEPChallenge",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("challenge_sha256", models.CharField(max_length=64, unique=True)),
                ("csr_config", models.TextField()),
                ("expires_at", models.DateTimeField(db_index=True)),
                ("csr_sha256", models.CharField(max_length=64, null=True)),
                ("transaction_sha256", models.CharField(max_length=64, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]
