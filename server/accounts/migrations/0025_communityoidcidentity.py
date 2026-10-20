from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0024_alter_oidcapitokenissuer_cel_condition"),
    ]

    operations = [
        migrations.CreateModel(
            name="CommunityOIDCIdentity",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("issuer", models.CharField(max_length=512)),
                ("subject", models.CharField(max_length=255)),
                ("user", models.OneToOneField(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="community_oidc_identity",
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                "constraints": [
                    models.UniqueConstraint(fields=("issuer", "subject"), name="community_oidc_issuer_subject"),
                ],
            },
        ),
    ]
