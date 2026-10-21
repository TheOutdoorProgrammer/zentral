from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [("mdm", "0112_depenrollment_do_not_use_profile_from_backup")]

    operations = [
        migrations.CreateModel(
            name="FamilySetupAccess",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("audience", models.CharField(choices=[("adult", "Adult"), ("child", "Child")], max_length=8)),
                ("token_digest", models.CharField(max_length=64, unique=True)),
                ("enrollment_fingerprint", models.CharField(max_length=64)),
                ("expires_at", models.DateTimeField()),
                ("revoked_at", models.DateTimeField(null=True)),
                ("completed_steps", models.JSONField(default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("enrolled_device", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE,
                                                         to="mdm.enrolleddevice")),
                ("blueprint", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="mdm.blueprint")),
                ("artifact", models.OneToOneField(null=True, on_delete=django.db.models.deletion.PROTECT,
                                                  to="mdm.artifact")),
                ("tag", models.OneToOneField(null=True, on_delete=django.db.models.deletion.PROTECT,
                                            to="inventory.tag")),
            ],
        ),
    ]
