from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mdm', '0111_scepchallenge'),
    ]

    operations = [
        migrations.AddField(
            model_name='depenrollment',
            name='do_not_use_profile_from_backup',
            field=models.BooleanField(
                default=False,
                db_default=False,
                verbose_name='Fetch current enrollment profile during restore',
                help_text="On iOS 26.x and visionOS 26.x, fetch the current enrollment profile instead of "
                          "using the backup's profile. On version 26.4 or later, also remove restored configuration "
                          "profiles; the MDM service must deliver the current configurations again.",
            ),
        ),
    ]
