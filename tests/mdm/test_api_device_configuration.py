from datetime import datetime

from accounts.models import APIToken, User
from django.contrib.auth.models import Group
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from pbac.engine import engine

from tests.zentral_test_utils.login_case import LoginCase

from zentral.contrib.inventory.models import MachineTag, MetaBusinessUnit, Tag
from zentral.contrib.mdm.models import (
    Artifact, ArtifactVersion, ArtifactVersionTag, BlueprintArtifact,
    BlueprintArtifactTag, Channel, Declaration, DeviceCommand, Platform, Profile,
)

from .utils import force_artifact, force_blueprint, force_dep_enrollment_session


class DeviceConfigurationTargetTests(TestCase, LoginCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create(username="configuration-lookup-test", is_superuser=True, is_service_account=True)
        cls.group = Group.objects.create(name="configuration-lookup-test")
        cls.user.groups.add(cls.group)
        _, cls.token = APIToken.objects.create_for_user(cls.user)
        cls.mbu = MetaBusinessUnit.objects.create(name="lookup-test")
        session, _, _ = force_dep_enrollment_session(cls.mbu, completed=True)
        cls.device = session.enrolled_device
        cls.device.blueprint = force_blueprint()
        cls.device.os_version = "14.0"
        cls.device.save()
        cls.tag = Tag.objects.create(name="exclusive-configuration-test")
        MachineTag.objects.create(serial_number=cls.device.serial_number, tag=cls.tag)
        cls.app = Artifact.objects.create(name="Exact App", type=Artifact.Type.ENTERPRISE_APP,
                                          channel=Channel.DEVICE, platforms=[Platform.MACOS])
        cls.app_version = ArtifactVersion.objects.create(artifact=cls.app, version=1, macos=True)
        cls.profile, versions = force_artifact(requires=cls.app)
        cls.version = versions[0]
        cls.version.default_shard = 0
        cls.version.save()
        ArtifactVersionTag.objects.create(artifact_version=cls.version, tag=cls.tag, shard=100)
        cls.attachment = BlueprintArtifact.objects.create(
            blueprint=cls.device.blueprint, artifact=cls.profile, macos=True, default_shard=0,
        )
        BlueprintArtifactTag.objects.create(blueprint_artifact=cls.attachment, tag=cls.tag, shard=100)

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "mdm_api"

    def setUp(self):
        from zentral.contrib.mdm.api_views.device_configuration import DeviceConfigurationTarget
        self.set_policy("\n".join(
            f'permit (principal in Role::"{self.group.pk}", action == {engine.legacy_perm_actions[permission]}, resource);'
            for permission in DeviceConfigurationTarget.permission_required
        ))

    def get_target(self, *, serial=None, app_name=None, token=True):
        headers = {"HTTP_AUTHORIZATION": f"Token {self.token}"} if token else {}
        return self.client.get(reverse("mdm_api:device_configuration_target"), {
            "serial_number": serial or self.device.serial_number,
            "app_name": app_name or self.app.name,
        }, **headers)

    def test_authentication_required(self):
        self.assertEqual(self.get_target(token=False).status_code, 401)

    def test_permissions_required(self):
        self.set_permissions()
        self.user.is_superuser = False
        self.user.save()
        self.assertEqual(self.get_target().status_code, 403)

    def test_exact_metadata_without_profile_source_or_mutation(self):
        Profile.objects.filter(artifact_version=self.version).update(source=b"private-test-source")
        commands = DeviceCommand.objects.count()
        with CaptureQueriesContext(connection) as queries:
            response = self.get_target()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            "found": True, "app_eligible": True, "artifact_id": str(self.profile.pk),
            "attachment_id": self.attachment.pk, "tag_id": self.tag.pk,
        })
        self.assertNotIn("private-test-source", response.content.decode())
        self.assertFalse(any('"mdm_profile"' in query["sql"] for query in queries))
        self.assertFalse(any('"mdm_enterpriseapp"' in query["sql"] for query in queries))
        self.assertEqual(DeviceCommand.objects.count(), commands)

    def test_disabled_attachment_can_be_discovered(self):
        self.attachment.item_tags.all().delete()
        self.assertEqual(self.get_target().json()["attachment_id"], self.attachment.pk)

    def test_detached_configuration_can_be_discovered(self):
        self.attachment.delete()
        result = self.get_target().json()
        self.assertTrue(result["found"])
        self.assertIsNone(result["attachment_id"])

    def test_other_blueprint_attachment_is_not_adopted(self):
        self.attachment.blueprint = force_blueprint()
        self.attachment.save()
        result = self.get_target().json()
        self.assertTrue(result["found"])
        self.assertIsNone(result["attachment_id"])

    def test_shared_tag_is_rejected(self):
        MachineTag.objects.create(serial_number="another-device", tag=self.tag)
        response = self.get_target()
        self.assertEqual(response.status_code, 400)
        self.assertNotIn(self.device.serial_number, response.content.decode())

    def test_broad_version_is_rejected(self):
        self.version.default_shard = 100
        self.version.save()
        self.assertEqual(self.get_target().status_code, 400)

    def test_broad_historical_version_is_rejected(self):
        ArtifactVersion.objects.create(artifact=self.profile, version=0, macos=True)
        self.assertEqual(self.get_target().status_code, 400)

    def test_historical_version_targeting_another_device_is_rejected(self):
        other_tag = Tag.objects.create(name="another-exclusive-tag")
        MachineTag.objects.create(serial_number="another-device", tag=other_tag)
        other_version = ArtifactVersion.objects.create(artifact=self.profile, version=0, macos=True,
                                                       default_shard=0)
        ArtifactVersionTag.objects.create(artifact_version=other_version, tag=other_tag, shard=100)
        self.assertEqual(self.get_target().status_code, 400)

    def test_inactive_historical_version_is_preserved(self):
        ArtifactVersion.objects.create(artifact=self.profile, version=0, macos=True, default_shard=0)
        self.assertTrue(self.get_target().json()["found"])

    def test_broad_attachment_is_rejected(self):
        self.attachment.default_shard = 100
        self.attachment.save()
        self.assertEqual(self.get_target().status_code, 400)

    def test_multiple_configurations_are_rejected(self):
        _, versions = force_artifact(requires=self.app)
        version = versions[0]
        version.default_shard = 0
        version.save()
        ArtifactVersionTag.objects.create(artifact_version=version, tag=self.tag, shard=100)
        self.assertEqual(self.get_target().status_code, 400)

    def test_duplicate_active_serial_is_rejected(self):
        force_dep_enrollment_session(self.mbu, completed=True, serial_number=self.device.serial_number)
        self.assertEqual(self.get_target().status_code, 400)

    def test_checked_out_and_blocked_history_is_excluded(self):
        for field in ("checkout_at", "blocked_at"):
            session, _, _ = force_dep_enrollment_session(self.mbu, completed=True,
                                                        serial_number=self.device.serial_number)
            setattr(session.enrolled_device, field, datetime(2026, 1, 1))
            session.enrolled_device.save()
        self.assertTrue(self.get_target().json()["found"])

    def test_missing_device_or_app_returns_no_identity(self):
        for kwargs in ({"serial": "different-full-serial"}, {"app_name": "Exact App suffix"}):
            with self.subTest(kwargs=kwargs):
                response = self.get_target(**kwargs)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json(), {"found": False, "app_eligible": False,
                                                   "artifact_id": None, "attachment_id": None, "tag_id": None})

    def test_app_eligibility_does_not_require_blueprint_assignment(self):
        self.assertFalse(BlueprintArtifact.objects.filter(artifact=self.app).exists())
        self.assertTrue(self.get_target().json()["app_eligible"])
        self.app_version.default_shard = 0
        self.app_version.save()
        self.assertFalse(self.get_target().json()["app_eligible"])
        ArtifactVersionTag.objects.create(artifact_version=self.app_version, tag=self.tag, shard=100)
        self.assertTrue(self.get_target().json()["app_eligible"])

    def test_managed_app_declaration_eligibility_without_loading_payload(self):
        self.app.type = Artifact.Type.CONFIGURATION
        self.app.save()
        Declaration.objects.create(
            artifact_version=self.app_version, type="com.apple.configuration.app.managed",
            identifier="test-managed-app", server_token="test-managed-app-token",
            payload={"ManifestURL": "https://private-test.example/app.plist"},
        )
        with CaptureQueriesContext(connection) as queries:
            response = self.get_target()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["app_eligible"])
        self.assertTrue(response.json()["found"])
        self.assertFalse(any('"mdm_declaration"' in query["sql"] for query in queries))
        self.assertNotIn("private-test.example", response.content.decode())

    def test_artifact_name_and_blueprint_attachment_are_unique(self):
        self.assertTrue(Artifact._meta.get_field("name").unique)
        self.assertIn(("blueprint", "artifact"), BlueprintArtifact._meta.unique_together)

    def test_native_platform_os_and_excluded_tags_are_respected(self):
        self.app_version.macos_min_version = "15"
        self.app_version.save()
        self.assertFalse(self.get_target().json()["app_eligible"])
        self.app_version.macos_min_version = ""
        self.app_version.save()
        self.app_version.excluded_tags.add(self.tag)
        self.assertFalse(self.get_target().json()["app_eligible"])
        self.app.platforms = [Platform.IOS]
        self.app.save()
        self.assertFalse(self.get_target().json()["app_eligible"])

    def test_read_only_endpoint(self):
        response = self.client.post(reverse("mdm_api:device_configuration_target"), {},
                                    HTTP_AUTHORIZATION=f"Token {self.token}")
        self.assertEqual(response.status_code, 405)
