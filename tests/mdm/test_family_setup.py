import json
import plistlib
import secrets
import uuid
from datetime import timedelta
from unittest.mock import patch

from accounts.models import User
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from zentral.contrib.inventory.models import MachineTag
from zentral.contrib.mdm.artifacts import Target, update_blueprint_serialized_artifacts
from zentral.contrib.mdm.family_setup import COOKIE, COOKIE_PATH, active_access, digest_token, enrollment_fingerprint
from zentral.contrib.mdm.family_setup_admin import provision
from zentral.contrib.mdm.models import BlueprintArtifact, DeviceArtifact, EnrolledDevice, FamilySetupAccess, Platform

from .utils import force_blueprint, force_blueprint_artifact, force_push_certificate


@override_settings(AUTHENTICATION_BACKENDS=["accounts.auth_backends.ZentralBackend"])
class FamilySetupTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.blueprint = force_blueprint()
        cls.push_certificate = force_push_certificate()

    def setUp(self):
        self.profile_secret = secrets.token_urlsafe(24)
        self.device, self.access, self.token = self.make_access()
        self.client.cookies[COOKIE] = self.token

    def make_access(self, audience=FamilySetupAccess.Audience.CHILD):
        device = EnrolledDevice.objects.create(
            name="Test iPhone", udid=str(uuid.uuid4()), serial_number=uuid.uuid4().hex,
            platform=Platform.IOS, os_version="26.0", supervised=True, dep_enrollment=True,
            blueprint=self.blueprint, push_certificate=self.push_certificate,
            cert_fingerprint=secrets.token_bytes(32),
        )
        token = secrets.token_urlsafe(32)
        access = FamilySetupAccess.objects.create(
            enrolled_device=device, blueprint=self.blueprint, audience=audience,
            token_digest=digest_token(token), expires_at=timezone.now() + timedelta(days=180),
            enrollment_fingerprint=enrollment_fingerprint(device),
        )
        return device, access, token

    def url(self, endpoint):
        return reverse("mdm_public:family_setup" + ("_" + endpoint if endpoint != "index" else ""))

    def post(self, endpoint, data, client=None, **kwargs):
        return (client or self.client).post(self.url(endpoint), json.dumps(data),
                                            content_type="application/json", secure=True, **kwargs)

    def get_status(self, client=None):
        return (client or self.client).get(self.url("status"), secure=True)

    def assert_private(self, response):
        directives = {value.strip() for value in response["Cache-Control"].split(",")}
        self.assertTrue({"no-store", "private"}.issubset(directives))
        self.assertEqual(response["Referrer-Policy"], "no-referrer")
        self.assertEqual(response["X-Robots-Tag"], "noindex, nofollow")
        self.assertIn("Cookie", response["Vary"])

    def make_profile(self, payload_type="com.apple.wifi.managed", version_count=1, blueprint=None):
        attachment, artifact, versions = force_blueprint_artifact(
            blueprint=blueprint or self.blueprint, platforms=[Platform.IOS], version_count=version_count,
        )
        for version in versions:
            version.ios = True
            version.save()
            profile = version.profile
            source = plistlib.loads(profile.source)
            source["PayloadContent"] = [{"PayloadType": payload_type, "Password": self.profile_secret}]
            profile.source = plistlib.dumps(source)
            profile.save()
        update_blueprint_serialized_artifacts(attachment.blueprint)
        return attachment, artifact, versions

    def checks_by_id(self):
        response = self.get_status()
        self.assertEqual(response.status_code, 200)
        return {item["id"]: item for item in response.json()["checks"]}

    def test_page_is_public_sets_csrf_and_contains_no_device_identity(self):
        self.client.cookies.clear()
        response = self.client.get(self.url("index"), secure=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("csrftoken", response.cookies)
        self.assert_private(response)
        for value in (self.token, self.device.serial_number, self.device.udid, self.device.name):
            self.assertNotContains(response, value)

    def test_post_endpoints_require_csrf_even_with_valid_capability(self):
        client = Client(enforce_csrf_checks=True)
        client.cookies[COOKIE] = self.token
        for endpoint, data in (("activate", {"token": self.token}),
                               ("step", {"step": "wifi", "done": True}), ("forget", {})):
            with self.subTest(endpoint=endpoint):
                response = self.post(endpoint, data, client=client)
                self.assertEqual(response.status_code, 403)
        self.access.refresh_from_db()
        self.assertEqual(self.access.completed_steps, {})

    def test_activate_with_csrf_sets_private_cookie_without_echoing_token(self):
        client = Client(enforce_csrf_checks=True)
        client.get(self.url("index"), secure=True)
        response = self.post("activate", {"token": self.token}, client=client,
                             HTTP_X_CSRFTOKEN=client.cookies["csrftoken"].value,
                             HTTP_ORIGIN="https://testserver")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"paired": True})
        cookie = response.cookies[COOKIE]
        self.assertEqual(cookie.value, self.token)
        self.assertTrue(cookie["secure"])
        self.assertTrue(cookie["httponly"])
        self.assertEqual(cookie["samesite"], "Strict")
        self.assertEqual(cookie["path"], COOKIE_PATH)
        self.assertLessEqual(int(cookie["max-age"]), 30 * 86400)
        self.assert_private(response)

    def test_cookie_lifetime_does_not_exceed_access_expiry(self):
        self.access.expires_at = timezone.now() + timedelta(minutes=5)
        self.access.save()
        response = self.post("activate", {"token": self.token})
        self.assertGreater(int(response.cookies[COOKIE]["max-age"]), 0)
        self.assertLessEqual(int(response.cookies[COOKIE]["max-age"]), 300)

    def test_missing_unknown_and_malformed_tokens_are_denied(self):
        for token in (None, "", secrets.token_urlsafe(32), "a" * 42, "a" * 44, "é" * 43,
                      "a" * 42 + "\n", 123, [self.token]):
            with self.subTest(token_type=type(token).__name__):
                response = self.post("activate", {"token": token})
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.cookies[COOKIE]["max-age"], 0)
                self.assert_private(response)
        self.client.cookies.clear()
        self.assertEqual(self.get_status().status_code, 401)

    def test_invalid_new_link_cannot_fall_back_to_a_previous_device(self):
        self.assertEqual(self.post("activate", {"token": self.token}).status_code, 200)
        self.assertEqual(self.get_status().status_code, 200)
        self.assertEqual(self.post("activate", {"token": secrets.token_urlsafe(32)}).status_code, 401)
        self.assertEqual(self.get_status().status_code, 401)

    def test_expired_and_revoked_access_denies_activation_status_and_updates(self):
        for field, value in (("expires_at", timezone.now() - timedelta(seconds=1)),
                             ("revoked_at", timezone.now())):
            with self.subTest(field=field):
                original = getattr(self.access, field)
                setattr(self.access, field, value)
                self.access.save()
                self.assertEqual(self.post("activate", {"token": self.token}).status_code, 401)
                self.assertEqual(self.get_status().status_code, 401)
                self.assertEqual(self.post("step", {"step": "wifi", "done": True}).status_code, 401)
                setattr(self.access, field, original)
                self.access.save()

    def test_device_eligibility_is_rechecked_on_every_request(self):
        mutations = (("blocked_at", timezone.now()), ("checkout_at", timezone.now()),
                     ("supervised", False), ("dep_enrollment", False), ("platform", Platform.MACOS),
                     ("blueprint", force_blueprint()), ("blueprint", None))
        for field, value in mutations:
            with self.subTest(field=field, value=str(value)):
                original = getattr(self.device, field)
                setattr(self.device, field, value)
                self.device.save()
                self.assertEqual(self.post("activate", {"token": self.token}).status_code, 401)
                self.assertEqual(self.get_status().status_code, 401)
                self.assertEqual(self.post("step", {"step": "wifi", "done": True}).status_code, 401)
                setattr(self.device, field, original)
                self.device.save()

    def test_ipad_is_eligible(self):
        self.device.platform = Platform.IPADOS
        self.device.save()
        self.assertEqual(self.get_status().status_code, 200)

    def test_reenrollment_invalidates_old_capability_until_admin_renews(self):
        self.access.completed_steps = {"wifi": True, "family": True}
        self.access.save()
        self.device.cert_fingerprint = secrets.token_bytes(32)
        self.device.save()
        self.assertEqual(self.get_status().status_code, 401)
        self.assertEqual(self.post("activate", {"token": self.token}).status_code, 401)
        self.assertEqual(self.post("step", {"step": "wifi", "done": True}).status_code, 401)
        renewed = provision(self.device, FamilySetupAccess.Audience.CHILD)
        source = plistlib.loads(renewed.artifact.artifactversion_set.get().profile.source)
        new_token = source["PayloadContent"][0]["URL"].split("#token=", 1)[1]
        self.assertIsNone(active_access(self.token))
        self.assertIsNotNone(active_access(new_token))
        self.assertEqual(renewed.completed_steps, {})

    def test_changing_audience_resets_previously_confirmed_steps(self):
        access = provision(self.device, FamilySetupAccess.Audience.CHILD)
        access.completed_steps = {"wifi": True, "family": True}
        access.save()
        renewed = provision(self.device, FamilySetupAccess.Audience.ADULT)
        self.assertEqual(renewed.audience, FamilySetupAccess.Audience.ADULT)
        self.assertEqual(renewed.completed_steps, {})

    def test_client_device_identifier_cannot_change_capability_scope(self):
        other, other_access, _ = self.make_access()
        other.name = "Another device"
        other.save()
        response = self.client.get(self.url("status"), {"device_id": other.pk, "udid": other.udid}, secure=True)
        self.assertEqual(response.json()["device_name"], self.device.name)
        response = self.post("step", {"step": "wifi", "done": True, "device_id": other.pk,
                                     "access_id": other_access.pk, "udid": other.udid})
        self.assertEqual(response.status_code, 200)
        other_access.refresh_from_db()
        self.access.refresh_from_db()
        self.assertEqual(other_access.completed_steps, {})
        self.assertEqual(self.access.completed_steps, {"wifi": True})

    def test_progress_persists_and_can_be_unchecked(self):
        for done in (True, False):
            self.assertEqual(self.post("step", {"step": "wifi", "done": done}).status_code, 200)
            client = Client()
            client.cookies[COOKIE] = self.token
            steps = {item["id"]: item for item in self.get_status(client).json()["steps"]}
            self.assertIs(steps["wifi"]["done"], done)
            self.access.refresh_from_db()
            self.assertIs(self.access.completed_steps["wifi"], done)

    def test_progress_rejects_unknown_steps_and_non_boolean_values(self):
        invalid = [{"step": "wifi", "done": value} for value in (0, 1, "true", "false", None, [], {})]
        invalid.extend([{"step": "unknown", "done": True}, {"step": "shortcuts", "done": True},
                        {"step": ["wifi"], "done": True}, {"done": True}, {"step": "wifi"}])
        for data in invalid:
            with self.subTest(data=data):
                self.assertEqual(self.post("step", data).status_code, 400)
        self.access.refresh_from_db()
        self.assertEqual(self.access.completed_steps, {})

    def test_adult_cannot_complete_child_only_step(self):
        self.access.audience = FamilySetupAccess.Audience.ADULT
        self.access.save()
        self.assertNotIn("family", {step["id"] for step in self.get_status().json()["steps"]})
        self.assertEqual(self.post("step", {"step": "family", "done": True}).status_code, 400)

    def test_child_can_complete_parent_assisted_family_step(self):
        response = self.post("step", {"step": "family", "done": True})
        self.assertEqual(response.status_code, 200)
        self.access.refresh_from_db()
        self.assertEqual(self.access.completed_steps, {"family": True})

    def test_malformed_oversize_and_non_json_requests_are_rejected(self):
        for body, content_type in (("{", "application/json"), ("[]", "application/json"),
                                   ("null", "application/json"), ("{}", "text/plain"),
                                   (json.dumps({"step": "wifi", "done": True, "extra": "x" * 2048}),
                                    "application/json")):
            with self.subTest(content_type=content_type, length=len(body)):
                response = self.client.post(self.url("step"), body, content_type=content_type, secure=True)
                self.assertEqual(response.status_code, 400)

    def test_forget_removes_only_browser_cookie(self):
        response = self.post("forget", {})
        self.assertEqual(response.status_code, 200)
        cookie = response.cookies[COOKIE]
        self.assertEqual(cookie["path"], COOKIE_PATH)
        self.assertEqual(cookie["max-age"], 0)
        self.assertTrue(cookie["secure"])
        self.assertEqual(cookie["samesite"], "Strict")
        self.assertEqual(self.get_status().status_code, 401)
        self.access.refresh_from_db()
        self.assertIsNone(self.access.revoked_at)

    def test_status_is_private_and_excludes_device_and_profile_secrets(self):
        _, artifact, versions = self.make_profile()
        DeviceArtifact.objects.create(enrolled_device=self.device, artifact_version=versions[0],
                                      status=DeviceArtifact.Status.FAILED,
                                      extra_info={"error": "private-device-error"})
        response = self.get_status()
        self.assert_private(response)
        for value in (self.device.udid, self.device.serial_number, self.token, self.access.token_digest,
                      self.profile_secret, "private-device-error", versions[0].profile.payload_identifier):
            self.assertNotContains(response, value)
        self.assertEqual(response.json()["device_name"], self.device.name)
        self.assertIn(str(artifact.pk), {item["id"] for item in response.json()["checks"]})

    def test_only_confirmed_installed_status_is_shown_as_installed(self):
        _, artifact, versions = self.make_profile()
        report = DeviceArtifact.objects.create(enrolled_device=self.device, artifact_version=versions[0])
        for native, public in ((DeviceArtifact.Status.ACKNOWLEDGED, "pending"),
                               (DeviceArtifact.Status.AWAITING_CONFIRMATION, "pending"),
                               (DeviceArtifact.Status.INSTALLED, "installed"),
                               (DeviceArtifact.Status.FAILED, "failed"),
                               (DeviceArtifact.Status.REMOVAL_FAILED, "failed"),
                               (DeviceArtifact.Status.UNINSTALLED, "pending")):
            with self.subTest(native=native):
                report.status = native
                report.save()
                self.assertEqual(self.checks_by_id()[str(artifact.pk)]["status"], public)

    def test_latest_failed_revision_is_not_hidden_by_old_installed_revision(self):
        _, artifact, versions = self.make_profile(version_count=2)
        latest, older = versions
        DeviceArtifact.objects.create(enrolled_device=self.device, artifact_version=older,
                                      status=DeviceArtifact.Status.INSTALLED)
        DeviceArtifact.objects.create(enrolled_device=self.device, artifact_version=latest,
                                      status=DeviceArtifact.Status.FAILED)
        self.assertEqual(self.checks_by_id()[str(artifact.pk)]["status"], "failed")

    def test_out_of_scope_artifacts_and_another_device_reports_are_excluded(self):
        _, own_artifact, versions = self.make_profile()
        _, foreign_artifact, foreign_versions = self.make_profile(blueprint=force_blueprint())
        DeviceArtifact.objects.create(enrolled_device=self.device, artifact_version=foreign_versions[0],
                                      status=DeviceArtifact.Status.INSTALLED)
        other, _, _ = self.make_access()
        DeviceArtifact.objects.create(enrolled_device=other, artifact_version=versions[0],
                                      status=DeviceArtifact.Status.INSTALLED)
        checks = self.checks_by_id()
        self.assertNotIn(str(foreign_artifact.pk), checks)
        self.assertEqual(checks[str(own_artifact.pk)]["status"], "pending")

    def test_zero_shard_artifact_is_not_in_scope_even_when_previously_installed(self):
        attachment, artifact, versions = self.make_profile()
        attachment.default_shard = 0
        attachment.save()
        update_blueprint_serialized_artifacts(self.blueprint)
        DeviceArtifact.objects.create(enrolled_device=self.device, artifact_version=versions[0],
                                      status=DeviceArtifact.Status.INSTALLED)
        self.assertNotIn(str(artifact.pk), self.checks_by_id())

    def test_missing_vpn_is_visible_until_an_eligible_profile_exists(self):
        self.assertEqual(self.checks_by_id()["vpn"]["status"], "not_configured")
        _, artifact, _ = self.make_profile(payload_type="com.apple.vpn.managed")
        checks = self.checks_by_id()
        self.assertNotIn("vpn", checks)
        self.assertEqual(checks[str(artifact.pk)]["status"], "pending")

    def test_setup_webclip_does_not_appear_in_managed_checks(self):
        _, artifact, _ = self.make_profile(payload_type="com.apple.webClip.managed")
        self.access.artifact = artifact
        self.access.save()
        self.assertNotIn(str(artifact.pk), self.checks_by_id())

    def test_adult_does_not_require_child_web_protection(self):
        self.assertIn("web", self.checks_by_id())
        self.access.audience = FamilySetupAccess.Audience.ADULT
        self.access.save()
        self.assertNotIn("web", self.checks_by_id())

    def test_shortcut_links_accept_only_exact_icloud_share_urls(self):
        valid = "https://www.icloud.com/shortcuts/" + "a" * 32
        invalid = ["http://www.icloud.com/shortcuts/" + "a" * 32,
                   valid + "?token=private", valid + "#fragment", valid + "/",
                   valid.replace("www.icloud.com", "www.icloud.com.evil.example"),
                   valid.replace("www.icloud.com", "evil.example@www.icloud.com"),
                   "javascript:alert(1)", "/shortcuts/" + "a" * 32]
        config = {"shortcuts": [{"title": "Safe shortcut", "url": valid}]
                  + [{"title": "Unsafe", "url": url} for url in invalid]
                  + [None, {"title": 12, "url": valid}]}
        with patch("zentral.contrib.mdm.family_setup.zentral_settings.get", return_value=config):
            response = self.get_status()
            self.assertEqual(response.json()["shortcuts"], [{"title": "Safe shortcut", "url": valid}])
            self.assertIn("shortcuts", {step["id"] for step in response.json()["steps"]})
            self.assertEqual(self.post("step", {"step": "shortcuts", "done": True}).status_code, 200)

    def test_http_method_restrictions(self):
        for endpoint in ("activate", "step", "forget"):
            with self.subTest(endpoint=endpoint):
                self.assertEqual(self.client.get(self.url(endpoint), secure=True).status_code, 405)
        self.assertEqual(self.post("status", {}).status_code, 405)

    def test_provision_scopes_private_profile_to_exactly_one_device(self):
        other, _, _ = self.make_access()
        access = provision(self.device, FamilySetupAccess.Audience.CHILD)
        version = access.artifact.artifactversion_set.get()
        profile = plistlib.loads(version.profile.source)
        url = profile["PayloadContent"][0]["URL"]
        token = url.split("#token=", 1)[1]
        self.assertEqual(digest_token(token), access.token_digest)
        self.assertIsNotNone(active_access(token))
        self.assertTrue(url.startswith("https://zentral/public/mdm/family-setup/#token="))
        self.assertEqual(version.default_shard, 0)
        self.assertEqual(list(version.item_tags.values_list("tag_id", "shard")), [(access.tag_id, 100)])
        attachment = BlueprintArtifact.objects.get(artifact=access.artifact)
        self.assertEqual(attachment.default_shard, 0)
        self.assertEqual(list(attachment.item_tags.values_list("tag_id", "shard")), [(access.tag_id, 100)])
        self.device.refresh_from_db()
        other.refresh_from_db()
        self.assertIn(str(access.artifact_id), {a["pk"] for a, _ in Target(self.device).all_in_scope_serialized()})
        self.assertNotIn(str(access.artifact_id), {a["pk"] for a, _ in Target(other).all_in_scope_serialized()})

    def test_renewal_rotates_capability_and_preserves_immutable_profile_and_progress(self):
        access = provision(self.device, FamilySetupAccess.Audience.CHILD)
        access.completed_steps = {"wifi": True}
        access.save()
        old_version = access.artifact.artifactversion_set.get()
        old_source = bytes(old_version.profile.source)
        old_payload = plistlib.loads(old_source)
        old_token = old_payload["PayloadContent"][0]["URL"].split("#token=", 1)[1]
        renewed = provision(self.device, FamilySetupAccess.Audience.CHILD)
        self.assertEqual(renewed.pk, access.pk)
        self.assertEqual(renewed.artifact_id, access.artifact_id)
        self.assertEqual(renewed.tag_id, access.tag_id)
        self.assertEqual(renewed.completed_steps, {"wifi": True})
        self.assertIsNone(active_access(old_token))
        versions = list(renewed.artifact.artifactversion_set.order_by("version"))
        self.assertEqual([version.version for version in versions], [1, 2])
        self.assertEqual(bytes(versions[0].profile.source), old_source)
        new_payload = plistlib.loads(versions[1].profile.source)
        self.assertEqual(new_payload["PayloadIdentifier"], old_payload["PayloadIdentifier"])
        self.assertEqual(new_payload["PayloadUUID"], old_payload["PayloadUUID"])
        self.assertNotEqual(new_payload["PayloadContent"][0]["URL"], old_payload["PayloadContent"][0]["URL"])
        self.assertLessEqual(renewed.expires_at, timezone.now() + timedelta(days=180))

    def test_provision_rejects_unsupervised_device_without_changing_access(self):
        self.device.supervised = False
        self.device.save()
        with self.assertRaises(ValueError):
            provision(self.device, FamilySetupAccess.Audience.CHILD)
        self.access.refresh_from_db()
        self.assertEqual(self.access.token_digest, digest_token(self.token))
        self.assertIsNone(self.access.artifact_id)
        self.assertIsNone(self.access.tag_id)

    def test_shared_device_tag_rejects_renewal_and_rolls_back_token_change(self):
        access = provision(self.device, FamilySetupAccess.Audience.CHILD)
        other, _, _ = self.make_access()
        MachineTag.objects.create(serial_number=other.serial_number, tag=access.tag)
        original_digest = access.token_digest
        with self.assertRaisesMessage(ValueError, "Setup tag must belong only"):
            provision(self.device, FamilySetupAccess.Audience.CHILD)
        access.refresh_from_db()
        self.assertEqual(access.token_digest, original_digest)
        self.assertEqual(access.artifact.artifactversion_set.count(), 1)

    def test_broad_blueprint_attachment_rejects_renewal_and_rolls_back_new_version(self):
        access = provision(self.device, FamilySetupAccess.Audience.CHILD)
        attachment = BlueprintArtifact.objects.get(artifact=access.artifact)
        attachment.default_shard = 100
        attachment.save()
        with self.assertRaisesMessage(ValueError, "no longer has exclusive scope"):
            provision(self.device, FamilySetupAccess.Audience.CHILD)
        self.assertEqual(access.artifact.artifactversion_set.count(), 1)
        access.refresh_from_db()
        self.assertEqual(access.token_digest, digest_token(
            plistlib.loads(access.artifact.artifactversion_set.get().profile.source)
            ["PayloadContent"][0]["URL"].split("#token=", 1)[1]))

    def test_management_requires_superuser_and_csrf(self):
        url = reverse("mdm:family_setup_manage", args=[self.device.pk])
        self.assertEqual(self.client.get(url).status_code, 302)
        user = User.objects.create_user("family-setup-test", "test@example.com", "test-password-only")
        self.client.force_login(user, backend="accounts.auth_backends.ZentralBackend")
        self.assertEqual(self.client.get(url).status_code, 403)
        user.is_superuser = True
        user.save()
        client = Client(enforce_csrf_checks=True)
        client.force_login(user, backend="accounts.auth_backends.ZentralBackend")
        self.assertEqual(client.get(url, secure=True).status_code, 200)
        self.assertEqual(client.post(url, {"audience": "child", "action": "revoke", "confirm": "on"},
                                     secure=True).status_code, 403)
        self.access.refresh_from_db()
        self.assertIsNone(self.access.revoked_at)

    def test_admin_revoke_disables_existing_browser_access(self):
        user = User.objects.create_user("setup-admin", "test@example.com", "test-password-only", is_superuser=True)
        self.client.force_login(user, backend="accounts.auth_backends.ZentralBackend")
        response = self.client.post(reverse("mdm:family_setup_manage", args=[self.device.pk]),
                                    {"audience": "child", "action": "revoke", "confirm": "on"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.get_status().status_code, 401)
