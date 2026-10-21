import plistlib
import secrets
import struct
import uuid
from datetime import timedelta
from importlib.resources import files
from urllib.parse import urlsplit

from django import forms
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from zentral import telemetry
from zentral.conf import settings as zentral_settings
from zentral.contrib.inventory.models import MachineTag, Tag
from .apns import send_enrolled_device_notification
from .artifacts import Target, update_blueprint_serialized_artifacts
from .family_setup import active_access, digest_token, eligible_device, enrollment_fingerprint, private_response
from .forms import UploadProfileForm, UpgradeProfileForm
from .models import (ArtifactVersion, ArtifactVersionTag, BlueprintArtifact, BlueprintArtifactTag,
                     Channel, EnrolledDevice, FamilySetupAccess, Platform)


class SetupForm(forms.Form):
    audience = forms.ChoiceField(choices=FamilySetupAccess.Audience.choices)
    action = forms.ChoiceField(choices=(("publish", "Publish or renew setup access"),
                                       ("revoke", "Revoke setup access")))
    confirm = forms.BooleanField(label="I checked this device and its Adult or Child blueprint.")


def _setup_url():
    origin = zentral_settings["api"]["tls_hostname"].rstrip("/")
    parsed = urlsplit(origin)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.path or parsed.query or parsed.fragment
            or parsed.username or parsed.password):
        raise ValueError("Family Setup requires a configured HTTPS application origin")
    return origin + reverse("mdm_public:family_setup")


def _icon():
    icon = files("zentral.contrib.mdm").joinpath("static/mdm/family-setup-icon.png").read_bytes()
    if (len(icon) > 1024 * 1024 or len(icon) < 24 or icon[:8] != b"\x89PNG\r\n\x1a\n"
            or icon[12:16] != b"IHDR" or struct.unpack(">II", icon[16:24]) != (384, 384)):
        raise ValueError("Family Setup requires a 384px PNG icon smaller than 1MB")
    return icon


def _profile(access, token):
    identifier = f"com.zentral.family-setup.{access.pk}"
    payload = {
        "PayloadType": "Configuration", "PayloadVersion": 1, "PayloadScope": "System",
        "PayloadRemovalDisallowed": True,
        "PayloadIdentifier": identifier, "PayloadUUID": str(uuid.uuid5(uuid.NAMESPACE_URL, identifier)).upper(),
        "PayloadDisplayName": "Family Setup", "PayloadDescription": "Private setup checklist for this device.",
        "PayloadContent": [{
            "PayloadType": "com.apple.webClip.managed", "PayloadVersion": 1,
            "PayloadIdentifier": identifier + ".webclip",
            "PayloadUUID": str(uuid.uuid5(uuid.NAMESPACE_URL, identifier + ".webclip")).upper(),
            "PayloadDisplayName": "Family Setup", "Label": "Family Setup",
            "URL": _setup_url() + "#token=" + token,
            "FullScreen": True, "IsRemovable": False, "IgnoreManifestScope": True,
            "Precomposed": True, "Icon": _icon(),
        }],
    }
    return SimpleUploadedFile("family-setup.mobileconfig", plistlib.dumps(payload), "application/x-apple-aspen-config")


@transaction.atomic
def provision(device, audience):
    # Lock the device even on first creation, when there is no access row to lock yet.
    device = EnrolledDevice.objects.select_for_update(of=("self",)).select_related("blueprint").get(pk=device.pk)
    if not eligible_device(device) or audience not in FamilySetupAccess.Audience.values:
        raise ValueError("Choose a supervised, active ADE iPhone or iPad with a blueprint")
    access = FamilySetupAccess.objects.select_for_update().filter(enrolled_device=device).first()
    if access and access.blueprint_id != device.blueprint_id:
        raise ValueError("The blueprint changed. Reconcile the existing setup artifact before publishing again")
    token = secrets.token_urlsafe(32)
    if access is None:
        access = FamilySetupAccess(enrolled_device=device, blueprint=device.blueprint)
    elif access.enrollment_fingerprint != enrollment_fingerprint(device) or access.audience != audience:
        access.completed_steps = {}
    access.audience = audience
    access.token_digest = digest_token(token)
    access.enrollment_fingerprint = enrollment_fingerprint(device)
    access.expires_at = timezone.now() + timedelta(days=180)
    access.revoked_at = None
    access.save()
    access.enrolled_device = device
    return _save_profile(access, token)


@transaction.atomic
def refresh_profile(device):
    device = EnrolledDevice.objects.select_for_update(of=("self",)).select_related("blueprint").get(pk=device.pk)
    access = FamilySetupAccess.objects.select_for_update().filter(enrolled_device=device).first()
    if not access or not access.artifact_id or not access.tag_id:
        raise ValueError("Publish setup access before refreshing its profile")
    latest = access.artifact.artifactversion_set.order_by("-version").first()
    try:
        payload = plistlib.loads(latest.profile.source)
        clips = payload["PayloadContent"]
        if len(clips) != 1 or clips[0]["PayloadType"] != "com.apple.webClip.managed":
            raise ValueError
        prefix = _setup_url() + "#token="
        url = clips[0]["URL"]
        if not isinstance(url, str) or not url.startswith(prefix):
            raise ValueError
        token = url[len(prefix):]
        current = active_access(token)
        if current is None or current.pk != access.pk:
            raise ValueError
        expected = plistlib.loads(_profile(access, token).read())
        for actual, wanted in ((payload, expected), (clips[0], expected["PayloadContent"][0])):
            if any(actual[key] != wanted[key] for key in ("PayloadIdentifier", "PayloadUUID")):
                raise ValueError
    except (AttributeError, KeyError, TypeError, ValueError, plistlib.InvalidFileException):
        raise ValueError("Existing setup profile does not contain this device's current private link") from None
    access.enrolled_device = device
    return _save_profile(access, token)


def _save_profile(access, token):
    device = access.enrolled_device

    if access.tag_id is None:
        access.tag = Tag.objects.create(name="setup-device-" + uuid.uuid4().hex)
        MachineTag.objects.create(serial_number=device.serial_number, tag=access.tag)
    elif (access.tag.meta_business_unit_id is not None
          or set(MachineTag.objects.filter(tag=access.tag).values_list("serial_number", flat=True))
          != {device.serial_number}):
        raise ValueError("Setup tag must belong only to the selected device")

    source = _profile(access, token)
    new_version = True
    if access.artifact_id:
        artifact = access.artifact
        latest = artifact.artifactversion_set.order_by("-version").first()
        if (latest.default_shard != 0 or latest.shard_modulo != 100
                or list(latest.item_tags.values_list("tag_id", "shard")) != [(access.tag_id, 100)]):
            raise ValueError("Existing setup version no longer has exclusive scope")
        if bytes(latest.profile.source) == source.read():
            version = latest
            new_version = False
        else:
            source.seek(0)
            form = UpgradeProfileForm({}, {"source_file": source}, artifact=artifact, instance=latest.profile)
            if not form.is_valid():
                raise ValueError("The generated setup profile failed validation")
            version = ArtifactVersion.objects.create(artifact=artifact, version=latest.version + 1,
                                                     ios=True, ipados=True, default_shard=0, shard_modulo=100)
            form.save(version)
    else:
        form = UploadProfileForm({}, {"source_file": source})
        if not form.is_valid():
            raise ValueError("The generated setup profile failed validation")
        artifact = form.save()
        artifact.platforms = [Platform.IOS, Platform.IPADOS]
        artifact.save(update_fields=("platforms",))
        if artifact.channel != Channel.DEVICE:
            raise ValueError("Setup profile must use the device channel")
        version = artifact.artifactversion_set.get()
        version.ios = version.ipados = True
        version.macos = version.tvos = False
        version.default_shard = 0
        version.shard_modulo = 100
        version.save()
        access.artifact = artifact
    if new_version:
        ArtifactVersionTag.objects.create(artifact_version=version, tag=access.tag, shard=100)
    assignment, created = BlueprintArtifact.objects.get_or_create(
        blueprint=device.blueprint, artifact=artifact,
        defaults={"ios": True, "ipados": True, "default_shard": 0, "shard_modulo": 100},
    )
    if not created:
        if (assignment.default_shard != 0 or assignment.shard_modulo != 100
                or list(assignment.item_tags.values_list("tag_id", "shard")) != [(access.tag_id, 100)]):
            raise ValueError("Existing setup attachment no longer has exclusive scope")
    else:
        BlueprintArtifactTag.objects.create(blueprint_artifact=assignment, tag=access.tag, shard=100)
    if BlueprintArtifact.objects.filter(artifact=artifact).exclude(pk=assignment.pk).exists():
        raise ValueError("Setup profile is attached to another blueprint")
    access.save(update_fields=("artifact", "tag", "updated_at"))
    update_blueprint_serialized_artifacts(device.blueprint)
    matches = []
    for candidate in EnrolledDevice.objects.filter(blueprint=device.blueprint, checkout_at__isnull=True):
        candidate.blueprint = device.blueprint
        if any(item["pk"] == str(artifact.pk) for item, _ in Target(candidate).all_in_scope_serialized()):
            matches.append(candidate.pk)
    if matches != [device.pk]:
        raise ValueError("Setup profile must resolve to exactly the selected device")
    return access


@login_required
@require_http_methods(["GET", "POST"])
def manage(request, pk):
    if not request.user.is_superuser:
        raise PermissionDenied
    device = get_object_or_404(EnrolledDevice.objects.select_related("blueprint"), pk=pk)
    access = FamilySetupAccess.objects.filter(enrolled_device=device).first()
    form = SetupForm(request.POST if request.method == "POST" else None,
                     initial={"audience": access.audience if access else None, "action": "publish"})
    if request.method == "POST" and form.is_valid():
        action = form.cleaned_data["action"]
        if action == "revoke":
            with telemetry.operation("family_setup.revoke"):
                FamilySetupAccess.objects.filter(enrolled_device=device).update(revoked_at=timezone.now())
                telemetry.event("family_setup.revoke")
            return redirect("mdm:family_setup_manage", pk=device.pk)
        try:
            with telemetry.operation("family_setup.provision"):
                provision(device, form.cleaned_data["audience"])
                telemetry.event("family_setup.provision")
        except ValueError as error:
            form.add_error(None, str(error))
        else:
            send_enrolled_device_notification(device, request=request)
            return redirect("mdm:family_setup_manage", pk=device.pk)
    return private_response(render(request, "mdm/family_setup_manage.html",
                                   {"device": device, "access": access, "form": form}))
