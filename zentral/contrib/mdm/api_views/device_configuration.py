from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from zentral.contrib.inventory.models import MachineTag
from zentral.contrib.mdm.artifacts import Target, _serialize_filtered_blueprint_item
from zentral.contrib.mdm.models import Artifact, BlueprintArtifact, Channel, EnrolledDevice
from zentral.utils.drf import DjangoPermissionRequired


class DeviceConfigurationQuery(serializers.Serializer):
    serial_number = serializers.CharField(max_length=256, trim_whitespace=False)
    app_name = serializers.CharField(max_length=256, trim_whitespace=False)


def _matches(target, item):
    metadata = _serialize_filtered_blueprint_item(item)
    metadata["pk"] = str(item.pk)
    return target._test_filtered_blueprint_item(metadata)


def _exclusive_tag(item, serial_number, allow_disabled=False):
    shards = list(item.item_tags.values_list("tag_id", "shard"))
    if allow_disabled and item.default_shard == 0 and not shards:
        return None
    if item.default_shard != 0 or item.shard_modulo != 100 or len(shards) != 1 or shards[0][1] != 100:
        raise ValidationError("Configuration targeting is not restricted to one exclusive device tag.")
    tag_id = shards[0][0]
    members = MachineTag.objects.filter(tag_id=tag_id).values_list("serial_number", flat=True).distinct()
    if set(members) != {serial_number}:
        raise ValidationError("Configuration tag membership is not exclusive to the requested device.")
    return tag_id


class DeviceConfigurationTarget(APIView):
    """Resolve safe targeting metadata without selecting or serializing profile source."""

    permission_classes = [DjangoPermissionRequired]
    permission_required = (
        "mdm.view_enrolleddevice",
        "mdm.view_artifact",
        "mdm.view_blueprintartifact",
        "inventory.view_machinesnapshot",
        "inventory.view_tag",
    )

    def get(self, request):
        query = DeviceConfigurationQuery(data=request.query_params)
        query.is_valid(raise_exception=True)
        serial_number = query.validated_data["serial_number"]
        devices = list(EnrolledDevice.objects.only("id", "serial_number", "platform", "os_version", "blueprint_id").filter(
            serial_number=serial_number, checkout_at__isnull=True, blocked_at__isnull=True,
        )[:2])
        if len(devices) > 1:
            raise ValidationError("Multiple active enrollments match the exact serial number.")
        result = {"found": False, "app_eligible": False, "artifact_id": None,
                  "attachment_id": None, "tag_id": None}
        if not devices:
            return Response(result)
        device = devices[0]
        try:
            app = Artifact.objects.get(
                name=query.validated_data["app_name"], channel=Channel.DEVICE,
                type__in=(Artifact.Type.STORE_APP, Artifact.Type.ENTERPRISE_APP, Artifact.Type.CONFIGURATION),
            )
        except Artifact.DoesNotExist:
            return Response(result)
        except Artifact.MultipleObjectsReturned:
            raise ValidationError("Multiple app artifacts match the exact name.")
        target = Target(device)
        if device.platform in app.platforms:
            result["app_eligible"] = any(_matches(target, version) for version in (
                app.artifactversion_set.prefetch_related("item_tags", "excluded_tags")
            ))
        if device.blueprint_id is None:
            return Response(result)
        configurations = Artifact.objects.filter(
            requires=app, type=Artifact.Type.PROFILE, channel=Channel.DEVICE,
            platforms__contains=[device.platform],
        ).prefetch_related("artifactversion_set__item_tags", "artifactversion_set__excluded_tags")
        for artifact in configurations:
            # Historical versions can expose the same credential to another device.
            # Validate every nonempty rollout, including versions this target cannot use.
            versions = list(artifact.artifactversion_set.all())
            if not any(_matches(target, version) for version in versions):
                continue
            tags = {_exclusive_tag(version, serial_number, allow_disabled=True) for version in versions}
            tags.discard(None)
            if len(tags) != 1:
                raise ValidationError("Configuration versions do not agree on one exclusive device tag.")
            tag_id = tags.pop()
            attachment_id = None
            for attachment in BlueprintArtifact.objects.filter(artifact=artifact).prefetch_related("item_tags"):
                attachment_tag = _exclusive_tag(attachment, serial_number, allow_disabled=True)
                if attachment_tag is not None and attachment_tag != tag_id:
                    raise ValidationError("Configuration attachment and version tags do not match.")
                if attachment.blueprint_id == device.blueprint_id:
                    if attachment_id is not None:
                        raise ValidationError("Multiple configuration attachments match the current blueprint.")
                    attachment_id = attachment.pk
            if result["found"]:
                raise ValidationError("Multiple device configurations require this app; resolve the ambiguity in Zentral.")
            result.update(found=True, artifact_id=str(artifact.pk), attachment_id=attachment_id, tag_id=tag_id)
        return Response(result)
