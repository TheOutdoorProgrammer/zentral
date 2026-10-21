import hashlib
import json
import re
from functools import wraps

from django.db import transaction
from django.http import JsonResponse
from django.shortcuts import render
from django.templatetags.static import static
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.http import require_GET, require_POST

from zentral import telemetry
from zentral.conf import settings as zentral_settings
from .artifacts import Target
from .models import Artifact, DeviceArtifact, FamilySetupAccess, Platform, Profile


COOKIE = "__Secure-family_setup"
COOKIE_PATH = "/public/mdm/family-setup/"
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}\Z")

STEPS = (
    {
        "id": "wifi", "title": "Try your home Wi-Fi",
        "description": "An installed profile is a good start. Check that the connection actually works.",
        "instructions": ["Open Settings, then Wi-Fi, and connect to your assigned home network.",
                         "Open a website in Safari and check that it loads."],
    },
    {
        "id": "passwords", "title": "Make passwords easy",
        "description": "Sign in to 1Password and choose it for AutoFill.",
        "instructions": ["Open 1Password and sign in to your own account.",
                         "In Settings, open General, then AutoFill & Passwords. Turn on 1Password.",
                         "If you want only 1Password suggestions, turn off Passwords there.",
                         "Try filling a login. Enabling the Safari extension is a separate, optional step."],
        "link": {"label": "1Password setup help", "url": "https://support.1password.com/ios-autofill/"},
    },
    {
        "id": "apps", "title": "Open your apps",
        "description": "Installation does not sign you in. Open each app and finish its account setup.",
        "instructions": ["Check the managed installation list below for apps still pending.",
                         "Open each installed family app and complete its sign-in or invitation.",
                         "Ask your parent or administrator if an app is missing or cannot open."],
    },
    {
        "id": "vpn", "title": "Test the connection away from home",
        "description": "Your device needs its own VPN profile before this test.",
        "instructions": ["Open WireGuard once after it installs.",
                         "Switch to cellular or a different Wi-Fi network and check that your tunnel connects.",
                         "Check that a website loads. Return to home Wi-Fi and check that the tunnel disconnects.",
                         "For a Wi-Fi-only iPad, use a phone hotspot for the away-from-home test.",
                         "Do not copy someone else's tunnel. Ask for help if your profile is missing or fails."],
    },
    {
        "id": "location", "title": "Share your location with family",
        "description": "Choose who can see you in Find My. A parent helps with a child's device.",
        "instructions": ["Check that this device uses your personal Apple Account "
                         "and belongs to your Family Sharing group.",
                         "Open Settings, then Family, then Location Sharing. Choose the family members to share with.",
                         "In Settings, tap your name, then Find My. Check that Share My Location is on.",
                         "On the iPhone you carry, tap Use This iPhone as My Location if it is available. "
                         "An iPad left at home should not replace that phone as your location source.",
                         "Check Find My on the receiving family member's device and confirm your location appears.",
                         "Mark this done after checking together. "
                         "This checklist cannot turn sharing on or verify your location."],
        "link": {"label": "Apple's family location-sharing guide", "url": "https://support.apple.com/105107"},
    },
    {
        "id": "family", "title": "Finish family settings together",
        "description": "A parent completes this step with you.", "audience": "child",
        "instructions": ["Sign in with the child's personal Apple Account and check Family Sharing.",
                         "On the parent's device, review Ask to Buy and Screen Time for this child.",
                         "Check the agreed limits and allowed websites together.",
                         "Managed app installations do not use the Ask to Buy approval flow."],
    },
)


def digest_token(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def enrollment_fingerprint(device):
    return hashlib.sha256(bytes(device.cert_fingerprint or b"")).hexdigest()


def eligible_device(device):
    return (device.platform in (Platform.IOS, Platform.IPADOS) and device.supervised and device.dep_enrollment
            and device.blueprint_id and not device.checkout_at and not device.blocked_at)


def active_access(token, lock=False):
    if not isinstance(token, str) or not TOKEN_PATTERN.fullmatch(token):
        return None
    qs = FamilySetupAccess.objects.select_related("enrolled_device__blueprint")
    if lock:
        qs = qs.select_for_update(of=("self",))
    access = qs.filter(token_digest=digest_token(token), revoked_at__isnull=True,
                       expires_at__gt=timezone.now()).first()
    if (access and eligible_device(access.enrolled_device)
            and access.blueprint_id == access.enrolled_device.blueprint_id
            and access.enrollment_fingerprint == enrollment_fingerprint(access.enrolled_device)):
        return access


def private_response(response):
    response["Cache-Control"] = "no-store, private"
    response["Referrer-Policy"] = "no-referrer"
    response["X-Robots-Tag"] = "noindex, nofollow"
    response["Vary"] = "Cookie"
    return response


def endpoint(name):
    def decorate(view):
        @wraps(view)
        def wrapped(request, *args, **kwargs):
            with telemetry.operation(name):
                response = view(request, *args, **kwargs)
                telemetry.event(name, "denied" if response.status_code < 500 and response.status_code >= 400
                                else "failure" if response.status_code >= 500 else "success")
                return private_response(response)
        return wrapped
    return decorate


def read_json(request):
    if request.content_type != "application/json" or len(request.body) > 2048:
        return None
    try:
        data = json.loads(request.body)
    except (ValueError, UnicodeError):
        return None
    return data if isinstance(data, dict) else None


def shortcuts():
    links = []
    for item in zentral_settings.get("family_setup", {}).get("shortcuts", [])[:20]:
        if (isinstance(item, dict) and isinstance(item.get("title"), str)
                and re.fullmatch(r"https://www\.icloud\.com/shortcuts/[a-fA-F0-9]{32}", str(item.get("url", "")))):
            links.append({"title": item["title"][:100], "url": item["url"]})
    return links


def device_status(access):
    device = access.enrolled_device
    scoped = Target(device).all_in_scope_serialized()
    versions = {version["pk"]: artifact for artifact, version in scoped
                if artifact["type"] not in (Artifact.Type.ASSET, Artifact.Type.DATA_ASSET, Artifact.Type.CERT_ASSET,
                                            Artifact.Type.ACTIVATION)
                and artifact["pk"] != str(access.artifact_id)}
    reports = {str(report.artifact_version_id): report for report in
               DeviceArtifact.objects.filter(enrolled_device=device, artifact_version_id__in=versions)}
    checks = []
    for version_id, artifact in versions.items():
        report = reports.get(version_id)
        status = "pending"
        if report:
            if report.status == DeviceArtifact.Status.INSTALLED:
                status = "installed"
            elif report.status in (DeviceArtifact.Status.FAILED, DeviceArtifact.Status.REMOVAL_FAILED):
                status = "failed"
        checks.append({"id": artifact["pk"], "title": artifact["name"], "status": status,
                       "reported_at": report.updated_at.isoformat() if report else None})

    payload_types = set()
    for profile in Profile.objects.filter(artifact_version_id__in=versions).only("source"):
        payload_types.update(payload_type for payload_type, _ in profile.payloads)
    required = [("wifi", "Home Wi-Fi profile", "com.apple.wifi.managed"),
                ("vpn", "Personal VPN profile", "com.apple.vpn.managed")]
    if access.audience == FamilySetupAccess.Audience.CHILD:
        required.append(("web", "Child web protection", "com.apple.webcontent-filter"))
    for key, title, payload_type in required:
        if payload_type not in payload_types:
            checks.append({"id": key, "title": title, "status": "not_configured", "reported_at": None})

    steps = [{**{k: v for k, v in step.items() if k != "audience"}, "link": step.get("link"),
              "done": access.completed_steps.get(step["id"]) is True}
             for step in STEPS if step.get("audience", access.audience) == access.audience]
    links = shortcuts()
    if links:
        steps.append({"id": "shortcuts", "title": "Add your shortcuts",
                      "description": "Choose the shared shortcuts below and approve adding each one.",
                      "instructions": ["Review each shortcut before adding it.",
                                       "Approve requested permissions and configure any automation on this device."],
                      "link": None, "done": access.completed_steps.get("shortcuts") is True})
    return {"device_name": device.name or "Your device", "audience": access.audience,
            "last_seen_at": device.last_seen_at.isoformat() if device.last_seen_at else None,
            "checks": checks, "steps": steps, "shortcuts": links}


@require_GET
@ensure_csrf_cookie
@endpoint("family_setup.page")
def index(request):
    config = {key + "_url": reverse("mdm_public:family_setup_" + key)
              for key in ("activate", "status", "step", "forget")}
    config["telemetry_script_url"] = static("dist/telemetry.js")
    return render(request, "mdm/family_setup.html", {"family_setup_config": config})


@require_POST
@sensitive_post_parameters()
@endpoint("family_setup.activate")
def activate(request):
    data = read_json(request)
    access = active_access(data.get("token") if data else None)
    if not access:
        response = JsonResponse({"error": "Open a current Family Setup link for this device."}, status=401)
        response.delete_cookie(COOKIE, path=COOKIE_PATH, samesite="Strict")
        return response
    response = JsonResponse({"paired": True})
    response.set_cookie(COOKIE, data["token"], secure=True, httponly=True, samesite="Strict", path=COOKIE_PATH,
                        max_age=max(0, min(30 * 86400, int((access.expires_at - timezone.now()).total_seconds()))))
    return response


@require_GET
@endpoint("family_setup.status")
def status(request):
    access = active_access(request.COOKIES.get(COOKIE))
    if not access:
        return JsonResponse({"error": "Setup access is missing or expired."}, status=401)
    return JsonResponse(device_status(access))


@require_POST
@sensitive_post_parameters()
@endpoint("family_setup.step")
def step(request):
    data = read_json(request)
    if not data or not isinstance(data.get("step"), str) or type(data.get("done")) is not bool:
        return JsonResponse({"error": "Choose a step and whether it is complete."}, status=400)
    with transaction.atomic():
        access = active_access(request.COOKIES.get(COOKIE), lock=True)
        if not access:
            return JsonResponse({"error": "Setup access is missing or expired."}, status=401)
        current = device_status(access)
        if data["step"] not in {item["id"] for item in current["steps"]}:
            return JsonResponse({"error": "Unknown setup step."}, status=400)
        access.completed_steps[data["step"]] = data["done"]
        access.save(update_fields=("completed_steps", "updated_at"))
        for item in current["steps"]:
            if item["id"] == data["step"]:
                item["done"] = data["done"]
        return JsonResponse(current)


@require_POST
@endpoint("family_setup.forget")
def forget(request):
    response = JsonResponse({"paired": False})
    response.delete_cookie(COOKIE, path=COOKIE_PATH, samesite="Strict")
    return response
