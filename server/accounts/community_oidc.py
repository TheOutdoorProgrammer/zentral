import secrets
import time
import uuid
from functools import wraps
from urllib.parse import urlsplit

from authlib.integrations.base_client import OAuthError
from authlib.integrations.django_client import OAuth
from django.conf import settings
from django.contrib.auth import login
from django.core.exceptions import ImproperlyConfigured, PermissionDenied
from django.db import IntegrityError, transaction
from django.http import Http404
from django.shortcuts import redirect
from django.template.response import TemplateResponse
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_variables
from django.views.decorators.http import require_GET, require_POST
from joserfc.errors import JoseError
import requests

from accounts.auth_backends import ZentralBackend
from accounts.models import CommunityOIDCIdentity, User
from zentral.telemetry import event


BACKEND = "accounts.community_oidc.CommunityOIDCBackend"
FLOW_KEY = "community_oidc_flow"
FLOW_TTL = 300
SIGNING_ALGORITHMS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}


def email_set(values):
    return {value.strip().lower() for value in values if isinstance(value, str) and value.strip()}


def enabled():
    return bool(settings.COMMUNITY_OIDC.get("issuer"))


def https_url(value):
    parsed = urlsplit(value)
    return (parsed.scheme == "https" and bool(parsed.hostname)
            and not parsed.username and not parsed.password and not parsed.fragment)


def configuration():
    cfg = settings.COMMUNITY_OIDC
    if not enabled():
        raise Http404
    if (not https_url(cfg["issuer"]) or urlsplit(cfg["issuer"]).query
            or not https_url(cfg["redirect_uri"]) or urlsplit(cfg["redirect_uri"]).query
            or not cfg["client_id"] or not cfg["client_secret"]
            or not email_set(cfg["admin_emails"]) <= email_set(cfg["allowed_emails"])):
        raise ImproperlyConfigured("Invalid community OIDC configuration")
    return cfg


@sensitive_variables()
def oidc_client(cfg):
    response = requests.get(
        cfg["issuer"].rstrip("/") + "/.well-known/openid-configuration",
        timeout=10,
        allow_redirects=False,
    )
    response.raise_for_status()
    metadata = response.json()
    if metadata.get("issuer") != cfg["issuer"]:
        raise ValueError("OIDC discovery issuer mismatch")
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not isinstance(metadata.get(key), str) or not https_url(metadata[key]):
            raise ValueError("Invalid OIDC endpoint")
    algorithms = metadata.get("id_token_signing_alg_values_supported", [])
    if not isinstance(algorithms, list):
        raise ValueError("Invalid OIDC signing algorithms")
    algorithms = [alg for alg in algorithms if alg in SIGNING_ALGORITHMS]
    if not algorithms:
        raise ValueError("No supported OIDC signing algorithm")
    oauth = OAuth()
    return oauth.register(
        name="community",
        client_id=cfg["client_id"],
        client_secret=cfg["client_secret"],
        authorize_url=metadata["authorization_endpoint"],
        access_token_url=metadata["token_endpoint"],
        jwks_uri=metadata["jwks_uri"],
        issuer=cfg["issuer"],
        id_token_signing_alg_values_supported=algorithms,
        client_kwargs={
            "scope": "openid email profile",
            "code_challenge_method": "S256",
            "token_endpoint_auth_method": "client_secret_basic",
            "timeout": 10,
        },
    )


class CommunityOIDCBackend(ZentralBackend):
    def authenticate(self, request, **kwargs):
        return None

    def get_user(self, user_id):
        if not enabled():
            return None
        cfg = settings.COMMUNITY_OIDC
        identity = CommunityOIDCIdentity.objects.select_related("user").filter(
            user_id=user_id, issuer=cfg["issuer"],
        ).first()
        if not identity:
            return None
        user = identity.user
        if not self.user_can_authenticate(user) or user.email.lower() not in email_set(cfg["allowed_emails"]):
            return None
        # Revoking an administrator in deployment configuration applies to existing sessions too.
        user.is_superuser = user.email.lower() in email_set(cfg["admin_emails"])
        return user


@sensitive_variables()
def resolve_identity(cfg, claims):
    subject, email = claims.get("sub"), claims.get("email")
    if (claims.get("iss") != cfg["issuer"] or not isinstance(subject, str) or not 0 < len(subject) <= 255
            or not isinstance(email, str) or not 0 < len(email) <= 254
            or claims.get("email_verified") is not True):
        raise PermissionDenied
    email = email.strip().lower()
    if email not in email_set(cfg["allowed_emails"]):
        raise PermissionDenied
    with transaction.atomic():
        identity = CommunityOIDCIdentity.objects.select_for_update().select_related("user").filter(
            issuer=cfg["issuer"], subject=subject,
        ).first()
        if identity:
            user = identity.user
            if not user.is_active or user.is_service_account or user.email.lower() != email:
                raise PermissionDenied
        else:
            # Matching an email must never take over an existing local or differently bound account.
            if User.objects.filter(email__iexact=email).exists():
                raise PermissionDenied
            user = User(
                username="oidc-" + uuid.uuid4().hex,
                email=email,
                is_remote=True,
            )
            user.set_unusable_password()
            user.save()
            CommunityOIDCIdentity.objects.create(user=user, issuer=cfg["issuer"], subject=subject)
        user.is_superuser = email in email_set(cfg["admin_emails"])
        user.save(update_fields=["is_superuser", "password"])
        return user


def failure(request, status=403):
    return TemplateResponse(request, "registration/community_oidc_error.html", status=status)


def no_referrer(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        response = view(*args, **kwargs)
        response["Referrer-Policy"] = "no-referrer"
        return response
    return wrapped


@never_cache
@no_referrer
@require_POST
@csrf_protect
@sensitive_variables()
def begin(request):
    if request.user.is_authenticated:
        return redirect(settings.LOGIN_REDIRECT_URL)
    try:
        cfg = configuration()
        client = oidc_client(cfg)
        state = secrets.token_urlsafe(32)
        # Only one pending login is retained, so an abandoned flow cannot accumulate session state.
        for key in list(request.session.keys()):
            if key.startswith("_state_community_"):
                del request.session[key]
        request.session.cycle_key()
        request.session[FLOW_KEY] = {"state": state, "started": time.time()}
        response = client.authorize_redirect(request, cfg["redirect_uri"], state=state)
        event("oidc.login", outcome="success")
        return response
    except (ImproperlyConfigured, OAuthError, requests.RequestException, ValueError, KeyError, TypeError):
        event("oidc.login", outcome="failure")
        return failure(request, 503)


@never_cache
@no_referrer
@require_GET
@sensitive_variables()
def callback(request):
    flow = request.session.pop(FLOW_KEY, None)
    state = request.GET.get("state", "")
    try:
        if (not flow or not state or not state.isascii() or not secrets.compare_digest(state, flow["state"])
                or not 0 <= time.time() - flow["started"] <= FLOW_TTL):
            raise PermissionDenied
        cfg = configuration()
        client = oidc_client(cfg)
        token = client.authorize_access_token(
            request, allow_redirects=False,
            claims_options={"iss": {"essential": True, "value": cfg["issuer"]}},
            leeway=30,
        )
        claims = token.get("userinfo")
        if not claims or not token.get("id_token"):
            raise PermissionDenied
        user = resolve_identity(cfg, claims)
        login(request, user, backend=BACKEND)
        request.session.pop("realm_authentication_session", None)
        request.session.pop("verification_token", None)
        request.session.pop("mfa_authenticated", None)
        # Authentication tokens stay in this request, never the application session or database.
        event("oidc.login", outcome="success")
        return redirect(settings.LOGIN_REDIRECT_URL)
    except (PermissionDenied, IntegrityError):
        event("oidc.login", outcome="denied")
        return failure(request)
    except (ImproperlyConfigured, OAuthError, JoseError, requests.RequestException, ValueError, KeyError, TypeError):
        event("oidc.login", outcome="failure")
        return failure(request)
    finally:
        for key in list(request.session.keys()):
            if key.startswith("_state_community_"):
                del request.session[key]
