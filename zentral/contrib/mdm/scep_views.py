import hmac
import os

import requests
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods, require_POST

from zentral import telemetry
from .scep_broker import (
    authorize_challenge, BrokerUnavailable, decode_json, InvalidChallenge, mint_challenge, verify_webhook,
)


SCEP_URL = "https://localhost:9000/scep/zentral"
SCEP_ROOT = "/etc/zentral-ca/root_ca.crt"
MAX_MESSAGE = 128 * 1024
MAX_RESPONSE = 2 * 1024 * 1024


def _body(request, limit):
    if request.content_type != "application/json":
        raise InvalidChallenge()
    body = request.read(limit + 1)
    if len(body) > limit:
        raise InvalidChallenge()
    return body


def _result(name, status, data):
    telemetry.event(name, "success" if status == 200 else "denied" if status < 500 else "failure")
    response = JsonResponse(data, status=status)
    response["Cache-Control"] = "no-store"
    return response


@csrf_exempt
@require_POST
def challenge(request):
    name = "mdm.scep.challenge"
    with telemetry.operation(name):
        token = os.environ.get("ZENTRAL_SCEP_BROKER_TOKEN", "")
        if len(token) < 32:
            return _result(name, 503, {"error": "unavailable"})
        authorization = request.headers.get("Authorization", "").encode()
        if not hmac.compare_digest(authorization, f"Bearer {token}".encode()):
            return _result(name, 403, {"error": "denied"})
        try:
            value = mint_challenge(decode_json(_body(request, 8192)))
        except InvalidChallenge:
            return _result(name, 400, {"error": "invalid request"})
        except BrokerUnavailable:
            return _result(name, 503, {"error": "unavailable"})
        return _result(name, 200, {"challenge": value})


@csrf_exempt
@require_POST
def authorize(request):
    name = "mdm.scep.authorize"
    with telemetry.operation(name):
        try:
            payload = verify_webhook(
                _body(request, 65536),
                request.headers.get("X-Smallstep-Signature", ""),
                request.headers.get("X-Smallstep-Webhook-ID", ""),
            )
            authorize_challenge(payload)
        except InvalidChallenge:
            return _result(name, 403, {"allow": False})
        except BrokerUnavailable:
            return _result(name, 503, {"allow": False})
        return _result(name, 200, {"allow": True})


@csrf_exempt
@require_http_methods(["GET", "POST"])
def proxy(request):
    name = "mdm.scep.proxy"
    with telemetry.operation(name) as span:
        if len(request.META.get("QUERY_STRING", "")) > MAX_MESSAGE:
            return _result(name, 400, {"error": "invalid request"})
        operation = request.GET.get("operation")
        if (operation not in ("GetCACaps", "GetCACert", "PKIOperation") or
                set(request.GET) - {"operation", "message"} or
                any(len(values) != 1 for _, values in request.GET.lists()) or
                (request.method == "POST" and operation != "PKIOperation")):
            return _result(name, 400, {"error": "invalid request"})
        span.set_attribute("mdm.scep.operation", operation)
        body = request.read(MAX_MESSAGE + 1)
        if (len(body) > MAX_MESSAGE or (request.method == "GET" and body) or
                (request.method == "POST" and
                 (request.content_type != "application/x-pki-message" or not body))):
            return _result(name, 400, {"error": "invalid request"})
        try:
            with requests.Session() as session:
                session.trust_env = False
                with session.request(
                    request.method, SCEP_URL, params=request.GET.dict(), data=body or None,
                    headers={"Content-Type": "application/x-pki-message"} if body else {},
                    timeout=(3, 20), verify=SCEP_ROOT, allow_redirects=False, stream=True,
                ) as upstream:
                    if upstream.status_code != 200:
                        return _result(name, 502, {"error": "upstream unavailable"})
                    chunks = []
                    size = 0
                    for chunk in upstream.iter_content(65536):
                        size += len(chunk)
                        if size > MAX_RESPONSE:
                            return _result(name, 502, {"error": "upstream unavailable"})
                        chunks.append(chunk)
                    content_type = upstream.headers.get("Content-Type", "").split(";")[0].lower()
                    if content_type not in {
                        "application/x-pki-message", "application/x-x509-ca-cert",
                        "application/x-x509-ca-ra-cert", "text/plain",
                    }:
                        return _result(name, 502, {"error": "upstream unavailable"})
                    response = HttpResponse(b"".join(chunks), content_type=content_type)
        except requests.RequestException:
            return _result(name, 502, {"error": "upstream unavailable"})
        response["Cache-Control"] = "no-store"
        telemetry.event(name, "success")
        return response
