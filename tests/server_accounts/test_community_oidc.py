import base64
import hashlib
import json
import secrets
import time
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth import SESSION_KEY
from django.test import Client, TestCase, override_settings
import jwt
from requests import Response

from accounts.community_oidc import BACKEND, FLOW_KEY
from accounts.models import CommunityOIDCIdentity, User


ISSUER = "https://identity.example"
CONFIG = {
    "issuer": ISSUER,
    "client_id": "zentral-test-client",
    "client_secret": "test-client-secret",
    "redirect_uri": "https://testserver/accounts/oidc/callback/",
    "allowed_emails": ["admin@example.com", "reader@example.com"],
    "admin_emails": ["admin@example.com"],
    "label": "Example",
    "only": True,
}


@override_settings(COMMUNITY_OIDC=CONFIG)
class CommunityOIDCTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(cls.key.public_key()))
        cls.jwk.update(kid="test-key", use="sig", alg="RS256")

    def setUp(self):
        self.client = Client()
        self.claim_overrides = {}
        self.token_overrides = {}
        self.signature_key = self.key
        self.nonce = None
        self.challenge = None
        self.requests = []
        self.metadata = {
            "issuer": ISSUER,
            "authorization_endpoint": ISSUER + "/authorize",
            "token_endpoint": ISSUER + "/token",
            "jwks_uri": ISSUER + "/jwks",
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        self.transport = patch("requests.sessions.Session.send", side_effect=self.send)
        self.transport.start()
        self.addCleanup(self.transport.stop)
        self.events = patch("accounts.events.post_event")
        self.events.start()
        self.addCleanup(self.events.stop)

    def send(self, request, **kwargs):
        self.requests.append(request)
        response = Response()
        response.status_code = 200
        response.request = request
        response.url = request.url
        if request.url.endswith("/.well-known/openid-configuration"):
            data = self.metadata
        elif request.url == ISSUER + "/jwks":
            data = {"keys": [self.jwk]}
        elif request.url == ISSUER + "/token":
            body = request.body.decode() if isinstance(request.body, bytes) else request.body
            params = parse_qs(body)
            verifier = params["code_verifier"][0]
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            self.assertEqual(challenge, self.challenge)
            self.assertEqual(params["redirect_uri"], [CONFIG["redirect_uri"]])
            self.assertNotIn("test-client-secret", request.url)
            claims = {
                "iss": ISSUER, "sub": "subject-123", "aud": CONFIG["client_id"],
                "exp": int(time.time()) + 300, "iat": int(time.time()),
                "nonce": self.nonce, "email": "admin@example.com", "email_verified": True,
            }
            claims.update(self.claim_overrides)
            data = {
                "access_token": "test-access-token", "token_type": "Bearer",
                "id_token": jwt.encode(claims, self.signature_key, algorithm="RS256", headers={"kid": "test-key"}),
            }
            data.update(self.token_overrides)
        else:
            self.fail("Unexpected outbound request")
        response._content = json.dumps(data).encode()
        response.headers["Content-Type"] = "application/json"
        return response

    def begin(self):
        response = self.client.post("/accounts/oidc/login/", secure=True)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        query = parse_qs(urlsplit(response.url).query)
        self.assertEqual(query["scope"], ["openid email profile"])
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.nonce = query["nonce"][0]
        self.challenge = query["code_challenge"][0]
        self.assertNotIn("test-client-secret", response.url)
        return query["state"][0]

    def callback(self, state):
        return self.client.get("/accounts/oidc/callback/", {"code": "single-use-code", "state": state}, secure=True)

    def test_success_binds_subject_without_storing_tokens(self):
        state = self.begin()
        response = self.callback(state)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        identity = CommunityOIDCIdentity.objects.get()
        self.assertEqual(identity.issuer, ISSUER)
        self.assertEqual(identity.subject, "subject-123")
        self.assertTrue(identity.user.is_superuser)
        self.assertTrue(identity.user.is_remote)
        self.assertFalse(identity.user.has_usable_password())
        session = dict(self.client.session)
        self.assertEqual(session["_auth_user_backend"], BACKEND)
        self.assertNotIn(FLOW_KEY, session)
        self.assertNotIn("test-access-token", json.dumps(session))
        self.assertFalse(any(key.startswith("_state_community_") for key in session))

    def test_state_missing_wrong_and_replayed(self):
        state = self.begin()
        before = len(self.requests)
        self.assertEqual(self.callback("wrong-state").status_code, 403)
        self.assertEqual(len(self.requests), before)
        self.assertEqual(self.callback(state).status_code, 403)
        state = self.begin()
        self.assertEqual(self.callback(state).status_code, 302)
        self.assertEqual(self.callback(state).status_code, 403)

    def test_expired_flow(self):
        state = self.begin()
        session = self.client.session
        session[FLOW_KEY]["started"] -= 301
        session.save()
        self.assertEqual(self.callback(state).status_code, 403)
        self.assertNotIn(SESSION_KEY, self.client.session)

    def test_non_ascii_state_is_denied_and_clears_pending_secrets(self):
        self.begin()
        response = self.callback("é")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        self.assertNotIn(FLOW_KEY, self.client.session)
        self.assertFalse(any(key.startswith("_state_community_") for key in self.client.session.keys()))

    def test_signed_invalid_claims_are_rejected(self):
        for overrides in [
            {"iss": "https://evil.example"}, {"aud": "another-client"},
            {"nonce": "wrong"}, {"nonce": None}, {"exp": int(time.time()) - 120},
            {"email_verified": False}, {"email_verified": "true"},
            {"email": "intruder@example.com"}, {"sub": ""}, {"email": None},
            {"aud": [CONFIG["client_id"], "other"], "azp": "other"},
        ]:
            with self.subTest(overrides=overrides):
                self.client = Client()
                self.claim_overrides = overrides
                self.assertEqual(self.callback(self.begin()).status_code, 403)
                self.assertNotIn(SESSION_KEY, self.client.session)
        self.assertFalse(User.objects.exists())

    def test_invalid_signature_is_rejected(self):
        self.signature_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.assertEqual(self.callback(self.begin()).status_code, 403)
        self.assertFalse(User.objects.exists())

    def test_access_token_without_id_token_is_rejected(self):
        self.token_overrides["id_token"] = None
        self.assertEqual(self.callback(self.begin()).status_code, 403)
        self.assertFalse(User.objects.exists())

    def test_existing_account_is_never_linked_by_email(self):
        user = User.objects.create_user("local-admin", "ADMIN@example.com", "a-test-password", is_superuser=True)
        self.assertEqual(self.callback(self.begin()).status_code, 403)
        user.refresh_from_db()
        self.assertTrue(user.has_usable_password())
        self.assertFalse(CommunityOIDCIdentity.objects.exists())

    def test_changed_subject_cannot_take_over_same_email(self):
        self.callback(self.begin())
        self.client = Client()
        self.claim_overrides["sub"] = "different-subject"
        self.assertEqual(self.callback(self.begin()).status_code, 403)
        self.assertEqual(CommunityOIDCIdentity.objects.count(), 1)

    def test_reader_is_not_administrator(self):
        self.claim_overrides["email"] = "reader@example.com"
        self.assertEqual(self.callback(self.begin()).status_code, 302)
        self.assertFalse(User.objects.get().is_superuser)

    def test_inactive_user_cannot_sign_in(self):
        self.callback(self.begin())
        User.objects.update(is_active=False)
        self.client = Client()
        self.assertEqual(self.callback(self.begin()).status_code, 403)

    def test_revoked_allowlist_invalidates_existing_session(self):
        self.callback(self.begin())
        with override_settings(COMMUNITY_OIDC={**CONFIG, "allowed_emails": [], "admin_emails": []}):
            response = self.client.get("/accounts/settings/profile/", secure=True)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/accounts/login/", response.url)

    def test_discovery_requires_exact_issuer_and_https(self):
        for override in [{"issuer": "https://evil.example"}, {"token_endpoint": "http://identity.example/token"}]:
            with self.subTest(override=override):
                original = self.metadata.copy()
                self.metadata.update(override)
                self.assertEqual(self.client.post("/accounts/oidc/login/", secure=True).status_code, 503)
                self.metadata = original

    def test_login_requires_post_and_csrf(self):
        self.assertEqual(self.client.get("/accounts/oidc/login/", secure=True).status_code, 405)
        client = Client(enforce_csrf_checks=True)
        self.assertEqual(client.post("/accounts/oidc/login/", secure=True).status_code, 403)

    def test_oidc_only_does_not_accept_local_password_login(self):
        password = secrets.token_urlsafe(24)
        User.objects.create_user("local-admin", "local@example.com", password)
        response = self.client.post("/accounts/login/", {
            "username": "local-admin", "password": password,
        }, secure=True)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(SESSION_KEY, self.client.session)
        self.assertContains(response, "Sign in with Example")
        self.assertNotContains(response, "Forgot password")

    def test_disabled_provider_has_no_login_endpoint(self):
        with override_settings(COMMUNITY_OIDC={**CONFIG, "issuer": ""}):
            self.assertEqual(self.client.post("/accounts/oidc/login/", secure=True).status_code, 404)
