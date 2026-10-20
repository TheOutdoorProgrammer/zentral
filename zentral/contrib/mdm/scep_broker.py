import base64
from collections import Counter
from datetime import datetime, timedelta, timezone as dt_timezone
import hashlib
import hmac
import json
import os
import secrets

from asn1crypto.core import UTF8String
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier
from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from zentral.core.secret_engines import secret_engines
from .models import SCEPChallenge


CHALLENGE_TTL = timedelta(minutes=15)
WEBHOOK_CLOCK_SKEW = timedelta(minutes=5)
SUBJECT_FIELDS = {
    "common_name": NameOID.COMMON_NAME,
    "serial_number": NameOID.SERIAL_NUMBER,
    "country": NameOID.COUNTRY_NAME,
    "organization": NameOID.ORGANIZATION_NAME,
    "organizational_unit": NameOID.ORGANIZATIONAL_UNIT_NAME,
}
SAN_FIELDS = {"dns_names", "email_addresses", "nt_principal_names"}
UPN_OID = ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")


class InvalidChallenge(ValueError):
    pass


class BrokerUnavailable(RuntimeError):
    pass


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidChallenge()
        result[key] = value
    return result


def decode_json(body):
    try:
        value = json.loads(body, object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError, RecursionError):
        raise InvalidChallenge() from None
    if not isinstance(value, dict):
        raise InvalidChallenge()
    return value


def _values(value):
    if not isinstance(value, list) or not 1 <= len(value) <= 16:
        raise InvalidChallenge()
    if any(not isinstance(item, str) or not item or len(item) > 1024 for item in value):
        raise InvalidChallenge()
    return value


def validate_config(config):
    if not isinstance(config, dict) or set(config) - {"subject", "subject_alternative_names", "key_usage"}:
        raise InvalidChallenge()
    # The dedicated CA template issues only RSA clientAuth certificates with usage 5.
    if type(config.get("key_usage")) is not int or config["key_usage"] != 5:
        raise InvalidChallenge()
    subject = config.get("subject")
    if not isinstance(subject, dict) or not subject or set(subject) - SUBJECT_FIELDS.keys():
        raise InvalidChallenge()
    for name, value in subject.items():
        _values([value] if name in ("common_name", "serial_number") else value)
    if not subject.get("common_name"):
        raise InvalidChallenge()
    sans = config.get("subject_alternative_names", {})
    if not isinstance(sans, dict) or set(sans) - SAN_FIELDS:
        raise InvalidChallenge()
    for value in sans.values():
        _values(value)


def mint_challenge(config):
    validate_config(config)
    engine = secret_engines.default_secret_engine
    if engine.__class__.__module__ == secret_engines.noop_engine_backend:
        raise BrokerUnavailable()
    challenge = secrets.token_urlsafe(32)
    row = SCEPChallenge(
        challenge_sha256=hashlib.sha256(challenge.encode()).hexdigest(),
        expires_at=timezone.now() + CHALLENGE_TTL,
    )
    row.set_csr_config(json.dumps(config, separators=(",", ":")))
    row.save(force_insert=True)
    return challenge


def verify_webhook(body, signature, webhook_id):
    configured_id = os.environ.get("ZENTRAL_SCEP_WEBHOOK_ID", "")
    try:
        key = base64.b64decode(os.environ.get("ZENTRAL_SCEP_WEBHOOK_SECRET", ""), validate=True)
    except ValueError:
        raise BrokerUnavailable() from None
    if not configured_id or len(key) < 32:
        raise BrokerUnavailable()
    expected = hmac.new(key, body, hashlib.sha256).hexdigest()
    if (not hmac.compare_digest(expected.encode(), signature.encode()) or
            not hmac.compare_digest(configured_id.encode(), webhook_id.encode())):
        raise InvalidChallenge()
    payload = decode_json(body)
    try:
        timestamp = parse_datetime(payload["timestamp"])
        if timestamp is None or timezone.is_naive(timestamp):
            raise InvalidChallenge()
        if abs(datetime.now(dt_timezone.utc) - timestamp) > WEBHOOK_CLOCK_SKEW:
            raise InvalidChallenge()
    except (KeyError, TypeError, ValueError):
        raise InvalidChallenge() from None
    if payload.get("provisionerName") != "zentral":
        raise InvalidChallenge()
    return payload


def _csr_matches(csr, config):
    if not csr.is_signature_valid:
        return False
    key = csr.public_key()
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048 or key.key_size > 8192:
        return False
    expected_subject = Counter()
    for name, value in config["subject"].items():
        for item in ([value] if name in ("common_name", "serial_number") else value):
            expected_subject[(SUBJECT_FIELDS[name], item)] += 1
    if Counter((attr.oid, attr.value) for attr in csr.subject) != expected_subject:
        return False
    expected_sans = Counter(
        (name, value)
        for name, values in config.get("subject_alternative_names", {}).items()
        for value in values
    )
    actual_sans = Counter()
    for extension in csr.extensions:
        value = extension.value
        if isinstance(value, x509.SubjectAlternativeName):
            for name in value:
                if isinstance(name, x509.DNSName):
                    actual_sans[("dns_names", name.value)] += 1
                elif isinstance(name, x509.RFC822Name):
                    actual_sans[("email_addresses", name.value)] += 1
                elif isinstance(name, x509.OtherName) and name.type_id == UPN_OID:
                    decoded = UTF8String.load(name.value, strict=True)
                    if decoded.dump() != name.value:
                        return False
                    actual_sans[("nt_principal_names", decoded.native)] += 1
                else:
                    return False
        elif isinstance(value, x509.KeyUsage):
            if (not value.digital_signature or not value.key_encipherment or
                    value.content_commitment or value.data_encipherment or value.key_agreement or
                    value.key_cert_sign or value.crl_sign):
                return False
        elif isinstance(value, x509.BasicConstraints):
            if value.ca or value.path_length is not None:
                return False
        elif isinstance(value, x509.ExtendedKeyUsage):
            if list(value) != [ExtendedKeyUsageOID.CLIENT_AUTH]:
                return False
        else:
            return False
    # Apple does not guarantee a CSR KeyUsage extension; the CA fixes issuance usage.
    return actual_sans == expected_sans


def authorize_challenge(payload):
    try:
        challenge = payload["scepChallenge"]
        transaction_id = payload["scepTransactionID"]
        if (not isinstance(challenge, str) or len(challenge) != 43 or
                not isinstance(transaction_id, str) or not 1 <= len(transaction_id) <= 256):
            raise InvalidChallenge()
        raw = base64.b64decode(payload["x509CertificateRequest"]["raw"], validate=True)
        if not raw or len(raw) > 16384:
            raise InvalidChallenge()
        csr = x509.load_der_x509_csr(raw)
        csr_digest = hashlib.sha256(raw).hexdigest()
        transaction_digest = hashlib.sha256(transaction_id.encode()).hexdigest()
        challenge_digest = hashlib.sha256(challenge.encode()).hexdigest()
        with transaction.atomic():
            row = SCEPChallenge.objects.select_for_update().get(challenge_sha256=challenge_digest)
            if row.expires_at <= timezone.now():
                raise InvalidChallenge()
            config = decode_json(row.get_csr_config())
            validate_config(config)
            if not _csr_matches(csr, config):
                raise InvalidChallenge()
            if row.csr_sha256 is not None:
                if row.csr_sha256 != csr_digest or row.transaction_sha256 != transaction_digest:
                    raise InvalidChallenge()
            else:
                row.csr_sha256 = csr_digest
                row.transaction_sha256 = transaction_digest
                row.save(update_fields=("csr_sha256", "transaction_sha256"))
    except (SCEPChallenge.DoesNotExist, KeyError, TypeError, ValueError, UnsupportedAlgorithm,
            x509.DuplicateExtension, x509.UnsupportedGeneralNameType):
        raise InvalidChallenge() from None
