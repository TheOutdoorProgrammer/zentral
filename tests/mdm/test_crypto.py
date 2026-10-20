import os.path
import plistlib
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID
from django.core.exceptions import SuspiciousOperation
from django.test import SimpleTestCase
from django.test.client import RequestFactory
from OpenSSL import crypto

from zentral.conf import settings
from zentral.contrib.mdm.crypto import verify_iphone_ca_signed_payload, verify_signed_payload, verify_store_certificate
from zentral.contrib.mdm.public_views.mdm import MDMView


class MDMCryptoTestCase(SimpleTestCase):
    def test_verify_iphone_ca_signed_payload(self):
        with open(
            os.path.join(os.path.dirname(__file__), "testdata/ota_playload_phase_2"),
            "rb",
        ) as f:
            signed_payload = f.read()
        payload = verify_iphone_ca_signed_payload(signed_payload)
        self.assertEqual(
            plistlib.loads(payload),
            {
                "CHALLENGE": "8gLEIttrT7qbLOZs3XzL5XPgNXCliGwRLtn2Lfe4GBsa7g6MGm2sJjicKrLFal4D",
                "IMEI": "",
                "MEID": "",
                "NotOnConsole": False,
                "PRODUCT": "VirtualMac2,1",
                "SERIAL": "ZDL2M9PTJ3",
                "UDID": "78897E40-F532-5DE0-A7DC-56BAC5CEEB9C",
                "UserID": "D9DD912C-1B1E-413F-86A5-3BE29F13AB2D",
                "UserLongName": "admin",
                "UserShortName": "admin",
                "VERSION": "22A380",
            },
        )


class SignedPayloadIntegrityTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test signer")])
        now = datetime.now(timezone.utc)
        cls.certificate = (
            x509.CertificateBuilder().subject_name(cls.name).issuer_name(cls.name)
            .public_key(cls.key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
            .sign(cls.key, hashes.SHA256())
        )
        cls.payload = plistlib.dumps({"MessageType": "Authenticate"})

    def sign(self, detached=False, no_attributes=False):
        options = [pkcs7.PKCS7Options.Binary]
        if detached:
            options.append(pkcs7.PKCS7Options.DetachedSignature)
        if no_attributes:
            options.append(pkcs7.PKCS7Options.NoAttributes)
        return (
            pkcs7.PKCS7SignatureBuilder().set_data(self.payload)
            .add_signer(self.certificate, self.key, hashes.SHA256())
            .sign(serialization.Encoding.DER, options)
        )

    def test_attached_and_detached_signatures(self):
        for detached in (False, True):
            for no_attributes in (False, True):
                with self.subTest(detached=detached, no_attributes=no_attributes):
                    signed = self.sign(detached, no_attributes)
                    certs, data = verify_signed_payload(
                        self.payload if detached else signed, signed if detached else None)
                    self.assertEqual(data, self.payload)
                    self.assertEqual(certs[0][2], self.certificate)

    def test_detached_payload_tampering(self):
        for no_attributes in (False, True):
            with self.subTest(no_attributes=no_attributes), self.assertRaises(ValueError):
                verify_signed_payload(self.payload + b"modified", self.sign(True, no_attributes))

    def test_attached_payload_tampering(self):
        content = cms.ContentInfo.load(self.sign())
        content["content"]["encap_content_info"]["content"] = self.payload + b"modified"
        with self.assertRaises(ValueError):
            verify_signed_payload(content.dump())

    def test_unsigned_and_missing_signer_certificate(self):
        for field in ("signer_infos", "certificates"):
            content = cms.ContentInfo.load(self.sign())
            content["content"][field] = []
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify_signed_payload(content.dump())

    def test_malformed_signed_attributes(self):
        for attribute_name in ("message_digest", "content_type"):
            for duplicate in (False, True):
                content = cms.ContentInfo.load(self.sign())
                signer = content["content"]["signer_infos"][0]
                attributes = list(signer["signed_attrs"])
                if duplicate:
                    attributes += [a for a in attributes if a["type"].native == attribute_name]
                else:
                    attributes = [a for a in attributes if a["type"].native != attribute_name]
                signer["signed_attrs"] = attributes
                with self.subTest(attribute=attribute_name, duplicate=duplicate), self.assertRaises(ValueError):
                    verify_signed_payload(content.dump())

    def test_attached_signature_not_accepted_as_detached(self):
        with self.assertRaises(ValueError):
            verify_signed_payload(self.payload, self.sign())

    def test_trailing_data_rejected(self):
        with self.assertRaises(ValueError):
            verify_signed_payload(self.sign() + b"trailing")

    def test_untrusted_signed_mdm_request_rejected_before_database_access(self):
        import base64

        request = RequestFactory().put(
            "/", data=self.payload, content_type="application/x-apple-aspen-mdm",
            HTTP_MDM_SIGNATURE=base64.b64encode(self.sign(True)).decode(),
        )
        with patch("zentral.contrib.mdm.crypto.SCEP_CA_STORE", crypto.X509Store()), \
                patch.object(MDMView, "post_event") as event, \
                self.assertRaises(SuspiciousOperation):
            MDMView.as_view()(request)
        event.assert_called_once_with("failure", reason="Invalid header signature")

    def test_proxy_identity_cannot_bypass_required_signature(self):
        request = RequestFactory().put(
            "/", data=self.payload, content_type="application/x-apple-aspen-mdm",
            HTTP_X_SSL_CLIENT_S_DN="CN=MDM$OTA$forged,O=MBU$1,serialNumber=forged",
        )
        with patch.dict(settings["apps"]["zentral.contrib.mdm"], {"mtls_proxy": False}), \
                patch.object(MDMView, "post_event") as event, \
                self.assertRaises(SuspiciousOperation):
            MDMView.as_view()(request)
        event.assert_called_once_with("failure", reason="Missing header signature")

    def test_device_certificate_chain_and_validity(self):
        now = datetime.now(timezone.utc)
        ca = (
            x509.CertificateBuilder().subject_name(self.name).issuer_name(self.name)
            .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=2)).not_valid_after(now + timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(self.key, hashes.SHA256())
        )
        store = crypto.X509Store()
        store.add_cert(crypto.X509.from_cryptography(ca))
        device_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        for start, end, trusted in (
            (-1, 1, True),
            (-2, -1, False),
            (1, 2, False),
        ):
            certificate = (
                x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "device")]))
                .issuer_name(self.name).public_key(device_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now + timedelta(days=start))
                .not_valid_after(now + timedelta(days=end))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .sign(self.key, hashes.SHA256())
            )
            with self.subTest(start=start, end=end):
                self.assertEqual(verify_store_certificate(
                    store, certificate.public_bytes(serialization.Encoding.DER)), trusted)
