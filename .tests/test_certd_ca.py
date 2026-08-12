from __future__ import annotations

import base64
import io
import importlib.util
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID


ROOT = Path(__file__).resolve().parents[1]
CERTD_PATH = ROOT / "ansible/roles/haproxy-admin/files/haproxy-certd.py"
SPEC = importlib.util.spec_from_file_location("haproxy_certd_test", CERTD_PATH)
assert SPEC and SPEC.loader
CERTD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CERTD)


class Upload:
    def __init__(self, filename: str, content: bytes) -> None:
        self.filename = filename
        self.file = io.BytesIO(content)


class Form(dict):
    def __init__(self, fields: dict[str, str], files: dict[str, Upload]) -> None:
        super().__init__(files)
        self.fields = fields

    def getfirst(self, name: str, default: str = "") -> str:
        return self.fields.get(name, default)


class CertificateAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        CERTD.HAPROXY_CERTS_DIR = (root / "certs").resolve()
        CERTD.CA_ROOT_DIR = (root / "certificate-authorities").resolve()
        CERTD.LETSENCRYPT_ROOT_DIR = (root / "letsencrypt").resolve()
        CERTD.CERTBOT_BIN = root / "certbot"
        CERTD.CERTBOT_BIN.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        CERTD.CERTD_DRY_RUN = True

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_internal_ca_issues_server_pem_and_exports_only_public_cert(self) -> None:
        status, result = CERTD.handle_internal_cert_issue(
            {"domain": "app.example.com", "alt_names": ["www.example.com"]}
        )

        self.assertEqual(status, 200)
        self.assertTrue(result["ok"], result)
        pem_path = Path(result["path"])
        certificates, _ = CERTD._validate_server_pem(
            pem_path.read_bytes(), "app.example.com"
        )
        san = certificates[0].extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
        self.assertEqual(
            set(san.get_values_for_type(x509.DNSName)),
            {"app.example.com", "www.example.com"},
        )

        export_status, exported = CERTD.handle_ca_export({"ca_id": "internal"})
        self.assertEqual(export_status, 200)
        public_data = base64.b64decode(exported["certificate_b64"])
        self.assertIn(b"BEGIN CERTIFICATE", public_data)
        self.assertNotIn(b"PRIVATE KEY", public_data)

    def test_letsencrypt_rejects_reserved_test_domain_with_actionable_error(self) -> None:
        status, result = CERTD.handle_certs_issue(
            {"domain": "app.example.test", "alt_names": []}
        )

        self.assertEqual(status, 200)
        self.assertFalse(result["ok"])
        self.assertEqual(result["domain"], "app.example.test")
        self.assertIn("Select Internal CA", result["error"])

    def test_first_letsencrypt_issue_allows_certbot_to_create_account(self) -> None:
        completed = {
            "lineage": "app.example.com",
            "rc": 0,
            "stdout": "created",
            "stderr": "",
            "cmd": "certbot",
        }
        with mock.patch.object(
            CERTD, "_run_certbot_for_lineage", return_value=completed
        ) as run_certbot:
            status, result = CERTD.handle_certs_issue(
                {"domain": "app.example.com", "key_types": ["ecdsa"]}
            )

        self.assertEqual(status, 200)
        self.assertTrue(result["ok"], result)
        self.assertIsNone(run_certbot.call_args.kwargs["account_id"])

    def test_letsencrypt_failure_returns_certbot_diagnostics(self) -> None:
        completed = {
            "lineage": "app.example.com",
            "rc": 1,
            "stdout": "",
            "stderr": "ACME challenge failed",
            "cmd": "certbot",
        }
        with mock.patch.object(
            CERTD, "_run_certbot_for_lineage", return_value=completed
        ):
            status, result = CERTD.handle_certs_issue(
                {"domain": "app.example.com", "key_types": ["ecdsa"]}
            )

        self.assertEqual(status, 200)
        self.assertFalse(result["ok"])
        self.assertEqual(result["domain"], "app.example.com")
        self.assertEqual(result["error"], "ACME challenge failed")

    def test_internal_ca_is_reused(self) -> None:
        _, first = CERTD.handle_internal_ca_ensure({})
        _, second = CERTD.handle_internal_ca_ensure({})

        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        key_path, _ = CERTD._internal_ca_paths()
        self.assertEqual(stat.S_IMODE(CERTD.CA_ROOT_DIR.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)
        self.assertEqual(
            first["certificate_authority"]["sha256"],
            second["certificate_authority"]["sha256"],
        )

    def test_internal_ca_rotation_reissues_every_signed_certificate(self) -> None:
        CERTD.handle_internal_cert_issue({"domain": "app.example.com"})
        CERTD.handle_internal_cert_issue(
            {"domain": "api.example.com", "alt_names": ["www.example.com"]}
        )
        _, before = CERTD.handle_internal_ca_ensure({})

        status, result = CERTD.handle_internal_ca_rotate({"confirmation": "ROTATE"})

        self.assertEqual(status, 200)
        self.assertTrue(result["ok"], result)
        self.assertEqual(len(result["reissued"]), 2)
        self.assertNotEqual(
            before["certificate_authority"]["sha256"],
            result["certificate_authority"]["sha256"],
        )
        new_ca, _, _ = CERTD._ensure_internal_ca()
        for path in CERTD.HAPROXY_CERTS_DIR.glob("*.pem"):
            leaf = CERTD._load_first_cert_from_pem(path)
            self.assertIsNotNone(leaf)
            self.assertTrue(CERTD._certificate_is_issued_by(leaf, new_ca))

    def test_internal_ca_rotation_rolls_back_when_haproxy_rejects_it(self) -> None:
        CERTD.handle_internal_cert_issue({"domain": "app.example.com"})
        pem_path = CERTD.HAPROXY_CERTS_DIR / "app.example.com.pem"
        previous_pem = pem_path.read_bytes()
        _, previous = CERTD.handle_internal_ca_ensure({})
        CERTD.CERTD_DRY_RUN = False

        with mock.patch.object(
            CERTD, "_reload_haproxy", return_value=(1, "", "invalid configuration")
        ):
            status, result = CERTD.handle_internal_ca_rotate(
                {"confirmation": "ROTATE"}
            )

        self.assertEqual(status, 500)
        self.assertFalse(result["ok"])
        self.assertEqual(pem_path.read_bytes(), previous_pem)
        _, restored = CERTD.handle_internal_ca_ensure({})
        self.assertEqual(
            restored["certificate_authority"]["sha256"],
            previous["certificate_authority"]["sha256"],
        )

    def test_internal_ca_delete_is_blocked_until_signed_certificates_are_removed(self) -> None:
        CERTD.handle_internal_cert_issue({"domain": "app.example.com"})

        blocked_status, blocked = CERTD.handle_internal_ca_delete(
            {"confirmation": "DELETE"}
        )
        self.assertEqual(blocked_status, 409)
        self.assertEqual(len(blocked["blocking_certificates"]), 1)

        (CERTD.HAPROXY_CERTS_DIR / "app.example.com.pem").unlink()
        deleted_status, deleted = CERTD.handle_internal_ca_delete(
            {"confirmation": "DELETE"}
        )
        self.assertEqual(deleted_status, 200)
        self.assertTrue(deleted["ok"])
        self.assertFalse((CERTD.CA_ROOT_DIR / "internal").exists())

    def test_ca_bundle_rejects_private_keys(self) -> None:
        cert, key, _ = CERTD._ensure_internal_ca()
        bundle = cert.public_bytes(serialization.Encoding.PEM) + key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

        with self.assertRaisesRegex(ValueError, "must not contain a private key"):
            CERTD._validate_ca_bundle(bundle)

    def test_server_pem_rejects_mismatched_private_key(self) -> None:
        CERTD.handle_internal_cert_issue({"domain": "app.example.com"})
        pem_path = CERTD.HAPROXY_CERTS_DIR / "app.example.com.pem"
        certificates = CERTD._load_pem_certificates(pem_path.read_bytes())
        unrelated_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        invalid_pem = b"".join(
            cert.public_bytes(serialization.Encoding.PEM) for cert in certificates
        ) + unrelated_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

        with self.assertRaisesRegex(ValueError, "does not match"):
            CERTD._validate_server_pem(invalid_pem, "app.example.com")

    def test_external_ca_import_and_server_chain_verification(self) -> None:
        CERTD.handle_internal_cert_issue({"domain": "app.example.com"})
        server_pem = (
            CERTD.HAPROXY_CERTS_DIR / "app.example.com.pem"
        ).read_bytes()
        _, root_path = CERTD._internal_ca_paths()
        ca_form = Form(
            {"name": "company-pki"},
            {"ca_file": Upload("root.crt", root_path.read_bytes())},
        )

        ca_status, ca_result = CERTD.handle_external_ca_upload_form(ca_form)
        self.assertEqual(ca_status, 200)
        self.assertTrue(ca_result["ok"], ca_result)

        cert_form = Form(
            {
                "site_name": "app",
                "domain": "app.example.com",
                "external_ca_id": "company-pki",
            },
            {"cert_file": Upload("app.pem", server_pem)},
        )
        cert_status, cert_result = CERTD.handle_certs_upload_form(cert_form)

        self.assertEqual(cert_status, 200)
        self.assertTrue(cert_result["ok"], cert_result)
        self.assertEqual(cert_result["external_ca_id"], "company-pki")

    def test_ca_root_symlink_is_rejected(self) -> None:
        target = Path(self.temporary.name) / "redirected"
        target.mkdir()
        CERTD.CA_ROOT_DIR.symlink_to(target, target_is_directory=True)

        with self.assertRaisesRegex(ValueError, "must not be a symlink"):
            CERTD._ensure_internal_ca()


if __name__ == "__main__":
    unittest.main()
