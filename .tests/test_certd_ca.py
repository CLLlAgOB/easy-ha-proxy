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
from cryptography.hazmat.primitives import hashes, serialization
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
        self.content = content


def Form(fields: dict[str, str], files: dict[str, Upload]):
    """Build the cgi.FieldStorage the daemon will really be handed.

    This used to be a dict subclass, and that is exactly how an upload could
    crash the daemon while the tests stayed green: a real FieldStorage part
    holding a file raises TypeError from ``bool()`` and from ``in``, and a
    dict does neither. A stand-in that is easier to satisfy than the real
    thing tests nothing about the real thing, so the multipart body is
    assembled here for real and parsed by cgi itself.
    """
    import cgi

    boundary = "----easyhaproxytestboundary"
    parts: list[bytes] = []
    for name, value in fields.items():
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'
            f"{value}\r\n".encode("utf-8")
        )
    for name, upload in files.items():
        parts.append(
            f"--{boundary}\r\nContent-Disposition: form-data; "
            f'name="{name}"; filename="{upload.filename}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n".encode("utf-8")
        )
        parts.append(upload.content + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode("utf-8"))
    body = b"".join(parts)

    return cgi.FieldStorage(
        fp=io.BytesIO(body),
        headers={
            "content-type": f"multipart/form-data; boundary={boundary}",
            "content-length": str(len(body)),
        },
        environ={
            "REQUEST_METHOD": "POST",
            "CONTENT_TYPE": f"multipart/form-data; boundary={boundary}",
        },
        keep_blank_values=True,
    )


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

    def test_an_upload_with_no_file_answers_instead_of_crashing(self) -> None:
        # The operator submitting the form with nothing attached must get a
        # message, not a dropped connection.
        status, result = CERTD.handle_external_ca_upload_form(
            Form({"name": "company-pki"}, {})
        )
        self.assertEqual(status, 400)
        self.assertIn("ca_file", result["error"])

        status, result = CERTD.handle_certs_upload_form(Form({"domain": "a.test"}, {}))
        self.assertFalse(result["ok"])
        self.assertIn("cert_file", result["error"])

    def test_ca_root_symlink_is_rejected(self) -> None:
        target = Path(self.temporary.name) / "redirected"
        target.mkdir()
        CERTD.CA_ROOT_DIR.symlink_to(target, target_is_directory=True)

        with self.assertRaisesRegex(ValueError, "must not be a symlink"):
            CERTD._ensure_internal_ca()


class SortedUploadTests(unittest.TestCase):
    """One field that reads the file and works out what it is.

    The point of the feature is that the operator does not have to know
    whether they were handed PEM, DER or PKCS#12, nor which piece is an
    authority and which is the server certificate -- so the tests hand it
    each of those shapes and check it sorts them the same way.
    """

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        CERTD.HAPROXY_CERTS_DIR = (root / "certs").resolve()
        CERTD.CA_ROOT_DIR = (root / "certificate-authorities").resolve()
        CERTD.MTLS_DIR = (root / "mtls").resolve()
        self.reload = mock.patch.object(
            CERTD, "_reload_haproxy", return_value=(0, "", "")
        )
        self.reload.start()
        self.addCleanup(self.reload.stop)
        self.addCleanup(self.temporary.cleanup)
        self.build_pki()

    def build_pki(self) -> None:
        import datetime

        from cryptography.x509.oid import NameOID

        now = datetime.datetime.now(datetime.timezone.utc)

        def name(common: str) -> x509.Name:
            return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)])

        def sign(subject, issuer_name, issuer_key, key, *, ca, san=None):
            builder = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer_name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=30))
                .add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
            )
            if san:
                builder = builder.add_extension(
                    x509.SubjectAlternativeName([x509.DNSName(san)]), False
                )
            return builder.sign(issuer_key, hashes.SHA256())

        self.root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.root = sign(
            name("Third Party Root"), name("Third Party Root"), self.root_key,
            self.root_key, ca=True,
        )
        self.interm_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.interm = sign(
            name("Third Party Issuing"), self.root.subject, self.root_key,
            self.interm_key, ca=True,
        )
        self.leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.leaf = sign(
            name("app.example.test"), self.interm.subject, self.interm_key,
            self.leaf_key, ca=False, san="app.example.test",
        )

    def pem(self, *parts: object) -> bytes:
        out = b""
        for part in parts:
            if isinstance(part, x509.Certificate):
                out += part.public_bytes(serialization.Encoding.PEM)
            else:
                out += part.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
        return out

    def test_a_pem_holding_everything_is_sorted(self) -> None:
        form = Form(
            {},
            {"file": Upload(
                "everything.pem",
                self.pem(self.leaf, self.interm, self.root, self.leaf_key),
            )},
        )
        status, plan = CERTD.handle_certs_inspect_form(form)
        self.assertEqual(status, 200, plan)
        self.assertEqual(plan["format"], "PEM")
        self.assertEqual(len(plan["authorities"]), 2)
        self.assertEqual(plan["server_certificate"]["domain"], "app.example.test")
        self.assertEqual(plan["ca_id"], "third-party-root")

    def test_inspecting_installs_nothing(self) -> None:
        CERTD.handle_certs_inspect_form(
            Form({}, {"file": Upload("all.pem", self.pem(self.root, self.leaf, self.leaf_key))})
        )
        self.assertFalse(CERTD.HAPROXY_CERTS_DIR.exists())
        self.assertFalse((CERTD.CA_ROOT_DIR / "external").exists())

    def test_importing_places_each_piece_where_it_belongs(self) -> None:
        status, result = CERTD.handle_certs_import_form(
            Form(
                {"name": "third-party"},
                {"file": Upload(
                    "everything.pem",
                    self.pem(self.leaf, self.interm, self.root, self.leaf_key),
                )},
            )
        )
        self.assertEqual(status, 200, result)
        self.assertTrue(result["ok"], result)
        bundle = CERTD.CA_ROOT_DIR / "external" / "third-party.pem"
        self.assertEqual(bundle.read_bytes().count(b"BEGIN CERTIFICATE"), 2)
        installed = CERTD.HAPROXY_CERTS_DIR / "app.example.test.pem"
        self.assertTrue(installed.is_file())
        self.assertEqual(len(result["completed"]), 2)

    def test_the_root_is_left_out_of_what_haproxy_sends(self) -> None:
        # A client that does not already trust the root will not start
        # trusting it because the server attached a copy.
        CERTD.handle_certs_import_form(
            Form(
                {"name": "third-party"},
                {"file": Upload(
                    "everything.pem",
                    self.pem(self.leaf, self.interm, self.root, self.leaf_key),
                )},
            )
        )
        installed = (CERTD.HAPROXY_CERTS_DIR / "app.example.test.pem").read_bytes()
        subjects = [
            CERTD._certificate_label(cert)
            for cert in CERTD._load_pem_certificates(installed)
        ]
        self.assertEqual(subjects, ["app.example.test", "Third Party Issuing"])

    def test_pkcs12_is_read_the_same_way(self) -> None:
        from cryptography.hazmat.primitives.serialization import pkcs12

        blob = pkcs12.serialize_key_and_certificates(
            b"bundle", self.leaf_key, self.leaf, [self.interm, self.root],
            serialization.BestAvailableEncryption(b"secret"),
        )
        status, plan = CERTD.handle_certs_inspect_form(
            Form({"password": "secret"}, {"file": Upload("bundle.p12", blob)})
        )
        self.assertEqual(status, 200, plan)
        self.assertEqual(plan["format"], "PKCS#12")
        self.assertEqual(len(plan["authorities"]), 2)
        self.assertEqual(plan["server_certificate"]["domain"], "app.example.test")

    def test_a_pkcs12_without_its_password_says_so(self) -> None:
        from cryptography.hazmat.primitives.serialization import pkcs12

        blob = pkcs12.serialize_key_and_certificates(
            b"bundle", self.leaf_key, self.leaf, None,
            serialization.BestAvailableEncryption(b"secret"),
        )
        status, result = CERTD.handle_certs_inspect_form(
            Form({}, {"file": Upload("bundle.p12", blob)})
        )
        self.assertEqual(status, 400)
        self.assertIn("password", result["error"])

    def test_a_der_certificate_is_recognised(self) -> None:
        status, plan = CERTD.handle_certs_inspect_form(
            Form(
                {},
                {"file": Upload(
                    "root.cer", self.root.public_bytes(serialization.Encoding.DER)
                )},
            )
        )
        self.assertEqual(status, 200, plan)
        self.assertEqual(plan["format"], "DER")
        self.assertEqual(len(plan["authorities"]), 1)
        self.assertIsNone(plan["server_certificate"])

    def test_a_certificate_without_its_key_is_not_installed(self) -> None:
        status, result = CERTD.handle_certs_import_form(
            Form({}, {"file": Upload("leaf.pem", self.pem(self.leaf))})
        )
        self.assertEqual(status, 400)
        self.assertIn("private key", result["error"])
        self.assertFalse(CERTD.HAPROXY_CERTS_DIR.exists())

    def test_something_that_is_not_certificate_material(self) -> None:
        status, result = CERTD.handle_certs_inspect_form(
            Form({}, {"file": Upload("notes.txt", b"just some notes\n")})
        )
        self.assertEqual(status, 400)
        self.assertIn("PEM, DER or PKCS#12", result["error"])

    def test_replacing_an_authority_needs_saying_so(self) -> None:
        first = Form(
            {"name": "third-party"},
            {"file": Upload("root.pem", self.pem(self.root))},
        )
        CERTD.handle_certs_import_form(first)

        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        import datetime

        from cryptography.x509.oid import NameOID

        now = datetime.datetime.now(datetime.timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Someone Else")])
        other = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(other_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(other_key, hashes.SHA256())
        )

        status, result = CERTD.handle_certs_import_form(
            Form(
                {"name": "third-party"},
                {"file": Upload("other.pem", self.pem(other))},
            )
        )
        self.assertEqual(status, 409)
        self.assertTrue(result["needs_replace"])

        status, result = CERTD.handle_certs_import_form(
            Form(
                {"name": "third-party", "replace": "true"},
                {"file": Upload("other.pem", self.pem(other))},
            )
        )
        self.assertEqual(status, 200, result)

    def test_the_same_authority_again_is_not_a_conflict(self) -> None:
        for _ in range(2):
            status, result = CERTD.handle_certs_import_form(
                Form(
                    {"name": "third-party"},
                    {"file": Upload("root.pem", self.pem(self.root))},
                )
            )
            self.assertEqual(status, 200, result)

    def test_a_leaf_that_the_bundled_authority_did_not_sign_is_refused(self) -> None:
        # The chain is verified against the authority from the same upload,
        # so a mismatched pair cannot be installed as if it were consistent.
        import datetime

        from cryptography.x509.oid import NameOID

        now = datetime.datetime.now(datetime.timezone.utc)
        stranger_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "app.example.test")]
        )
        stranger = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(stranger_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("app.example.test")]), False
            )
            .sign(stranger_key, hashes.SHA256())
        )
        status, result = CERTD.handle_certs_import_form(
            Form(
                {"name": "third-party"},
                {"file": Upload(
                    "mixed.pem", self.pem(stranger, self.root, stranger_key)
                )},
            )
        )
        self.assertEqual(status, 400)
        self.assertIn("does not verify", result["error"])


if __name__ == "__main__":
    unittest.main()
