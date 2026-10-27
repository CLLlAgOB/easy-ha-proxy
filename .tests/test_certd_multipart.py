"""Certificate uploads are read without the cgi module.

cgi, which parsed the multipart uploads, was removed in Python 3.13, and
Debian 13 ships 3.13: the certificate daemon would not even start there. The
email parser now reads the same bodies. What must hold: every byte of a
binary file arrives unchanged (a PKCS#12 bundle is binary), field values are
UTF-8, a file input left empty counts as no file, and the request handler
answers through the new parser end to end.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import email.message
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID


ROOT = Path(__file__).resolve().parents[1]
CERTD_PATH = ROOT / "ansible/roles/haproxy-admin/files/haproxy-certd.py"
SPEC = importlib.util.spec_from_file_location("haproxy_certd_multipart_test", CERTD_PATH)
assert SPEC and SPEC.loader
CERTD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CERTD
SPEC.loader.exec_module(CERTD)

BOUNDARY = "----easyhaproxytestboundary"
CONTENT_TYPE = f"multipart/form-data; boundary={BOUNDARY}"


def body(fields: dict[str, str], files: dict[str, tuple[str, bytes]]) -> bytes:
    """A multipart body the way a browser sends it."""
    parts: list[bytes] = []
    for name, value in fields.items():
        parts.append(
            f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'
            f"{value}\r\n".encode("utf-8")
        )
    for name, (filename, content) in files.items():
        parts.append(
            f"--{BOUNDARY}\r\nContent-Disposition: form-data; "
            f'name="{name}"; filename="{filename}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n".encode("utf-8")
        )
        parts.append(content + b"\r\n")
    parts.append(f"--{BOUNDARY}--\r\n".encode("utf-8"))
    return b"".join(parts)


class Parsing(unittest.TestCase):
    def test_every_byte_of_a_binary_file_arrives_unchanged(self):
        tails = (b"", b"\r", b"\n", b"\r\n", b"\r\n\r\n", b"\n\r", b"--")
        for tail in tails:
            content = bytes(range(256)) * 4 + tail
            with self.subTest(tail=tail):
                form = CERTD.MultipartForm.parse(
                    CONTENT_TYPE, body({}, {"file": ("bundle.p12", content)})
                )
                self.assertEqual(form.files["file"].file.read(), content)
                self.assertEqual(form.files["file"].filename, "bundle.p12")

    def test_fields_are_text_and_the_first_value_wins(self):
        raw = body({"name": "сертификат для теста", "password": "", "domain": "a.test"}, {})
        raw = raw.replace(
            f"--{BOUNDARY}--".encode(),
            f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="domain"\r\n\r\nb.test\r\n'
            f"--{BOUNDARY}--".encode(),
        )
        form = CERTD.MultipartForm.parse(CONTENT_TYPE, raw)
        self.assertEqual(form.getfirst("name"), "сертификат для теста")
        self.assertEqual(form.getfirst("password", "x"), "")
        self.assertEqual(form.getfirst("domain"), "a.test")
        self.assertIsNone(form.getfirst("missing"))
        self.assertEqual(form.getfirst("missing", "fallback"), "fallback")

    def test_a_file_input_left_empty_is_no_file(self):
        form = CERTD.MultipartForm.parse(CONTENT_TYPE, body({}, {"file": ("", b"")}))
        self.assertIsNone(CERTD._uploaded_file(form, "file"))
        self.assertIsNone(CERTD._uploaded_file(form, "cert_file"))

    def test_the_content_type_header(self):
        boundary = CERTD.MultipartForm.boundary
        self.assertEqual(boundary(CONTENT_TYPE), ("multipart/form-data", BOUNDARY))
        self.assertEqual(
            boundary('Multipart/Form-Data; boundary="quoted boundary"'),
            ("multipart/form-data", "quoted boundary"),
        )
        self.assertEqual(boundary("multipart/form-data"), ("multipart/form-data", None))
        self.assertEqual(boundary("application/json")[0], "application/json")
        with self.assertRaises(ValueError):
            CERTD.MultipartForm.parse("application/json", b"{}")


def pkcs12_bundle(password: bytes) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "upload.test")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("upload.test")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return pkcs12.serialize_key_and_certificates(
        b"upload", key, certificate, None,
        serialization.BestAvailableEncryption(password),
    )


class TheRequestHandler(unittest.TestCase):
    def post(self, path: str, raw: bytes, content_type: str = CONTENT_TYPE, length=None):
        handler = CERTD.CertdHandler.__new__(CERTD.CertdHandler)
        headers = email.message.Message()
        headers["Content-Type"] = content_type
        headers["Content-Length"] = str(len(raw) if length is None else length)
        handler.headers = headers
        handler.rfile = io.BytesIO(raw)
        handler.wfile = io.BytesIO()
        handler.path = path
        handler.command = "POST"
        handler.request_version = "HTTP/1.1"
        handler.requestline = f"POST {path} HTTP/1.1"
        handler.client_address = "test"
        handler.do_POST()
        head, _, payload = handler.wfile.getvalue().partition(b"\r\n\r\n")
        return int(head.split(b" ", 2)[1]), json.loads(payload)

    def test_a_password_protected_bundle_is_inspected(self):
        raw = body({"password": "pässword"}, {"file": ("site.p12", pkcs12_bundle("pässword".encode()))})
        status, result = self.post("/api/v1/certs/inspect", raw)
        self.assertEqual(status, 200, result)
        self.assertTrue(result["ok"], result)
        self.assertIn("upload.test", json.dumps(result))

    def test_what_is_not_an_upload_is_refused_with_a_reason(self):
        status, result = self.post("/api/v1/certs/inspect", b"{}", content_type="application/json")
        self.assertFalse(result["ok"])
        self.assertIn("multipart/form-data", result["error"])

        status, result = self.post("/api/v1/certs/inspect", b"x", content_type="multipart/form-data")
        self.assertEqual(result["error"], "multipart boundary missing")

        status, result = self.post("/api/v1/certs/inspect", b"", length=0)
        self.assertEqual(status, 413)

        raw = body({}, {"file": ("site.p12", b"abc")})
        status, result = self.post("/api/v1/certs/inspect", raw, length=len(raw) + 10)
        self.assertEqual((status, result["error"]), (400, "the upload was cut short"))

        status, result = self.post("/api/v1/certs/inspect", body({"name": "x"}, {}))
        self.assertEqual((status, result["error"]), (400, "file is required"))


if __name__ == "__main__":
    unittest.main()
