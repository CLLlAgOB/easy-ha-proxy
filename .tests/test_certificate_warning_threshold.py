"""A certificate warning means renewal is failing, not that it is due.

Every Let's Encrypt certificate raised "expires soon" once per cycle. certbot
renews when less than 30 days remain; the warning fired at 30 or fewer,
counted in whole days rounded down -- so from 31 days out, a day before
certbot even looked, and certbot looks only twice a day besides.

An automated certificate (100 days or less) is now reported at a quarter of
its lifetime: 22 days of a 90-day one, after eight days of failed renewals,
and 11 of a 45-day one. A certificate renewed by hand keeps 30 days to act.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


ROOT = Path(__file__).resolve().parents[1]
CERTD_PATH = ROOT / "ansible/roles/haproxy-admin/files/haproxy-certd.py"
SPEC = importlib.util.spec_from_file_location("haproxy_certd_warn", CERTD_PATH)
CERTD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CERTD)


def certificate(directory: Path, *, lifetime: int, left: float) -> Path:
    now = datetime.now(timezone.utc)
    not_after = now + timedelta(days=left)
    not_before = not_after - timedelta(days=lifetime)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "shop.example.test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before).not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    path = directory / f"cert-{lifetime}-{left}.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path


class Thresholds(unittest.TestCase):
    def test_by_lifetime(self):
        self.assertEqual(CERTD.cert_warn_days(90), 22)
        self.assertEqual(CERTD.cert_warn_days(45), 11)
        self.assertEqual(CERTD.cert_warn_days(6), 1)
        self.assertEqual(CERTD.cert_warn_days(365), 30)
        self.assertEqual(CERTD.cert_warn_days(None), 30)


class RealCertificates(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.dir = Path(directory.name)

    def info(self, **kwargs):
        return CERTD._load_cert_info(certificate(self.dir, **kwargs))

    def test_a_lets_encrypt_certificate_due_for_renewal_is_not_a_warning(self):
        # The reported case: 30 days and a bit left, certbot about to renew.
        info = self.info(lifetime=90, left=30.5)
        self.assertEqual(info["lifetime_days"], 90)
        self.assertGreater(info["days_left"], info["warn_days"])
        info = self.info(lifetime=90, left=25.5)
        self.assertGreater(info["days_left"], info["warn_days"])

    def test_one_whose_renewal_has_been_failing_is(self):
        info = self.info(lifetime=90, left=21.5)
        self.assertLessEqual(info["days_left"], info["warn_days"])

    def test_a_certificate_renewed_by_hand_still_warns_a_month_ahead(self):
        info = self.info(lifetime=365, left=29.5)
        self.assertEqual(info["warn_days"], 30)
        self.assertLessEqual(info["days_left"], info["warn_days"])

    def test_the_list_and_the_alert_use_the_same_threshold(self):
        source = CERTD_PATH.read_text(encoding="utf-8")
        watch = source.split("class CertificateExpiryWatch")[1].split("\ndef ")[0]
        self.assertIn('days <= int(info["warn_days"])', watch)
        self.assertNotIn("<= CERT_WARN_DAYS", source)


if __name__ == "__main__":
    unittest.main()
