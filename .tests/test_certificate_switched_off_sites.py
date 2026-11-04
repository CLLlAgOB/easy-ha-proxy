"""A certificate only switched-off sites use is not checked (F29).

Confirmed on a production gateway on 31 October: a site paused, with its
renewal paused too, kept raising "certificate expires soon" by email --
nobody was served by the certificate and nobody would renew it. It is now
left out, and an alert it already held closes without a recovery. Anything
else -- a name another site, the admin or sign-in host, or a delivery
target still uses, a certificate nobody is known to use, sites that cannot
be read -- is checked as before.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / "ansible/roles/haproxy-admin/files"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CERTD = load(FILES / "haproxy-certd.py", "haproxy_certd_switched_off")
ALERTD = load(FILES / "easy-ha-proxy-alertd.py", "alertd_switched_off")
CLIENT = load(FILES / "easy_ha_proxy_alert_client.py", "alert_client_switched_off")


def certificate(directory: Path, stem: str, names, *, days_left: float = 10) -> Path:
    now = datetime.now(timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=80)).not_valid_after(now + timedelta(days=days_left))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name) for name in names]), critical=False)
        .sign(key, hashes.SHA256())
    )
    path = directory / f"{stem}.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path


SITES = """\
sites:
  - name: old
    domain: old.example.test
    alt_names: [www.old.example.test]
    paused: true
    cert_renewal_paused: true
  - name: resting
    domain: resting.example.test
    paused: true
  - name: shop
    domain: shop.example.test
"""


class TheScan(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.certs = self.root / "certs"
        self.certs.mkdir()
        (self.root / "websites.yml").write_text(SITES, encoding="utf-8")
        (self.root / "vars.yml").write_text("admin_domain: ha.example.test\n", encoding="utf-8")
        self.deliveries = self.root / "deliveries"
        self.deliveries.mkdir()
        self.reports = []
        for patcher in (
            mock.patch.object(CERTD, "APPLIED_WEBSITES", self.root / "websites.yml"),
            mock.patch.object(CERTD, "CONFIG_YAML", self.root / "vars.yml"),
            mock.patch.object(CERTD, "DELIVERY_DIR", self.deliveries),
            mock.patch.object(CERTD, "_get_haproxy_certs_dir", return_value=self.certs),
            mock.patch.object(CERTD, "report_alert_level",
                              side_effect=lambda rule, subject, **kw: self.reports.append((subject, kw))),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def scanned(self):
        CERTD.CertificateExpiryWatch().scan()
        return {subject: kwargs for subject, kwargs in self.reports}

    def test_a_certificate_only_switched_off_sites_use_is_left_out(self):
        certificate(self.certs, "old.example.test-ecdsa", ["old.example.test", "www.old.example.test"])
        certificate(self.certs, "shop.example.test", ["shop.example.test"])
        seen = self.scanned()
        self.assertTrue(seen["old.example.test-ecdsa"]["retired"])
        self.assertFalse(seen["old.example.test-ecdsa"]["active"])
        self.assertIn("not checked", seen["old.example.test-ecdsa"]["summary"])
        self.assertTrue(seen["shop.example.test"]["active"])
        self.assertNotIn("retired", seen["shop.example.test"])

    def test_paused_but_still_renewed_is_checked(self):
        certificate(self.certs, "resting.example.test", ["resting.example.test"])
        self.assertTrue(self.scanned()["resting.example.test"]["active"])

    def test_shared_with_a_site_in_use_is_checked(self):
        certificate(self.certs, "wild", ["*.example.test"])
        self.assertTrue(self.scanned()["wild"]["active"])

    def test_one_nobody_is_known_to_use_is_checked(self):
        certificate(self.certs, "orphan", ["orphan.example.test"])
        self.assertTrue(self.scanned()["orphan"]["active"])

    def test_the_admin_host_counts_as_in_use(self):
        (self.root / "websites.yml").write_text(
            SITES + "  - name: ha\n    domain: ha.example.test\n    paused: true\n    cert_renewal_paused: true\n",
            encoding="utf-8",
        )
        certificate(self.certs, "ha", ["ha.example.test"])
        self.assertTrue(self.scanned()["ha"]["active"])

    def test_a_name_a_delivery_target_sends_elsewhere_is_in_use(self):
        (self.deliveries / "office.json").write_text(json.dumps({"domains": ["old.example.test"]}), encoding="utf-8")
        certificate(self.certs, "old.example.test-ecdsa", ["old.example.test", "www.old.example.test"])
        self.assertTrue(self.scanned()["old.example.test-ecdsa"]["active"])

    def test_sites_that_cannot_be_read_mean_everything_is_checked(self):
        (self.root / "websites.yml").write_text("sites: [", encoding="utf-8")
        certificate(self.certs, "old.example.test-ecdsa", ["old.example.test"])
        self.assertTrue(self.scanned()["old.example.test-ecdsa"]["active"])


class TheEngine(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.database = ALERTD.AlertDatabase(str(Path(folder.name) / "alerts.db"))
        self.addCleanup(self.database.close)
        self.sent = []
        sent = self.sent

        class Channel(ALERTD.Channel):
            name = "recording"

            def available(self, config):
                return True

            def send(self, config, subject, body):
                sent.append(subject)
                return True, ""

        self.engine = ALERTD.AlertEngine(ALERTD.AlertConfig(recipient="ops@example.test"),
                                         self.database, [Channel()])

    def test_a_retired_certificate_closes_its_alert_without_a_recovery(self):
        self.engine.observe({"rule": "certificate.expiring", "subject": "old.example.test-ecdsa", "active": True})
        self.assertEqual(len(self.sent), 1)
        result = self.engine.observe({"rule": "certificate.expiring", "subject": "old.example.test-ecdsa",
                                      "active": False, "retired": True,
                                      "summary": "not checked: only switched-off sites use it"})
        self.assertEqual(result["transition"], "retired")
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.database.open_states(), [])
        event = self.database.events(limit=1)["events"][0]
        self.assertEqual((event["transition"], event["detail"]),
                         ("retired", "not checked: only switched-off sites use it"))

    def test_retired_with_nothing_open_records_nothing(self):
        self.engine.observe({"rule": "certificate.expiring", "subject": "old", "active": False, "retired": True})
        self.assertEqual(self.database.open_states(), [])
        self.assertEqual(self.database.events(limit=5)["events"], [])


class SavedButNotApplied(unittest.TestCase):
    """R05 (4 November review): the sites as applied were read with the
    admin and sign-in names of the saved draft. After a Save without Apply
    the old admin name -- still served -- looked unused, and a certificate
    for it and a switched-off site was left unchecked."""

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        root = Path(folder.name)
        self.draft = root / "config"
        self.applied = root / "applied"
        self.draft.mkdir()
        self.applied.mkdir()
        for patcher in (
            mock.patch.object(CERTD, "CONFIG_YAML", self.draft / "vars.yml"),
            mock.patch.object(CERTD, "APPLIED_WEBSITES", self.applied / "last_applied_websites.yml"),
            mock.patch.object(CERTD, "APPLIED_VARS", self.applied / "last_applied_vars.yml"),
            mock.patch.object(CERTD, "DELIVERY_DIR", root / "deliveries"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def write(self, applied_sites, applied_vars, draft_sites, draft_vars):
        (self.applied / "last_applied_websites.yml").write_text(applied_sites, encoding="utf-8")
        (self.applied / "last_applied_vars.yml").write_text(applied_vars, encoding="utf-8")
        (self.draft / "websites.yml").write_text(draft_sites, encoding="utf-8")
        (self.draft / "vars.yml").write_text(draft_vars, encoding="utf-8")

    def only_switched_off(self, *names):
        return CERTD._only_switched_off(list(names), CERTD.certificate_users())

    OFF = ("sites:\n  - name: old\n    domain: old.example.test\n"
           "    paused: true\n    cert_renewal_paused: true\n")

    def test_the_admin_name_still_served_counts_after_a_save_without_apply(self):
        self.write(self.OFF, "admin_domain: old.example.test\n", self.OFF, "admin_domain: new.example.test\n")
        self.assertFalse(self.only_switched_off("old.example.test"))

    def test_a_site_switched_on_again_but_not_applied_counts(self):
        on = "sites:\n  - name: old\n    domain: old.example.test\n"
        self.write(self.OFF, "admin_domain: ha.example.test\n", on, "admin_domain: ha.example.test\n")
        self.assertFalse(self.only_switched_off("old.example.test"))

    def test_switched_off_in_both_is_still_left_out(self):
        self.write(self.OFF, "admin_domain: ha.example.test\n", self.OFF, "admin_domain: ha.example.test\n")
        self.assertTrue(self.only_switched_off("old.example.test"))

    def test_nothing_applied_yet_reads_the_draft(self):
        (self.draft / "websites.yml").write_text(self.OFF, encoding="utf-8")
        (self.draft / "vars.yml").write_text("admin_domain: ha.example.test\n", encoding="utf-8")
        self.assertTrue(self.only_switched_off("old.example.test"))
        self.assertFalse(self.only_switched_off("ha.example.test"))


class TheClient(unittest.TestCase):
    def test_it_passes_retired_on(self):
        source = (FILES / "easy_ha_proxy_alert_client.py").read_text(encoding="utf-8")
        self.assertIn('payload["retired"] = True', source)
        # Part of what makes two reports the same, or a retire after an
        # identical active report would be dropped as a repeat.
        self.assertIn("retired)", source.split("signature = (")[1].split("\n")[0])


if __name__ == "__main__":
    unittest.main()
