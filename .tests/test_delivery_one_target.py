"""Sending to one delivery target writes that target alone (F18).

From the 30 October review, reproduced there without SSH: "Send now" on a
target handed the worker the target's domains, and the worker sent to
every target naming any of them. With A on a.example.test and
b.example.test and B on b.example.test, sending to A overwrote B's files
and ran B's post_command -- with a certificate that need not cover B.

The worker now takes --target for an operator's send and writes that one
record only. Before any connection, renewal or not, the certificate must
cover every name the target lists: a target receives one certificate.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / "ansible" / "roles" / "haproxy-admin" / "files"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


deliver = load("cert_deliver_one_target", FILES / "easy-ha-proxy-cert-deliver.py")


def have_openssl():
    try:
        return subprocess.run(["openssl", "version"], capture_output=True, check=False).returncode == 0
    except OSError:
        return False


def issue(lineage: Path, *names):
    lineage.mkdir(parents=True)
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
         "-nodes", "-days", "2", "-subj", f"/CN={names[0]}",
         "-addext", "subjectAltName=" + ",".join(f"DNS:{n}" for n in names),
         "-keyout", str(lineage / "privkey.pem"), "-out", str(lineage / "fullchain.pem")],
        capture_output=True, check=True,
    )


@unittest.skipUnless(have_openssl(), "openssl is not installed here")
class TheWorker(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.targets = self.root / "targets"
        self.targets.mkdir()
        patcher = mock.patch.object(deliver, "DESTINATIONS_DIR", self.targets)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.sent = []
        for name, value in (("send", lambda record, files: self.sent.append(record["name"])),
                            ("run_post_command", lambda record: None)):
            patcher = mock.patch.object(deliver, name, side_effect=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.both = self.root / "live" / "ab"
        issue(self.both, "a.example.test", "b.example.test")

    def target(self, name, *domains):
        record = {"domains": list(domains), "transport": "sftp", "host": "203.0.113.5",
                  "port": 22, "user": "u", "remote_path": "cert.pem", "format": "pem-combined"}
        (self.targets / f"{name}.json").write_text(json.dumps(record), encoding="utf-8")
        (self.targets / f"{name}.key").write_text("key\n", encoding="utf-8")
        (self.targets / f"{name}.known_hosts").write_text("host\n", encoding="utf-8")

    def test_send_now_writes_the_chosen_target_only(self):
        self.target("a", "a.example.test", "b.example.test")
        self.target("b", "b.example.test")
        self.assertEqual(deliver.main(["--lineage", str(self.both), "--target", "a"]), 0)
        self.assertEqual(self.sent, ["a"])

    def test_a_certificate_short_of_a_name_is_not_sent(self):
        self.target("a", "a.example.test", "c.example.test")
        self.assertEqual(deliver.main(["--lineage", str(self.both), "--target", "a"]), 1)
        self.assertEqual(self.sent, [])

    def test_a_renewal_does_not_send_a_certificate_short_of_a_name(self):
        only_a = self.root / "live" / "a"
        issue(only_a, "a.example.test")
        self.target("pair", "a.example.test", "b.example.test")
        self.target("single", "a.example.test")
        results = deliver.deliver_all(only_a, ["a.example.test"])
        self.assertEqual(self.sent, ["single"])
        failed = [r for r in results if not r["ok"]]
        self.assertIn("does not cover b.example.test", failed[0]["error"])

    def test_an_unknown_target_is_an_error_not_a_broadcast(self):
        self.target("b", "a.example.test")
        self.assertEqual(deliver.main(["--lineage", str(self.both), "--target", "nope"]), 1)
        self.assertEqual(self.sent, [])

    def test_a_wildcard_covers_one_label(self):
        held = ["*.example.test"]
        self.assertTrue(deliver.name_covered("shop.example.test", held))
        self.assertFalse(deliver.name_covered("example.test", held))
        self.assertFalse(deliver.name_covered("a.shop.example.test", held))


class TheDaemon(unittest.TestCase):
    def setUp(self):
        try:
            self.certd = load("certd_one_target", FILES / "haproxy-certd.py")
        except Exception:  # noqa: BLE001 - its dependencies are not installed here
            self.skipTest("certd needs cryptography")
        if not have_openssl():
            self.skipTest("openssl is not installed here")
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.live = root / "live"
        issue(self.live / "a.example.test", "a.example.test")
        issue(self.live / "b.example.test", "b.example.test")
        issue(self.live / "pair", "a.example.test", "b.example.test")
        self.dir = root / "targets"
        for name, value in (("_get_le_live_dir", lambda: self.live), ("DELIVERY_DIR", self.dir)):
            patcher = mock.patch.object(self.certd, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def save(self, *domains):
        return self.certd.save_cert_delivery({
            "name": "rdg", "domains": list(domains), "host": "203.0.113.5",
            "user": "u", "remote_path": "cert.pfx",
        })

    def test_send_now_names_the_target_and_a_covering_certificate(self):
        self.save("a.example.test", "b.example.test")
        calls = []

        def run(argv, **_kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        with mock.patch.object(self.certd, "_run_bounded", side_effect=run):
            outcome = self.certd.test_cert_delivery("rdg")
        argv = calls[0]
        self.assertEqual(argv[argv.index("--target") + 1], "rdg")
        self.assertNotIn("--domains", argv)
        self.assertEqual(outcome["lineage"], "pair")

    def test_two_separate_certificates_are_refused_at_save(self):
        (self.live / "pair" / "fullchain.pem").unlink()
        with self.assertRaises(ValueError) as caught:
            self.save("a.example.test", "b.example.test")
        self.assertIn("target of its own", str(caught.exception))

    def test_a_name_not_yet_issued_can_still_be_saved(self):
        self.save("new.example.test", "other.example.test")


if __name__ == "__main__":
    unittest.main()
