"""The internal CA is not rotated or deleted while it vouches for clients (F19).

From the 30 October review, reproduced there on real certificates: with
the internal CA trusted for client certificates, ROTATE answered 200 and
replaced the root and the server PEMs but left clients-ca.pem and the
issuers file on the old root; DELETE answered 200 and left "internal" on
the trust list and in the bundle. HAProxy went on trusting a root the
certificates page no longer showed, and did not trust the new one.

Until the trust material moves together with the root, both operations
are refused before anything is written, removed or reloaded, and say which
sites ask for that CA's client certificates. An internal CA nobody trusts
for clients rotates and deletes as before. This is the mitigation the plan
asks for first; a rotation that carries the trust along is separate work.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
CERTD_PATH = ROOT / "ansible/roles/haproxy-admin/files/haproxy-certd.py"

try:
    SPEC = importlib.util.spec_from_file_location("certd_client_trust_guard", CERTD_PATH)
    CERTD = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(CERTD)
except Exception:  # noqa: BLE001 - its dependencies are not installed here
    CERTD = None


@unittest.skipIf(CERTD is None, "certd needs cryptography")
class TheGuard(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.config = root / "config"
        self.config.mkdir()
        self.mtls = root / "mtls"
        haproxy_cfg = root / "haproxy.cfg"
        haproxy_cfg.write_text("frontend fe\n", encoding="utf-8")
        self.reloads = []
        for name, value in (
            ("HAPROXY_CERTS_DIR", (root / "certs").resolve()),
            ("CA_ROOT_DIR", (root / "ca").resolve()),
            ("MTLS_DIR", self.mtls.resolve()),
            ("HAPROXY_CFG", haproxy_cfg),
            ("CONFIG_YAML", self.config / "vars.yml"),
            ("APPLIED_WEBSITES", root / "absent.yml"),
            ("CERTD_DRY_RUN", True),
        ):
            patcher = mock.patch.object(CERTD, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(CERTD, "_reload_haproxy",
                                    side_effect=lambda: self.reloads.append(1) or (0, "", ""))
        patcher.start()
        self.addCleanup(patcher.stop)
        CERTD.handle_internal_cert_issue({"domain": "app.example.test"})
        _, self.before = CERTD.handle_internal_ca_ensure({})

    def trust_internal(self):
        status, response = CERTD.handle_ca_client_auth({"ids": ["internal"]})
        self.assertEqual(status, 200, response)
        self.reloads.clear()

    def material(self):
        return {path.name: path.read_bytes() for path in sorted(self.mtls.glob("*"))}

    def root_sha(self):
        return CERTD.handle_internal_ca_ensure({})[1]["certificate_authority"]["sha256"]

    def test_a_trusted_root_is_not_rotated(self):
        self.trust_internal()
        material = self.material()
        status, response = CERTD.handle_internal_ca_rotate({"confirmation": "ROTATE"})
        self.assertEqual(status, 409)
        self.assertTrue(response["client_trust"]["trust_list"])
        self.assertEqual(self.root_sha(), self.before["certificate_authority"]["sha256"])
        self.assertEqual(self.material(), material)
        self.assertEqual(self.reloads, [])

    def test_a_trusted_root_is_not_deleted(self):
        self.trust_internal()
        status, response = CERTD.handle_internal_ca_delete({"confirmation": "DELETE"})
        self.assertEqual(status, 409)
        self.assertIn("client certificates", response["error"])
        self.assertEqual(self.root_sha(), self.before["certificate_authority"]["sha256"])

    def test_a_root_still_in_the_bundle_counts_though_off_the_list(self):
        self.trust_internal()
        trust_file = CERTD._client_auth_trust_path()
        trust_file.write_text('{"version": 1, "ids": []}\n', encoding="utf-8")
        status, response = CERTD.handle_internal_ca_rotate({"confirmation": "ROTATE"})
        self.assertEqual(status, 409)
        self.assertTrue(response["client_trust"]["bundle"])

    def test_the_sites_asking_for_it_are_named(self):
        self.trust_internal()
        (self.config / "websites.yml").write_text(yaml.safe_dump({"sites": [
            {"name": "vpn", "domain": "vpn.example.test", "mtls_mode": "required", "mtls_ca_id": "internal"},
            {"name": "shop", "domain": "shop.example.test"},
        ]}), encoding="utf-8")
        _, response = CERTD.handle_internal_ca_rotate({"confirmation": "ROTATE"})
        self.assertEqual(response["client_trust"]["sites"], ["vpn"])

    def test_a_root_nobody_trusts_for_clients_rotates_as_before(self):
        status, response = CERTD.handle_internal_ca_rotate({"confirmation": "ROTATE"})
        self.assertEqual(status, 200, response)
        self.assertNotEqual(self.root_sha(), self.before["certificate_authority"]["sha256"])

    def test_once_untrusted_it_rotates(self):
        self.trust_internal()
        CERTD.handle_ca_client_auth({"ids": []})
        status, response = CERTD.handle_internal_ca_rotate({"confirmation": "ROTATE"})
        self.assertEqual(status, 200, response)


class TheWords(unittest.TestCase):
    def test_the_refusal_with_its_sites_translates_whole(self):
        try:
            spec = importlib.util.spec_from_file_location(
                "client_trust_i18n", ROOT / "docker/app/haproxy_admin/i18n.py")
            i18n = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(i18n)
        except ImportError:
            self.skipTest("the panel's dependencies are not installed here")
        source = CERTD_PATH.read_text(encoding="utf-8")
        routes = (ROOT / "docker/app/haproxy_admin/routes_haproxy_config.py").read_text(encoding="utf-8")
        self.assertIn('" Sites that ask for its client certificates: "', routes)
        for verb in ("rotating it", "deleting it"):
            block = source.split(f"and {verb} would")[0].rsplit('"error": (', 1)[1]
            rest = source.split(f"and {verb} would")[1].split('"client_trust"')[0]
            pieces = [line.strip().strip('"') for line in (block + f"and {verb} would" + rest).splitlines()]
            sentence = "".join(piece for piece in pieces if piece and piece not in ("),",))
            sentence = sentence.replace('"', "")
            for message in (sentence, sentence + " Sites that ask for its client certificates: 'vpn', 'files'."):
                translated = i18n.translate(message, "ru")
                self.assertNotEqual(translated, message, message)
                self.assertNotRegex(translated, r"(trusted|rotate|delete|Sites|Move)")


if __name__ == "__main__":
    unittest.main()
