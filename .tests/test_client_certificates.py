"""Per-site client certificates (mTLS).

The behavioural claims underneath this feature were checked against a real
HAProxy 2.8.16 before it was written: that a bind-level ``verify optional``
with the CA errors ignored lets a certless client through, that
``ssl_c_i_dn(CN)`` tells two authorities apart, that
``ssl_c_der,sha2(256),hex,lower`` produces the same string as
``openssl dgst -sha256``, and that a pattern file holding only a comment
loads. What is left for a unit test is that the generated configuration and
the code around it keep asking for exactly that.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from jinja2 import Environment, FileSystemLoader


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_DIR = ROOT / "ansible/roles/haproxy/templates"
APP_DIR = ROOT / "docker/app/haproxy_admin"
sys.path.insert(0, str(ROOT / "docker" / "app"))

from haproxy_admin import validation  # noqa: E402
from haproxy_admin.services_haproxy_config import (  # noqa: E402
    jinja_combine,
    jinja_regex_replace,
)


def load_certd():
    path = ROOT / "ansible/roles/haproxy-admin/files/haproxy-certd.py"
    spec = importlib.util.spec_from_file_location("certd_for_mtls", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CERTD = load_certd()


def render(sites, **extra):
    environment = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    # The same helpers the renderer registers, so the test exercises the
    # template as the application will render it.
    environment.filters["regex_replace"] = jinja_regex_replace
    environment.filters["combine"] = jinja_combine
    context = {
        "sites": sites,
        "tcp_proxies": [],
        "tcp": [],
        "site_defaults": {},
        "admin_domain": "admin.example.test",
        "authelia_enabled": False,
        "easy_ha_proxy_runtime_vars": {},
        "easy_ha_proxy_runtime_websites": {},
        "easy_ha_proxy_runtime_tcp": {},
    }
    context.update(extra)
    return environment.get_template("haproxy.cfg.j2").render(**context)


def site(name, domain, **extra):
    base = {
        "name": name,
        "domain": domain,
        "backend_ip": "10.0.0.10",
        "backend_port": 8080,
    }
    base.update(extra)
    return base


class TemplateTests(unittest.TestCase):
    def test_a_gateway_without_mtls_asks_for_no_certificate(self):
        # The bind is shared by every site. Enabling nothing must leave the
        # handshake exactly as it was.
        config = render([site("shop", "shop.example.test")])
        bind = [
            line for line in config.splitlines()
            if line.strip().startswith("bind") and "ssl crt" in line
        ]
        self.assertTrue(bind)
        for line in bind:
            self.assertNotIn("ca-file", line)
            self.assertNotIn("verify optional", line)
        self.assertNotIn("ssl_c_used", config)

    def test_one_site_is_enough_to_arm_the_bind(self):
        config = render([
            site("shop", "shop.example.test"),
            site("ops", "ops.example.test", mtls_mode="required", mtls_ca_id="corp"),
        ])
        bind = next(
            line for line in config.splitlines()
            if line.strip().startswith("bind ipv4@*:443")
        )
        self.assertIn("ca-file /etc/haproxy/mtls/clients-ca.pem", bind)
        self.assertIn("verify optional", bind)
        # Without these a client offering a certificate this gateway does not
        # know loses the handshake -- on every site sharing the bind, not just
        # the one that asked for mTLS.
        self.assertIn("ca-ignore-err all", bind)
        self.assertIn("crt-ignore-err all", bind)

    def test_required_refuses_a_request_with_no_certificate(self):
        config = render([
            site("ops", "ops.example.test", mtls_mode="required", mtls_ca_id="corp")
        ])
        self.assertIn(
            "http-request deny status 403 if host_ops !mtls_present", config
        )

    def test_optional_lets_a_visitor_without_one_through(self):
        config = render([
            site("ops", "ops.example.test", mtls_mode="optional", mtls_ca_id="corp")
        ])
        self.assertNotIn(
            "http-request deny status 403 if host_ops !mtls_present", config
        )
        # But a certificate that was presented still has to hold up.
        self.assertIn(
            "http-request deny status 403 if host_ops mtls_present !mtls_verified",
            config,
        )

    def test_a_site_only_accepts_its_own_authority(self):
        config = render([
            site("ops", "ops.example.test", mtls_mode="required", mtls_ca_id="corp"),
            site("lab", "lab.example.test", mtls_mode="required", mtls_ca_id="labs"),
        ])
        self.assertIn(
            "acl mtls_ca_1 ssl_c_i_dn(CN) -f /etc/haproxy/mtls/issuers-corp.list",
            config,
        )
        self.assertIn(
            "acl mtls_ca_2 ssl_c_i_dn(CN) -f /etc/haproxy/mtls/issuers-labs.list",
            config,
        )
        self.assertIn(
            "http-request deny status 403 if host_ops mtls_present !mtls_ca_1",
            config,
        )
        self.assertIn(
            "http-request deny status 403 if host_lab mtls_present !mtls_ca_2",
            config,
        )

    def test_two_authorities_that_sanitize_alike_stay_apart(self):
        # sanitize() collapses dots and dashes to underscores, so naming the
        # ACL after the authority would merge corp.pki and corp-pki into one
        # and silently widen both sites' trust.
        config = render([
            site("a", "a.example.test", mtls_mode="required", mtls_ca_id="corp.pki"),
            site("b", "b.example.test", mtls_mode="required", mtls_ca_id="corp-pki"),
        ])
        self.assertIn("issuers-corp.pki.list", config)
        self.assertIn("issuers-corp-pki.list", config)
        self.assertIn("!mtls_ca_1", config)
        self.assertIn("!mtls_ca_2", config)

    def test_the_gate_runs_before_authelia(self):
        # They are independent layers, and a request that cannot present the
        # certificate has no business reaching the identity provider.
        config = render(
            [
                site(
                    "ops",
                    "ops.example.test",
                    mtls_mode="required",
                    mtls_ca_id="corp",
                    authelia_enabled=True,
                )
            ],
            authelia_enabled=True,
            aut_domain="auth.example.test",
        )
        gate = config.index("deny status 403 if host_ops !mtls_present")
        forward_auth = config.index("lua.auth-intercept")
        self.assertLess(gate, forward_auth)

    def test_a_revoked_fingerprint_is_checked_in_the_form_haproxy_produces(self):
        config = render([
            site("ops", "ops.example.test", mtls_mode="required", mtls_ca_id="corp")
        ])
        self.assertIn(
            "acl mtls_revoked  ssl_c_der,sha2(256),hex,lower "
            "-f /etc/haproxy/mtls/revoked.list",
            config,
        )
        self.assertIn(
            "http-request deny status 403 if host_ops mtls_present mtls_revoked",
            config,
        )

    def test_identity_headers_are_deleted_before_they_are_set(self):
        config = render([
            site("ops", "ops.example.test", mtls_mode="required", mtls_ca_id="corp")
        ])
        for header in (
            "X-Client-Cert-Subject",
            "X-Client-Cert-Issuer",
            "X-Client-Cert-Serial",
            "X-Client-Cert-Fingerprint",
        ):
            deleted = config.index(f"http-request del-header {header}")
            written = config.index(f"http-request set-header {header}")
            self.assertLess(deleted, written, header)

    def test_a_site_without_mtls_learns_nothing_about_the_client(self):
        config = render([
            site("shop", "shop.example.test"),
            site("ops", "ops.example.test", mtls_mode="required", mtls_ca_id="corp"),
        ])
        for line in config.splitlines():
            if "set-header X-Client-Cert" in line:
                self.assertIn("if mtls_host mtls_present mtls_verified", line)
        self.assertIn("acl mtls_host hdr(host) -i ops.example.test", config)

    def test_a_mode_without_an_authority_arms_nothing(self):
        # Validation refuses this, but a hand-edited websites.yml must not be
        # able to produce a configuration that names a file nobody wrote.
        config = render([site("ops", "ops.example.test", mtls_mode="required")])
        self.assertNotIn("ca-file /etc/haproxy/mtls", config)
        self.assertNotIn("issuers-", config)


class CertdTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.ca_root = root / "ca"
        self.mtls = root / "mtls"
        self.config = root / "haproxy.cfg"
        self.config.write_text("frontend fe\n", encoding="utf-8")
        patches = [
            mock.patch.object(CERTD, "CA_ROOT_DIR", self.ca_root),
            mock.patch.object(CERTD, "MTLS_DIR", self.mtls),
            mock.patch.object(CERTD, "HAPROXY_CFG", self.config),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        CERTD._prepare_ca_root(create=True)
        CERTD._prepare_ca_subdir("external", create=True)
        self.addCleanup(self.tmp.cleanup)

    def make_ca(self, ca_id, common_name):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import datetime

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(key, hashes.SHA256())
        )
        path = CERTD._prepare_ca_subdir("external") / f"{ca_id}.pem"
        path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return path

    def test_importing_a_ca_does_not_make_it_a_client_authority(self):
        self.make_ca("corp", "Corp Issuing CA")
        listing = CERTD._list_certificate_authorities()
        item = listing["external"][0]
        self.assertFalse(item["client_auth"])
        self.assertEqual(item["subject_cns"], ["Corp Issuing CA"])
        self.assertEqual(listing["client_auth_ids"], [])

    def test_marking_one_writes_what_the_frontend_reads(self):
        self.make_ca("corp", "Corp Issuing CA")
        status, response = CERTD.handle_ca_client_auth({"ids": ["corp"]})
        self.assertEqual(status, 200)
        self.assertTrue(response["ok"])
        bundle = self.mtls / "clients-ca.pem"
        issuers = self.mtls / "issuers-corp.list"
        self.assertIn(b"BEGIN CERTIFICATE", bundle.read_bytes())
        self.assertEqual(issuers.read_text(encoding="utf-8"), "Corp Issuing CA\n")
        # Public material, and HAProxy runs as another user.
        self.assertEqual(bundle.stat().st_mode & 0o777, 0o644)

    def test_a_bundle_contributes_every_name_that_could_be_the_issuer(self):
        # Root plus the intermediate that actually signs clients: only the
        # direct issuer appears in ssl_c_i_dn, and it may be either.
        first = self.make_ca("root", "Test Root")
        second = self.make_ca("interm", "Test Issuing")
        combined = CERTD._prepare_ca_subdir("external") / "chain.pem"
        combined.write_bytes(first.read_bytes() + second.read_bytes())
        CERTD.handle_ca_client_auth({"ids": ["chain"]})
        names = (self.mtls / "issuers-chain.list").read_text(encoding="utf-8")
        self.assertEqual(sorted(names.split()), ["Issuing", "Root", "Test", "Test"])

    def test_two_authorities_sharing_a_name_are_refused(self):
        # The site tells them apart by Common Name; if two share one, it
        # cannot, and the safe moment to say so is now.
        self.make_ca("one", "Shared Name")
        self.make_ca("two", "Shared Name")
        status, response = CERTD.handle_ca_client_auth({"ids": ["one", "two"]})
        self.assertEqual(status, 400)
        self.assertIn("Shared Name", response["error"])
        self.assertFalse((self.mtls / "issuers-two.list").exists())

    def test_untrusting_a_referenced_authority_empties_it_rather_than_deleting(self):
        # Deleting the file would leave the live configuration pointing at
        # something that no longer exists, and the next reload would fail --
        # so the change to close access would be the change that prevents it.
        self.make_ca("corp", "Corp Issuing CA")
        CERTD.handle_ca_client_auth({"ids": ["corp"]})
        self.config.write_text(
            "acl mtls_ca_1 ssl_c_i_dn(CN) -f /etc/haproxy/mtls/issuers-corp.list\n",
            encoding="utf-8",
        )
        CERTD.handle_ca_client_auth({"ids": []})
        issuers = self.mtls / "issuers-corp.list"
        self.assertTrue(issuers.exists())
        self.assertNotIn("Corp Issuing CA", issuers.read_text(encoding="utf-8"))

    def test_an_unreferenced_authority_is_removed_outright(self):
        self.make_ca("corp", "Corp Issuing CA")
        CERTD.handle_ca_client_auth({"ids": ["corp"]})
        CERTD.handle_ca_client_auth({"ids": []})
        self.assertFalse((self.mtls / "issuers-corp.list").exists())

    def test_deleting_an_authority_takes_it_out_of_the_trust_list(self):
        self.make_ca("corp", "Corp Issuing CA")
        CERTD.handle_ca_client_auth({"ids": ["corp"]})
        status, response = CERTD.handle_external_ca_delete({"ca_id": "corp"})
        self.assertEqual(status, 200, response)
        self.assertEqual(CERTD._load_client_auth_ids(), [])

    def test_the_files_exist_before_anything_is_imported(self):
        # The configuration may name them on a gateway where nobody has
        # imported an authority, and HAProxy will not start without them.
        CERTD._rebuild_client_auth_material([])
        for name in ("clients-ca.pem", "revoked.list"):
            path = self.mtls / name
            self.assertTrue(path.is_file(), name)
            self.assertTrue(path.read_text(encoding="utf-8").startswith("#"), name)

    def test_fingerprints_are_stored_the_way_haproxy_will_read_them(self):
        with mock.patch.object(CERTD, "_reload_haproxy", return_value=(0, "", "")):
            status, response = CERTD.handle_ca_revoked({
                "fingerprints": [
                    "AB:CD:" + "00" * 30,
                    "  " + "ff" * 32 + "  ",
                ]
            })
        self.assertEqual(status, 200, response)
        lines = (self.mtls / "revoked.list").read_text(encoding="utf-8").splitlines()
        self.assertEqual(lines[0][0], "#")
        self.assertEqual(lines[1], "abcd" + "00" * 30)
        self.assertEqual(lines[2], "ff" * 32)

    def test_something_that_is_not_a_fingerprint_is_refused(self):
        status, response = CERTD.handle_ca_revoked({"fingerprints": ["nonsense"]})
        self.assertEqual(status, 400)
        self.assertIn("SHA-256", response["error"])

    def test_saving_the_list_reloads_so_it_is_actually_in_force(self):
        with mock.patch.object(
            CERTD, "_reload_haproxy", return_value=(1, "", "boom")
        ) as reload:
            _status, response = CERTD.handle_ca_revoked({"fingerprints": []})
        reload.assert_called_once()
        self.assertEqual(response["reload_error"], "boom")

    def test_a_ca_that_vanished_does_not_cost_the_others_their_material(self):
        self.make_ca("corp", "Corp Issuing CA")
        CERTD.handle_ca_client_auth({"ids": ["corp"]})
        path = self.ca_root / "client-auth.json"
        path.write_text(
            json.dumps({"version": 1, "ids": ["gone", "corp"]}), encoding="utf-8"
        )
        surviving = []
        for ca_id in CERTD._load_client_auth_ids():
            try:
                CERTD._ca_certificates(ca_id)
            except (OSError, ValueError):
                continue
            surviving.append(ca_id)
        self.assertEqual(surviving, ["corp"])
        CERTD._rebuild_client_auth_material(surviving)
        self.assertTrue((self.mtls / "issuers-corp.list").is_file())


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.validation = validation

    def _site(self, **extra):
        base = {"name": "ops", "domain": "ops.example.test"}
        base.update(extra)
        return base

    def test_a_mode_without_an_authority_is_refused(self):
        with self.assertRaises(ValueError) as caught:
            self.validation._validate_site(self._site(mtls_mode="required"), 0)
        self.assertIn("mtls_ca_id", str(caught.exception))

    def test_an_unknown_mode_is_refused(self):
        with self.assertRaises(ValueError):
            self.validation._validate_site(self._site(mtls_mode="maybe"), 0)

    def test_an_identifier_that_could_escape_the_directory_is_refused(self):
        for bad in ("../../etc/passwd", "corp/../x", "Corp Ltd"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self.validation._validate_site(
                        self._site(mtls_mode="required", mtls_ca_id=bad), 0
                    )

    def test_a_disabled_site_needs_no_authority(self):
        self.validation._validate_site(self._site(mtls_mode="disabled"), 0)


class PageTests(unittest.TestCase):
    def setUp(self):
        self.certs_page = (
            APP_DIR / "templates" / "haproxy_certs.html"
        ).read_text(encoding="utf-8")
        self.site_page = (
            APP_DIR / "templates" / "haproxy_site_edit.html"
        ).read_text(encoding="utf-8")
        self.site_js = (
            APP_DIR / "static" / "js" / "haproxy_site_edit.js"
        ).read_text(encoding="utf-8")
        self.routes = (
            APP_DIR / "routes_haproxy_config.py"
        ).read_text(encoding="utf-8")

    def test_the_whole_trust_set_is_posted_not_one_toggle(self):
        # Two operators toggling different rows would otherwise decide the
        # trust set by whichever request landed last.
        self.assertIn('name="client_auth_ca"', self.certs_page)
        self.assertIn('request.form.getlist("client_auth_ca")', self.routes)

    def test_an_authority_with_no_common_name_cannot_be_ticked(self):
        self.assertIn("{% if not ca.subject_cns %}disabled{% endif %}", self.certs_page)

    def test_the_site_editor_only_offers_client_auth_authorities(self):
        self.assertIn("selectattr('client_auth')", self.site_page)
        self.assertIn('name="mtls_mode"', self.site_page)
        self.assertIn('name="mtls_ca_id"', self.site_page)

    def test_the_script_sends_both_fields_together(self):
        block = self.site_js.split("var mtlsModeEl")[1].split("// Certificate source")[0]
        self.assertIn("site.mtls_mode = mtlsModeEl.value;", block)
        self.assertIn("site.mtls_ca_id", block)

    def test_a_passthrough_site_drops_them(self):
        block = self.site_js.split("delete site.zero_trust;")[1]
        self.assertIn("delete site.mtls_mode;", block)
        self.assertIn("delete site.mtls_ca_id;", block)

    def test_the_no_javascript_form_moves_both_or_neither(self):
        block = self.routes.split('if "mtls_mode" in form:')[1].split(
            "for field in FORM_TRISTATE_FIELDS"
        )[0]
        self.assertIn('site["mtls_ca_id"]', block)
        self.assertIn('site.pop("mtls_ca_id", None)', block)

    def test_both_actions_are_audited(self):
        self.assertIn('"set_client_auth_cas": ("ca.client_auth"', self.routes)
        self.assertIn('"set_revoked_client_certs": ("ca.revoke_client"', self.routes)


if __name__ == "__main__":
    unittest.main()
