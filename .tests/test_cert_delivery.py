"""Handing a renewed certificate to the other machines that hold it.

The gateway is rarely the only thing with the certificate on it. A Remote
Desktop Gateway wants the same one as a PKCS#12; a web server on another host
wants the PEM pair; an appliance wants them concatenated. That used to be one
hand-written hook per gateway with the host, the port, the path and the format
baked into the script -- and a second copy in the Ansible role that had
drifted out of agreement with the one actually running, to the point where the
role's version could not fire at all.

Targets are records now, edited from the interface, the same shape as an
off-host backup destination: one JSON each, the private key and the pinned
host key beside it, the directory root-only.

Two properties matter more than the rest and are tested by behaviour rather
than by reading the source. The artefact has to be the right bytes in the
right format, because nothing downstream checks. And one unreachable machine
must not cost the others their certificate.

The third is what "send now" costs. A hand-written hook can only run during
a renewal, because it reads RENEWED_LINEAGE and RENEWED_DOMAINS out of the
environment certbot gives it. Here those are the hook's business only: it
passes them as arguments, and the worker takes them from arguments, which is
what makes an on-demand run possible at all. The price is that on demand
something has to find the lineage, and it is not simply the domain -- this
installation issues example.com-ecdsa and example.com-rsa, and certbot
appends -0001 on a reused name. The first version looked for live/<domain>
and would have reported "no certificate issued" for every dual-key site on
the gateway.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKER = (
    ROOT / "ansible" / "roles" / "haproxy-admin" / "files"
    / "easy-ha-proxy-cert-deliver.py"
)
HOOK = ROOT / "ansible" / "roles" / "cert" / "templates" / "906-deliver-certificates.sh.j2"
HOOKS_TASK = ROOT / "ansible" / "roles" / "cert" / "tasks" / "hooks.yml"
CERTD = ROOT / "ansible" / "roles" / "haproxy-admin" / "files" / "haproxy-certd.py"
APP = ROOT / "docker" / "app" / "haproxy_admin"


def load():
    spec = importlib.util.spec_from_file_location("cert_deliver", WORKER)
    module = importlib.util.module_from_spec(spec)
    sys.modules["cert_deliver"] = module
    spec.loader.exec_module(module)
    return module


deliver = load()


def import_certd():
    """certd, or None where its dependencies are not installed."""

    try:
        spec = importlib.util.spec_from_file_location("certd_for_tests", CERTD)
        module = importlib.util.module_from_spec(spec)
        sys.modules["certd_for_tests"] = module
        spec.loader.exec_module(module)
        return module
    except Exception:  # noqa: BLE001 - the point is to skip, not to fail
        return None


def have_openssl() -> bool:
    try:
        subprocess.run(["openssl", "version"], capture_output=True, check=False)
        return True
    except OSError:
        return False


class ChoosingTargets(unittest.TestCase):
    def test_a_target_wants_a_domain_it_names(self):
        record = {"domains": ["rdg.example.com", "mail.example.com"]}
        self.assertTrue(deliver.wants_domain(record, ["rdg.example.com"]))

    def test_case_and_padding_do_not_matter(self):
        record = {"domains": [" RDG.Example.COM "]}
        self.assertTrue(deliver.wants_domain(record, ["rdg.example.com"]))

    def test_a_neighbouring_name_is_not_a_match(self):
        # Substring matching here would deliver example.com's certificate to
        # whoever configured notexample.com.
        record = {"domains": ["example.com"]}
        for renewed in ("notexample.com", "example.com.evil.test",
                        "sub.example.com"):
            with self.subTest(renewed=renewed):
                self.assertFalse(deliver.wants_domain(record, [renewed]))

    def test_a_target_naming_nothing_never_fires(self):
        self.assertFalse(deliver.wants_domain({"domains": []}, ["a.example.com"]))
        self.assertFalse(deliver.wants_domain({}, ["a.example.com"]))


class BuildingTheArtefact(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.lineage = root / "live"
        self.lineage.mkdir()
        # Content, not real PEM: only the pfx branch shells out to openssl,
        # and that case is skipped when openssl is not present.
        (self.lineage / "fullchain.pem").write_text("CHAIN\n", encoding="utf-8")
        (self.lineage / "privkey.pem").write_text("KEY\n", encoding="utf-8")
        self.work = root / "work"
        self.work.mkdir()

    def build(self, record):
        return deliver.build_artefacts(self.lineage, record, self.work)

    def test_pem_combined_is_the_chain_then_the_key(self):
        # The order HAProxy and most appliances expect. Reversed, the far end
        # loads a key and reports no certificate.
        out = self.build({"format": "pem-combined", "remote_path": "/tmp/x.pem"})
        self.assertEqual(len(out), 1)
        local, remote = out[0]
        self.assertEqual(local.read_text(encoding="utf-8"), "CHAIN\nKEY\n")
        self.assertEqual(remote, "/tmp/x.pem")

    def test_pem_pair_sends_two_files_into_the_directory(self):
        out = self.build({"format": "pem-pair", "remote_path": "/etc/ssl/site/"})
        remotes = sorted(remote for _, remote in out)
        self.assertEqual(
            remotes, ["/etc/ssl/site/fullchain.pem", "/etc/ssl/site/privkey.pem"]
        )

    def test_the_private_half_is_not_world_readable(self):
        out = self.build({"format": "pem-pair", "remote_path": "/etc/ssl/site"})
        for local, remote in out:
            if remote.endswith("privkey.pem"):
                self.assertEqual(local.stat().st_mode & 0o077, 0)

    def test_a_missing_lineage_says_which_file(self):
        (self.lineage / "privkey.pem").unlink()
        with self.assertRaises(deliver.DeliveryError) as caught:
            self.build({"format": "pem-combined", "remote_path": "/tmp/x"})
        self.assertIn("privkey.pem", str(caught.exception))

    def test_a_format_nobody_implements_is_refused(self):
        with self.assertRaises(deliver.DeliveryError):
            self.build({"format": "jks", "remote_path": "/tmp/x"})

    def test_a_target_with_no_remote_path_is_refused(self):
        # Silently sending to the account's home directory is worse than
        # saying the field is required.
        with self.assertRaises(deliver.DeliveryError):
            self.build({"format": "pfx", "remote_path": "  "})

    @unittest.skipUnless(have_openssl(), "openssl is not installed here")
    def test_a_pfx_is_actually_a_pkcs12_file(self):
        import shutil

        # A real key and certificate, because openssl will not export
        # anything else.
        key = self.lineage / "privkey.pem"
        chain = self.lineage / "fullchain.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(key), "-out", str(chain), "-days", "1",
             "-subj", "/CN=example.com"],
            capture_output=True, check=True,
        )
        out = self.build({"format": "pfx", "remote_path": "cert.pfx",
                          "pfx_password": ""})
        self.assertEqual(len(out), 1)
        local, remote = out[0]
        self.assertEqual(remote, "cert.pfx")
        check = subprocess.run(
            ["openssl", "pkcs12", "-in", str(local), "-info", "-nokeys",
             "-passin", "pass:"],
            capture_output=True, check=False,
        )
        self.assertEqual(check.returncode, 0, check.stderr.decode()[:300])
        self.assertEqual(local.stat().st_mode & 0o077, 0)
        del shutil


class TheTransportIsPinned(unittest.TestCase):
    def test_the_host_key_is_required_and_checked(self):
        command = deliver.ssh_base_command({"name": "rdg", "port": 2222},
                                           "/usr/bin/sftp")
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertTrue(
            any("UserKnownHostsFile=" in part for part in command),
            "nothing tells ssh which host key to trust",
        )

    def test_only_the_saved_key_is_offered(self):
        # Without IdentitiesOnly an agent key can be tried instead, and the
        # target then works until the agent is gone.
        command = deliver.ssh_base_command({"name": "rdg"}, "/usr/bin/sftp")
        self.assertIn("IdentitiesOnly=yes", command)
        self.assertIn("BatchMode=yes", command)

    def test_the_port_flag_matches_the_binary(self):
        # sftp wants -P, ssh and scp want -p. The wrong one is taken as a
        # different option entirely.
        sftp = deliver.ssh_base_command({"name": "x", "port": 2222}, "/usr/bin/sftp")
        ssh = deliver.ssh_base_command({"name": "x", "port": 2222}, "/usr/bin/ssh")
        self.assertIn("-P", sftp)
        self.assertNotIn("-p", sftp)
        self.assertIn("-p", ssh)

    def test_a_remote_name_with_a_space_survives_the_batch_language(self):
        quoted = deliver.remote_quote("/srv/my certs/cert.pfx")
        self.assertTrue(quoted.startswith('"') and quoted.endswith('"'))
        self.assertIn("my certs", quoted)


class OneFailureDoesNotStopTheRest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.original = deliver.DESTINATIONS_DIR
        deliver.DESTINATIONS_DIR = self.dir
        self.addCleanup(setattr, deliver, "DESTINATIONS_DIR", self.original)

        self.lineage = self.dir / "live"
        self.lineage.mkdir()
        (self.lineage / "fullchain.pem").write_text("C", encoding="utf-8")
        (self.lineage / "privkey.pem").write_text("K", encoding="utf-8")

    def target(self, name, **extra):
        record = {
            "domains": ["a.example.com"], "transport": "sftp",
            "host": "h", "port": 22, "user": "u",
            "remote_path": "cert.pem", "format": "pem-combined",
        }
        record.update(extra)
        (self.dir / f"{name}.json").write_text(json.dumps(record), encoding="utf-8")
        return record

    def test_every_target_is_attempted_even_after_one_fails(self):
        # Neither has key material, so both fail -- but both must be tried.
        self.target("first")
        self.target("second")
        results = deliver.deliver_all(self.lineage, ["a.example.com"])
        self.assertEqual(len(results), 2)
        self.assertEqual([r["ok"] for r in results], [False, False])

    def test_a_target_with_no_key_says_so_rather_than_crashing(self):
        self.target("first")
        results = deliver.deliver_all(self.lineage, ["a.example.com"])
        self.assertIn("private key", results[0]["error"])

    def test_a_disabled_target_is_skipped_not_failed(self):
        self.target("off", enabled=False)
        results = deliver.deliver_all(self.lineage, ["a.example.com"])
        self.assertTrue(results[0]["ok"])
        self.assertEqual(results[0]["skipped"], "disabled")

    def test_a_target_for_another_domain_is_not_touched(self):
        self.target("other", domains=["b.example.com"])
        self.assertEqual(deliver.deliver_all(self.lineage, ["a.example.com"]), [])

    def test_a_corrupt_record_does_not_hide_the_others(self):
        (self.dir / "broken.json").write_text("{ not json", encoding="utf-8")
        self.target("good")
        results = deliver.deliver_all(self.lineage, ["a.example.com"])
        self.assertEqual([r["name"] for r in results], ["good"])

    def test_nothing_to_do_is_not_a_failure(self):
        self.assertEqual(deliver.main(["--lineage", "", "--domains", ""]), 0)


class TheHookRunsAfterTheReload(unittest.TestCase):
    def test_the_worker_is_installed_where_the_hook_calls_it(self):
        # The cert role writes the hook; the haproxy-admin role installs the
        # program it runs, because the cert role's files/ is not tracked.
        certd_task = (
            ROOT / "ansible" / "roles" / "haproxy-admin" / "tasks" / "certd.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("easy-ha-proxy-cert-deliver.py", certd_task)
        self.assertIn("/usr/local/sbin/easy-ha-proxy-cert-deliver", certd_task)
        self.assertIn(
            "/usr/local/sbin/easy-ha-proxy-cert-deliver",
            HOOK.read_text(encoding="utf-8"),
        )

    def test_it_is_numbered_after_the_pem_rebuild(self):
        # The whole reason for 906 rather than 904: a machine that is
        # switched off must never be able to leave this gateway serving an
        # expired certificate.
        self.assertIn("906-deliver-certificates.sh",
                      HOOKS_TASK.read_text(encoding="utf-8"))
        self.assertIn("905-haproxy-pems-reload.sh",
                      HOOKS_TASK.read_text(encoding="utf-8"))

    def test_it_is_a_deploy_hook_because_it_needs_the_certbot_variables(self):
        tasks = HOOKS_TASK.read_text(encoding="utf-8")
        block = tasks.split("906-deliver-certificates.sh")[0]
        self.assertIn("renewal-hooks/deploy", block)

    def test_the_hook_passes_what_certbot_gives_it(self):
        source = HOOK.read_text(encoding="utf-8")
        self.assertIn("RENEWED_LINEAGE", source)
        self.assertIn("RENEWED_DOMAINS", source)

    def test_the_hook_holds_no_configuration_of_its_own(self):
        # Everything the old hand-written hooks baked in -- host, port, path,
        # format -- is a record now. A value here would be one the interface
        # cannot see or change.
        source = HOOK.read_text(encoding="utf-8")
        for leaked in ("sftp ", "openssl", "SSH_USER", "REMOTE_PATH"):
            with self.subTest(leaked=leaked):
                self.assertNotIn(leaked, source)


class FindingTheCertificateOnDemand(unittest.TestCase):
    """The part a hook never has to do, because certbot tells it."""

    def setUp(self):
        self.source = CERTD.read_text(encoding="utf-8")
        self.block = self.source.split("def _resolve_lineage")[1].split(
            "def handle_deliveries_list")[0]

    def test_the_worker_takes_arguments_rather_than_the_environment(self):
        # This is the whole reason an on-demand run can exist. A worker
        # reading RENEWED_LINEAGE directly could only ever run under certbot.
        worker = WORKER.read_text(encoding="utf-8")
        self.assertIn('"--lineage"', worker)
        self.assertIn('"--domains"', worker)
        hook = HOOK.read_text(encoding="utf-8")
        self.assertIn("--lineage", hook)
        self.assertIn("RENEWED_LINEAGE", hook)

    def test_the_key_type_suffixes_are_tried(self):
        # The fault the first version had: live/<domain> only.
        self.assertIn("-ecdsa", self.block)
        self.assertIn("-rsa", self.block)

    def test_a_name_it_cannot_guess_is_found_by_reading_the_certificates(self):
        # -0001 and friends. Guessing names cannot cover those.
        self.assertIn("_cert_matches_domain", self.block)

    def test_it_reports_which_lineage_it_used(self):
        # Two lineages for one domain is normal here; the operator should
        # not have to wonder which one was sent.
        send = self.source.split("def test_cert_delivery")[1].split(
            chr(10) + "def ")[0]
        self.assertIn('"lineage"', send)

    def test_it_finds_each_naming_shape_a_gateway_actually_uses(self):
        """Behaviour, not a grep. The shapes are taken from a live gateway,
        where the apex site is example.com-ecdsa and example.com-rsa while
        every subdomain is a plain directory."""

        certd = import_certd()
        if certd is None:
            self.skipTest("certd needs cryptography, which is not installed here")

        with tempfile.TemporaryDirectory() as tmp:
            live = Path(tmp)
            for name in ("mail.example.com", "example.com-ecdsa",
                         "example.com-rsa", "shop.example.com-0001"):
                (live / name).mkdir()
                (live / name / "fullchain.pem").write_text("x", encoding="utf-8")

            original = certd._get_le_live_dir
            certd._get_le_live_dir = lambda: live
            self.addCleanup(setattr, certd, "_get_le_live_dir", original)

            # A plain directory.
            self.assertEqual(
                certd._resolve_lineage("mail.example.com").name,
                "mail.example.com",
            )
            # Two key types: one of them, deterministically, rather than
            # sending twice to the same remote path.
            self.assertEqual(
                certd._resolve_lineage("example.com").name, "example.com-ecdsa"
            )
            # Nothing issued under that name at all.
            self.assertIsNone(certd._resolve_lineage("absent.example.com"))

    def test_nothing_issued_yet_says_so_rather_than_sending_nothing(self):
        send = self.source.split("def test_cert_delivery")[1].split(
            chr(10) + "def ")[0]
        self.assertIn("no issued certificate", send)


class TheDaemonKeepsTheSecrets(unittest.TestCase):
    def setUp(self):
        self.source = CERTD.read_text(encoding="utf-8")

    def test_the_listing_never_returns_key_material(self):
        block = self.source.split("def _delivery_public")[1].split("\ndef ")[0]
        for secret in ('"private_key"', '"host_key"', '"pfx_password":'):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, block)

    def test_it_says_whether_a_secret_is_set(self):
        block = self.source.split("def _delivery_public")[1].split("\ndef ")[0]
        for flag in ("pfx_password_set", "key_present", "host_key_present"):
            with self.subTest(flag=flag):
                self.assertIn(flag, block)

    def test_an_edit_does_not_silently_clear_a_stored_password(self):
        block = self.source.split("def save_cert_delivery")[1].split("\ndef ")[0]
        self.assertIn('existing.get("pfx_password"', block)

    def test_the_secret_files_get_their_mode_before_their_content(self):
        # The window between creating a key file and chmod-ing it is the one
        # a reader needs.
        block = self.source.split("def _write_delivery_secret")[1].split("\ndef ")[0]
        self.assertIn("0o600", block)
        self.assertIn("os.open", block)

    def test_a_rejected_save_does_not_echo_the_payload_back(self):
        block = self.source.split("def handle_delivery_save")[1].split("\ndef ")[0]
        self.assertNotIn("body", block.split("except")[1])


class TheWebLayerGuardsIt(unittest.TestCase):
    def setUp(self):
        self.source = (APP / "routes_cert_delivery.py").read_text(encoding="utf-8")

    def test_every_mutating_route_is_superadmin_only(self):
        for route in ("save", "delete", "test"):
            with self.subTest(route=route):
                block = self.source.split(f"cert-delivery/{route}")[1].split("@bp.")[0]
                self.assertIn("_superadmin()", block)

    def test_sending_now_is_treated_as_mutating(self):
        # It writes a file on another machine. Read-only it is not.
        self.assertIn('@bp.post("/api/haproxy/cert-delivery/test")', self.source)

    def test_every_action_reaches_the_change_log(self):
        for action in ("cert_delivery.save", "cert_delivery.delete",
                       "cert_delivery.test"):
            with self.subTest(action=action):
                self.assertIn(action, self.source)


if __name__ == "__main__":
    unittest.main()
