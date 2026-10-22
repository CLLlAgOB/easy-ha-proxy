"""An SFTP destination pins its host key on first use and signs in by password.

Saving a destination used to demand the far end's host key, copied by hand
out of ssh-keyscan. Now an empty field means "pin what the server offers on
the first connection", and the fingerprints are shown to compare with the
server's own. What still matters is that the key cannot change silently: a
different key stops every transfer, the destination says so, and the
operator trusts the new key with one deliberate click.

A destination can also sign in with a password. It is stored root-only like
the key and handed to OpenSSH through an askpass program, never through an
argument list or the environment.
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
APP = ROOT / "docker/app/haproxy_admin"


def load_backupd():
    path = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-backupd.py"
    spec = importlib.util.spec_from_file_location("backupd_first_use", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


backupd = load_backupd()

OFFERED = b"backup.example.test ssh-ed25519 AAAAoffered\n"
SECOND = b"backup.example.test ssh-ed25519 AAAAreplaced\n"
CHANGED = (
    b"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
    b"@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n"
    b"Host key verification failed.\n"
)


class Destinations(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.dir = Path(directory.name) / "dest"
        self.scans = []
        self.offer = OFFERED
        for patcher in (
            mock.patch.object(backupd, "DESTINATIONS_DIR", self.dir),
            mock.patch.object(backupd, "scan_host_key", side_effect=self.scan),
            mock.patch.object(
                backupd, "host_key_fingerprints",
                side_effect=lambda known: ["ED25519 SHA256:" + known.split()[-1].decode()[-8:]],
            ),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def scan(self, host, port):
        self.scans.append((host, port))
        return self.offer

    def save(self, **overrides):
        payload = {
            "action": "destination_save", "name": "offsite", "type": "sftp",
            "host": "backup.example.test", "port": 22, "user": "gateway",
            "path": "/srv/backups/gw",
            "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----",
        }
        payload.update(overrides)
        return backupd.save_destination(payload)

    def known_hosts(self):
        return (self.dir / "offsite.known_hosts").read_bytes()


class FirstUse(Destinations):
    def test_an_empty_host_key_pins_what_the_server_offers(self):
        result = self.save()
        self.assertEqual(self.scans, [("backup.example.test", 22)])
        self.assertEqual(self.known_hosts(), OFFERED)
        shown = result["destination"]
        self.assertTrue(shown["host_key_pinned"])
        self.assertEqual(shown["host_key_source"], "first-use")
        self.assertEqual(shown["host_key_fingerprints"], ["ED25519 SHA256:Aoffered"])

    def test_a_key_given_by_hand_is_used_and_nothing_is_scanned(self):
        self.save(host_key="backup.example.test ssh-ed25519 AAAAbyhand")
        self.assertEqual(self.scans, [])
        self.assertIn(b"AAAAbyhand", self.known_hosts())

    def test_saving_again_keeps_the_pin_and_does_not_rescan(self):
        # Otherwise every save would quietly accept a changed key.
        self.save()
        self.offer = SECOND
        self.save(path="/srv/backups/other")
        self.assertEqual(len(self.scans), 1)
        self.assertEqual(self.known_hosts(), OFFERED)

    def test_a_new_host_or_port_is_scanned_afresh(self):
        self.save()
        self.offer = SECOND
        self.save(port=2222)
        self.assertEqual(self.scans[-1], ("backup.example.test", 2222))
        self.assertEqual(self.known_hosts(), SECOND)


class AChangedKey(Destinations):
    def failing(self, *args, **kwargs):
        return subprocess.CompletedProcess(args, 255, b"", CHANGED)

    def test_the_transfer_stops_and_the_destination_says_why(self):
        self.save()
        self.offer = SECOND
        with mock.patch.object(backupd.subprocess, "run", side_effect=self.failing):
            result = backupd.test_destination({"name": "offsite"})
        self.assertFalse(result["ok"])
        self.assertIn("different host key", result["error"])
        self.assertIn("SHA256:replaced", result["error"])
        # Nothing was trusted on the way.
        self.assertEqual(self.known_hosts(), OFFERED)
        shown = backupd.list_destinations({})["destinations"][0]
        self.assertEqual(shown["host_key_changed"]["offered"], ["ED25519 SHA256:replaced"])

    def test_trusting_the_new_key_pins_it_and_clears_the_warning(self):
        self.save()
        self.offer = SECOND
        with mock.patch.object(backupd.subprocess, "run", side_effect=self.failing):
            backupd.test_destination({"name": "offsite"})
        result = backupd.retrust_destination({"name": "offsite"})
        self.assertEqual(self.known_hosts(), SECOND)
        self.assertIsNone(result["destination"]["host_key_changed"])
        self.assertEqual(result["destination"]["host_key_source"], "trusted-after-change")

    def test_an_ordinary_failure_is_not_taken_for_a_changed_key(self):
        self.assertFalse(backupd.host_key_problem(b"Permission denied (publickey).\n"))
        self.assertTrue(backupd.host_key_problem(CHANGED))


class Password(Destinations):
    def test_a_password_destination_needs_no_key(self):
        result = self.save(private_key="", auth="password", password="s3cret pass")
        self.assertEqual(result["destination"]["auth"], "password")
        self.assertTrue(result["destination"]["has_password"])
        stored = self.dir / "offsite.password"
        self.assertEqual(stored.read_text(encoding="utf-8"), "s3cret pass")
        self.assertEqual(stored.stat().st_mode & 0o777, 0o600)
        self.assertNotIn("s3cret", json.dumps(backupd.list_destinations({})))

    def test_a_password_is_required_the_first_time(self):
        with self.assertRaises(backupd.BackupdError):
            self.save(private_key="", auth="password")

    def test_a_second_save_keeps_the_stored_password(self):
        self.save(private_key="", auth="password", password="s3cret pass")
        self.save(private_key="", auth="password", path="/srv/other")
        self.assertEqual(
            (self.dir / "offsite.password").read_text(encoding="utf-8"), "s3cret pass"
        )

    def test_a_password_with_a_line_break_is_refused(self):
        with self.assertRaises(backupd.BackupdError):
            self.save(private_key="", auth="password", password="a\nb")

    def test_the_client_signs_in_through_askpass(self):
        self.save(private_key="", auth="password", password="s3cret pass")
        record = backupd.load_destination("offsite")
        command = backupd.sftp_base_command(record, "/usr/bin/sftp")
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertIn("BatchMode=no", command)
        self.assertIn("PubkeyAuthentication=no", command)
        self.assertIn("NumberOfPasswordPrompts=1", command)
        self.assertNotIn("-i", command)
        self.assertNotIn("s3cret pass", " ".join(command))
        environment = backupd.sftp_environment(record)
        self.assertEqual(environment["SSH_ASKPASS_REQUIRE"], "force")
        self.assertEqual(
            environment["EASY_HA_PROXY_SFTP_PASSWORD_FILE"], str(self.dir / "offsite.password")
        )
        self.assertNotIn("s3cret pass", json.dumps(environment))
        helper = Path(environment["SSH_ASKPASS"])
        self.assertEqual(helper.stat().st_mode & 0o777, 0o700)
        self.assertIn(b"EASY_HA_PROXY_SFTP_PASSWORD_FILE", helper.read_bytes())

    def test_a_key_destination_keeps_batch_mode_and_its_key(self):
        self.save()
        record = backupd.load_destination("offsite")
        command = backupd.sftp_base_command(record, "/usr/bin/sftp")
        self.assertIn("BatchMode=yes", command)
        self.assertIn("-i", command)
        self.assertIsNone(backupd.sftp_environment(record))

    def test_deleting_removes_the_password_too(self):
        self.save(private_key="", auth="password", password="s3cret pass")
        backupd.delete_destination({"name": "offsite"})
        self.assertFalse((self.dir / "offsite.password").exists())


class ThePage(unittest.TestCase):
    def test_the_daemon_and_the_routes_know_the_new_fields_and_action(self):
        source = (ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-backupd.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('"auth", "password",', source)
        self.assertIn('if action == "destination_retrust":', source)
        routes = (APP / "routes_backup.py").read_text(encoding="utf-8")
        self.assertIn('"/api/destinations/trust-host-key"', routes)
        self.assertIn('"verify", "auth", "password",', routes)
        # The audit names the destination, never the secret.
        audited = routes.split("AUDITED_ACTIONS = {")[1].split("}")[0]
        self.assertNotIn("password", audited)

    def test_the_form_offers_both_sign_ins_and_the_list_a_way_out(self):
        page = (APP / "templates/system_backups.html").read_text(encoding="utf-8")
        self.assertIn('<option value="password">Password</option>', page)
        self.assertIn('id="dest-password"', page)
        self.assertIn("Host key (optional)", page)
        script = (APP / "static/js/backup_destinations.js").read_text(encoding="utf-8")
        self.assertIn('"/api/destinations/trust-host-key"', script)
        self.assertIn("host_key_changed", script)


if __name__ == "__main__":
    unittest.main()
