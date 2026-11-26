"""Mutating installer commands share custody with backups and host updates."""

from contextlib import redirect_stderr, redirect_stdout
import fcntl
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "installer"))
import easy_ha_proxy as cli  # noqa: E402


class InstallerMaintenanceLock(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.lock = self.root / "operation.lock"
        self.config = self.root / "config"
        self.config.mkdir()
        self.fixture = {
            "vars.yml": {"root_domain": "example.test", "admin_domain": "ha.example.test",
                         "aut_domain": "aut.example.test", "certbot_email": "ops@example.test",
                         "haproxy_admin_timezone": "UTC"},
            "authelia.yml": {"aut_domain": "aut.example.test", "authelia_timezone": "UTC"},
            "metadata.yml": {"source_channel": "github", "image_channel": "latest",
                             "certificate_source": "letsencrypt", "configuration_pending": False,
                             "test_mode": False, "installation_complete": True},
            "secrets.yml": {"authelia_session_secret": "synthetic"},
            "authelia_users_initial.yml": {"authelia_users": {"admin": {"password": "synthetic"}}},
            "websites.yml": {"sites": []}, "tcp.yml": {"tcp_proxies": []},
        }
        for name, value in self.fixture.items():
            cli.write_yaml(self.config / name, value)
        for patch in (
            mock.patch.dict(os.environ, {"EASY_HA_PROXY_CONFIG_DIR": str(self.config),
                                        "EASY_HA_PROXY_ALLOW_STDIN": "1"}),
            mock.patch.object(cli, "MAINTENANCE_LOCK_PATH", self.lock),
            mock.patch.object(cli, "started_by_update_broker", return_value=False),
            mock.patch.object(cli, "require_root"),
            mock.patch.object(cli, "RUNTIME_HAPROXY_CONFIG_DIR", self.root / "absent-runtime"),
            mock.patch.object(cli, "dns_preflight"),
            mock.patch.object(cli, "record_applied_source"),
        ):
            patch.start()
            self.addCleanup(patch.stop)
        os.environ.pop(cli.MAINTENANCE_LOCK_HELD_ENV, None)
        self.addCleanup(self.release)

    def release(self):
        if cli._maintenance_lock_descriptor >= 0:
            os.close(cli._maintenance_lock_descriptor)
            cli._maintenance_lock_descriptor = -1
        os.environ.pop(cli.MAINTENANCE_LOCK_HELD_ENV, None)

    def run_cli(self, *arguments):
        with mock.patch.object(sys, "argv", ["easy-ha-proxy", *arguments]), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return cli.main()

    def assert_lock_held(self):
        with self.lock.open("a+") as other:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def answer(self, label, *, default=None, **kwargs):
        if label == "Timezone":
            return "Europe/London"
        self.assertIsNotNone(default, label)
        return default

    def test_configure_refuses_before_the_wizard_or_any_managed_write(self):
        before = {path.name: path.read_bytes() for path in self.config.iterdir()}
        with self.lock.open("w") as owner, \
                mock.patch.object(cli, "configure_interactively", wraps=cli.configure_interactively) as wizard, \
                mock.patch.object(cli, "run_playbook") as playbook:
            fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
            for arguments in (("configure", "--apply"), ("configure",)):
                with self.subTest(arguments=arguments):
                    self.assertEqual(self.run_cli(*arguments), 2)
            wizard.assert_not_called()
            playbook.assert_not_called()
            self.assertEqual(before, {path.name: path.read_bytes() for path in self.config.iterdir()})
            self.assertEqual(list(self.config.glob("backups/*")), [])

    def test_other_external_mutations_refuse_the_same_real_flock(self):
        with self.lock.open("w") as owner, \
                mock.patch.object(cli, "config_dir") as config_dir, \
                mock.patch.object(cli, "configure_interactively") as wizard, \
                mock.patch.object(cli, "run_playbook") as playbook:
            fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
            for arguments in (
                ("install",), ("install", "--reconfigure"),
                ("language", "--language", "ru", "--apply"),
                ("language", "--language", "ru"),
                ("migrate-domain", "--new-domain", "new.example.test"),
                ("promote-production", "--new-domain", "new.example.test"),
                ("set-channels", "--release-channel", "alpha"),
            ):
                with self.subTest(arguments=arguments):
                    self.assertEqual(self.run_cli(*arguments), 2)
            config_dir.assert_not_called()
            wizard.assert_not_called()
            playbook.assert_not_called()

    def test_displaying_channels_does_not_need_the_mutation_lock(self):
        with self.lock.open("w") as owner:
            fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.run_cli("set-channels"), 0)
            self.assertEqual(cli._maintenance_lock_descriptor, -1)

    def test_real_configuration_writes_and_apply_keep_custody(self):
        writes = []
        write_yaml = cli.write_yaml

        def checked_write(path, value):
            self.assert_lock_held()
            writes.append(Path(path).name)
            return write_yaml(path, value)

        with mock.patch.object(cli, "write_yaml", side_effect=checked_write), \
                mock.patch.object(cli, "prompt", side_effect=self.answer), \
                mock.patch("builtins.input", return_value=""), \
                mock.patch.object(cli, "run_playbook", side_effect=lambda *a, **kw: self.assert_lock_held()) as playbook:
            result = self.run_cli("configure", "--apply", "--certificate-source", "letsencrypt",
                                  "--image-channel", "latest")
        self.assertEqual(result, 0)
        self.assertIn("vars.yml", writes)
        self.assertIn("metadata.yml", writes)
        self.assertEqual(cli.load_yaml_mapping(self.config / "vars.yml")["haproxy_admin_timezone"],
                         "Europe/London")
        self.assertEqual(playbook.call_args.args[0], cli.CONFIGURE_TAGS)
        self.assert_lock_held()

    def test_apply_failure_does_not_drop_custody(self):
        with mock.patch.object(cli, "configure_interactively", return_value=self.config), \
                mock.patch.object(cli, "run_playbook", side_effect=cli.InstallerError("apply failed")):
            self.assertEqual(self.run_cli("configure", "--apply"), 2)
        self.assert_lock_held()

    def test_inherited_or_broker_custody_does_not_reacquire_the_lock(self):
        with self.lock.open("w") as owner, \
                mock.patch.object(cli, "configure_interactively", return_value=self.config), \
                mock.patch.object(cli, "run_playbook", side_effect=lambda *a, **kw: self.assert_lock_held()):
            fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
            for value in ("cli", "updated"):
                with self.subTest(value=value):
                    os.environ[cli.MAINTENANCE_LOCK_HELD_ENV] = value
                    self.assertEqual(self.run_cli("configure", "--apply"), 0)
                    self.assertEqual(cli._maintenance_lock_descriptor, -1)
            os.environ.pop(cli.MAINTENANCE_LOCK_HELD_ENV)
            with mock.patch.object(cli, "started_by_update_broker", return_value=True):
                self.assertEqual(self.run_cli("configure", "--apply"), 0)
                self.assertEqual(cli._maintenance_lock_descriptor, -1)

    def test_internal_restore_reconciliation_keeps_the_backup_brokers_custody(self):
        # Older backup brokers have no HELD environment marker. Their internal
        # apply-restored child must continue under the parent's existing lock.
        with self.lock.open("w") as owner, \
                mock.patch.object(cli, "ensure_security_secrets"), \
                mock.patch.object(cli, "sync_runtime_authelia_rules_to_managed"), \
                mock.patch.object(cli, "run_playbook", side_effect=lambda *a, **kw: self.assert_lock_held()):
            fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
            for scope in ("full", "config"):
                with self.subTest(scope=scope):
                    self.assertEqual(self.run_cli("apply-restored", "--scope", scope), 0)
            self.assertEqual(cli._maintenance_lock_descriptor, -1)


if __name__ == "__main__":
    unittest.main()
