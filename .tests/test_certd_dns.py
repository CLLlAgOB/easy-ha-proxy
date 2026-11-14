"""Regression checks for DNS-01 issuance and provider credentials."""

from __future__ import annotations

import configparser
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_certd():
    path = ROOT / "ansible/roles/haproxy-admin/files/haproxy-certd.py"
    spec = importlib.util.spec_from_file_location("easy_ha_proxy_certd", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


certd = load_certd()


class CredentialsTestCase(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        patcher = mock.patch.object(
            certd, "DNS_CREDENTIALS_DIR", Path(self.directory.name) / "dns"
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        le_root = mock.patch.object(certd, "LETSENCRYPT_ROOT_DIR", Path(self.directory.name) / "letsencrypt")
        le_root.start()
        self.addCleanup(le_root.stop)

    def save(self, **overrides):
        payload = {
            "name": "my-cloudflare",
            "provider": "cloudflare",
            "credentials": {"dns_cloudflare_api_token": "secret-token"},
        }
        payload.update(overrides)
        return certd.save_dns_provider(payload)


class ProfileStorageTests(CredentialsTestCase):
    def test_credentials_are_written_root_only(self):
        self.save()
        path = certd.DNS_CREDENTIALS_DIR / "my-cloudflare.ini"
        self.assertTrue(path.is_file())
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(
            stat.S_IMODE(certd.DNS_CREDENTIALS_DIR.stat().st_mode), 0o700
        )

    def test_the_file_is_the_ini_certbot_expects(self):
        self.save()
        text = (certd.DNS_CREDENTIALS_DIR / "my-cloudflare.ini").read_text()
        self.assertIn("dns_cloudflare_api_token = secret-token", text)
        self.assertIn("# provider: cloudflare", text)

    def test_a_newline_in_a_value_is_refused(self):
        # Otherwise one value could introduce another directive into a file
        # certbot reads as root.
        for hostile in (
            "token\ndns_cloudflare_email = attacker@example.com",
            "token\rmore",
            "token\x00",
        ):
            with self.assertRaises(ValueError):
                self.save(credentials={"dns_cloudflare_api_token": hostile})

    def test_an_unsupported_provider_is_refused(self):
        for provider in ("", "nope", "cloudflare; rm -rf /", None):
            with self.assertRaises(ValueError):
                self.save(provider=provider)

    def test_an_unknown_credential_field_is_refused(self):
        with self.assertRaises(ValueError):
            self.save(credentials={"dns_cloudflare_api_token": "x", "extra": "y"})

    def test_empty_credentials_are_refused(self):
        with self.assertRaises(ValueError):
            self.save(credentials={})
        with self.assertRaises(ValueError):
            self.save(credentials={"dns_cloudflare_api_token": ""})

    def test_an_oversized_value_is_refused(self):
        with self.assertRaises(ValueError):
            self.save(credentials={"dns_cloudflare_api_token": "x" * 99999})

    def test_the_profile_name_cannot_escape_the_directory(self):
        for hostile in (
            "../../etc/passwd", "..", "", "with space", "UPPER", "a" * 60, "x/y",
        ):
            with self.assertRaises(ValueError, msg=hostile):
                certd._dns_profile_path(hostile)

    def test_listing_never_returns_a_secret(self):
        self.save()
        with mock.patch.object(certd, "_installed_dns_plugins", return_value=set()):
            payload = certd.list_dns_providers()
        blob = repr(payload)
        self.assertNotIn("secret-token", blob)
        profile = payload["profiles"][0]
        self.assertEqual(profile["name"], "my-cloudflare")
        self.assertEqual(profile["provider"], "cloudflare")
        self.assertFalse(profile["plugin_available"])

    def test_listing_reports_which_plugins_are_installed(self):
        with mock.patch.object(
            certd, "_installed_dns_plugins", return_value={"dns-cloudflare"}
        ):
            payload = certd.list_dns_providers()
        self.assertTrue(payload["providers"]["cloudflare"]["available"])
        self.assertFalse(payload["providers"]["route53"]["available"])
        self.assertEqual(
            payload["providers"]["cloudflare"]["snap"], "certbot-dns-cloudflare"
        )

    def test_saving_twice_replaces_rather_than_appends(self):
        self.save()
        self.save(credentials={"dns_cloudflare_api_token": "second"})
        text = (certd.DNS_CREDENTIALS_DIR / "my-cloudflare.ini").read_text()
        self.assertIn("second", text)
        self.assertNotIn("secret-token", text)

    def test_deleting_a_profile_removes_the_file(self):
        self.save()
        self.assertTrue(certd.delete_dns_provider("my-cloudflare")["deleted"])
        self.assertFalse((certd.DNS_CREDENTIALS_DIR / "my-cloudflare.ini").exists())
        self.assertFalse(certd.delete_dns_provider("my-cloudflare")["deleted"])

    def test_deleting_refuses_a_hostile_name(self):
        with self.assertRaises(ValueError):
            certd.delete_dns_provider("../../etc/passwd")


class ChallengeFlagTests(CredentialsTestCase):
    def test_the_plugin_and_credentials_come_from_the_table(self):
        self.save()
        with mock.patch.object(
            certd, "_installed_dns_plugins", return_value={"dns-cloudflare"}
        ):
            flags = certd._dns_challenge_flags("my-cloudflare", 90)
        self.assertIn("--dns-cloudflare", flags)
        self.assertIn("--preferred-challenges", flags)
        self.assertIn("dns-01", flags)
        self.assertIn("--dns-cloudflare-credentials", flags)
        self.assertIn("90", flags)

    def test_propagation_is_clamped(self):
        self.save()
        with mock.patch.object(
            certd, "_installed_dns_plugins", return_value={"dns-cloudflare"}
        ):
            for supplied, expected in ((1, "10"), (99999, "1800"), ("abc", "60")):
                flags = certd._dns_challenge_flags("my-cloudflare", supplied)
                self.assertIn(expected, flags, str(supplied))

    def test_route53_takes_no_credentials_file(self):
        self.save(
            name="aws",
            provider="route53",
            credentials={"aws_access_key_id": "AK", "aws_secret_access_key": "s"},
        )
        with mock.patch.object(
            certd, "_installed_dns_plugins", return_value={"dns-route53"}
        ):
            flags = certd._dns_challenge_flags("aws")
        self.assertIn("--dns-route53", flags)
        self.assertNotIn("--dns-route53-credentials", flags)

    def test_a_missing_plugin_is_reported_with_what_to_install(self):
        self.save()
        with mock.patch.object(certd, "_installed_dns_plugins", return_value=set()):
            with self.assertRaises(ValueError) as caught:
                certd._dns_challenge_flags("my-cloudflare")
        self.assertIn("certbot-dns-cloudflare", str(caught.exception))

    def test_an_unknown_profile_is_refused(self):
        with self.assertRaises(ValueError):
            certd._dns_challenge_flags("nonexistent")


class IssuanceTests(CredentialsTestCase):
    def run_certbot(self, **kwargs):
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            captured["timeout"] = kwargs.get("timeout")
            return mock.Mock(returncode=0, stdout="", stderr="")

        arguments = {
            "lineage": "shop",
            "domain": "shop.example.com",
            "alt_names": [],
            "key_type": "ecdsa",
            "email": "a@example.com",
            "rsa_key_size": 2048,
            "ecdsa_curve": "secp256r1",
        }
        arguments.update(kwargs)
        with (
            mock.patch.object(certd, "_run_bounded", side_effect=fake_run),
            mock.patch.object(
                certd, "_installed_dns_plugins", return_value={"dns-cloudflare"}
            ),
        ):
            certd._run_certbot_for_lineage(**arguments)
        self.last_timeout = captured["timeout"]
        return captured["cmd"]

    def test_certbot_is_given_its_dns_wait_on_top_of_its_own_time(self):
        self.run_certbot()
        self.assertEqual(self.last_timeout, certd.CERTBOT_TIMEOUT_SECONDS)
        self.save()
        self.run_certbot(dns_profile="my-cloudflare", dns_propagation=1800)
        self.assertEqual(self.last_timeout, certd.CERTBOT_TIMEOUT_SECONDS + 1800)
        # Asked for longer than allowed: certbot is told the maximum, and
        # gets exactly that much more time.
        cmd = self.run_certbot(dns_profile="my-cloudflare", dns_propagation=99999)
        self.assertIn(str(certd.DNS_PROPAGATION_MAX), cmd)
        self.assertEqual(
            self.last_timeout, certd.CERTBOT_TIMEOUT_SECONDS + certd.DNS_PROPAGATION_MAX
        )

    def test_without_a_profile_the_existing_http_path_is_unchanged(self):
        cmd = self.run_certbot()
        self.assertIn("--standalone", cmd)
        self.assertIn("http-01", cmd)
        self.assertNotIn("--dns-cloudflare", cmd)

    def test_with_a_profile_the_challenge_becomes_dns(self):
        self.save()
        cmd = self.run_certbot(dns_profile="my-cloudflare")
        self.assertIn("--dns-cloudflare", cmd)
        self.assertIn("dns-01", cmd)
        self.assertNotIn("--standalone", cmd)
        self.assertNotIn("http-01", cmd)

    def test_a_wildcard_without_dns_is_refused_before_certbot_runs(self):
        # HTTP-01 cannot validate a wildcard; letting certbot discover that
        # wastes a rate-limited ACME attempt.
        with self.assertRaises(ValueError) as caught:
            self.run_certbot(domain="*.example.com")
        self.assertIn("wildcard", str(caught.exception).lower())

    def test_a_wildcard_in_an_alt_name_is_caught_too(self):
        with self.assertRaises(ValueError):
            self.run_certbot(
                domain="example.com", alt_names=["*.example.com"]
            )

    def test_a_wildcard_with_dns_is_allowed(self):
        self.save()
        cmd = self.run_certbot(
            domain="example.com",
            alt_names=["*.example.com"],
            dns_profile="my-cloudflare",
        )
        self.assertIn("*.example.com", cmd)
        self.assertIn("--dns-cloudflare", cmd)

    def test_no_request_value_reaches_the_command_as_a_flag(self):
        self.save()
        cmd = self.run_certbot(dns_profile="my-cloudflare", dns_propagation="60")
        # Everything certbot is told about the plugin is derived from the
        # provider table; the request only chose a profile name.
        for argument in cmd:
            if argument.startswith("--"):
                self.assertNotIn(" ", argument)


class WildcardNameTests(unittest.TestCase):
    def test_a_wildcard_is_refused_unless_it_is_asked_for(self):
        with self.assertRaises(ValueError):
            certd._normalize_dns_name("*.example.com")

    def test_only_the_leftmost_label_may_be_a_wildcard(self):
        for hostile in ("shop.*.example.com", "*.*.example.com", "*example.com"):
            with self.assertRaises(ValueError, msg=hostile):
                certd._normalize_dns_name(hostile, allow_wildcard=True)

    def test_a_wildcard_needs_a_registrable_domain_beneath_it(self):
        # "*.com" would ask a public CA for every name in a TLD.
        with self.assertRaises(ValueError):
            certd._normalize_dns_name("*.com", allow_wildcard=True)

    def test_an_accepted_wildcard_is_normalized(self):
        self.assertEqual(
            certd._normalize_dns_name("*.Example.COM.", allow_wildcard=True),
            "*.example.com",
        )


class LineageNameTests(CredentialsTestCase):
    def issue(self, **overrides):
        payload = {
            "domain": "*.example.com",
            "alt_names": [],
            "key_types": ["ecdsa"],
            "dns_profile": "my-cloudflare",
        }
        payload.update(overrides)
        captured = []

        def fake_lineage(**kwargs):
            captured.append(kwargs["lineage"])
            return {"rc": 1, "stdout": "", "stderr": "stopped in the test"}

        with (
            mock.patch.object(
                certd, "_run_certbot_for_lineage", side_effect=fake_lineage
            ),
            mock.patch.object(
                certd, "_installed_dns_plugins", return_value={"dns-cloudflare"}
            ),
            mock.patch.object(
                certd,
                "_get_certbot_settings",
                return_value=("a@example.com", "ecdsa", 2048, "secp256r1"),
            ),
            mock.patch.object(certd, "get_latest_account_id", return_value=None),
            mock.patch.object(
                certd.Path, "is_file", lambda self: True
            ),
        ):
            status, body = certd.handle_certs_issue(payload)
        return status, body, captured

    def test_a_wildcard_lineage_drops_its_leftmost_label(self):
        # The lineage is a directory name under /etc/letsencrypt/live and a PEM
        # file name in the HAProxy certificate directory; a literal "*" there
        # would be read as a glob by everything downstream.
        self.save()
        _status, _body, lineages = self.issue()
        self.assertEqual(lineages, ["example.com"])

    def test_the_key_type_suffix_still_applies(self):
        self.save()
        _status, _body, lineages = self.issue(key_types=["ecdsa", "rsa"])
        self.assertEqual(lineages, ["example.com-ecdsa", "example.com-rsa"])

    def test_a_wildcard_without_a_profile_is_refused_by_the_handler(self):
        status, body, lineages = self.issue(dns_profile="")
        self.assertEqual(status, 400)
        self.assertIn("wildcard", str(body.get("error")).lower())
        self.assertEqual(lineages, [])

    def test_an_unknown_profile_fails_before_any_certbot_run(self):
        status, body, lineages = self.issue(
            domain="example.com", dns_profile="nonexistent"
        )
        self.assertEqual(status, 400)
        self.assertEqual(lineages, [])


class DeploymentNoteTests(unittest.TestCase):
    def test_the_provider_table_records_the_snap_to_install(self):
        # Certbot here is a snap, so plugins are snaps too and must match its
        # version; apt packages are not the mechanism on this platform.
        for name, spec in certd.DNS_PROVIDERS.items():
            self.assertTrue(spec["snap"].startswith("certbot-dns-"), name)
            self.assertTrue(spec["plugin"].startswith("dns-"), name)
            self.assertTrue(spec["keys"], name)



class Route53ProcessContractTests(CredentialsTestCase):
    """Exercise real local subprocesses; no Certbot, AWS or service access."""

    def setUp(self):
        super().setUp()
        self.root = Path(self.directory.name)
        self.log = self.root / "children.jsonl"
        self.probe = self.root / "certbot-probe"
        self.probe.write_text("#!" + sys.executable + "\n" + r'''
import configparser
import json
import os
from pathlib import Path
import sys
import time
argv = sys.argv[1:]
lineage = argv[argv.index("--cert-name") + 1]
record = {"argv": argv, "lineage": lineage,
          "aws": {key: value for key, value in os.environ.items() if key.startswith("AWS_")}}
filename = os.environ.get("AWS_SHARED_CREDENTIALS_FILE", "")
if filename and Path(filename).is_file():
    parser = configparser.RawConfigParser()
    parser.read(filename)
    record["selected"] = dict(parser["default"])
with open(os.environ["PROBE_LOG"], "a") as handle:
    handle.write(json.dumps(record) + "\n")
if os.environ.get("PROBE_HANG_LINEAGE") == lineage:
    time.sleep(30)
print(json.dumps(record))
sys.exit(1 if os.environ.get("PROBE_FAIL_LINEAGE") == lineage else 0)
''')
        self.probe.chmod(0o700)
        environment = mock.patch.dict(os.environ, {
            "PROBE_LOG": str(self.log),
            "AWS_ACCESS_KEY_ID": "synthetic-ambient-key",
            "AWS_SECRET_ACCESS_KEY": "synthetic-ambient-secret",
            "AWS_SESSION_TOKEN": "synthetic-ambient-session",
            "AWS_ROLE_ARN": "synthetic-ambient-role",
            "AWS_WEB_IDENTITY_TOKEN_FILE": "/missing-web-identity",
            "AWS_PROFILE": "ambient-profile",
            "AWS_SHARED_CREDENTIALS_FILE": str(self.root / "ambient.ini"),
        })
        environment.start()
        self.addCleanup(environment.stop)
        for attribute, value in (
            ("CERTBOT_BIN", self.probe),
            ("CERTD_DRY_RUN", False),
        ):
            patcher = mock.patch.object(certd, attribute, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        plugins = mock.patch.object(certd, "_installed_dns_plugins", return_value={"dns-route53", "dns-cloudflare"})
        plugins.start()
        self.addCleanup(plugins.stop)

    def route53(self, name="zone-a"):
        return self.save(name=name, provider="route53", credentials={
            "aws_access_key_id": f"synthetic-{name}-key",
            "aws_secret_access_key": f"synthetic-{name}-secret%value",
        })

    def issue(self, lineage="a.example.com", profile="zone-a"):
        return certd._run_certbot_for_lineage(
            lineage, lineage, [], "rsa", "test@example.com", 2048, "secp256r1", dns_profile=profile
        )

    def conf(self, lineage, authenticator="dns-route53"):
        directory = certd.LETSENCRYPT_ROOT_DIR / "renewal"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"{lineage}.conf").write_text(
            f"version = 4.0\n[renewalparams]\nauthenticator = {authenticator}\n"
            "[[webroot_map]]\nexample.com = /var/www\n"
        )

    def children(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_initial_issuance_selects_each_profile_in_the_real_child(self):
        environment_before = dict(os.environ)
        for profile, lineage in (("zone-a", "a.example.com"), ("zone-b", "b.example.com")):
            self.route53(profile)
            result = self.issue(lineage, profile)
            self.assertEqual(result["rc"], 0)
            child = json.loads(result["stdout"])
            self.assertEqual(child["selected"]["aws_access_key_id"], f"synthetic-{profile}-key")
            self.assertEqual(child["selected"]["aws_secret_access_key"], f"synthetic-{profile}-secret%value")
            self.assertEqual(child["aws"]["AWS_PROFILE"], "default")
            self.assertEqual(child["aws"]["AWS_CONFIG_FILE"], "/dev/null")
            self.assertNotIn("AWS_ACCESS_KEY_ID", child["aws"])
            self.assertNotIn("AWS_ROLE_ARN", child["aws"])
            self.assertNotIn("AWS_SESSION_TOKEN", child["aws"])
            self.assertNotIn("synthetic-", result["cmd"])
            binding = certd._dns_binding_path(lineage)
            self.assertEqual(json.loads(binding.read_text()), {"profile": profile})
            for path, mode in ((binding, 0o600), (binding.parent, 0o700),
                               (certd._dns_profile_path(profile), 0o600)):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
        self.assertEqual(dict(os.environ), environment_before)

    def test_legacy_sectionless_profiles_migrate_to_private_aws_ini(self):
        path = certd._dns_profile_path("legacy")
        path.parent.mkdir()
        original = "# provider: route53\naws_access_key_id = legacy-key\naws_secret_access_key = legacy-secret\n"
        path.write_text(original)
        environment = certd._route53_environment("legacy")
        parser = configparser.RawConfigParser()
        parser.read(environment["AWS_SHARED_CREDENTIALS_FILE"])
        self.assertEqual(parser["default"]["aws_access_key_id"], "legacy-key")
        self.assertEqual(parser["default"]["aws_secret_access_key"], "legacy-secret")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)

    def test_failed_legacy_migration_leaves_the_original_file_intact(self):
        self.route53()
        path = certd._dns_profile_path("zone-a")
        path.write_text(path.read_text().replace("[default]\n", ""))
        before = path.read_bytes()
        # Path.replace, not os.replace: on Python 3.10 Path.replace reaches
        # os.replace through an accessor bound when pathlib is imported.
        with mock.patch.object(certd.Path, "replace", side_effect=OSError("atomic replace denied")):
            with self.assertRaisesRegex(OSError, "atomic replace denied"):
                certd._route53_environment("zone-a")
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(list(path.parent.iterdir()), [path])

    def test_an_incomplete_legacy_profile_cannot_fall_back_to_ambient_credentials(self):
        path = certd._dns_profile_path("broken")
        path.parent.mkdir()
        path.write_text("# provider: route53\naws_access_key_id = partial-key\n")
        with self.assertRaisesRegex(ValueError, "both AWS"):
            self.issue(profile="broken")
        self.assertFalse(self.log.exists())

    def test_a_failed_issuance_restores_the_previous_profile_binding(self):
        self.route53("zone-a")
        self.route53("zone-b")
        self.issue()
        binding = certd._dns_binding_path("a.example.com")
        before = binding.read_bytes()
        with mock.patch.dict(os.environ, {"PROBE_FAIL_LINEAGE": "a.example.com"}):
            self.assertEqual(self.issue(profile="zone-b")["rc"], 1)
        self.assertEqual(binding.read_bytes(), before)
        with mock.patch.object(certd, "CERTBOT_BIN", self.root / "missing-certbot"):
            with self.assertRaises(FileNotFoundError):
                self.issue(profile="zone-b")
        self.assertEqual(binding.read_bytes(), before)

    def test_reissue_with_another_method_removes_binding_only_after_success(self):
        self.route53()
        self.save()
        self.issue()
        binding = certd._dns_binding_path("a.example.com")
        with mock.patch.dict(os.environ, {"PROBE_FAIL_LINEAGE": "a.example.com"}):
            self.assertEqual(self.issue(profile="my-cloudflare")["rc"], 1)
        self.assertTrue(binding.exists())
        self.conf("a.example.com", "dns-cloudflare")
        self.assertEqual(self.issue(profile="my-cloudflare")["rc"], 0)
        self.assertFalse(binding.exists())

    def test_a_successful_certbot_noop_keeps_the_current_route53_binding(self):
        self.route53()
        self.save()
        self.issue()
        self.conf("a.example.com")
        binding = certd._dns_binding_path("a.example.com")
        before = binding.read_bytes()
        self.assertEqual(self.issue(profile="my-cloudflare")["rc"], 0)
        self.assertEqual(binding.read_bytes(), before)
        self.assertEqual(certd.renew_certificates(), 0)
        self.assertEqual(self.children()[-1]["selected"]["aws_access_key_id"], "synthetic-zone-a-key")

    def test_a_manual_authenticator_change_supersedes_an_old_binding(self):
        self.route53()
        self.issue()
        self.conf("a.example.com", "standalone")
        self.assertTrue(certd.delete_dns_provider("zone-a")["deleted"])
        self.assertEqual(certd.renew_certificates(), 0)
        self.assertEqual(self.children()[-1]["aws"]["AWS_ACCESS_KEY_ID"], "synthetic-ambient-key")

    def test_renewal_uses_two_selected_accounts_and_preserves_other_methods_and_hooks(self):
        for profile, lineage in (("zone-a", "a.example.com"), ("zone-b", "b.example.com")):
            self.route53(profile)
            self.issue(lineage, profile)
            self.conf(lineage)
        self.conf("http.example.com", "standalone")
        self.conf("cloudflare.example.com", "dns-cloudflare")
        self.conf("manual-aws.example.com")
        self.log.unlink()
        calls = []
        real = certd._run_bounded

        def bounded(*args, **kwargs):
            calls.append(kwargs["timeout"])
            return real(*args, **kwargs)

        with mock.patch.object(certd, "_run_bounded", side_effect=bounded):
            self.assertEqual(certd.renew_certificates(), 0)
        children = {child["lineage"]: child for child in self.children()}
        self.assertEqual(len(children), 5)
        self.assertEqual(len(calls), 5)
        self.assertTrue(all(value == certd.CERTBOT_TIMEOUT_SECONDS + certd.DNS_PROPAGATION_MAX for value in calls))
        for profile, lineage in (("zone-a", "a.example.com"), ("zone-b", "b.example.com")):
            self.assertEqual(children[lineage]["selected"]["aws_access_key_id"], f"synthetic-{profile}-key")
        for lineage in ("http.example.com", "cloudflare.example.com", "manual-aws.example.com"):
            self.assertEqual(children[lineage]["aws"]["AWS_ACCESS_KEY_ID"], "synthetic-ambient-key")
        for child in children.values():
            self.assertEqual(child["argv"][0], "renew")
            self.assertIn("--no-random-sleep-on-renew", child["argv"])
            self.assertIn(str(certd.LETSENCRYPT_ROOT_DIR), child["argv"])
            self.assertNotIn("--force-renewal", child["argv"])
            self.assertNotIn("--no-directory-hooks", child["argv"])

    def test_renewal_continues_after_a_bad_binding_or_failed_certbot(self):
        self.route53()
        self.issue("a.example.com")
        self.conf("a.example.com")
        certd._dns_profile_path("zone-a").unlink()
        self.conf("b.example.com", "standalone")
        self.conf("c.example.com", "standalone")
        self.log.unlink()
        with mock.patch.dict(os.environ, {"PROBE_FAIL_LINEAGE": "b.example.com"}):
            self.assertEqual(certd.renew_certificates(), 1)
        self.assertEqual([child["lineage"] for child in self.children()], ["b.example.com", "c.example.com"])

    def test_a_timed_out_renewal_does_not_skip_the_next_lineage(self):
        self.conf("a.example.com", "standalone")
        self.conf("b.example.com", "standalone")
        started = time.monotonic()
        # Long enough for the healthy lineage's probe to start on a slow host
        # (0.2 s failed on an ARM test machine), short beside the 8 s bound.
        with mock.patch.object(certd, "CERTBOT_TIMEOUT_SECONDS", 2), \
                mock.patch.object(certd, "DNS_PROPAGATION_MAX", 0), \
                mock.patch.dict(os.environ, {"PROBE_HANG_LINEAGE": "a.example.com"}):
            self.assertEqual(certd.renew_certificates(), 1)
        self.assertLess(time.monotonic() - started, 8)
        self.assertEqual([child["lineage"] for child in self.children()], ["a.example.com", "b.example.com"])

    def test_active_bindings_prevent_deleting_or_changing_the_provider(self):
        self.route53()
        self.issue()
        self.conf("a.example.com")
        with self.assertRaisesRegex(ValueError, "a.example.com"):
            certd.delete_dns_provider("zone-a")
        with self.assertRaisesRegex(ValueError, "automatic renewal"):
            self.save(name="zone-a")
        # Rotating a key in the same account/profile remains supported.
        self.save(name="zone-a", provider="route53", credentials={"aws_access_key_id": "rotated-key"})
        self.assertEqual(certd.renew_certificates(), 0)
        self.assertEqual(self.children()[-1]["selected"]["aws_access_key_id"], "rotated-key")
        self.assertIn("aws_secret_access_key", self.children()[-1]["selected"])
        (certd.LETSENCRYPT_ROOT_DIR / "renewal/a.example.com.conf").unlink()
        self.assertTrue(certd.delete_dns_provider("zone-a")["deleted"])

    def test_deleting_a_lineage_removes_its_binding(self):
        self.route53()
        self.issue()
        with mock.patch.object(certd, "_run_bounded", return_value=mock.Mock(returncode=0, stdout="", stderr="")):
            _status, result = certd.handle_delete_le({"lineage": "a.example.com"})
        self.assertTrue(result["ok"])
        self.assertFalse(certd._dns_binding_path("a.example.com").exists())


class RenewalServiceContractTests(unittest.TestCase):
    def test_the_managed_snap_timer_override_renders_default_and_custom_paths(self):
        from jinja2 import Environment, StrictUndefined
        import yaml

        template = ROOT / "ansible/roles/haproxy-admin/templates/certbot-renew.service.conf.j2"
        for context, root, credentials in (
            ({}, "/etc/letsencrypt", "/etc/easy-ha-proxy/dns-providers"),
            ({"letsencrypt_root_dir": "/srv/acme", "dns_credentials_dir": "/srv/dns"}, "/srv/acme", "/srv/dns"),
        ):
            rendered = Environment(undefined=StrictUndefined).from_string(template.read_text()).render(**context)
            self.assertIn("ExecStart=\nExecStart=/usr/bin/python3 /usr/local/sbin/haproxy-certd.py --renew", rendered)
            self.assertIn(f'Environment="LETSENCRYPT_ROOT_DIR={root}"', rendered)
            self.assertIn(f'Environment="HAPROXY_DNS_CREDENTIALS_DIR={credentials}"', rendered)
            self.assertIn("TimeoutStartSec=infinity", rendered)
            self.assertIn("KillMode=control-group", rendered)
        tasks = yaml.safe_load((ROOT / "ansible/roles/haproxy-admin/tasks/certd.yml").read_text())
        override = next(item for item in tasks if item.get("register") == "certbot_renew_unit")
        self.assertEqual(override["ansible.builtin.template"]["dest"],
                         "/etc/systemd/system/snap.certbot.renew.service.d/easy-ha-proxy.conf")
        reload_task = next(item for item in tasks if item.get("ansible.builtin.systemd", {}).get("daemon_reload"))
        self.assertIn("certbot_renew_unit.changed", reload_task["when"])

if __name__ == "__main__":
    unittest.main()
