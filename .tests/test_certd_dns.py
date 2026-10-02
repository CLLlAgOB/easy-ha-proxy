"""Regression checks for DNS-01 issuance and provider credentials."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
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

        def fake_run(cmd, **_kwargs):
            captured["cmd"] = cmd
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
            mock.patch.object(certd.subprocess, "run", side_effect=fake_run),
            mock.patch.object(
                certd, "_installed_dns_plugins", return_value={"dns-cloudflare"}
            ),
        ):
            certd._run_certbot_for_lineage(**arguments)
        return captured["cmd"]

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


if __name__ == "__main__":
    unittest.main()
