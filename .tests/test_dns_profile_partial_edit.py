"""A partial edit of a DNS profile keeps what it does not change (F20).

From the 30 October review, reproduced there: the page sends only the
fields filled in (an empty one means "unchanged"), but certd wrote the file
from the sent fields alone -- changing an RFC 2136 server erased the TSIG
name and secret, the save looked fine, and the next issuance or renewal
lacked them.
"""

from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".tests"))

from test_certd_dns import certd  # noqa: E402

FULL = {
    "dns_rfc2136_server": "192.0.2.53",
    "dns_rfc2136_port": "53",
    "dns_rfc2136_name": "acme.example.test.",
    "dns_rfc2136_secret": "c2VjcmV0LXRzaWcta2V5",
    "dns_rfc2136_algorithm": "HMAC-SHA512",
}


class PartialEdit(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        patcher = mock.patch.object(certd, "DNS_CREDENTIALS_DIR", Path(directory.name) / "dns")
        patcher.start()
        self.addCleanup(patcher.stop)

    def save(self, provider, credentials):
        return certd.save_dns_provider({"name": "zone", "provider": provider, "credentials": credentials})

    def stored(self):
        return certd._read_dns_profile(certd._dns_profile_path("zone"))

    def test_changing_one_field_keeps_the_secrets(self):
        self.save("rfc2136", FULL)
        self.save("rfc2136", {"dns_rfc2136_server": "198.51.100.53"})
        stored = self.stored()
        self.assertEqual(stored["values"]["dns_rfc2136_server"], "198.51.100.53")
        self.assertEqual(stored["values"]["dns_rfc2136_secret"], FULL["dns_rfc2136_secret"])
        self.assertEqual(stored["values"]["dns_rfc2136_name"], FULL["dns_rfc2136_name"])

    def test_an_empty_field_is_unchanged(self):
        self.save("rfc2136", FULL)
        self.save("rfc2136", {"dns_rfc2136_secret": "", "dns_rfc2136_port": "5353"})
        self.assertEqual(self.stored()["values"]["dns_rfc2136_secret"], FULL["dns_rfc2136_secret"])

    def test_another_provider_starts_afresh(self):
        self.save("rfc2136", FULL)
        self.save("cloudflare", {"dns_cloudflare_api_token": "token"})
        stored = self.stored()
        self.assertEqual(stored["provider"], "cloudflare")
        self.assertEqual(stored["values"], {"dns_cloudflare_api_token": "token"})

    def test_the_file_stays_private(self):
        self.save("rfc2136", FULL)
        self.save("rfc2136", {"dns_rfc2136_server": "198.51.100.53"})
        path = certd._dns_profile_path("zone")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
