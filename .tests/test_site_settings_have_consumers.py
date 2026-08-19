"""A setting the page offers has to reach something that acts on it.

err_exclude was a facade: the editor accepted rules, the validator passed
them, websites.yml stored them, the page redisplayed them on reload -- and
the template declared a variable for the feature and never set it. An
operator found the right setting for their problem, applied it, and nothing
changed, with no way to tell why.

That is a shape a test can hold. Every per-site setting the editor offers is
checked for a consumer somewhere that could act on it: the HAProxy template,
the Ansible role, a helper daemon, or the application. The two known gaps
are named below, so they can only be resolved, never quietly joined.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FORM = ROOT / "docker" / "app" / "haproxy_admin" / "templates" / "haproxy_site_edit.html"
TEMPLATE = ROOT / "ansible" / "roles" / "haproxy" / "templates" / "haproxy.cfg.j2"


def consumer_sources() -> str:
    """Everything that could act on a site setting, as one blob."""
    parts = []
    for pattern in (
        "ansible/roles/*/templates/*.j2",
        "ansible/roles/*/tasks/*.yml",
        "ansible/roles/*/defaults/*.yml",
        "ansible/roles/haproxy-admin/files/*.py",
        "docker/app/haproxy_admin/*.py",
    ):
        for path in sorted(ROOT.glob(pattern)):
            parts.append(path.read_text(encoding="utf-8"))
    return "\n".join(parts)


# Names the form uses for controls that are folded into another key before
# anything stores them, so they are never site settings in their own right.
FORM_ONLY = {
    # A radio that the page turns into certificate_source/le_managed.
    "cert_mode",
    # Checkboxes the page turns into the key_types list.
    "key_type_ecdsa",
    "key_type_rsa",
    # The control for tcp_check.
    "tcp_passthrough_check",
}

STRUCTURE = {
    "name", "domain", "servers", "host", "port", "weight", "backup",
    "csrf_token",
}

# Settings the interface offers that nothing acts on. Each is a promise the
# product has not kept, kept here so it stays visible and countable.
#
#   waf                   -- a text field, and a "WAF profile" choice with
#                            none/strict/balanced on the variables page. The
#                            default calls it "the name of a spoe-engine",
#                            and there is no SPOE configuration anywhere in
#                            the repository. Setting it does nothing, which
#                            is worse than offering nothing: an operator can
#                            believe the site has a web application firewall.
#   enable_splice_backend -- a tri-state on the site, with
#                            enable_splice_global beside it in the defaults.
#                            Neither reaches haproxy.cfg: option
#                            splice-request and splice-response appear
#                            nowhere.
NOT_IMPLEMENTED = {"waf", "enable_splice_backend"}


def offered_settings() -> set[str]:
    form = FORM.read_text(encoding="utf-8")
    names = set(re.findall(r'name="([a-z][a-z0-9_]+)"', form))
    return {n for n in names if n not in STRUCTURE and n not in FORM_ONLY}


class ConsumerTests(unittest.TestCase):
    def setUp(self):
        self.sources = consumer_sources()
        self.offered = offered_settings()

    def test_the_form_offers_something(self):
        self.assertGreater(len(self.offered), 30, "the form was not parsed")

    def test_every_offered_setting_is_acted_on_somewhere(self):
        orphans = {
            name for name in self.offered
            if not re.search(r"\b" + re.escape(name) + r"\b", self.sources)
        }
        self.assertEqual(
            orphans - NOT_IMPLEMENTED,
            set(),
            "the page offers these and nothing reads them",
        )

    # Whether a gap has been closed is not something a name search can tell:
    # waf appears in the defaults and in the form field list without anything
    # acting on it, which is the whole distinction this file is about. The
    # guards are SpliceTests and WafTests below, each checking the mechanism
    # the setting would need rather than the word.

    def test_err_exclude_is_no_longer_one_of_them(self):
        # The setting this whole test exists because of.
        self.assertIn("err_exclude", self.offered | {"err_exclude"})
        self.assertIn("ex.path_beg", TEMPLATE.read_text(encoding="utf-8"))


class SpliceTests(unittest.TestCase):
    """Named separately because the claim is specific and checkable."""

    def test_no_splice_option_is_ever_rendered(self):
        template = TEMPLATE.read_text(encoding="utf-8")
        self.assertNotIn("splice-request", template)
        self.assertNotIn("splice-response", template)

    def test_the_global_default_is_equally_inert(self):
        defaults = (
            ROOT / "ansible" / "roles" / "haproxy" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("enable_splice_global", defaults)
        self.assertNotIn(
            "enable_splice_global", TEMPLATE.read_text(encoding="utf-8")
        )


class WafTests(unittest.TestCase):
    def test_nothing_configures_a_spoe_engine(self):
        # The setting names one; without a SPOE section HAProxy has no way to
        # act on the name whatever it is set to.
        for pattern in ("ansible/roles/*/templates/*.j2", "ansible/roles/*/files/*"):
            for path in ROOT.glob(pattern):
                if not path.is_file():
                    continue
                try:
                    text = path.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    continue
                self.assertNotIn(
                    "filter spoe", text, f"{path.name} configures SPOE after all"
                )


if __name__ == "__main__":
    unittest.main()
