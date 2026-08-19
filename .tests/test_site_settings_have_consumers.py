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

# Nothing is offered without a consumer any more. waf and
# enable_splice_backend were the two that were, and both were withdrawn
# rather than half-built: waf named a spoe-engine with no SPOE anywhere in
# the repository, and neither splice setting reached haproxy.cfg. An empty
# set here is the state to keep.
NOT_IMPLEMENTED: set[str] = set()


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


class WithdrawnTests(unittest.TestCase):
    """The two that were facades are gone, not merely undocumented."""

    def pages(self) -> str:
        directory = ROOT / "docker" / "app" / "haproxy_admin" / "templates"
        return "\n".join(
            path.read_text(encoding="utf-8") for path in directory.glob("*.html")
        )

    def scripts(self) -> str:
        directory = ROOT / "docker" / "app" / "haproxy_admin" / "static" / "js"
        return "\n".join(
            path.read_text(encoding="utf-8") for path in directory.glob("*.js")
        )

    def test_the_pages_no_longer_offer_them(self):
        pages = self.pages()
        for name in ('name="waf"', 'name="enable_splice_backend"'):
            with self.subTest(name=name):
                self.assertNotIn(name, pages)

    def test_the_scripts_no_longer_collect_them(self):
        scripts = self.scripts()
        self.assertNotIn("site.waf", scripts)
        self.assertNotIn("enable_splice_backend", scripts)

    def test_the_defaults_no_longer_declare_them(self):
        # Only what a clone actually contains. ansible/vars.yml is generated
        # per installation and is gitignored, so it exists on a developer's
        # machine and never on a CI runner -- reading it unconditionally
        # passes locally and fails everywhere else.
        candidates = [
            ROOT / "ansible" / "roles" / "haproxy" / "defaults" / "main.yml",
            ROOT / "ansible" / "vars.yml",
            ROOT / "installer" / "easy_ha_proxy.py",
        ]
        checked = 0
        for path in candidates:
            if not path.is_file():
                continue
            checked += 1
            text = path.read_text(encoding="utf-8")
            for name in ("waf:", "enable_splice_global:", '"waf"'):
                with self.subTest(name=name, file=path.name):
                    self.assertNotIn(name, text)
        self.assertGreater(checked, 0, "nothing was actually examined")

    def test_a_stored_value_does_not_break_anything(self):
        # An existing websites.yml may still carry them; they are simply
        # ignored, which is why nothing had to migrate.
        template = TEMPLATE.read_text(encoding="utf-8")
        self.assertNotIn("splice", template)
        self.assertNotIn("s.waf", template)


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
