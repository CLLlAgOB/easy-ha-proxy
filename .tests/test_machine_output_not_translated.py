"""Machine output must reach the operator unaltered.

The DOM translator walks text nodes and substitutes word by word whatever it
does not recognise as a whole phrase. Point it at a daemon's output and it
rewrites the parts of a message that matter most:

    usr/локальный/bin/update-geoip.sh
    etc/iptables/haproxy_ban.правила
    etc/systemd/system/iptables-haproxy-бан.service
    /tmp/easy-ha-proxy-бэкап.zeq_kt_2/payload.tar.gz

Those are real lines an operator was shown for a failed backup. local, ban,
rules and backup are ordinary English words to the translator and load-bearing
path components to everyone else. The daemon's own journal had them right;
only the page was wrong, and the operator could neither find the files nor
search for the error.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "docker" / "app" / "haproxy_admin" / "templates"

# Containers a script fills with text that came from a daemon: paths, commands,
# exit codes, log lines, addresses. Each must be exempt from translation.
MACHINE_OUTPUT = {
    "system_backups.html": (
        "backup-jobs-body",        # the Result column carries the helper error
        "backup-job-log",          # raw job log
        "backup-destinations-body",
        "schedule-status",
        "schedule-last-run",
        "schedule-last-result",
        "schedule-next-run",
        "schedule-destinations",
        "schedule-passphrase-state",
        "dest-status",
    ),
    # A chosen file's name belongs to the operating system. Left
    # translatable, site-backup.pem is shown as site-бэкап.pem.
    "haproxy_certs.html": (
        "material-name",
        "backup_file_name",
    ),
    "haproxy_site_edit.html": (
        "cert-file-name",
    ),
    "detection_rules.html": (
        "dr-mine",          # the operator's own signatures
        "dr-shipped",       # every shipped signature
        "dr-category",      # category names in the add form
        "dr-query-note",    # the query rule names
        "dr-counts",
        "dr-version",
        "dr-result",
    ),
}


def attributes_of(markup: str, element_id: str) -> str:
    """The attribute text of the element carrying this id."""
    match = re.search(
        r"<[a-zA-Z]+[^>]*\bid=\"" + re.escape(element_id) + r"\"[^>]*>", markup
    )
    if match is None:
        raise AssertionError(f"no element with id={element_id}")
    return match.group(0)


class MachineOutputTests(unittest.TestCase):
    def test_every_machine_output_container_is_exempt(self):
        for name, ids in MACHINE_OUTPUT.items():
            markup = (TEMPLATES / name).read_text(encoding="utf-8")
            for element_id in ids:
                with self.subTest(template=name, element=element_id):
                    tag = attributes_of(markup, element_id)
                    self.assertIn(
                        "data-i18n-skip",
                        tag,
                        f"{element_id} shows daemon output and would be translated",
                    )
                    # translate="no" is the half browsers and extensions obey;
                    # data-i18n-skip is the half this application obeys. A
                    # container needs both or one of the two will rewrite it.
                    self.assertIn('translate="no"', tag)

    def test_the_jobs_table_specifically(self):
        # The one that produced the mangled paths. Named on its own so a
        # regression here is unmistakable in the failure output.
        markup = (TEMPLATES / "system_backups.html").read_text(encoding="utf-8")
        tag = attributes_of(markup, "backup-jobs-body")
        self.assertIn("data-i18n-skip", tag)
        self.assertIn('translate="no"', tag)


    def test_a_signature_specifically(self):
        """The second time this bug shipped, and on the worst possible page.

        backup.sql was displayed as бэкап.sql and database.sql as БД.sql,
        because "backup" and "database" are ordinary words in the catalogue
        and the translator substitutes any it finds inside a string it does
        not recognise whole. A signature rewritten on screen is a rule the
        operator cannot match against their own traffic, on the one page
        whose entire purpose is to show exactly what the engine matches.
        """
        markup = (TEMPLATES / "detection_rules.html").read_text(encoding="utf-8")
        for element_id in ("dr-shipped", "dr-mine"):
            with self.subTest(element=element_id):
                tag = attributes_of(markup, element_id)
                self.assertIn("data-i18n-skip", tag)
                self.assertIn('translate="no"', tag)

    def test_a_translated_placeholder_survives_the_exemption(self):
        # Exempting the container also stops the fallback text being
        # translated, so the script has to translate it instead -- otherwise
        # fixing the file name leaves "No file selected" in English.
        js = ROOT / "docker" / "app" / "haproxy_admin" / "static" / "js"
        for name in ("haproxy_certs.js", "haproxy_site_edit.js"):
            with self.subTest(script=name):
                source = (js / name).read_text(encoding="utf-8")
                self.assertNotIn('= "No file selected"', source)
                self.assertIn('window.t("No file selected")', source)

    def test_the_script_marks_the_signatures_itself(self):
        # Belt and braces: the container attribute is one edit away from
        # being lost, and a signature must survive that edit.
        script = (
            ROOT / "docker" / "app" / "haproxy_admin" / "static" / "js"
            / "detection_rules.js"
        ).read_text(encoding="utf-8")
        self.assertIn('setAttribute("data-i18n-skip", "")', script)
        self.assertIn('setAttribute("translate", "no")', script)
        # Applied to the chip that carries a signature, not only somewhere.
        block = script.split("function token(")[1].split("function ruleCard")[0]
        self.assertIn("keepVerbatim(", block)


class VocabularyTests(unittest.TestCase):
    """Words that are load-bearing in a path and ordinary in a sentence."""

    DANGEROUS = ("local", "ban", "rules", "backup", "key", "state",
                 "database", "custom")

    def test_the_replacement_rules_are_what_make_this_necessary(self):
        # Not a rule to change -- word-by-word substitution is the documented
        # fallback -- but a reason the exemptions above are not optional.
        catalogue = ROOT / "docker" / "app" / "haproxy_admin" / "translations"
        russian = "".join(
            path.read_text(encoding="utf-8")
            for path in catalogue.rglob("*.json")
        ).lower()
        hits = [word for word in self.DANGEROUS if f'"{word}"' in russian]
        self.assertTrue(
            hits,
            "if no single dangerous word is translated any more, this whole "
            "class of bug is gone and these exemptions can be revisited",
        )


if __name__ == "__main__":
    unittest.main()
