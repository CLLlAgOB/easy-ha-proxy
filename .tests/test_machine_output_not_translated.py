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


class VocabularyTests(unittest.TestCase):
    """Words that are load-bearing in a path and ordinary in a sentence."""

    DANGEROUS = ("local", "ban", "rules", "backup", "key", "state")

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
