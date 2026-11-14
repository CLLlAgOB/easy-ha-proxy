"""The CI fallback installs the same Ansible collections the playbook pins.

When Galaxy does not answer, the Ansible job builds the collections from
their GitHub tags. Those versions are written out in the workflow, so a bump
in ansible/requirements.yml that forgot the workflow would quietly check the
playbook against an older collection whenever Galaxy was down.
"""

from __future__ import annotations

from pathlib import Path
import re
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]


class TheFallbackMatchesThePins(unittest.TestCase):
    def test_every_pinned_collection_has_the_same_version_in_the_fallback(self):
        pins = {
            entry["name"]: str(entry["version"])
            for entry in yaml.safe_load(
                (ROOT / "ansible/requirements.yml").read_text(encoding="utf-8")
            )["collections"]
        }
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        fallback = dict(
            re.findall(
                r"git\+https://github\.com/ansible-collections/([a-z_.]+)\.git,([0-9.]+)",
                workflow,
            )
        )
        self.assertEqual(fallback, pins)


if __name__ == "__main__":
    unittest.main()
