"""The installer installs pinned Ansible collections and never a role (N07).

ansible-core stays on 2.17 because Ubuntu 22.04 has Python 3.10 and 2.18
needs 3.11. That branch no longer receives fixes, and PYSEC-2026-3458
(CVE-2026-11332) is open in it: `ansible-galaxy role install` lets a malicious
role inject git arguments through its requirements, which runs code on the
machine installing it. The weekly dependency audit ignores that advisory on
the grounds that nothing here ever installs a role.

That ground was a sentence in a workflow comment. Held here as a fact: every
`ansible-galaxy` call is `collection install`, the requirements name only
pinned collections, and no role declares dependencies to fetch -- for as long
as the audit goes on ignoring the advisory.
"""

from __future__ import annotations

from pathlib import Path
import re
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
ADVISORY = "PYSEC-2026-3458"
SKIPPED = {".git", ".tests", "HIDE", "node_modules", "__pycache__", ".venv", "venv"}
CONTINUATION = chr(92) + chr(10)


def source_files():
    """The files a gateway runs or CI executes; documentation only describes."""
    for path in sorted(ROOT.rglob("*")):
        relative = path.relative_to(ROOT)
        if not path.is_file() or SKIPPED.intersection(relative.parts):
            continue
        if path.suffix in {".py", ".sh", ".yml", ".yaml", ".j2"} or relative.as_posix() == "installer/easy-ha-proxy":
            yield relative.as_posix(), path.read_text(encoding="utf-8", errors="replace")


def galaxy_calls(name, text):
    if name.endswith(".py"):
        # The installer builds its command as a list: [str(galaxy), "collection", "install", ...]
        return re.findall(r"[\[]\s*str[(]galaxy[)]\s*,([^\]]*)[\]]", text)
    joined = text.replace(CONTINUATION, " ")
    # A comment may name the command it warns about; only what runs is a call.
    return [line.split("ansible-galaxy", 1)[1] for line in joined.splitlines()
            if "ansible-galaxy" in line and not line.lstrip().startswith("#")]


class TheInstaller(unittest.TestCase):
    def test_the_audit_still_ignores_the_advisory_for_this_reason(self):
        workflow = (ROOT / ".github/workflows/dependencies.yml").read_text(encoding="utf-8")
        self.assertIn(f"--ignore-vuln {ADVISORY}", workflow)
        self.assertIn("never roles", workflow)

    def test_ansible_core_is_still_the_branch_the_advisory_is_open_in(self):
        requirements = (ROOT / "installer/requirements.txt").read_text(encoding="utf-8")
        self.assertRegex(requirements, r"(?m)^ansible-core~=2[.]17[.]")

    def test_every_galaxy_call_installs_collections(self):
        installs = []
        for name, text in source_files():
            installs.extend((name, rest) for rest in galaxy_calls(name, text) if "install" in rest)
        self.assertTrue(installs, "no ansible-galaxy install call was found at all")
        for name, rest in installs:
            with self.subTest(file=name):
                words = re.findall(r"[A-Za-z-]+", rest)
                self.assertIn("collection", words, f"{name}: {rest.strip()[:120]}")
                self.assertEqual(words[words.index("collection") + 1], "install", f"{name}: {rest.strip()[:120]}")
                self.assertNotIn("role", words, f"{name}: {rest.strip()[:120]}")

    def test_the_requirements_name_only_pinned_collections(self):
        data = yaml.safe_load((ROOT / "ansible/requirements.yml").read_text(encoding="utf-8"))
        self.assertEqual(set(data), {"collections"})
        for item in data["collections"]:
            self.assertEqual(set(item), {"name", "version"}, item)
            self.assertRegex(str(item["version"]), r"^[0-9]+[.][0-9]+[.][0-9]+$", item)

    def test_no_role_declares_dependencies_to_fetch(self):
        roles = ROOT / "ansible/roles"
        self.assertFalse((roles / "requirements.yml").exists())
        for role in sorted(path for path in roles.iterdir() if path.is_dir()):
            self.assertFalse((role / "meta/requirements.yml").exists(), role.name)
            meta = role / "meta/main.yml"
            if meta.is_file():
                declared = (yaml.safe_load(meta.read_text(encoding="utf-8")) or {}).get("dependencies") or []
                for dependency in declared:
                    source = dependency.get("src") if isinstance(dependency, dict) else None
                    self.assertFalse(source, f"{role.name} fetches {source}")


if __name__ == "__main__":
    unittest.main()
