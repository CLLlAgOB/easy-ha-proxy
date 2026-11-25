"""The cert role runs as root; nothing from the site configuration reaches a shell unquoted.

websites.yml is written by the panel, and its names, alt names and certificate
paths were placed into root shell scripts and certbot's argument line as they
were. A name like ``x$(id)`` ran a command, and ``x --deploy-hook ...`` gave
certbot a hook. Every value now goes through ``quote``.
"""

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible" / "roles" / "cert"
# Built by templates/_san_flags.j2, which quotes every name itself.
PREQUOTED = {"{{ san_flags }}"}


def command_blocks(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    i = 0
    while i < len(lines):
        match = re.match(r"^(\s*)(?:ansible\.builtin\.)?(shell|command|raw):\s*(.*)$", lines[i])
        if not match:
            i += 1
            continue
        indent, start, block = len(match.group(1)), i + 1, [match.group(3)]
        i += 1
        while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > indent):
            block.append(lines[i])
            i += 1
        yield start, "\n".join(block)


class CertRoleQuoting(unittest.TestCase):
    def test_every_interpolation_in_a_command_is_quoted(self):
        unquoted = []
        for path in sorted(ROLE.rglob("*.yml")):
            for line, block in command_blocks(path):
                for expression in re.findall(r"\{\{[^}]*\}\}", block):
                    if "quote" not in expression and expression not in PREQUOTED:
                        unquoted.append(f"{path.relative_to(ROOT)}:{line}: {expression}")
        self.assertEqual(unquoted, [])

    def test_the_san_flags_quote_each_name(self):
        template = (ROLE / "templates" / "_san_flags.j2").read_text(encoding="utf-8")
        self.assertIn("map('quote')", template)


if __name__ == "__main__":
    unittest.main()
