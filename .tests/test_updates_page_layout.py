"""The software-updates page leads with what there is to install.

The HAProxy card and the server-reboot card stood between the summary and the
list of updates, so a gateway with nothing wrong opened on three version
numbers that matched and a reboot form. Both now come last, and the HAProxy
card is shown only when HAProxy needs a look (updates_core.haproxyAttention,
tested in .tests/js/updates_core.test.js).
"""

from __future__ import annotations

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker/app/haproxy_admin"
PAGE = (APP / "templates/system_updates.html").read_text(encoding="utf-8")
SCRIPT = (APP / "static/js/system_updates.js").read_text(encoding="utf-8")


def position(marker: str) -> int:
    index = PAGE.find(marker)
    if index < 0:
        raise AssertionError(f"not on the page: {marker}")
    return index


class TheOrder(unittest.TestCase):
    def test_the_summary_and_the_updates_come_first(self):
        self.assertLess(position('class="card updates-hero"'), position('id="updates-plan-card"'))
        self.assertLess(position('id="updates-plan-card"'), position('id="updates-settings"'))

    def test_haproxy_and_the_reboot_come_last(self):
        history = position('id="updates-history"')
        haproxy = position('id="updates-haproxy-card"')
        reboot = position('id="updates-reboot-card"')
        self.assertLess(history, haproxy)
        self.assertLess(haproxy, reboot)
        cards = re.findall(r'<(?:section|details) [^>]*id="(updates-[a-z-]+)"', PAGE)
        self.assertEqual(cards[-2:], ["updates-haproxy-card", "updates-reboot-card"])


class TheHaproxyCard(unittest.TestCase):
    def test_it_starts_hidden_so_a_current_haproxy_never_flashes(self):
        tag = re.search(r'<section [^>]*id="updates-haproxy-card"[^>]*>', PAGE).group(0)
        self.assertIn(" hidden", tag)

    def test_the_page_asks_the_shared_rule(self):
        self.assertIn("core.haproxyAttention(haproxyComponent, {operation: haproxyOperation, migration: currentMigration})",
                      SCRIPT)
        self.assertIn("core.haproxyOnTarget(haproxyComponent, currentMigration)", SCRIPT)
        # Both the plan and the transition status decide, so both redraw it.
        for function in ("function renderHaproxy(plan)", "function renderMigration()"):
            start = SCRIPT.index(function)
            body = SCRIPT[start:SCRIPT.index("\n  }\n", start)]
            self.assertIn("showHaproxyCard();", body, function)

    def test_the_unfinished_phases_are_listed_once(self):
        self.assertNotIn('"recovery_exhausted"].includes(last.phase)', SCRIPT)
        self.assertIn("core.HAPROXY_UNFINISHED_PHASES.has(last.phase)", SCRIPT)


if __name__ == "__main__":
    unittest.main()
