"""Every page's header is the same height and the same shape.

The dashboard was the exception. It carried Refresh and Auto-refresh in the
header, which pushed the navigation onto a second row, and it hung the site
counters off the far right where nothing else sat. So the one page people
land on first was the one page whose header did not match the rest.

Actions on a page belong to the page; the header is for moving between
pages. These check that split holds, and that the counters stay at the head
of the row rather than drifting back to the edge.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "docker" / "app" / "haproxy_admin" / "templates"
STYLES = ROOT / "docker" / "app" / "haproxy_admin" / "static" / "css" / "styles.css"
BASE = TEMPLATES / "base.html"
INDEX = TEMPLATES / "index.html"


def header_block(markup: str, name: str) -> str:
    """The body of one {% block %} in a template."""
    start = markup.index("{% block " + name + " %}")
    end = markup.index("{% endblock %}", start)
    return markup[start:end]


class DashboardHeaderTests(unittest.TestCase):
    def setUp(self):
        self.index = INDEX.read_text(encoding="utf-8")
        self.base = BASE.read_text(encoding="utf-8")

    def test_the_page_actions_left_the_header(self):
        # Two buttons in the header were what made this page's header taller
        # than every other page's.
        buttons = header_block(self.index, "header_buttons")
        for control in ('id="refresh-btn"', 'id="auto-btn"'):
            with self.subTest(control=control):
                self.assertNotIn(control, buttons)

    def test_the_page_actions_are_still_on_the_page(self):
        # Moved, not deleted: dashboard.js binds both by id.
        content = header_block(self.index, "content")
        self.assertIn('id="refresh-btn"', content)
        self.assertIn('id="auto-btn"', content)
        self.assertIn('class="page-toolbar"', content)

    def test_the_header_carries_only_navigation(self):
        buttons = header_block(self.index, "header_buttons")
        self.assertIn("_haproxy_nav.html", buttons)
        # Nothing else: another control here and the second row comes back.
        self.assertNotIn("<button", buttons)

    def test_the_counters_sit_at_the_head_of_the_row(self):
        lead = header_block(self.index, "header_lead")
        self.assertIn('id="sites-meta"', lead)
        self.assertIn('id="toggle-compact"', lead)

    def test_the_slot_comes_before_the_language_switcher(self):
        # Otherwise "at the head of the row" is only true by accident of
        # source order in one template.
        controls = self.base.split('<div class="controls">')[1]
        lead = controls.index("{% block header_lead %}")
        language = controls.index('class="language-switcher"')
        self.assertLess(lead, language)

    def test_the_slot_is_empty_for_every_other_page(self):
        # A block nothing fills renders nothing, so the rest of the
        # application keeps the header it has.
        for path in sorted(TEMPLATES.glob("*.html")):
            if path.name in ("base.html", "index.html"):
                continue
            with self.subTest(page=path.name):
                self.assertNotIn(
                    "{% block header_lead %}",
                    path.read_text(encoding="utf-8"),
                )


class LeftoverTests(unittest.TestCase):
    """The centring machinery the old arrangement needed is gone."""

    def setUp(self):
        self.styles = STYLES.read_text(encoding="utf-8")

    def test_the_spacer_is_gone(self):
        # It existed only to push that group into the middle of the header.
        self.assertNotIn("controls-spacer", self.styles)
        for path in TEMPLATES.glob("*.html"):
            with self.subTest(page=path.name):
                self.assertNotIn(
                    "controls-spacer", path.read_text(encoding="utf-8")
                )

    def test_a_card_header_is_no_longer_a_header_concern(self):
        self.assertNotIn("header .controls .card-header", self.styles)

    def test_the_page_toolbar_is_styled(self):
        self.assertIn(".page-toolbar", self.styles)


if __name__ == "__main__":
    unittest.main()
