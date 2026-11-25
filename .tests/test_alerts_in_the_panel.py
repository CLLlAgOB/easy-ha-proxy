"""The panel's side of alerts in the header: every page carries the header's
indicator, and its scripts and translations are in place.

The tests of the routes themselves ran against the Flask panel and went with
it."""

from __future__ import annotations

from pathlib import Path
import unittest

_WEB_DIR = Path(__file__).resolve().parents[1] / "go" / "panel" / "web"


class EveryPage(unittest.TestCase):
    def test_the_header_carries_the_indicator_and_its_script(self):
        base = (_WEB_DIR / "templates/base.html").read_text(encoding="utf-8")
        self.assertIn('id="global-alerts"', base)
        self.assertIn("url_for('routes.api_alerts_portal')", base)
        self.assertIn("js/alerts_badge.js", base)
        # Shown to every operator, not only to a superadmin.
        indicator = base.split('<a id="global-alerts"')[0]
        self.assertEqual(indicator.count("{% if g.is_superadmin %}"), indicator.count("{% endif %}"))

    def test_the_script_does_not_cry_wolf(self):
        script = (_WEB_DIR / "static/js/alerts_badge.js").read_text(encoding="utf-8")
        # The alert service restarts with every update: one failed answer is
        # not shown, two in a row are.
        self.assertIn("if (failures >= 2) renderSilent(badge);", script)
        self.assertIn("badge.hidden = total === 0;", script)
        self.assertIn('"easy-ha-proxy:alerts-changed"', script)
        page = (_WEB_DIR / "static/js/alerts.js").read_text(encoding="utf-8")
        self.assertIn('new CustomEvent("easy-ha-proxy:alerts-changed")', page)

    def test_a_refresh_keeps_the_history_the_operator_is_looking_at(self):
        page = (_WEB_DIR / "static/js/alerts.js").read_text(encoding="utf-8")
        refresh = page.split("async function refresh(")[1].split("\n  }\n")[0]
        self.assertIn("if (!historyBusy()) await loadHistory(false);", refresh)
        busy = page.split("function historyBusy(")[1].split("\n  }\n")[0]
        self.assertIn("historyRows.length > HISTORY_PAGE", busy)
        self.assertIn("selectedHistory().length > 0", busy)

    def test_every_word_is_in_russian(self):
        import json

        catalog = {}
        for path in (_WEB_DIR / "translations").rglob("*.json"):
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("meta", {}).get("code") == "ru":
                catalog.update(data["messages"])
        words = {
            "Acknowledge", "Mute", "Unmute", "Undo", "Dismiss", "Muted until", "Acknowledged",
            "1 hour", "8 hours", "1 day", "7 days", "Delete selected", "Clear history",
            "Show more", "All severities", "All conditions", "Delete the selected entries?",
            "Delete the whole alert history?", "The action failed", "Show in the panel from",
            "Alerts: {count}", "The alert service is not answering", "Open alerts",
            "Mail cannot be delivered", "critical", "warning", "info", "fired", "recovered",
            "dismissed", "Actions",
        }
        self.assertEqual(sorted(word for word in words if word not in catalog), [])


if __name__ == "__main__":
    unittest.main()
