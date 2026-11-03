"""The Status page marks old rows old when healthd stops answering (F25).

From the 30 October review: the auto-refresh swallowed a failed refresh in
an empty catch, so the last rows -- green, typically -- stayed on screen
as if current; the page never showed when healthd had last confirmed
them; and a failure on the very first load threw out of init before the
Refresh button and auto-refresh were wired, leaving no way to retry
short of reloading the page.

Checked in a browser on the test host with healthd stopped; this pins the
shape that behaviour rests on.
"""

from __future__ import annotations

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker" / "app" / "haproxy_admin"
SCRIPT = (APP / "static/js/health.js").read_text(encoding="utf-8")
PAGE = (APP / "templates/health.html").read_text(encoding="utf-8")


def function(name):
    match = re.search(rf"\n  (?:async )?function {name}\(.*?\n  }}\n", SCRIPT, re.S)
    assert match, name
    return match.group(0)


class TheStatusPage(unittest.TestCase):
    def test_a_failed_refresh_marks_the_rows_stale(self):
        refresh = function("refreshAll")
        self.assertIn("showFreshness(error", refresh)
        self.assertNotIn("catch(() => { })", SCRIPT)
        self.assertIn('classList.toggle("is-stale", stale)', function("showFreshness"))
        self.assertIn(".monitoring-grid.is-stale", PAGE)

    def test_the_time_healthd_took_it_is_shown(self):
        self.assertIn("status.ts_utc", function("loadStatus"))
        self.assertIn('"Checked at"', function("showFreshness"))
        self.assertIn('"Not updated since"', function("showFreshness"))
        self.assertIn('id="status-freshness"', PAGE)

    def test_one_refresh_at_a_time(self):
        refresh = function("refreshAll")
        self.assertIn("if (refreshing) return refreshing;", refresh)
        self.assertIn("refreshing = null;", refresh)

    def test_the_controls_are_there_before_the_first_load(self):
        init = function("init")
        self.assertLess(init.index("bindControls()"), init.index("refreshAll(true)"))
        self.assertIn("btnRefresh.addEventListener", function("bindControls"))


if __name__ == "__main__":
    unittest.main()
