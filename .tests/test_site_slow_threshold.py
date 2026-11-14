"""A site's own slow-response threshold, or none at all.

Seen on a production gateway: a 1C site raised response.slow for hours
("responses take 11218 ms on average") because its web client holds
requests open on purpose. One threshold for every site either misses real
slowness or never stops alerting about that one. A site now carries its own
(alert_slow_ms in websites.yml, set in the site editor; 0 turns it off),
next to its own alert_after and alert_email.
"""

from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".tests"))
sys.path.insert(0, str(ROOT / "docker" / "app"))

from test_alert_producers import FakeAlerts, HEADER, metricsd, row  # noqa: E402

WINDOWS = sys.platform == "win32"
if not WINDOWS:
    from haproxy_admin import validation  # noqa: E402

APP = ROOT / "docker/app/haproxy_admin"
WEBSITES = """\
sites:
  - name: buh.example.test
    alert_slow_ms: 0
  - name: erp
    alert_slow_ms: 30000
  - name: shop
  - name: odd
    alert_slow_ms: lots
"""


class Thresholds(unittest.TestCase):
    def test_read_from_websites_by_backend_name(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "websites.yml"
            path.write_text(WEBSITES, encoding="utf-8")
            self.assertEqual(metricsd.site_slow_thresholds(str(path)),
                             {"be_buh_example_test": 0, "be_erp": 30000})
            self.assertEqual(metricsd.site_slow_thresholds(str(Path(folder) / "missing.yml")), {})
            path.write_text("sites: [", encoding="utf-8")
            self.assertEqual(metricsd.site_slow_thresholds(str(path)), {})


class TheCheck(unittest.TestCase):
    def setUp(self):
        from unittest import mock

        self.mock = mock
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        folder = Path(temporary.name)
        self.database = metricsd.MetricsDatabase(str(folder / "metrics.db"))
        self.addCleanup(self.database.close)
        self.config = metricsd.load_config("/nonexistent/metricsd.json")
        self.alerts = FakeAlerts()
        guard = metricsd.StorageGuard(self.config, self.database, alerts=self.alerts)
        self.collector = metricsd.Collector(self.config, self.database, storage=guard)
        self.collector.cgroup_root = str(folder / "no-cgroup")
        self.websites = folder / "websites.yml"
        self.websites.write_text(WEBSITES, encoding="utf-8")
        self.collector.websites_path = str(self.websites)

    def minute(self, rtime):
        rows = [row(name, "BACKEND", req_tot=100, rtime=rtime)
                for name in ("be_buh_example_test", "be_erp", "be_shop")]
        later = [row(name, "BACKEND", req_tot=200, rtime=rtime)
                 for name in ("be_buh_example_test", "be_erp", "be_shop")]
        for at, current in ((1_000_020, rows), (1_000_040, later)):
            text = "\n".join((HEADER, *current)) + "\n"
            with self.mock.patch.object(metricsd, "runtime_command", return_value=text), \
                    self.mock.patch.object(metricsd, "_utc_now", return_value=at):
                self.collector.poll()
        with self.mock.patch.object(metricsd, "_utc_now", return_value=1_000_100):
            self.collector.flush(force=True)

    def test_a_site_off_never_raises_and_clears_what_it_held(self):
        self.minute(11218)
        off = self.alerts.last("response.slow", "be_buh_example_test")
        self.assertFalse(off["active"])
        self.assertIn("off for this site", off["summary"])
        # The global threshold still holds for a site without its own.
        self.assertTrue(self.alerts.last("response.slow", "be_shop")["active"])

    def test_a_site_with_its_own_threshold_is_judged_by_it(self):
        self.minute(11218)
        self.assertFalse(self.alerts.last("response.slow", "be_erp")["active"])
        self.minute(31000)
        raised = self.alerts.last("response.slow", "be_erp")
        self.assertTrue(raised["active"])
        self.assertIn("threshold 30000 ms for this site", raised["detail"])

    def test_an_edit_of_the_file_is_read_without_a_restart(self):
        self.minute(11218)
        self.assertTrue(self.alerts.last("response.slow", "be_shop")["active"])
        self.websites.write_text(WEBSITES + "  - name: shop\n    alert_slow_ms: 0\n", encoding="utf-8")
        import os
        stamp = self.websites.stat().st_mtime + 5
        os.utime(self.websites, (stamp, stamp))
        self.minute(11218)
        self.assertFalse(self.alerts.last("response.slow", "be_shop")["active"])


@unittest.skipIf(WINDOWS, "the admin package needs fcntl")
class TheSiteEditor(unittest.TestCase):
    def check(self, value):
        validation._validate_site({"name": "erp", "domain": "erp.example.test",
                                   "backend_ip": "192.0.2.10", "backend_port": 80,
                                   "alert_slow_ms": value}, 0)

    def test_only_a_number_of_milliseconds_is_kept(self):
        for value in (0, 30000, 600000):
            self.check(value)
        for value in (-1, 600001, True, "30000", 1.5):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.check(value)

    def test_the_editor_offers_it_and_keeps_zero(self):
        template = (APP / "templates/haproxy_site_edit.html").read_text(encoding="utf-8")
        script = (APP / "static/js/haproxy_site_edit.js").read_text(encoding="utf-8")
        self.assertIn('id="alert_slow_ms"', template)
        self.assertIn("site.alert_slow_ms = parseInt(slowValue, 10);", script)
        # 0 is a choice, not an empty field.
        self.assertIn("/^[0-9]+$/.test(slowValue)", script)


if __name__ == "__main__":
    unittest.main()
