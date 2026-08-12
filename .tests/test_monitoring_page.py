"""Regression checks for the monitoring page and its metricsd client."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "docker" / "app" / "haproxy_admin"
sys.path.insert(0, str(ROOT / "docker" / "app"))

from haproxy_admin import services_monitoring as monitoring  # noqa: E402
from haproxy_admin.metricsd_client import MetricsdUnavailable  # noqa: E402


class InputNormalizationTests(unittest.TestCase):
    def test_unknown_range_falls_back_to_the_default(self):
        self.assertEqual(monitoring.normalize_range("24h"), "24h")
        self.assertEqual(monitoring.normalize_range("1y"), "1y")
        self.assertEqual(monitoring.normalize_range("9999d"), monitoring.DEFAULT_RANGE)
        self.assertEqual(monitoring.normalize_range(None), monitoring.DEFAULT_RANGE)
        self.assertEqual(
            monitoring.normalize_range("1h; DROP TABLE metric_1m"),
            monitoring.DEFAULT_RANGE,
        )

    def test_unknown_chart_is_rejected_rather_than_guessed(self):
        self.assertEqual(monitoring.normalize_chart("traffic"), "traffic")
        self.assertEqual(monitoring.normalize_chart("TRAFFIC"), "traffic")
        self.assertEqual(monitoring.normalize_chart("bytes_in"), "")
        self.assertEqual(monitoring.normalize_chart(None), "")

    def test_site_must_be_one_of_the_known_backends(self):
        sites = [{"proxy": "be_shop", "label": "shop.example.com"}]
        self.assertEqual(monitoring.normalize_site("be_shop", sites), "be_shop")
        self.assertEqual(monitoring.normalize_site("all", sites), "")
        self.assertEqual(monitoring.normalize_site("", sites), "")
        self.assertEqual(monitoring.normalize_site("be_other", sites), "")
        self.assertEqual(monitoring.normalize_site("' OR 1=1 --", sites), "")


class DisplayNameTests(unittest.TestCase):
    def test_backend_names_are_prettified_like_the_other_pages(self):
        with mock.patch.object(
            monitoring, "_load_display_map_from_cfg", return_value={}
        ):
            self.assertEqual(monitoring.display_name("be_shop_example_com"),
                             "shop.example.com")
            self.assertEqual(monitoring.display_name("fe_https"), "fe.https")

    def test_a_tagged_display_name_wins(self):
        with mock.patch.object(
            monitoring,
            "_load_display_map_from_cfg",
            return_value={"be_shop": "shop.example.com, www.example.com"},
        ):
            self.assertEqual(
                monitoring.display_name("be_shop"), "shop.example.com, www.example.com"
            )


class UnavailableTests(unittest.TestCase):
    def test_an_unreachable_collector_produces_a_typed_payload(self):
        payload = monitoring.unavailable_payload(
            MetricsdUnavailable("connection refused")
        )
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["unavailable"])
        self.assertIn("connection refused", payload["error"])


class SiteListTests(unittest.TestCase):
    def test_sites_are_labelled_and_sorted(self):
        with (
            mock.patch.object(
                monitoring,
                "metricsd_sites",
                return_value={
                    "sites": [
                        {"proxy": "be_zeta"},
                        {"proxy": "be_alpha"},
                        {"proxy": ""},
                    ]
                },
            ),
            mock.patch.object(
                monitoring, "_load_display_map_from_cfg", return_value={}
            ),
        ):
            sites = monitoring.list_sites()
        self.assertEqual([site["proxy"] for site in sites], ["be_alpha", "be_zeta"])
        self.assertEqual(sites[0]["label"], "alpha")


class SummaryTests(unittest.TestCase):
    def test_backend_entries_gain_display_labels(self):
        with (
            mock.patch.object(
                monitoring,
                "metricsd_summary",
                return_value={
                    "ok": True,
                    "health": {
                        "backends": [{"proxy": "be_shop", "state": "UP"}],
                        "servers": [{"proxy": "be_shop", "server": "srv1", "state": "UP"}],
                    },
                },
            ),
            mock.patch.object(
                monitoring, "_load_display_map_from_cfg", return_value={}
            ),
        ):
            payload = monitoring.summary("24h", "be_shop")
        self.assertEqual(payload["health"]["backends"][0]["label"], "shop")
        self.assertEqual(payload["site_label"], "shop")


class PageAssetTests(unittest.TestCase):
    """The template and its script have to agree on ids and CSP rules."""

    def setUp(self):
        self.template = (APP_DIR / "templates" / "monitoring.html").read_text(
            encoding="utf-8"
        )
        self.javascript = (APP_DIR / "static" / "js" / "monitoring.js").read_text(
            encoding="utf-8"
        )

    def test_every_element_the_script_writes_to_exists(self):
        referenced = set(re.findall(r'byId\("([a-z0-9-]+)"\)', self.javascript))
        referenced |= set(re.findall(r'setText\(\s*"([a-z0-9-]+)"', self.javascript))
        template_ids = set(re.findall(r'id="([a-z0-9-]+)"', self.template))
        # Chart and legend ids are built from the chart name at runtime.
        for chart in ("requests", "traffic", "responses", "latency", "connections"):
            template_ids.discard(f"mon-plot-{chart}")
            template_ids.discard(f"mon-legend-{chart}")
            referenced.discard(f"mon-plot-{chart}")
            referenced.discard(f"mon-legend-{chart}")
        missing = sorted(referenced - template_ids)
        self.assertEqual(missing, [], f"script writes to unknown ids: {missing}")

    def test_charts_in_the_script_have_a_plot_and_legend_in_the_page(self):
        charts = re.findall(r'name:\s*"([a-z]+)"', self.javascript)
        self.assertEqual(
            sorted(charts),
            sorted(["requests", "traffic", "responses", "latency", "connections"]),
        )
        for chart in charts:
            self.assertIn(f'id="mon-plot-{chart}"', self.template)
            self.assertIn(f'id="mon-legend-{chart}"', self.template)

    def test_charts_are_drawn_without_an_external_library(self):
        # A strict CSP blocks third-party script hosts; the page must not need
        # one, and must not reach for a CDN if someone adds a chart later.
        self.assertNotIn("http://", self.javascript.replace("http://www.w3.org", ""))
        self.assertNotIn("https://", self.javascript)
        self.assertIn("createElementNS", self.javascript)
        self.assertIn('"http://www.w3.org/2000/svg"', self.javascript)

    def test_the_script_is_loaded_from_our_own_static_files(self):
        self.assertIn(
            "url_for('static', filename='js/monitoring.js')", self.template
        )

    def test_numeric_readouts_are_excluded_from_dom_translation(self):
        for element_id in (
            "mon-rps",
            "mon-conns",
            "mon-traffic",
            "mon-classes",
            "mon-health",
            "mon-st-db",
            "mon-st-total",
        ):
            tag = re.search(rf'<[^>]+id="{element_id}"[^>]*>', self.template)
            self.assertIsNotNone(tag, element_id)
            self.assertIn("data-i18n-skip", tag.group(0))
            self.assertIn('translate="no"', tag.group(0))

    def test_the_ranges_offered_match_the_service_layer(self):
        offered = set(re.findall(r'data-range="([0-9a-z]+)"', self.template))
        # The template renders them from the service list, so the loop variable
        # is what appears here rather than literal values.
        self.assertEqual(offered, set())
        self.assertIn("{% for value in ranges %}", self.template)
        self.assertEqual(
            monitoring.RANGES, ("1h", "6h", "24h", "7d", "30d", "90d", "1y")
        )

    def test_the_paused_and_unavailable_notices_are_present(self):
        self.assertIn('id="mon-unavailable"', self.template)
        self.assertIn('id="mon-paused"', self.template)
        self.assertIn("HAProxy traffic is not affected", self.template)


class CatalogCoverageTests(unittest.TestCase):
    def test_every_new_ui_string_has_a_russian_translation(self):
        catalog = json.loads(
            (APP_DIR / "translations" / "ru" / "monitoring.json").read_text(
                encoding="utf-8"
            )
        )
        messages = catalog["messages"]
        javascript = (APP_DIR / "static" / "js" / "monitoring.js").read_text(
            encoding="utf-8"
        )
        # Every string the script sends through the translator must resolve,
        # either in this fragment or in one of the shared catalogs.
        shared = set()
        for path in (APP_DIR / "translations").rglob("*.json"):
            data = json.loads(path.read_text(encoding="utf-8"))
            if data["meta"]["code"] == "ru":
                shared |= set(data["messages"])
        for source in re.findall(r'uiText\("([^"]+)"\)', javascript):
            self.assertIn(source, shared, f"missing Russian translation: {source}")
        self.assertTrue(messages)


if __name__ == "__main__":
    unittest.main()
