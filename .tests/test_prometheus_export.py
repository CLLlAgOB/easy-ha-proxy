"""Regression checks for the optional Prometheus endpoint.

The endpoint is deliberately the only path that gets past Authelia besides the
control-plane probe, so most of these are about the locks rather than the
numbers.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import sys
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "docker" / "app" / "haproxy_admin"


def load_exporter():
    """Load the exposition builder alone, without the Flask package."""
    package = types.ModuleType("haproxy_admin")
    package.__path__ = [str(APP_DIR)]
    sys.modules.setdefault("haproxy_admin", package)
    spec = importlib.util.spec_from_file_location(
        "haproxy_admin.services_prometheus", APP_DIR / "services_prometheus.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


exporter = load_exporter()


def parse(text):
    """Turn an exposition into {name: {labels_tuple: value}}."""
    samples = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        head, _, value = line.rpartition(" ")
        name, _, labels = head.partition("{")
        samples.setdefault(name, {})[labels.rstrip("}")] = float(value)
    return samples


class FormatTests(unittest.TestCase):
    def test_an_empty_gateway_still_produces_a_valid_scrape(self):
        text = exporter.collect({})
        samples = parse(text)
        self.assertIn("easy_ha_proxy_build_info", samples)
        self.assertIn("easy_ha_proxy_scrape_timestamp_seconds", samples)
        for line in text.splitlines():
            self.assertTrue(line == "" or line.startswith("#") or " " in line)

    def test_every_family_carries_its_help_and_type(self):
        text = exporter.collect({"storage": lambda: {"state": "NORMAL"}})
        names = set(re.findall(r"^# TYPE (\S+) ", text, flags=re.MULTILINE))
        helped = set(re.findall(r"^# HELP (\S+) ", text, flags=re.MULTILINE))
        self.assertEqual(names, helped)
        for name in names:
            self.assertIn(f"\n{name}", "\n" + text)

    def test_a_family_with_nothing_to_report_is_omitted(self):
        # An empty family is indistinguishable from a genuine zero.
        text = exporter.collect({"haproxy": lambda: {"backends": []}})
        self.assertNotIn("easy_ha_proxy_backend_servers_total", text)

    def test_a_value_that_is_not_a_number_is_dropped_not_rendered(self):
        text = exporter.collect(
            {"storage": lambda: {"state": "NORMAL", "total_bytes": "lots"}}
        )
        self.assertNotIn("easy_ha_proxy_monitoring_database_bytes", text)
        self.assertIn("easy_ha_proxy_monitoring_storage_state", text)


class SourceFailureTests(unittest.TestCase):
    def test_one_dead_daemon_costs_its_own_metrics_and_nothing_else(self):
        def explode():
            raise RuntimeError("socket is gone")

        text = exporter.collect(
            {
                "guard": explode,
                "storage": lambda: {"state": "WARNING", "total_bytes": 10},
            }
        )
        samples = parse(text)
        self.assertNotIn("easy_ha_proxy_guard_bans_active", samples)
        self.assertIn("easy_ha_proxy_monitoring_database_bytes", samples)

    def test_the_scrape_says_which_source_did_not_answer(self):
        def explode():
            raise RuntimeError("socket is gone")

        samples = parse(
            exporter.collect({"guard": explode, "alerts": lambda: {"firing": 0}})
        )
        availability = samples["easy_ha_proxy_source_up"]
        self.assertEqual(availability['source="guard"'], 0.0)
        self.assertEqual(availability['source="alerts"'], 1.0)

    def test_a_source_returning_nonsense_is_ignored(self):
        text = exporter.collect({"storage": lambda: ["not", "a", "mapping"]})
        self.assertNotIn("easy_ha_proxy_monitoring_storage_state", text)


class ContentTests(unittest.TestCase):
    def test_backend_health_is_counted_per_backend(self):
        samples = parse(
            exporter.collect(
                {
                    "haproxy": lambda: {
                        "backends": [
                            {
                                "backend": "be_shop",
                                "servers": [
                                    {"status": "UP", "sessions": 3},
                                    {"status": "DOWN", "sessions": 0},
                                    {"status": "NO CHECK", "sessions": 1},
                                ],
                            }
                        ]
                    }
                }
            )
        )
        self.assertEqual(
            samples["easy_ha_proxy_backend_servers_total"]['backend="be_shop"'], 3.0
        )
        self.assertEqual(
            samples["easy_ha_proxy_backend_servers_up"]['backend="be_shop"'], 2.0
        )
        self.assertEqual(
            samples["easy_ha_proxy_backend_sessions"]['backend="be_shop"'], 4.0
        )

    def test_the_storage_state_is_one_hot_so_a_query_can_alert_on_it(self):
        samples = parse(
            exporter.collect({"storage": lambda: {"state": "PRESSURE"}})
        )
        state = samples["easy_ha_proxy_monitoring_storage_state"]
        self.assertEqual(state['state="PRESSURE"'], 1.0)
        self.assertEqual(state['state="NORMAL"'], 0.0)
        self.assertEqual(len(state), 4)

    def test_guard_reputation_is_counted_by_state(self):
        samples = parse(
            exporter.collect(
                {
                    "guard": lambda: {
                        "mode": "enforce",
                        "states": {"watch": 4, "suspect": 1},
                        "bans_active": 2,
                        "database": {"events": 900},
                    }
                }
            )
        )
        self.assertEqual(samples["easy_ha_proxy_guard_addresses"]['state="watch"'], 4.0)
        self.assertEqual(samples["easy_ha_proxy_guard_bans_active"][""], 2.0)
        self.assertEqual(samples["easy_ha_proxy_guard_enforcing"][""], 1.0)


class CardinalityTests(unittest.TestCase):
    def test_no_visitor_address_can_reach_a_label(self):
        # The plan forbids it and the shape of the payload has to make it
        # impossible, not merely unlikely.
        text = exporter.collect(
            {
                "guard": lambda: {
                    "states": {"watch": 1},
                    "bans_active": 1,
                    "addresses": [{"ip": "203.0.113.9", "score": 100}],
                }
            }
        )
        self.assertNotIn("203.0.113.9", text)

    def test_a_label_cannot_break_out_of_its_quotes(self):
        hostile = 'be_x" evil="1'
        text = exporter.collect(
            {
                "haproxy": lambda: {
                    "backends": [{"backend": hostile, "servers": []}]
                }
            }
        )
        self.assertNotIn('evil="1"', text)
        self.assertNotIn('"' + hostile, text)

    def test_a_newline_in_a_label_cannot_forge_a_sample(self):
        # The name surviving inside the quoted label is harmless. What must
        # not happen is a new line that a parser reads as another sample.
        text = exporter.collect(
            {
                "haproxy": lambda: {
                    "backends": [
                        {
                            "backend": "be_x\neasy_ha_proxy_fake 1",
                            "servers": [{"status": "UP"}],
                        }
                    ]
                }
            }
        )
        self.assertNotIn("easy_ha_proxy_fake", parse(text))
        for line in text.splitlines():
            self.assertFalse(line.startswith("easy_ha_proxy_fake"), line)

    def test_a_label_is_bounded(self):
        text = exporter.collect(
            {
                "haproxy": lambda: {
                    "backends": [{"backend": "b" * 5000, "servers": []}]
                }
            }
        )
        for line in text.splitlines():
            self.assertLess(len(line), 400)


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.source = (APP_DIR / "routes_prometheus.py").read_text(encoding="utf-8")

    def test_the_endpoint_is_off_unless_switched_on(self):
        self.assertIn("METRICS_EXPORT_ENABLED", self.source)
        self.assertIn("status=404", self.source)

    def test_the_token_is_compared_in_constant_time(self):
        self.assertIn("hmac.compare_digest", self.source)

    def test_an_empty_configured_token_does_not_mean_no_token(self):
        # Otherwise switching the export on without setting a token would
        # publish the metrics to everything on the allow-list.
        block = self.source.split("def _token_ok")[1].split("@bp.get")[0]
        self.assertIn("if not expected:", block)
        self.assertIn("return False", block)

    def test_a_broken_source_is_a_503_not_a_traceback(self):
        self.assertIn("status=503", self.source)

    def test_it_is_a_read_only_get(self):
        self.assertIn("@bp.get", self.source)
        self.assertNotIn("@bp.post", self.source)


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.source = (APP_DIR / "security.py").read_text(encoding="utf-8")

    def test_the_scrape_identity_is_accepted_for_exactly_one_get(self):
        self.assertIn('METRICS_SCRAPE_PATH = "/metrics"', self.source)
        self.assertIn('METRICS_SCRAPE_USER = "easy-ha-proxy-metrics"', self.source)
        block = self.source.split("is_metrics_scrape = (")[1].split(")")[0]
        self.assertIn('request.method == "GET"', block)
        self.assertIn("request.path == METRICS_SCRAPE_PATH", block)
        self.assertIn("groups == METRICS_SCRAPE_GROUPS", block)

    def test_the_scrape_identity_is_refused_everywhere_else(self):
        self.assertIn("username == METRICS_SCRAPE_USER", self.source)
        self.assertIn("groups.intersection(METRICS_SCRAPE_GROUPS)", self.source)

    def test_it_is_never_a_superadmin(self):
        block = self.source.split("if is_metrics_scrape:")[1].split("return None")[0]
        self.assertIn("g.is_superadmin = False", block)


class HaproxyPathTests(unittest.TestCase):
    def setUp(self):
        self.template = (
            ROOT / "ansible/roles/haproxy/templates/haproxy.cfg.j2"
        ).read_text(encoding="utf-8")

    def test_the_whole_path_is_behind_the_switch(self):
        # Nothing about this may appear in a configuration that did not ask
        # for it: it is the only Authelia bypass besides the local probe.
        self.assertEqual(
            self.template.count("metrics_export_enabled | default(false)"), 5
        )

    def test_the_bypass_needs_the_host_the_source_the_path_and_the_method(self):
        line = next(
            row
            for row in self.template.splitlines()
            if "set-var(txn.admin_metrics_scrape)" in row
        )
        for condition in (
            "host_admin",
            "metrics_scrape_source",
            "metrics_scrape_path",
            "metrics_scrape_method",
        ):
            self.assertIn(condition, line)

    def test_the_source_list_defaults_to_this_host_only(self):
        self.assertIn("metrics_scrape_sources | default(['127.0.0.1'])", self.template)
        defaults = (
            ROOT / "ansible/roles/haproxy/defaults/main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("metrics_export_enabled: false", defaults)

    def test_the_scrape_gets_its_own_identity_not_an_admin_one(self):
        self.assertIn(
            "set-header Remote-User easy-ha-proxy-metrics if host_admin "
            "admin_metrics_scrape",
            self.template,
        )
        self.assertIn(
            "set-header Remote-Groups metrics if host_admin admin_metrics_scrape",
            self.template,
        )

    def test_enabling_the_export_without_a_token_stops_the_install(self):
        tasks = (
            ROOT / "ansible/roles/haproxy/tasks/config.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("metrics_export_token", tasks)
        self.assertIn("| length >= 24", tasks)


if __name__ == "__main__":
    unittest.main()
