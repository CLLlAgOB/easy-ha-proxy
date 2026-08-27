"""Which link the traffic went out through, which nothing could say before.

A gateway usually reaches everything it proxies over one or two connections:
a main one and a reserve. HAProxy knows those only as the host on the far end
of each `server` line, repeated across every backend that uses it. The link
itself is named nowhere, and its traffic was only ever part of the total.

Grouping the servers by that host is the whole trick, and it needs no
configuration. On a real gateway it comes out as eight backends on one
address and two on another carrying `backup` -- the main channel and the
reserve, exactly as the operator described them.

Read from the generated haproxy.cfg rather than from the site model on
purpose: the names the collector stores are the ones HAProxy is running, and
re-deriving them from the model would be a second copy of the name sanitiser
to drift out of step.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker" / "app"))

from haproxy_admin import services_monitoring as monitoring  # noqa: E402


# The shape a real gateway has: one address carrying most of the sites, a
# second marked backup, and the machine's own services on loopback.
CONFIG = """
frontend fe_https
    bind *:443

backend be_admin
    server ui 127.0.0.1:5000 check

backend be_site_one
    server main 203.0.113.10:443 check
    server bkp 203.0.113.20:443 check backup

backend be_site_two
    server main 203.0.113.10:5010 check

backend be_site_three
    server main 203.0.113.10:5020 check
    server bkp 203.0.113.20:5020 check backup

backend be_certbot
    server certbot 127.0.0.1:8000 check
"""


def write_config(text: str) -> str:
    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".cfg", delete=False, encoding="utf-8"
    )
    handle.write(text)
    handle.close()
    return handle.name


class ReadingTheBackends(unittest.TestCase):
    def setUp(self):
        self.path = write_config(CONFIG)
        self.addCleanup(lambda: Path(self.path).unlink(missing_ok=True))
        self.servers = monitoring.backend_servers(self.path)

    def test_every_server_line_is_found_with_its_backend(self):
        self.assertEqual(len(self.servers), 7)
        pairs = {(s["proxy"], s["server"]) for s in self.servers}
        self.assertIn(("be_site_one", "main"), pairs)
        self.assertIn(("be_site_one", "bkp"), pairs)

    def test_the_host_is_separated_from_the_port(self):
        one = [s for s in self.servers if s["proxy"] == "be_site_two"][0]
        self.assertEqual(one["host"], "203.0.113.10")
        self.assertEqual(one["port"], 5010)

    def test_the_backup_keyword_is_noticed(self):
        backups = {s["server"] for s in self.servers if s["backup"]}
        self.assertEqual(backups, {"bkp"})

    def test_a_missing_file_is_not_fatal(self):
        # The page degrades; it does not fall over because a path moved.
        self.assertEqual(monitoring.backend_servers("/nonexistent.cfg"), [])


class WhatCountsAsALink(unittest.TestCase):
    def test_loopback_is_not_a_link(self):
        # Those backends are this machine's own services -- the interface,
        # certbot, Authelia. Counting them would put the gateway's own
        # traffic beside the uplinks it is being compared with.
        for host in ("127.0.0.1", "127.0.1.1", "localhost", "::1"):
            with self.subTest(host=host):
                self.assertTrue(monitoring._is_local(host))

    def test_an_ordinary_address_is(self):
        for host in ("203.0.113.10", "backend.example.com", "10.0.0.4"):
            with self.subTest(host=host):
                self.assertFalse(monitoring._is_local(host))


class GroupingAndTotalling(unittest.TestCase):
    def setUp(self):
        self.path = write_config(CONFIG)
        self.addCleanup(lambda: Path(self.path).unlink(missing_ok=True))

        # What the collector would return: it keys on (proxy, server), which
        # is exactly the join.
        self.measured = {
            "range": "24h", "since": 100, "until": 200, "labels": {},
            "servers": [
                {"proxy": "be_site_one", "server": "main",
                 "bytes_in": 1000, "bytes_out": 3000, "sessions": 10},
                {"proxy": "be_site_two", "server": "main",
                 "bytes_in": 500, "bytes_out": 1500, "sessions": 5},
                {"proxy": "be_site_three", "server": "main",
                 "bytes_in": 0, "bytes_out": 0, "sessions": 0},
                {"proxy": "be_site_one", "server": "bkp",
                 "bytes_in": 100, "bytes_out": 300, "sessions": 1},
                # A backend on loopback, which must not become a link.
                {"proxy": "be_admin", "server": "ui",
                 "bytes_in": 9999, "bytes_out": 9999, "sessions": 99},
            ],
        }

    def channels(self, labels=None):
        payload = dict(self.measured)
        payload["labels"] = labels or {}
        with mock.patch.object(monitoring, "HAPROXY_CFG", self.path), \
                mock.patch.object(monitoring, "metricsd_servers",
                                  return_value=payload):
            return monitoring.channels("24h")

    def test_servers_on_one_address_become_one_link(self):
        result = self.channels()
        hosts = [c["host"] for c in result["channels"]]
        self.assertEqual(hosts, ["203.0.113.10", "203.0.113.20"])

    def test_traffic_is_summed_across_every_backend_on_the_link(self):
        main = self.channels()["channels"][0]
        self.assertEqual(main["bytes_in"], 1500)
        self.assertEqual(main["bytes_out"], 4500)
        self.assertEqual(main["bytes_total"], 6000)

    def test_the_gateway_s_own_services_are_left_out(self):
        result = self.channels()
        self.assertNotIn("127.0.0.1", [c["host"] for c in result["channels"]])
        # And their traffic is not in the total either, or the shares lie.
        self.assertEqual(result["bytes_total"], 6000 + 400)

    def test_a_link_used_only_as_a_reserve_is_marked_so(self):
        reserve = self.channels()["channels"][1]
        self.assertTrue(reserve["backup"])
        self.assertEqual(reserve["host"], "203.0.113.20")

    def test_one_backend_using_it_in_anger_makes_it_a_live_link(self):
        mixed = CONFIG + """
backend be_site_four
    server bkp 203.0.113.20:6000 check
"""
        self.path = write_config(mixed)
        reserve = [c for c in self.channels()["channels"]
                   if c["host"] == "203.0.113.20"][0]
        self.assertFalse(reserve["backup"])

    def test_live_links_are_listed_before_reserves(self):
        channels = self.channels()["channels"]
        self.assertFalse(channels[0]["backup"])
        self.assertTrue(channels[-1]["backup"])

    def test_the_share_adds_up(self):
        channels = self.channels()["channels"]
        self.assertAlmostEqual(sum(c["share"] for c in channels), 100.0, places=1)

    def test_the_backend_count_is_the_honest_reason_a_link_is_busy(self):
        main = self.channels()["channels"][0]
        self.assertEqual(main["backend_count"], 3)

    def test_the_name_haproxy_was_given_is_the_default_label(self):
        # An operator who called the servers main and bkp has already named
        # the links; asking them again would be rude.
        channels = self.channels()
        self.assertEqual(channels["channels"][0]["default_label"], "main")
        self.assertEqual(channels["channels"][1]["default_label"], "bkp")

    def test_a_saved_name_wins(self):
        channels = self.channels({"203.0.113.10": "Rostelecom"})
        self.assertEqual(channels["channels"][0]["label"], "Rostelecom")
        # And the default is still there, so clearing the name restores it.
        self.assertEqual(channels["channels"][0]["default_label"], "main")

    def test_a_server_with_no_measurements_yet_does_not_break_the_sum(self):
        # be_site_three/main reported zeroes; a link with no data at all
        # should still appear rather than vanish.
        self.measured["servers"] = []
        result = self.channels()
        self.assertEqual(len(result["channels"]), 2)
        self.assertEqual(result["bytes_total"], 0)
        self.assertEqual(result["channels"][0]["share"], 0.0)


class SavingTheNames(unittest.TestCase):
    def test_it_refuses_anything_that_is_not_a_mapping(self):
        for payload in ([], "x", 7, None):
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    monitoring.save_channel_labels(payload)


class TheDaemonSideIsWired(unittest.TestCase):
    def setUp(self):
        self.source = (
            ROOT / "ansible" / "roles" / "haproxy-admin" / "files"
            / "easy-ha-proxy-metricsd.py"
        ).read_text(encoding="utf-8")

    def test_the_query_is_not_scoped_to_one_site(self):
        # A link carries every site pointed at it, and the whole question is
        # how much went through each link.
        block = self.source.split("def server_totals")[1].split("\n    def ")[0]
        self.assertIn("o.kind = 'server'", block)
        self.assertNotIn("_scope(site)", block)

    def test_it_groups_by_the_key_the_collector_stores(self):
        block = self.source.split("def server_totals")[1].split("\n    def ")[0]
        self.assertIn("GROUP BY o.proxy, o.server", block)

    def test_the_labels_live_in_the_collector_s_own_state(self):
        self.assertIn("CHANNEL_LABELS_KEY", self.source)
        block = self.source.split("def do_POST")[1].split("\n    def ")[0]
        self.assertIn("set_state(CHANNEL_LABELS_KEY", block)

    def test_a_label_that_is_too_long_or_absent_is_refused(self):
        block = self.source.split("def do_POST")[1].split("\n    def ")[0]
        self.assertIn("at most 64 labels", block)
        self.assertIn("too long", block)


if __name__ == "__main__":
    unittest.main()
