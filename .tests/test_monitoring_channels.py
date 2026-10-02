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


class PuttingALinkAway(unittest.TestCase):
    """Not every backend host is an uplink, and the list has to be tidyable."""

    def setUp(self):
        self.path = write_config(CONFIG + """
backend be_one_off
    server app1 203.0.113.99:8080 check
""")
        self.addCleanup(lambda: Path(self.path).unlink(missing_ok=True))
        self.payload = {
            "range": "24h", "since": 1, "until": 2, "labels": {}, "hidden": [],
            "servers": [
                {"proxy": "be_site_one", "server": "main",
                 "bytes_in": 400, "bytes_out": 600, "sessions": 4},
                {"proxy": "be_one_off", "server": "app1",
                 "bytes_in": 100, "bytes_out": 100, "sessions": 1},
            ],
        }

    def channels(self, hidden=()):
        payload = dict(self.payload, hidden=list(hidden))
        with mock.patch.object(monitoring, "HAPROXY_CFG", self.path),                 mock.patch.object(monitoring, "metricsd_servers",
                                  return_value=payload):
            return monitoring.channels("24h")

    def test_a_hidden_host_leaves_the_list(self):
        shown = [c["host"] for c in self.channels(["203.0.113.99"])["channels"]]
        self.assertNotIn("203.0.113.99", shown)

    def test_it_is_still_reachable_so_it_can_come_back(self):
        away = self.channels(["203.0.113.99"])["hidden"]
        self.assertEqual([c["host"] for c in away], ["203.0.113.99"])

    def test_its_traffic_leaves_the_total_and_the_shares(self):
        # Otherwise the percentages answer a question nobody asked: shares
        # of a set that includes something the operator said is not a link.
        before = self.channels()
        after = self.channels(["203.0.113.99"])
        self.assertEqual(before["bytes_total"], 1200)
        self.assertEqual(after["bytes_total"], 1000)
        self.assertAlmostEqual(
            sum(c["share"] for c in after["channels"]), 100.0, places=1
        )

    def test_a_hidden_link_carries_no_share(self):
        away = self.channels(["203.0.113.99"])["hidden"][0]
        self.assertEqual(away["share"], 0.0)


class TheChosenPeriod(unittest.TestCase):
    """A preset cannot answer what happened on Tuesday morning."""

    def test_a_valid_pair_is_taken(self):
        window = monitoring.normalize_window("1000000", "1003600")
        self.assertEqual(window, {"since": 1000000, "until": 1003600})

    def test_nonsense_falls_back_to_the_preset(self):
        for since, until in (("", ""), ("x", "y"), (None, None),
                             ("1000", "500"), ("-5", "100"), ("0", "0")):
            with self.subTest(since=since, until=until):
                self.assertEqual(monitoring.normalize_window(since, until), {})

    def test_a_window_too_short_to_mean_anything_is_refused(self):
        self.assertEqual(monitoring.normalize_window("1000000", "1000030"), {})

    def test_a_mistyped_year_is_clamped_rather_than_scanned(self):
        window = monitoring.normalize_window("0", "2000000000")
        self.assertEqual(window, {})
        window = monitoring.normalize_window("1", "2000000000")
        self.assertEqual(
            window["until"] - window["since"], monitoring.MAX_WINDOW_SECONDS
        )

    def test_the_daemon_prefers_the_pair_over_the_preset(self):
        source = (
            ROOT / "ansible" / "roles" / "haproxy-admin" / "files"
            / "easy-ha-proxy-metricsd.py"
        ).read_text(encoding="utf-8")
        block = source.split("def resolve_window")[1].split(chr(10) + "def ")[0]
        self.assertIn('return "custom"', block)
        self.assertIn("MAX_RANGE_SECONDS", block)
        # And the summary must not snap the end back to now, which would
        # report the wrong period while looking right.
        summary = source.split('if path == "/api/v1/metrics/summary"')[1][:900]
        self.assertNotIn("until = _utc_now()", summary)


class OneBackendOneRow(unittest.TestCase):
    """A backend with a single server said the same thing twice."""

    def payload(self, objects):
        return {"objects": objects, "since": 0, "until": 1}

    def states(self, objects):
        with mock.patch.object(monitoring, "metricsd_states",
                               return_value=self.payload(objects)),                 mock.patch.object(monitoring, "display_name",
                                  side_effect=lambda p: p):
            return monitoring.states("24h", "")

    def test_the_lone_server_row_goes_and_the_backend_row_stays(self):
        result = self.states([
            {"proxy": "be_authelia", "server": ""},
            {"proxy": "be_authelia", "server": "authelia"},
        ])
        self.assertEqual(len(result["objects"]), 1)
        self.assertEqual(result["objects"][0]["server"], "")
        self.assertEqual(result["collapsed"], 1)

    def test_several_servers_are_all_worth_showing(self):
        # Which member is down is exactly what an operator needs here.
        result = self.states([
            {"proxy": "be_site", "server": ""},
            {"proxy": "be_site", "server": "main"},
            {"proxy": "be_site", "server": "bkp"},
        ])
        self.assertEqual(len(result["objects"]), 3)
        self.assertEqual(result["collapsed"], 0)

    def test_a_server_with_no_backend_row_is_kept(self):
        # Never drop the only row an object has.
        result = self.states([{"proxy": "be_orphan", "server": "srv1"}])
        self.assertEqual(len(result["objects"]), 1)


class AnOlderCollectorSaysSo(unittest.TestCase):
    """Version skew has to announce itself, not look like missing data.

    A collector older than the page ignores since/until and answers with its
    own preset. The charts then plot a day of points inside a two-hour
    window, every one falls outside, and the page reports "no data for this
    period" -- true of what it was handed, and entirely misleading about
    why. Measured on a live gateway: asked for two hours, got range "24h"
    and 1439 points spanning the whole day. The hide button had the quieter
    version of the same fault: the request was accepted, the list dropped,
    and ok returned, so the button appeared to do nothing.
    """

    def setUp(self):
        self.script = (
            ROOT / "docker" / "app" / "haproxy_admin" / "static" / "js"
            / "monitoring.js"
        ).read_text(encoding="utf-8")

    def test_the_answer_is_checked_against_what_was_asked(self):
        block = self.script.split("function noteWindowSkew")[1][:600]
        self.assertIn('payload.range === "custom"', block)

    def test_it_only_complains_when_a_period_was_actually_chosen(self):
        block = self.script.split("function noteWindowSkew")[1][:600]
        self.assertIn("if (!customWindow", block)

    def test_the_hide_request_checks_the_answer_carried_the_list_back(self):
        block = self.script.split("async function saveChannels")[1][:2000]
        self.assertIn("data.hidden === undefined", block)

    def test_the_daemon_names_the_window_it_used(self):
        # The whole check rests on this: without a label in the answer the
        # page cannot tell a honoured window from an ignored one.
        source = (
            ROOT / "ansible" / "roles" / "haproxy-admin" / "files"
            / "easy-ha-proxy-metricsd.py"
        ).read_text(encoding="utf-8")
        block = source.split("def resolve_window")[1].split(chr(10) + "def ")[0]
        self.assertIn('return "custom"', block)


class SavingTheNames(unittest.TestCase):
    def test_it_refuses_anything_that_is_not_a_mapping(self):
        for payload in ([], "x", 7, None):
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    monitoring.save_channel_labels(payload)

    def test_hidden_must_be_a_list_when_given(self):
        with self.assertRaises(ValueError):
            monitoring.save_channel_labels({}, "not-a-list")

    def test_omitting_hidden_leaves_it_alone(self):
        # The daemon reads absent as "leave it", so a rename must not empty
        # the list of what was put away.
        with mock.patch.object(monitoring, "metricsd_channel_labels_save",
                               return_value={"ok": True}) as saved:
            monitoring.save_channel_labels({"h": "x"})
        self.assertIsNone(saved.call_args[0][1])


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




class TheWindowSurvivesTheWholeCallPath(unittest.TestCase):
    """Every read has to carry the period all the way to the socket.

    This exists because it did not. `metricsd_states` and `metricsd_series`
    never took the argument the service layer had started passing, and every
    chart on the page answered 500 with

        TypeError: metricsd_series() takes from 2 to 3 positional arguments
        but 4 were given

    while the summary cards above them, whose signature had been widened,
    kept showing numbers. The page reported "no data for this period" for
    all five charts, which is what the browser is left to say when the
    request fails.

    The suite did not catch it because it mocked the client functions, and a
    mock accepts any signature at all. So these call the real service
    functions and intercept the transport instead -- the one seam below
    which nothing of ours runs. A signature that stops matching raises here,
    the way it did in production.
    """

    def setUp(self):
        self.seen = []

        def record(path, params=None, timeout=None):
            self.seen.append((path, dict(params or {})))
            return {"ok": True, "objects": [], "points": [], "series": {},
                    "totals": {}, "health": {}, "servers": [], "labels": {},
                    "hidden": []}

        # Patch the module object, not a dotted string. Under discovery the
        # string form cannot be resolved -- by the time this runs, another
        # test module has imported the package without binding this
        # submodule as an attribute, and mock's lookup raises
        # AttributeError. Importing it here binds it and hands back the very
        # module whose globals the real client function consults.
        from haproxy_admin import metricsd_client

        patcher = mock.patch.object(
            metricsd_client, "_get_json", side_effect=record
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    WINDOW = {"since": 1787846270, "until": 1787853470}

    def params_for(self, fragment):
        for path, params in self.seen:
            if fragment in path:
                return params
        self.fail(f"nothing asked for {fragment}: {self.seen}")

    def test_the_charts_carry_it(self):
        monitoring.series("requests", "24h", "", self.WINDOW)
        params = self.params_for("/series")
        self.assertEqual(params.get("since"), self.WINDOW["since"])
        self.assertEqual(params.get("until"), self.WINDOW["until"])
        self.assertEqual(params.get("chart"), "requests")

    def test_the_timeline_carries_it(self):
        monitoring.states("24h", "", self.WINDOW)
        params = self.params_for("/states")
        self.assertEqual(params.get("since"), self.WINDOW["since"])
        self.assertEqual(params.get("until"), self.WINDOW["until"])

    def test_the_cards_carry_it(self):
        monitoring.summary("24h", "", self.WINDOW)
        params = self.params_for("/summary")
        self.assertEqual(params.get("since"), self.WINDOW["since"])
        self.assertEqual(params.get("until"), self.WINDOW["until"])

    def test_a_preset_sends_no_period_at_all(self):
        # The absence matters: sending a stale since/until alongside a preset
        # would pin every refresh to the moment the page was opened.
        monitoring.series("requests", "24h", "", {})
        params = self.params_for("/series")
        self.assertNotIn("since", params)
        self.assertNotIn("until", params)
        self.assertEqual(params.get("range"), "24h")

    def test_a_site_still_scopes_the_chart(self):
        monitoring.series("requests", "24h", "example.com", self.WINDOW)
        self.assertEqual(self.params_for("/series").get("site"), "example.com")


if __name__ == "__main__":
    unittest.main()
