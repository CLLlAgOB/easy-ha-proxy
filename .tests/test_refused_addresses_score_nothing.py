"""An address the gateway already refuses must not accumulate a score.

A 403 or a 451 means HAProxy turned the request away on identity -- a GeoIP
country block, or a per-site address rule -- before any backend saw it. The
address reaches nothing, so banning it changes nothing, and every finding
built from such a request scores zero and says so on the page:

    SCANNER_PATH_DECISIVE (secrets)  /.aws/credentials  0 · already refused

Except that the two derived findings did not. SCANNER_MULTI_CATEGORY and
LOW_AND_SLOW_SCANNER are emitted from the accumulated activity rather than
from one request, and they were emitted without the flag -- so an address
whose every single request was refused still showed:

    LOW_AND_SLOW_SCANNER    hits=32 categories=3   +22.45
    SCANNER_MULTI_CATEGORY  categories=3           +14.96

Thirty-seven points built entirely out of findings worth zero. Reported from
a live gateway, off a timeline where every other line read "already refused".

Mixed traffic is the case that stops this being a one-line change: an
address refused on one site and served on another is reaching something, and
its derived findings are worth their points.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GUARDD = (
    ROOT / "ansible" / "roles" / "haproxy-admin" / "files"
    / "easy-ha-proxy-guardd.py"
)


def load():
    spec = importlib.util.spec_from_file_location("guardd_refused", GUARDD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["guardd_refused"] = module
    spec.loader.exec_module(module)
    return module


guardd = load()


class WhatCountsAsRefused(unittest.TestCase):
    def test_the_identity_refusals_are_403_and_451(self):
        self.assertEqual(
            set(guardd.ParsedRequest.IDENTITY_REFUSALS), {403, 451}
        )

    def test_a_malformed_request_is_not_a_shield(self):
        # 400 was in this set once. It is the opposite case: the gateway
        # rejected one bad request and carried on serving that address
        # everything else it asked for.
        self.assertNotIn(400, guardd.ParsedRequest.IDENTITY_REFUSALS)


class TheDerivedFindingsFollowTheEvidence(unittest.TestCase):
    def activity(self, hits: int, denied: int) -> "guardd.IpActivity":
        record = guardd.IpActivity()
        record.scanner_hits = hits
        record.scanner_hits_denied = denied
        return record

    def test_all_refused_means_the_derived_finding_is_refused_too(self):
        self.assertTrue(self.activity(32, 32).scanning_was_all_refused)

    def test_one_request_that_got_through_is_enough_to_count(self):
        # The mixed case: refused on one site, served on another. That
        # address is reaching something, and a ban would change that.
        self.assertFalse(self.activity(32, 31).scanning_was_all_refused)

    def test_an_address_with_no_scanning_at_all_is_not_called_refused(self):
        # Otherwise an empty record would report "all of nothing was
        # refused" and suppress a finding it knows nothing about.
        self.assertFalse(self.activity(0, 0).scanning_was_all_refused)

    def test_the_counter_cannot_be_read_as_a_ratio(self):
        for hits, denied in ((10, 0), (10, 5), (10, 9)):
            with self.subTest(hits=hits, denied=denied):
                self.assertFalse(
                    self.activity(hits, denied).scanning_was_all_refused
                )


class BothDerivedFindingsPassIt(unittest.TestCase):
    """The bug was that these two emitted without the flag at all."""

    def setUp(self):
        self.source = GUARDD.read_text(encoding="utf-8")

    def block(self, function: str) -> str:
        return self.source.split(f"def {function}(")[1].split("\n    def ")[0]

    def test_multi_category(self):
        self.assertIn("handled=activity.scanning_was_all_refused",
                      self.block("_check_multi_category"))

    def test_low_and_slow(self):
        self.assertIn("handled=activity.scanning_was_all_refused",
                      self.block("_check_low_and_slow"))

    def test_the_counter_is_kept_where_the_hit_is_counted(self):
        # Both emission paths -- a matched path and a query injection --
        # have to feed it, or the ratio silently under-counts.
        self.assertEqual(
            self.source.count("activity.scanner_hits_denied += 1"), 2
        )

    def test_enumeration_needs_no_flag_because_a_404_is_not_a_refusal(self):
        # NOT_FOUND_ENUMERATION is built from 404s, and a 404 means the
        # request reached a backend that did not have the path. It is
        # never an identity refusal, so there is nothing to inherit.
        block = self.block("_check_not_found_enumeration")
        self.assertNotIn("handled=", block)
        self.assertNotIn(404, guardd.ParsedRequest.IDENTITY_REFUSALS)


class DrivenThroughTheEngine(unittest.TestCase):
    """Source assertions prove the flag is passed; this proves the effect."""

    def setUp(self):
        import sqlite3
        import tempfile

        self.sqlite3 = sqlite3
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.log = root / "haproxy.log"
        self.log.write_text("", encoding="utf-8")
        config = guardd.GuardConfig(log_file=str(self.log))
        self.database = guardd.SecurityDatabase(str(root / "security.db"))
        self.addCleanup(self.database.close)
        self.engine = guardd.GuardEngine(config, self.database)
        self.engine.cursor.read(4096)

    def line(self, ip, path, status):
        return (
            "2026-08-11T07:00:00.000000+00:00 host haproxy[1]: "
            f"{ip}:1234 [11/Aug/2026:07:00:00.000] fe_https~ be_shop/srv1 "
            f"0/0/0/1/1 {status} 100 ---- 1/1/0/0/0 0/0 GET {path} HTTP/1.1"
        )

    def run_scan(self, ip, requests):
        """Enough distinct categories and hits to trigger both derived rules.

        Order matters and is given explicitly: a derived finding is emitted
        the moment its threshold is crossed, so what counts is what had
        happened by then, not what happens later.
        """
        with self.log.open("a", encoding="utf-8") as handle:
            for path, status in requests:
                handle.write(self.line(ip, path, status) + chr(10))
        self.engine.ingest_log(1000)
        connection = self.sqlite3.connect(str(self.database.path))
        connection.row_factory = self.sqlite3.Row
        try:
            rows = [dict(r) for r in connection.execute(
                "SELECT event_type, handled FROM security_events "
                "WHERE ip = ? ORDER BY id", (ip,))]
        finally:
            connection.close()
        return {r["event_type"]: r["handled"] for r in rows}

    ALL_REFUSED = [
        ("/.git/config", 451), ("/.env", 451), ("/backup.sql", 451),
        ("/wp-admin/x", 451), ("/phpmyadmin", 451), ("/server-status", 451),
    ]
    # The same scan, except the first request reached a backend and was
    # answered 404. By the time the third category arrives -- which is when
    # the derived findings fire -- this address has demonstrably got through.
    ONE_GOT_THROUGH = [
        ("/wp-admin/x", 404), ("/.git/config", 451), ("/.env", 451),
        ("/backup.sql", 451), ("/phpmyadmin", 451), ("/server-status", 451),
    ]

    def test_an_address_refused_on_every_request_earns_nothing(self):
        seen = self.run_scan("203.0.113.10", self.ALL_REFUSED)
        self.assertIn(guardd.EVENT_SCANNER_MULTI, seen)
        self.assertIn(guardd.EVENT_LOW_AND_SLOW, seen)
        for event in (guardd.EVENT_SCANNER_MULTI, guardd.EVENT_LOW_AND_SLOW):
            with self.subTest(event=event):
                self.assertEqual(
                    seen[event], 1,
                    "a finding built only from refused requests scored",
                )

    def test_an_address_that_reached_a_backend_once_still_counts(self):
        # Refused on five, served a 404 on one. It is reaching something.
        seen = self.run_scan("203.0.113.11", self.ONE_GOT_THROUGH)
        self.assertIn(guardd.EVENT_SCANNER_MULTI, seen)
        self.assertEqual(seen[guardd.EVENT_SCANNER_MULTI], 0)

    def test_a_finding_is_judged_on_what_had_happened_when_it_fired(self):
        """Not on everything the address ever did.

        The derived findings fire the moment the third category arrives. If
        every request up to that point was refused, the finding is worth
        nothing even if the address gets through afterwards -- and the
        finding recorded later, on fresh evidence, is the one that counts.
        """
        late = [
            ("/.git/config", 451), ("/.env", 451), ("/backup.sql", 451),
            ("/wp-admin/x", 404),
        ]
        seen = self.run_scan("203.0.113.12", late)
        self.assertEqual(seen[guardd.EVENT_SCANNER_MULTI], 1)


class TheScoreIsActuallyZero(unittest.TestCase):
    def test_a_handled_event_contributes_nothing_and_says_why(self):
        source = GUARDD.read_text(encoding="utf-8")
        block = source.split('if int(event.get("handled", 0)):')[1][:600]
        self.assertIn('"points": 0', block)
        self.assertIn('"already refused by the gateway"', block)


if __name__ == "__main__":
    unittest.main()
