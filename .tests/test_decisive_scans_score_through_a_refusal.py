"""A decisive scanner finding scores even when HAProxy refused the request.

An address spent a morning working through /.git-credentials under every
common web root of a gateway. Every request was answered 451 by GeoIP. The
adaptive engine recognised secrets, vcs and backup on each one -- and scored
the address zero, because a request the gateway had already refused was
taken to need nothing more. The address stayed free to try a site without a
country filter, or the login page, which cannot have one.

A decisive category is the content of the request, not the identity of the
client: no browser, framework or crawler ever asks for one. So it scores
whether or not the request was refused, and the ban -- every host and port,
before the TLS handshake -- does what the 451 could not. A plain refusal,
and an ordinary scanner finding behind one, still score nothing: a person
whose authorisation lapsed is never banned for being turned away.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
GUARDD = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py"


def load():
    spec = importlib.util.spec_from_file_location("guardd_decisive_refused", GUARDD)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


guardd = load()
NOW = 1_700_000_000


def event(event_type, category, handled, ts=NOW - 60):
    return {
        "ts": ts, "event_type": event_type, "category": category,
        "handled": int(handled), "site": "", "detail": "/x",
    }


class Scoring(unittest.TestCase):
    def score(self, events):
        return guardd.score_events(events, NOW, guardd.ScoringPolicy())

    def test_a_refused_decisive_finding_is_enough_for_a_ban(self):
        # The reported case: every request refused by GeoIP.
        result = self.score([event(guardd.EVENT_SCANNER_DECISIVE, "secrets", True)])
        self.assertGreaterEqual(result["score"], guardd.WOULD_BAN_SCORE)
        (contribution,) = result["contributions"]
        self.assertGreater(contribution["points"], 0)
        self.assertNotEqual(contribution.get("reason"), "already refused by the gateway")

    def test_it_scores_what_it_would_have_scored_unrefused(self):
        refused = self.score([event(guardd.EVENT_SCANNER_DECISIVE, "vcs", True)])
        served = self.score([event(guardd.EVENT_SCANNER_DECISIVE, "vcs", False)])
        self.assertEqual(refused["score"], served["score"])

    def test_an_ordinary_refused_finding_still_scores_nothing(self):
        for event_type, category in (
            (guardd.EVENT_SCANNER_PATH, "wordpress"),
            (guardd.EVENT_SCANNER_MULTI, ""),
            (guardd.EVENT_LOW_AND_SLOW, ""),
            (guardd.EVENT_INVALID_HOST, ""),
        ):
            with self.subTest(event_type=event_type):
                result = self.score([event(event_type, category, True)])
                self.assertEqual(result["score"], 0)
                self.assertEqual(
                    result["contributions"][0]["reason"], "already refused by the gateway"
                )

    def test_only_the_decisive_finding_is_exempt(self):
        self.assertEqual(guardd.REFUSAL_DOES_NOT_EXCUSE, frozenset({guardd.EVENT_SCANNER_DECISIVE}))


if __name__ == "__main__":
    unittest.main()
