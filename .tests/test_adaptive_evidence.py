"""Evidence a scanner produces must count against the scanner.

An operator asked why nothing ever gets banned. The security database
answered: of 140 events in a day, 108 scored nothing -- 77% -- and among
scanner findings specifically, 45 of 53 were discarded. The engine was
reaching its verdicts on under a quarter of what it had seen, and the
quarter it kept was the least incriminating part.

The cause was one status code. A request refused with 400 was recorded as
"already refused by the gateway" and scored zero, on the reasoning written
for GeoIP: banning an address the gateway already blocks adds nothing. But
400 is not that. It means one malformed request was rejected while the same
address went on being served everything else -- one of them sent 134
malformed requests and was served 5935 normal ones in the same day, and
scored zero for all 134. And a scanner's requests are malformed by nature,
so the discard fell hardest on exactly the traffic worth catching.
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
    spec = importlib.util.spec_from_file_location("guardd_evidence", GUARDD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["guardd_evidence"] = module
    spec.loader.exec_module(module)
    return module


guardd = load()


def request_with(status):
    """A parsed log line shaped like a scanner probe, varying only the status."""
    return guardd.ParsedRequest(
        client_ip="31.70.84.142",
        status=status,
        frontend="fe_https",
        backend="fe_https/<NOSRV>",
        method="GET",
        path="/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        host="",
    )


class RefusalTests(unittest.TestCase):
    def test_a_geo_block_still_stops_the_scoring(self):
        # The case the rule was written for: the address can reach nothing,
        # so there is nothing further to protect by scoring it.
        self.assertTrue(request_with(451).denied_by_gateway)

    def test_a_per_site_address_rule_counts_too(self):
        self.assertTrue(request_with(403).denied_by_gateway)

    def test_a_malformed_request_is_evidence_not_a_shield(self):
        # The production case: 21 of these from one scanner, every one of
        # them a probe, every one of them previously worth zero.
        self.assertFalse(request_with(400).denied_by_gateway)

    def test_ordinary_answers_are_not_refusals(self):
        for status in (200, 301, 404, 429, 500, 503):
            with self.subTest(status=status):
                self.assertFalse(request_with(status).denied_by_gateway)

    def test_the_set_is_stated_once_and_named(self):
        # So the next person changing it sees the reasoning attached.
        self.assertEqual(guardd.ParsedRequest.IDENTITY_REFUSALS, (403, 451))


class ScoringTests(unittest.TestCase):
    """What the change is worth, in points."""

    def policy(self):
        return guardd.ScoringPolicy()

    def score(self, events):
        return guardd.score_events(events, now=1_700_000_000, policy=self.policy())

    def event(self, event_type, handled, category="scanner"):
        return {
            "ts": 1_700_000_000 - 60,
            "event_type": event_type,
            "category": category,
            "detail": "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            "handled": 1 if handled else 0,
            "site": "",
        }

    def test_a_discarded_finding_contributes_nothing(self):
        result = self.score([self.event("SCANNER_PATH", handled=True)])
        self.assertEqual(result["score"], 0)

    def test_the_same_finding_counts_once_it_is_not_discarded(self):
        result = self.score([self.event("SCANNER_PATH", handled=False)])
        self.assertGreater(result["score"], 0)

    def test_a_discarded_finding_is_still_shown_with_its_reason(self):
        # Silently dropping it would leave the operator unable to see why a
        # scanner they can plainly observe is scoring nothing.
        result = self.score([self.event("SCANNER_PATH", handled=True)])
        shown = result["contributions"][0]
        self.assertEqual(shown["points"], 0)
        self.assertIn("already refused", shown["reason"])


class AdviceTests(unittest.TestCase):
    """Never offer to widen the door for whoever is probing it."""

    @staticmethod
    def load_service():
        # As part of its package: the module uses relative imports, so loading
        # it by path leaves it without a parent and it will not execute.
        app = ROOT / "docker" / "app"
        if str(app) not in sys.path:
            sys.path.insert(0, str(app))
        try:
            from haproxy_admin import services_security
        except Exception as exc:  # pragma: no cover - dependencies absent
            raise unittest.SkipTest(f"cannot import the service layer: {exc}")
        return services_security

    def setUp(self):
        self.service = self.load_service()

    def test_a_scanner_is_not_offered_a_higher_limit(self):
        # Straight from the reported page: an address probing for a PHP RCE
        # was told to raise err_limit to 37.
        contributions = [
            {"event_type": "SCANNER_PATH", "points": 0},
            {"event_type": "ERROR_RATE_EXCEEDED", "suggested": 37, "limit": 20},
        ]
        self.service._withhold_advice_from_attackers(contributions)
        self.assertNotIn("suggested", contributions[1])
        self.assertIn("advice_withheld", contributions[1])

    def test_the_measurement_itself_survives(self):
        # The operator still needs to see what was measured against what.
        contributions = [
            {"event_type": "INVALID_HOST_ACTIVITY", "points": 0},
            {
                "event_type": "ERROR_RATE_EXCEEDED",
                "suggested": 37,
                "limit": 20,
                "observed": 25,
                "over_by": 5,
            },
        ]
        self.service._withhold_advice_from_attackers(contributions)
        kept = contributions[1]
        self.assertEqual(kept["limit"], 20)
        self.assertEqual(kept["observed"], 25)
        self.assertEqual(kept["over_by"], 5)

    def test_an_ordinary_client_still_gets_the_advice(self):
        # The whole reason the suggestion exists: an application that opens
        # many connections at once and trips a threshold nobody tuned.
        contributions = [
            {"event_type": "RATE_EXCEEDED", "suggested": 300, "limit": 200},
        ]
        self.service._withhold_advice_from_attackers(contributions)
        self.assertEqual(contributions[0]["suggested"], 300)

    def test_every_hostile_marker_withholds_it(self):
        for marker in ("SCANNER_PATH", "SCANNER_MULTI_CATEGORY",
                       "INVALID_HOST_ACTIVITY", "NOSNI_PROBING",
                       "LEGACY_HAPROXY_BAN"):
            with self.subTest(marker=marker):
                contributions = [
                    {"event_type": marker},
                    {"event_type": "ERROR_RATE_EXCEEDED", "suggested": 37},
                ]
                self.service._withhold_advice_from_attackers(contributions)
                self.assertNotIn("suggested", contributions[1])


if __name__ == "__main__":
    unittest.main()
