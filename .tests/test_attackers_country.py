"""The threat-analytics top lists must carry a country for their flags.

guardd counts the 400 and 451 offenders as it reads the log, but it does no
geo lookup, so its answer is just {ip, count}. The dashboard draws a flag from
each row's country; when get_attackers started preferring guardd, the country
fell out and the flags on "Top 400" and "Top 451" went blank. get_attackers
now fills the country in for the guardd answer as it always did for controld.
"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker" / "app"))

from haproxy_admin import services  # noqa: E402
from haproxy_admin import guardd_client  # noqa: E402


class GuarddRowsGainACountry(unittest.TestCase):
    def test_the_guardd_answer_is_enriched_with_a_country(self):
        guardd_reply = {
            "ok": True,
            "since": 0,  # old enough that get_attackers trusts guardd
            "code_400": [{"ip": "203.0.113.5", "count": 42}],
            "code_451": [{"ip": "198.51.100.9", "count": 7}],
        }
        countries = {"203.0.113.5": "DE", "198.51.100.9": "FR"}
        with mock.patch.object(guardd_client, "guardd_attackers",
                               return_value=guardd_reply), \
                mock.patch.object(services, "get_country_code",
                                  side_effect=lambda ip: countries.get(ip, "")):
            result = services.get_attackers()

        self.assertEqual(result["diagnostic"]["source"], "guardd")
        self.assertEqual(result["code_400"][0]["country"], "DE")
        self.assertEqual(result["code_451"][0]["country"], "FR")
        self.assertEqual(result["code_400"][0]["count"], 42)

    def test_a_country_guardd_somehow_already_has_is_kept(self):
        guardd_reply = {
            "ok": True, "since": 0,
            "code_400": [{"ip": "203.0.113.5", "count": 1, "country": "NL"}],
            "code_451": [],
        }
        with mock.patch.object(guardd_client, "guardd_attackers",
                               return_value=guardd_reply), \
                mock.patch.object(services, "get_country_code",
                                  side_effect=AssertionError("should not look up")):
            result = services.get_attackers()
        self.assertEqual(result["code_400"][0]["country"], "NL")


if __name__ == "__main__":
    unittest.main()
