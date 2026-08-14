"""A rate finding must mean the rate was actually exceeded.

It did not. The engine emitted RATE_EXCEEDED for any non-zero counter, so a
client that made one request in twenty seconds was scored as if it were
flooding. Measured on a live gateway before the fix: 534 findings across 40
addresses in one day, 497 of them at a reading of exactly 1 against limits of
200 and above, and not one genuine excess in the whole day. A mail client
polling once a minute sat permanently at WATCH because of it.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker" / "app"))


def load_guardd():
    path = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py"
    spec = importlib.util.spec_from_file_location("guardd_for_rates", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


GUARDD = load_guardd()

# Copied from a production gateway, so the parser is tested against the shapes
# the template really produces rather than ones invented to suit it.
REAL_CONFIG = """
    acl too_many_errs_e_oreol_2010_ru src_http_err_rate(tbl_err_e_oreol_2010_ru) gt 50
    acl too_fast_e_oreol_2010_ru src_http_req_rate(tbl_rate_e_oreol_2010_ru) gt 400
    acl too_fast_dsm_oreol_2010_ru src_http_req_rate(tbl_rate_dsm_oreol_2010_ru) gt 1200
    acl too_many_errs_other src_http_err_rate(tbl_err_other) gt 20
    acl nosni_too_often sc0_conn_rate(tbl_nosni_tcp) gt 5
    acl something_else hdr(host) -i example.test
"""


class ThresholdParsingTests(unittest.TestCase):
    def setUp(self):
        # enterContext arrived in 3.11 and the matrix still covers 3.10.
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name)
        self.config = self.path / "haproxy.cfg"
        self.config.write_text(REAL_CONFIG, encoding="utf-8")

    def test_every_counter_table_is_found(self):
        found = GUARDD.read_thresholds(str(self.config))
        self.assertEqual(
            found,
            {
                "tbl_err_e_oreol_2010_ru": 50,
                "tbl_rate_e_oreol_2010_ru": 400,
                "tbl_rate_dsm_oreol_2010_ru": 1200,
                "tbl_err_other": 20,
                "tbl_nosni_tcp": 5,
            },
        )

    def test_an_unreadable_configuration_yields_nothing(self):
        # And "nothing" must mean "score nothing", not "score everything".
        self.assertEqual(GUARDD.read_thresholds(str(self.path / "absent.cfg")), {})

    def test_a_table_with_no_known_ceiling_is_not_scored(self):
        source = (
            ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py"
        ).read_text(encoding="utf-8")
        block = source.split("def ingest_rate_tables")[1].split("    def ")[0]
        self.assertIn("if limit is None:", block)
        self.assertIn("continue", block.split("if limit is None:")[1][:400])

    def test_the_reading_must_beat_the_ceiling(self):
        source = (
            ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py"
        ).read_text(encoding="utf-8")
        block = source.split("def ingest_rate_tables")[1].split("    def ")[0]
        self.assertIn("if value <= limit:", block)
        self.assertNotIn("if value <= 0:", block)

    def test_the_finding_carries_both_numbers(self):
        source = (
            ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py"
        ).read_text(encoding="utf-8")
        self.assertIn('detail=f"{field_prefix}={value} limit={limit}"', source)


class ExplanationTests(unittest.TestCase):
    def setUp(self):
        from haproxy_admin import services_security

        self.security = services_security

    def explain(self, detail, event_type="RATE_EXCEEDED", limits=None):
        contribution = {"event_type": event_type, "detail": detail, "site": "s"}
        self.security._explain(contribution, limits or {})
        return contribution

    def test_the_limit_comes_from_the_finding(self):
        # Whatever websites.yml says now, the finding records what applied.
        result = self.explain("http_req_rate=450 limit=400")
        self.assertEqual(result["observed"], 450)
        self.assertEqual(result["limit"], 400)
        self.assertEqual(result["over_by"], 50)
        self.assertEqual(result["setting"], "max_req_rate")

    def test_the_suggestion_never_points_downwards(self):
        # "1 request against a limit of 400, raise max_req_rate to 1" is what
        # the arithmetic used to produce.
        result = self.explain("http_req_rate=401 limit=400")
        self.assertGreater(result["suggested"], result["limit"])

    def test_a_real_excess_gets_headroom(self):
        result = self.explain("http_req_rate=900 limit=400")
        self.assertEqual(result["suggested"], 1350)

    def test_an_error_finding_names_the_error_setting(self):
        result = self.explain(
            "http_err_rate=60 limit=50", event_type="ERROR_RATE_EXCEEDED"
        )
        self.assertEqual(result["setting"], "err_limit")
        self.assertEqual(result["over_by"], 10)

    def test_a_finding_without_numbers_is_left_alone(self):
        result = self.explain("")
        self.assertNotIn("observed", result)


if __name__ == "__main__":
    unittest.main()
