"""Config-authoritative restoration of every HAProxy state field we consume."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


path = Path(__file__).resolve().parents[1] / "installer/haproxy_server_state.py"
spec = importlib.util.spec_from_file_location("state_normalizer", path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
HEADER = "# " + " ".join(module.FIELDS + module.OPTIONAL)
ROW = "36 target 1 main 127.0.0.1 0 73 17 100 10 15 2 0 6 0 0 0 old.example.test 1025 - 0 9999 127.0.0.8 127.0.0.9 9998"


class StateNormalizerTests(unittest.TestCase):
    def restore(self, endpoint="new.example.test:1026", *, options="check", row=ROW, preamble=""):
        text = "1\n" + HEADER + "\n" + row + "\n"
        config = preamble + "\nbackend target\n server main " + endpoint + " " + options + "\n"
        lines = module.normalize_state(text, config).splitlines()
        return dict(zip(module.FIELDS, lines[2].split(), strict=True))

    def test_new_dns_does_not_reuse_the_previous_address_or_runtime_fqdn_override(self):
        row = self.restore()
        self.assertEqual((row["srv_addr"], row["srv_fqdn"], row["srv_port"]), ("-", "new.example.test", "1026"))
        self.assertEqual((row["srv_admin_state"], row["srv_uweight"], row["srv_iweight"]), ("9", "17", "100"))

    def test_same_dns_keeps_its_last_known_address_for_resolver_outages(self):
        self.assertEqual(self.restore("old.example.test:1026")["srv_addr"], "127.0.0.1")

    def test_ip_to_dns_clears_cached_address(self):
        row = ROW.replace("old.example.test", "-")
        self.assertEqual(self.restore(row=row)["srv_addr"], "-")

    def test_fixed_ipv4_and_ipv6_always_come_from_config(self):
        for endpoint, address in (("127.0.0.2:1043", "127.0.0.2"), ("[::1]:1043", "::1"),
                                  ("ipv4@127.0.0.3:1043", "127.0.0.3")):
            with self.subTest(endpoint=endpoint):
                row = self.restore(endpoint)
                self.assertEqual((row["srv_addr"], row["srv_fqdn"], row["srv_port"]), (address, "-", "1043"))

    def test_unbracketed_ipv6_without_port_is_not_misread_as_port_one(self):
        self.assertEqual(module.endpoint("::1"), ("::1", None))

    def test_old_failure_cannot_pin_down_a_server_after_all_checks_are_removed(self):
        row = self.restore(options="")
        self.assertEqual((row["srv_op_state"], row["srv_check_state"], row["srv_agent_state"]), ("2", "0", "0"))
        self.assertEqual(row["srv_admin_state"], "9")

    def test_health_failure_and_explicit_disable_are_kept_while_checks_exist(self):
        row = self.restore(options="check", row=ROW.replace(" 6 0 0 0 ", " 2 0 0 0 "))
        self.assertEqual((row["srv_op_state"], row["srv_check_state"]), ("0", "2"))

    def test_agent_check_alone_still_preserves_health_state(self):
        self.assertEqual(self.restore(options="agent-check agent-port 9876")["srv_op_state"], "0")

    def test_default_checks_and_server_overrides_are_respected(self):
        preamble = "defaults\n default-server check agent-check\n"
        self.assertEqual(self.restore(options="", preamble=preamble)["srv_op_state"], "0")
        self.assertEqual(self.restore(options="no-check no-agent-check", preamble=preamble)["srv_op_state"], "2")

    def test_same_srv_record_keeps_discovery_but_changed_record_drops_old_target(self):
        row = ROW.replace("old.example.test 1025 -", "target.example.test 1025 _old._tcp.example.test")
        same = self.restore("_old._tcp.example.test", row=row)
        self.assertEqual((same["srv_addr"], same["srv_port"], same["srvrecord"]), ("127.0.0.1", "1025", "_old._tcp.example.test"))
        new = self.restore("_new._tcp.example.test", row=row)
        self.assertEqual((new["srv_addr"], new["srv_fqdn"], new["srv_port"], new["srvrecord"]), ("-", "-", "0", "-"))

    def test_every_optional_transport_override_is_removed(self):
        row = self.restore()
        self.assertEqual(tuple(row), module.FIELDS)
        self.assertTrue(set(module.OPTIONAL).isdisjoint(row))

    def test_unknown_header_truncated_row_and_non_numeric_state_are_rejected(self):
        for text in ("2\n" + HEADER + "\n" + ROW, "1\n# be_id broken\n" + ROW,
                     "1\n" + HEADER + "\n" + " ".join(ROW.split()[:-1]),
                     "1\n" + HEADER + "\n" + ROW.replace(" 73 ", " invalid ")):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    module.normalize_state(text, "")

    def test_empty_initial_state_is_supported(self):
        self.assertEqual(module.normalize_state("1\n", None), "1\n")


if __name__ == "__main__":
    unittest.main()
