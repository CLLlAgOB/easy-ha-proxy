"""Tests for the kernel-NAT UDP forwarding generator (variant A).

Exercises the pure, side-effect-free parts: config validation, catalog
loading, and the iptables rule plan. No root or iptables required.
"""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "ansible/roles/haproxy-admin/files/haproxy-udp-forward.py"

spec = importlib.util.spec_from_file_location("udp_forward", GENERATOR)
udp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(udp)


class NormalizeTests(unittest.TestCase):
    def test_valid_entry_is_normalized(self):
        out = udp.normalize_forward(
            {"name": "wg", "listen_port": 51820,
             "backend_host": "10.0.0.5", "backend_port": 51821}
        )
        self.assertEqual(out["listen_port"], 51820)
        self.assertEqual((out["listen_start"], out["listen_end"]), (51820, 51820))
        self.assertEqual(out["backend_ip"], "10.0.0.5")
        self.assertEqual(out["backend_port"], 51821)
        self.assertTrue(out["ban_check"])  # default on

    def test_equal_sized_ranges_are_normalized(self):
        out = udp.normalize_forward(
            {
                "name": "game",
                "listen_port": "19999-20010",
                "backend_host": "10.0.0.5",
                "backend_port": "9999-10010",
            }
        )
        self.assertEqual((out["listen_start"], out["listen_end"]), (19999, 20010))
        self.assertEqual((out["backend_start"], out["backend_end"]), (9999, 10010))

    def test_rejects_loopback_backend(self):
        with self.assertRaisesRegex(
            udp.ConfigError,
            "must not resolve to a loopback address",
        ):
            udp.normalize_forward(
                {
                    "name": "local",
                    "listen_port": 19999,
                    "backend_host": "127.0.0.1",
                    "backend_port": 9999,
                }
            )

    def test_rejects_mismatched_ranges(self):
        with self.assertRaises(udp.ConfigError):
            udp.normalize_forward(
                {
                    "listen_port": "20000-20002",
                    "backend_host": "10.0.0.5",
                    "backend_port": "10000-10001",
                }
            )

    def test_rejects_out_of_range_port(self):
        with self.assertRaises(udp.ConfigError):
            udp.normalize_forward(
                {"listen_port": 70000, "backend_host": "10.0.0.5", "backend_port": 53}
            )

    def test_rejects_non_numeric_port(self):
        with self.assertRaises(udp.ConfigError):
            udp.normalize_forward(
                {"listen_port": "; rm -rf /", "backend_host": "10.0.0.5",
                 "backend_port": 53}
            )

    def test_requires_backend_host(self):
        with self.assertRaises(udp.ConfigError):
            udp.normalize_forward({"listen_port": 53, "backend_port": 53})


class LoadForwardsTests(unittest.TestCase):
    def _write(self, text: str) -> str:
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".yml", delete=False, encoding="utf-8"
        )
        handle.write(text)
        handle.close()
        return handle.name

    def test_disabled_entries_are_skipped(self):
        path = self._write(
            """
            udp_forwards:
              - {name: a, listen_port: 51820, backend_host: 10.0.0.5, backend_port: 51820}
              - {name: off, listen_port: 500, backend_host: 10.0.0.6, backend_port: 500, enabled: false}
            """
        )
        forwards = udp.load_forwards(path)
        self.assertEqual([f["name"] for f in forwards], ["a"])

    def test_invalid_enabled_entry_fails_closed(self):
        path = self._write(
            """
            udp_forwards:
              - {name: bad, listen_port: 99999, backend_host: 10.0.0.7, backend_port: 5}
            """
        )
        with self.assertRaises(SystemExit):
            udp.load_forwards(path)

    def test_overlapping_ranges_fail_closed(self):
        path = self._write(
            """
            udp_forwards:
              - {name: a, listen_port: 51820-51830, backend_host: 10.0.0.5, backend_port: 6000-6010}
              - {name: b, listen_port: 51830-51840, backend_host: 10.0.0.9, backend_port: 7000-7010}
            """
        )
        with self.assertRaises(SystemExit):
            udp.load_forwards(path)

    def test_missing_file_is_empty(self):
        self.assertEqual(udp.load_forwards("/nonexistent/udp.yml"), [])


class RulePlanTests(unittest.TestCase):
    def _forward(self, ban_check=True):
        result = udp.normalize_forward(
            {
                "name": "wg",
                "listen_port": 51820,
                "backend_host": "10.0.0.5",
                "backend_port": 51820,
                "ban_check": ban_check,
            }
        )
        return result

    def test_ban_checked_forward_drops_before_dnat(self):
        cmds = udp.build_rule_commands([self._forward(ban_check=True)])
        joined = [" ".join(c) for c in cmds]
        drop = next(c for c in joined if "haproxy_ban" in c)
        dnat = next(c for c in joined if "DNAT" in c)
        # The raw DROP on the listen port must precede the DNAT.
        self.assertIn("--match-set haproxy_ban src", drop)
        self.assertIn("-t raw", drop)
        self.assertLess(joined.index(drop), joined.index(dnat))
        self.assertIn("--to-destination 10.0.0.5:51820", dnat)
        self.assertTrue(any("MASQUERADE" in c and "10.0.0.5" in c for c in joined))
        self.assertTrue(any("ESTABLISHED,RELATED" in c for c in joined))

    def test_ban_unchecked_forward_has_no_drop(self):
        cmds = udp.build_rule_commands([self._forward(ban_check=False)])
        self.assertFalse(any("haproxy_ban" in " ".join(c) for c in cmds))
        self.assertTrue(any("DNAT" in " ".join(c) for c in cmds))

    def test_zero_trust_forward_whitelists_authorized_ips(self):
        fwd = self._forward(ban_check=False)
        fwd["zero_trust"] = True
        joined = [" ".join(c) for c in udp.build_rule_commands([fwd])]
        auth = next(c for c in joined if "haproxy_ip_auth" in c)
        dnat = next(c for c in joined if "DNAT" in c)
        # Whitelist: drop packets whose source is NOT authorized, before DNAT.
        self.assertIn("-t raw", auth)
        self.assertIn("! --match-set haproxy_ip_auth src", auth)
        self.assertIn("-j DROP", auth)
        self.assertLess(joined.index(auth), joined.index(dnat))

    def test_forward_without_zero_trust_has_no_auth_rule(self):
        joined = [" ".join(c) for c in udp.build_rule_commands([self._forward()])]
        self.assertFalse(any("haproxy_ip_auth" in c for c in joined))

    def test_all_arguments_are_strings(self):
        # Guards against non-string args reaching subprocess (injection safety).
        for command in udp.build_rule_commands([self._forward()]):
            for token in command:
                self.assertIsInstance(token, str)

    def test_routed_backend_uses_forward_and_masquerade_only(self):
        joined = [
            " ".join(c)
            for c in udp.build_rule_commands([self._forward()])
        ]
        self.assertTrue(any("-A HP_UDP_FWD" in command for command in joined))
        self.assertTrue(any("MASQUERADE" in command for command in joined))
        self.assertFalse(any("HP_UDP_IN" in command for command in joined))
        self.assertFalse(any("127.0.0.0/8" in command for command in joined))

    def test_range_has_deterministic_per_port_dnat(self):
        forward = udp.normalize_forward(
            {
                "name": "range",
                "listen_port": "19999-20001",
                "backend_host": "10.0.0.5",
                "backend_port": "9999-10001",
            }
        )
        joined = [" ".join(c) for c in udp.build_rule_commands([forward])]
        self.assertTrue(
            any("--dport 19999 -j DNAT --to-destination 10.0.0.5:9999" in c
                for c in joined)
        )
        self.assertTrue(
            any("--dport 20001 -j DNAT --to-destination 10.0.0.5:10001" in c
                for c in joined)
        )
        self.assertTrue(
            any("--dport 19999:20001" in c and "haproxy_ban" in c
                for c in joined)
        )


class WebManagementTests(unittest.TestCase):
    def test_page_supports_edit_ranges_and_immediate_apply_feedback(self):
        template = (
            ROOT / "docker/app/haproxy_admin/templates/haproxy_udp.html"
        ).read_text(encoding="utf-8")
        route = (
            ROOT / "docker/app/haproxy_admin/routes_haproxy_udp.py"
        ).read_text(encoding="utf-8")
        service = (
            ROOT / "docker/app/haproxy_admin/services_haproxy_udp.py"
        ).read_text(encoding="utf-8")
        self.assertIn("Edit UDP forward", template)
        self.assertIn("Save and apply now", template)
        self.assertIn("19999-20010", template)
        self.assertIn("Loopback addresses", template)
        self.assertNotIn("and 127.0.0.1 are supported", template)
        self.assertIn("original_name", route)
        self.assertIn("rules were restored automatically", service)
        self.assertIn("must not use a loopback address", service)

    def test_loopback_routing_is_explicitly_disabled(self):
        tasks = (
            ROOT / "ansible/roles/haproxy-admin/tasks/iptables-udp.yml"
        ).read_text(encoding="utf-8")
        generator = GENERATOR.read_text(encoding="utf-8")
        self.assertIn("net.ipv4.conf.all.route_localnet", tasks)
        self.assertIn("net.ipv4.conf.default.route_localnet", tasks)
        self.assertGreaterEqual(tasks.count('value: "0"'), 2)
        self.assertIn(
            '_write_sysctl("/proc/sys/net/ipv4/conf/all/route_localnet", "0")',
            generator,
        )
        self.assertIn("_remove_legacy_loopback_scaffolding()", generator)
        self.assertNotIn('("filter", "INPUT", INPUT_CHAIN)', generator)


class HealthcheckRegistrationTests(unittest.TestCase):
    """The UDP loader and its generator must be monitored and update-tracked."""

    def _defaults(self):
        import yaml
        text = (ROOT / "ansible/roles/healthcheck/defaults/main.yml").read_text(
            encoding="utf-8"
        )
        return yaml.safe_load(text)

    def test_udp_loader_is_a_monitored_service(self):
        units = [s["name"] for s in self._defaults()["status_check_systemd_units"]]
        self.assertIn("iptables-haproxy-udp.service", units)

    def test_udp_generator_and_unit_are_tracked_artifacts(self):
        names = {a["name"] for a in self._defaults()["status_check_managed_artifacts"]}
        self.assertIn("iptables-udp-generator", names)
        self.assertIn("iptables-udp-unit", names)

    def test_healthd_default_units_include_the_udp_loader(self):
        healthd = (
            ROOT / "ansible/roles/haproxy-admin/templates/healthd.json.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("iptables-haproxy-udp.service", healthd)


if __name__ == "__main__":
    unittest.main()
