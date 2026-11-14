"""A UDP forward with a backup moves to it when its main backend stops answering.

The operator asked for it: a UDP forward to one address goes dark with that
address. A forward may now name a backup backend (and its own port if it
listens elsewhere) and how the main one is checked -- ping, or a connection
to a TCP port. haproxy-controld checks every five seconds; three missed
checks in a row send the forward to the backup, thirty seconds of answers
bring it back. Flows already under way move at once (their conntrack
entries are removed), and an alert stays open while the backup carries it.

Held here: the generator's rules for both sides, the switching rules
(including the gap that keeps a half-dead backend from flapping), what is
written and run on a switch, and the panel's form.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "ansible/roles/haproxy-admin/files/haproxy-udp-forward.py"
spec = importlib.util.spec_from_file_location("udp_forward_failover", GENERATOR)
udp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(udp)
sys.path.insert(0, str(ROOT / ".tests"))
import test_controld_ipset as ipset_tests  # noqa: E402

controld = ipset_tests.controld
APP = ROOT / "docker/app/haproxy_admin"


def forward(**more):
    return {"name": "voip", "listen_port": "5060", "backend_host": "10.0.0.5", "backend_port": "5060", **more}


class TheGenerator(unittest.TestCase):
    def test_a_forward_without_a_backup_is_as_before(self):
        out = udp.normalize_forward(forward())
        self.assertIsNone(out["backup"])
        self.assertEqual((out["active"], out["target_ip"]), ("primary", "10.0.0.5"))

    def test_a_backup_takes_the_backend_port_unless_it_has_its_own(self):
        out = udp.normalize_forward(forward(backup_host="10.0.0.6"))
        self.assertEqual((out["backup"]["ip"], out["backup"]["start"], out["backup"]["check"]), ("10.0.0.6", 5060, "ping"))
        out = udp.normalize_forward(forward(listen_port="5060-5061", backend_port="5060-5061",
                                            backup_host="10.0.0.6", backup_port="7060-7061",
                                            health_check="tcp", health_port="5061"))
        self.assertEqual((out["backup"]["start"], out["backup"]["end"], out["backup"]["health_port"]), (7060, 7061, 5061))

    def test_bad_backups_are_refused(self):
        for bad in ({"backup_host": "10.0.0.5"}, {"backup_host": "127.0.0.1"},
                    {"backup_host": "10.0.0.6", "backup_port": "7060-7061"},
                    {"backup_host": "10.0.0.6", "health_check": "http"},
                    {"backup_host": "10.0.0.6", "health_check": "tcp"},
                    {"backup_host": "10.0.0.6", "health_check": "tcp", "health_port": "70000"}):
            with self.subTest(bad=bad), self.assertRaises(udp.ConfigError):
                udp.normalize_forward(forward(**bad))

    def test_a_backup_that_does_not_resolve_does_not_stop_the_forward(self):
        with mock.patch.object(udp.socket, "getaddrinfo", side_effect=OSError("no such host")):
            out = udp.normalize_forward(forward(backup_host="backup.invalid"))
        self.assertIsNone(out["backup"]["ip"])
        udp.set_active([out], {"voip": "backup"})
        self.assertEqual(out["target_ip"], "10.0.0.5")

    def test_a_switched_forward_sends_to_its_backup(self):
        out = udp.normalize_forward(forward(backup_host="10.0.0.6", backup_port="7060"))
        udp.set_active([out], {"voip": "backup"})
        rules = [" ".join(rule) for rule in udp.build_rule_commands([out])]
        self.assertIn("--to-destination 10.0.0.6:7060", " | ".join(rules))
        self.assertNotIn("10.0.0.5", " | ".join(rules))

    def test_the_state_file_is_read_carefully(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "udp-failover.json"
            self.assertEqual(udp.load_failover(path), {})
            path.write_text('{"version": 1, "active": {"voip": "backup", "dns": "primary"}}')
            self.assertEqual(udp.load_failover(path), {"voip": "backup"})
            for broken in ("{", '{"version": 2, "active": {"voip": "backup"}}', '{"version": 1, "active": []}'):
                path.write_text(broken)
                self.assertEqual(udp.load_failover(path), {}, broken)

    def test_health_targets_name_what_controld_checks(self):
        forwards = [udp.normalize_forward(forward(backup_host="10.0.0.6", health_check="tcp", health_port="5061")),
                    udp.normalize_forward(forward(name="dns", listen_port="53", backend_port="53"))]
        self.assertEqual(udp.health_targets(forwards), [
            {"name": "voip", "primary": "10.0.0.5", "backup": "10.0.0.6", "check": "tcp", "health_port": 5061}])


class Switching(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.state_file = Path(folder.name) / "udp-failover.json"
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(controld, "UDP_FAILOVER_STATE", self.state_file).start()
        self.alerts = mock.Mock()
        mock.patch.object(controld, "_ALERTS", self.alerts).start()
        self.failover = controld.UdpFailover()
        self.target = {"name": "voip", "primary": "10.0.0.5", "backup": "10.0.0.6", "check": "ping", "health_port": None}
        mock.patch.object(self.failover, "load_targets", side_effect=lambda: [self.target]).start()
        self.up = {"10.0.0.5": True, "10.0.0.6": True}
        mock.patch.object(controld.UdpFailover, "probe", side_effect=lambda ip, check, port: self.up.get(ip, False)).start()
        self.commands = []
        mock.patch.object(controld, "run_cmd", side_effect=lambda args, **kw: self.commands.append(args)).start()
        self.now = 1_800_000_000.0

    def ticks(self, count):
        switches = []
        for _ in range(count):
            self.now += 5
            switches += self.failover.tick(self.now)
        return switches

    def written(self):
        return json.loads(self.state_file.read_text())["active"] if self.state_file.exists() else {}

    def test_a_healthy_main_backend_changes_nothing(self):
        self.assertEqual(self.ticks(10), [])
        self.assertEqual(self.commands, [])

    def test_three_missed_checks_send_it_to_the_backup(self):
        self.up["10.0.0.5"] = False
        self.assertEqual(self.ticks(2), [])
        switches = self.ticks(1)
        self.assertEqual([(name, old, new) for name, old, new, _ in switches], [("voip", "primary", "backup")])
        self.assertEqual(self.written(), {"voip": "backup"})
        self.assertIn(["systemctl", "restart", "iptables-haproxy-udp.service"], self.commands)
        self.assertIn(["conntrack", "-D", "-p", "udp", "--reply-src", "10.0.0.5"], self.commands)
        self.assertTrue(self.alerts.observe.call_args.kwargs["active"])
        self.assertEqual(self.alerts.observe.call_args.args, ("udp.failover", "voip"))

    def test_a_dead_backup_is_not_switched_to(self):
        self.up = {"10.0.0.5": False, "10.0.0.6": False}
        self.assertEqual(self.ticks(6), [])
        self.assertEqual(self.written(), {})

    def test_it_comes_back_after_thirty_seconds_of_answers(self):
        self.up["10.0.0.5"] = False
        self.ticks(3)
        self.up["10.0.0.5"] = True
        self.assertEqual(self.ticks(5), [])
        switches = self.ticks(1)
        self.assertEqual([(old, new) for _, old, new, _ in switches], [("backup", "primary")])
        self.assertEqual(self.written(), {})
        self.assertIn(["conntrack", "-D", "-p", "udp", "--reply-src", "10.0.0.6"], self.commands)
        self.assertFalse(self.alerts.observe.call_args.kwargs["active"])

    def test_a_main_backend_answering_one_check_in_two_does_not_bring_it_back(self):
        self.up["10.0.0.5"] = False
        self.ticks(3)
        for _ in range(10):
            self.up["10.0.0.5"] = not self.up["10.0.0.5"]
            self.ticks(1)
        self.assertEqual(self.written(), {"voip": "backup"})

    def test_a_backup_that_dies_too_hands_back_to_an_answering_main_at_once(self):
        self.up["10.0.0.5"] = False
        self.ticks(3)
        self.up = {"10.0.0.5": True, "10.0.0.6": False}
        self.assertEqual([(old, new) for _, old, new, _ in self.ticks(1)], [("backup", "primary")])

    def test_a_forward_whose_backup_is_removed_is_forgotten(self):
        self.up["10.0.0.5"] = False
        self.ticks(3)
        self.target = None
        self.failover.load_targets.side_effect = lambda: []
        self.ticks(1)
        self.assertEqual(self.written(), {})
        self.assertEqual(self.failover.public_state()["forwards"], {})
        self.assertFalse(self.alerts.observe.call_args.kwargs["active"])

    def test_a_restart_of_controld_rewrites_a_stale_file(self):
        self.state_file.write_text('{"version": 1, "active": {"voip": "backup"}}')
        self.ticks(1)  # a fresh controld starts on the main backend
        self.assertEqual(self.written(), {})

    def test_the_panel_sees_the_state(self):
        self.up["10.0.0.5"] = False
        self.ticks(3)
        state = self.failover.public_state()["forwards"]["voip"]
        self.assertEqual((state["active"], state["primary_ok"], state["backup_ok"]), ("backup", False, True))

    def test_a_failing_apply_is_said_and_retried_with_the_file_in_place(self):
        self.up["10.0.0.5"] = False

        def refuse(args, **kw):
            if args[:2] == ["systemctl", "restart"]:
                raise RuntimeError("unit failed")
            self.commands.append(args)

        controld.run_cmd.side_effect = refuse
        self.ticks(3)
        self.assertIn("could not be applied", self.failover.public_state()["error"])


class Checking(unittest.TestCase):
    def test_a_tcp_check_connects_and_a_ping_check_pings(self):
        with mock.patch.object(controld.socket, "create_connection") as connect:
            connect.return_value.__enter__ = lambda self: self
            connect.return_value.__exit__ = lambda self, *a: False
            self.assertTrue(controld.UdpFailover.probe("10.0.0.5", "tcp", 5061))
            connect.assert_called_once_with(("10.0.0.5", 5061), timeout=2)
            connect.side_effect = OSError("refused")
            self.assertFalse(controld.UdpFailover.probe("10.0.0.5", "tcp", 5061))
        with mock.patch.object(controld, "run_cmd") as run:
            self.assertTrue(controld.UdpFailover.probe("10.0.0.5", "ping", None))
            self.assertEqual(run.call_args.args[0][:1], ["ping"])
            self.assertEqual(run.call_args.args[0][-1], "10.0.0.5")
            run.side_effect = RuntimeError("100% packet loss")
            self.assertFalse(controld.UdpFailover.probe("10.0.0.5", "ping", None))
        self.assertFalse(controld.UdpFailover.probe(None, "ping", None))

    def test_the_loop_is_started_and_the_tools_are_installed(self):
        source = (ROOT / "ansible/roles/haproxy-admin/files/haproxy-controld.py").read_text(encoding="utf-8")
        self.assertIn('threading.Thread(target=udp_failover_loop, daemon=True, name="udp-failover-loop").start()', source)
        self.assertIn('"failover": UDP_FAILOVER.public_state()', source)
        tasks = (ROOT / "ansible/roles/haproxy-admin/tasks/iptables-udp.yml").read_text(encoding="utf-8")
        for package in ("iputils-ping", "conntrack"):
            self.assertIn(f"      - {package}", tasks)


@unittest.skipIf(sys.platform == "win32", "the admin package needs fcntl")
class ThePanel(unittest.TestCase):
    def normalize(self, **more):
        sys.path.insert(0, str(ROOT / "docker" / "app"))
        from haproxy_admin import services_haproxy_udp as service

        return service._normalize_udp_entry(forward(**more))

    def test_a_backup_is_saved_with_its_check(self):
        ok, message, entry = self.normalize(backup_host="10.0.0.6", health_check="tcp", health_port="5061")
        self.assertTrue(ok, message)
        self.assertEqual((entry["backup_host"], entry["health_check"], entry["health_port"]), ("10.0.0.6", "tcp", 5061))
        self.assertNotIn("backup_port", entry)

    def test_without_a_backup_nothing_of_it_is_written(self):
        ok, _message, entry = self.normalize(backup_host="", health_check="ping")
        self.assertTrue(ok)
        for field in ("backup_host", "backup_port", "health_check", "health_port"):
            self.assertNotIn(field, entry)

    def test_bad_input_is_refused_with_a_reason(self):
        for bad, words in (({"backup_host": "10.0.0.5"}, "different"), ({"backup_host": "localhost"}, "loopback"),
                           ({"backup_host": "10.0.0.6", "health_check": "tcp"}, "health_port"),
                           ({"backup_port": "7060"}, "needs a backup_host"),
                           ({"backup_host": "10.0.0.6", "backup_port": "7060-7062"}, "as many ports")):
            with self.subTest(bad=bad):
                ok, message, _entry = self.normalize(**bad)
                self.assertFalse(ok)
                self.assertIn(words, message)

    def test_the_form_has_the_fields_and_its_sentences_are_translated(self):
        page = (APP / "templates/haproxy_udp.html").read_text(encoding="utf-8")
        for field in ('name="backup_host"', 'name="backup_port"', 'name="health_check"', 'name="health_port"'):
            self.assertIn(field, page)
        catalogue = {}
        for path in list((APP / "translations/ru").glob("*.json")) + [APP / "translations/ru.json"]:
            data = json.loads(path.read_text(encoding="utf-8"))
            catalogue.update(data.get("messages", data))
        for sentence in ("Backup backend", "How the main backend is checked", "Connection to a TCP port",
                         "Traffic goes to the backup: the main backend does not answer",
                         "A UDP forward runs on its backup backend"):
            self.assertIn(sentence, catalogue)
        route = (APP / "routes_haproxy_udp.py").read_text(encoding="utf-8")
        self.assertIn('"backup_host": (request.form.get("backup_host") or "").strip(),', route)


if __name__ == "__main__":
    unittest.main()
