"""A decisive scanner is checked even behind thousands of noisy addresses.

On one gateway, 383 addresses competed for 200 places ordered by event count.
Two decisive findings already warranted a ban, but both reported scanners
waited for more zero-point findings before the executor would consider them.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_guardd import EnforcementTestCase, guardd  # noqa: E402

NOW = 1_000_000
IP = "203.0.113.250"


class PendingChecks(unittest.TestCase):
    def test_repetition_coalesces_and_promotes_without_growing_memory(self):
        queue = guardd.EnforcementQueue(3)
        for _ in range(10000):
            queue.mark(IP, urgent=False)
        queue.mark(IP, urgent=True)
        self.assertEqual(queue.status()["urgent"], 1)
        self.assertEqual(queue.status()["ordinary"], 0)
        self.assertEqual(len(queue.batch(100)), 1)

    def test_acknowledging_an_old_check_keeps_the_new_finding(self):
        queue = guardd.EnforcementQueue(3)
        queue.mark(IP, urgent=False)
        old = queue.batch(1)[0]
        queue.mark(IP, urgent=True)
        queue.acknowledge(*old)
        self.assertEqual(queue.status()["urgent"], 1)
        queue.acknowledge(*queue.batch(1)[0])
        self.assertEqual(queue.batch(1), [])

    def test_ordinary_work_keeps_a_share_under_an_urgent_flood(self):
        queue = guardd.EnforcementQueue(100)
        for i in range(80):
            queue.mark(f"urgent-{i}", urgent=True)
        for i in range(10):
            queue.mark(f"ordinary-{i}", urgent=False)
        batch = queue.batch(20)
        self.assertEqual(sum(ip.startswith("ordinary-") for ip, _ in batch), 5)
        self.assertEqual(len(batch), 20)

    def test_overflow_is_bounded_and_a_decisive_finding_displaces_ordinary_work(self):
        queue = guardd.EnforcementQueue(3)
        for i in range(10000):
            queue.mark(f"ordinary-{i}", urgent=False)
        queue.mark(IP, urgent=True)
        self.assertIn(IP, dict(queue.batch(3)))
        self.assertEqual(len(queue.batch(10000)), 3)
        self.assertEqual(queue.status()["overflows"], 9998)


class CandidateSelection(EnforcementTestCase):
    def setUp(self):
        super().setUp()
        self.engine.enforcer.mode = guardd.MODE_ENFORCE
        self.engine.exclusions.reload_files(force=True)
        quiet = mock.patch.object(guardd.LOG, "warning")
        quiet.start()
        self.addCleanup(quiet.stop)

    def quiet_history(self, count=500):
        """Noisy zero-point history, inserted as one fixture transaction."""
        ips = [str(ipaddress.IPv4Address(0x0A000001 + n)) for n in range(count)]
        with self.database._lock, self.database._conn:
            self.database._conn.executemany(
                "INSERT INTO ip_state (ip, family, enforceable, first_seen, last_seen) VALUES (?, 4, 1, ?, ?)",
                ((ip, NOW, NOW) for ip in ips),
            )
            self.database._conn.executemany(
                "INSERT INTO security_events (ts, ip, event_type, source, category, handled) "
                "VALUES (?, ?, ?, 'haproxy-log', 'wordpress', 1)",
                ((NOW, ip, guardd.EVENT_SCANNER_PATH) for ip in ips for _ in range(5)),
            )

    def finding(self, ip=IP, now=NOW):
        self.engine._emit(ip, guardd.EVENT_SCANNER_DECISIVE, now,
                          source="haproxy-log", category="secrets", detail="/.env", handled=True)

    def test_one_decisive_finding_is_banned_in_the_next_cycle_beyond_the_old_top_200(self):
        self.quiet_history(1000)
        self.finding()
        self.assertNotIn(IP, self.database.active_addresses(NOW - 86400, limit=200))
        with mock.patch.object(self.database, "active_addresses", side_effect=AssertionError("UI selection")), \
                mock.patch.object(self.engine, "reputation", wraps=self.engine.reputation) as checked:
            result = self.engine.apply_enforcement(NOW)
        self.assertIn(IP, result["applied"])
        self.assertLessEqual(checked.call_count, guardd.ENFORCEMENT_BATCH)
        # A first step, answered with a page (P7).
        self.assertEqual(self.table[IP]["gpt0"], str(guardd.ADAPTIVE_PAGE_CODE))

    def test_a_large_batch_drains_without_losing_the_tail_or_exceeding_the_budget(self):
        ips = [str(ipaddress.IPv4Address(0xCB007100 + i)) for i in range(450)]
        for ip in ips:
            self.finding(ip)
        applied = set()
        for _ in range(4):
            with mock.patch.object(self.engine, "reputation", wraps=self.engine.reputation) as checked:
                result = self.engine.apply_enforcement(NOW)
            self.assertLessEqual(checked.call_count, guardd.ENFORCEMENT_BATCH)
            applied.update(result["applied"])
        self.assertEqual(applied, set(ips))
        self.assertEqual(self.engine.enforcement_queue.batch(1000), [])

    def test_the_sweep_progresses_even_while_fresh_urgent_work_keeps_arriving(self):
        self.quiet_history(400)
        self.make_hostile(IP, NOW)  # older evidence, absent from the fresh queue
        for cycle in range(10):
            now = NOW + (cycle + 1) * 10
            for i in range(160):
                self.finding(str(ipaddress.IPv4Address(0xC0000200 + cycle * 160 + i)), now=now)
            self.engine.apply_enforcement(now)
            if IP in self.table:
                break
        self.assertIn(IP, self.table)

    def test_overflow_does_not_lose_evidence_and_the_sweep_eventually_bans_it(self):
        self.quiet_history(500)
        self.engine.enforcement_queue = guardd.EnforcementQueue(2)
        for ip in ("198.51.100.10", "198.51.100.11", IP):
            self.finding(ip)
        self.assertNotIn(IP, dict(self.engine.enforcement_queue.batch(10)))
        self.assertEqual(self.engine.health()["enforcement_checks"]["overflows"], 1)
        for _ in range(4):
            self.engine.apply_enforcement(NOW)
        self.assertIn(IP, self.table)

    def test_a_restart_recovers_recent_decisive_findings(self):
        self.quiet_history(1000)
        self.finding()
        with mock.patch.object(guardd, "_utc_now", return_value=NOW):
            self.engine = guardd.GuardEngine(self.config, self.database)
        self.engine.enforcer.mode = guardd.MODE_ENFORCE
        self.assertIn(IP, self.engine.apply_enforcement(NOW)["applied"])

    def test_the_sweep_resumes_across_restarts_even_beyond_the_recovery_tail(self):
        self.make_hostile(IP, NOW)
        self.quiet_history(500)  # pushes the finding beyond the bounded tail
        for _ in range(3):
            with mock.patch.object(guardd, "_utc_now", return_value=NOW):
                self.engine = guardd.GuardEngine(self.config, self.database)
            self.engine.enforcer.mode = guardd.MODE_ENFORCE
            self.engine.apply_enforcement(NOW)
        self.assertIn(IP, self.table)

    def test_a_temporary_write_failure_keeps_the_address_pending(self):
        self.quiet_history(500)
        self.finding()
        with mock.patch.object(self.engine.enforcer, "ban", return_value=False):
            self.assertNotIn(IP, self.engine.apply_enforcement(NOW)["applied"])
        self.assertIn(IP, dict(self.engine.enforcement_queue.batch(10)))
        self.assertIn(IP, self.engine.apply_enforcement(NOW)["applied"])

    def test_a_scoring_exception_does_not_acknowledge_or_skip_the_failed_check(self):
        self.finding()
        with mock.patch.object(self.engine, "reputation", side_effect=RuntimeError("read failed")):
            with self.assertRaises(RuntimeError):
                self.engine.apply_enforcement(NOW)
        self.assertIn(IP, dict(self.engine.enforcement_queue.batch(10)))
        self.assertIn(IP, self.engine.apply_enforcement(NOW)["applied"])

    def test_global_whitelist_and_current_auth_still_override_a_queued_finding(self):
        for ip in ("198.51.100.7", IP):
            self.finding(ip)
        self.engine.exclusions.refresh_authenticated({IP: {"gpc0": "1"}})
        result = self.engine.apply_enforcement(NOW)
        self.assertEqual(result["applied"], [])
        self.assertEqual(self.table, {})

    def test_monitor_keeps_work_and_enabling_enforcement_checks_it(self):
        self.finding()
        self.engine.enforcer.mode = guardd.MODE_MONITOR
        self.assertEqual(self.engine.apply_enforcement(NOW)["applied"], [])
        self.assertIn(IP, dict(self.engine.enforcement_queue.batch(10)))
        self.assertIn(IP, self.engine.set_mode(guardd.MODE_ENFORCE, NOW)["applied"])


if __name__ == "__main__":
    unittest.main()
