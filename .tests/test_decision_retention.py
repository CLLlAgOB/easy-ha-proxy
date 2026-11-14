"""Ban decisions: kept while they matter, said when they cannot be written,
and carried by the disaster-recovery backup (06.7).

- The sweep dropped the oldest decisions beyond 20 000 rows whatever they
  were, so a wave of bans could cost a ban still in force its reason. A
  decision whose ban has not ended is now never swept.
- A cycle that cannot write -- a full disk, a damaged database -- scores
  nothing, bans nothing and records no decision; it said so only in the
  service journal. It is now an alert (security.engine_failing) while it
  lasts, cleared once when the engine works again.
- The full backup archives the engine's database with the decisions, and
  leaves out the request log; a copy unpacked from a real archive opens
  with every reason intact.
"""

from __future__ import annotations

from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".tests"))
sys.path.insert(0, str(ROOT / "installer"))

import full_backup  # noqa: E402
import test_guardd as base  # noqa: E402

guardd = base.guardd
IP = "203.0.113.9"
NOW = 2_000_000_000


class TheSweep(base.EngineTestCase):
    def decisions(self, ip=IP):
        return self.database.ban_decisions(ip, limit=100)

    def test_a_ban_still_in_force_keeps_its_reason_past_the_age_limit(self):
        self.database.record_decision(IP, NOW - 90 * 86400, "applied", "operator", "applied",
                                      code=50, until=NOW + 86400, reason={"note": "long ban"})
        self.database.record_decision(IP, NOW - 90 * 86400, "lifted", "expiry", "applied", code=40)
        self.database.prune_decisions(before=NOW - 30 * 86400, keep=1000, now=NOW)
        [kept] = self.decisions()
        self.assertEqual((kept["action"], kept["reason"]), ("applied", {"note": "long ban"}))

    def test_and_past_the_row_limit(self):
        for index in range(5):
            self.database.record_decision(f"198.51.100.{index}", NOW - 100 + index, "applied",
                                          "adaptive", "applied", code=40, until=NOW + 3600)
        for index in range(20):
            self.database.record_decision(IP, NOW - 50 + index, "lifted", "expiry", "applied", code=40)
        self.database.prune_decisions(before=0, keep=3, now=NOW)
        standing = [self.database.ban_decisions(f"198.51.100.{i}", limit=5) for i in range(5)]
        self.assertTrue(all(len(rows) == 1 for rows in standing))
        # The ended ones still go, newest kept up to the limit.
        self.assertEqual(len(self.decisions()), 3)

    def test_an_ended_ban_goes_as_before(self):
        self.database.record_decision(IP, NOW - 90 * 86400, "applied", "adaptive", "applied",
                                      code=40, until=NOW - 89 * 86400)
        self.database.prune_decisions(before=NOW - 30 * 86400, keep=1000, now=NOW)
        self.assertEqual(self.decisions(), [])

    def test_the_maintenance_pass_says_what_now_is(self):
        source = (ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py").read_text(encoding="utf-8")
        block = source.split("    def run_maintenance(self)")[1].split("    def ")[0]
        self.assertIn("keep=DECISIONS_KEEP_ROWS, now=now", block)


class TheAlert(base.EngineTestCase):
    def setUp(self):
        super().setUp()
        self.engine.alerts = mock.Mock()

    def failing(self, cycles, error="database or disk is full"):
        self.engine.consecutive_failures = cycles
        self.engine.last_error = error
        self.engine.report_failing()

    def test_a_hiccup_is_not_an_alert(self):
        self.failing(guardd.ENGINE_FAILING_AFTER - 1)
        self.engine.alerts.observe.assert_not_called()
        self.engine.alerts.clear.assert_not_called()

    def test_failing_again_and_again_is_raised_with_the_error(self):
        self.failing(guardd.ENGINE_FAILING_AFTER)
        rule, subject = self.engine.alerts.observe.call_args.args
        kwargs = self.engine.alerts.observe.call_args.kwargs
        self.assertEqual((rule, subject, kwargs["active"]), ("security.engine_failing", "guardd", True))
        self.assertIn("database or disk is full", kwargs["summary"])
        self.assertIn("full disk", kwargs["detail"])

    def test_the_summary_does_not_change_every_cycle(self):
        # An unchanged report is sent again only every two minutes.
        self.failing(guardd.ENGINE_FAILING_AFTER)
        first = self.engine.alerts.observe.call_args.kwargs["summary"]
        self.failing(guardd.ENGINE_FAILING_AFTER + 7)
        self.assertEqual(self.engine.alerts.observe.call_args.kwargs["summary"], first)

    def test_it_is_cleared_once_when_the_engine_works_again(self):
        self.failing(guardd.ENGINE_FAILING_AFTER)
        self.failing(0, error=None)
        self.failing(0, error=None)
        self.engine.alerts.clear.assert_called_once()
        self.assertEqual(self.engine.alerts.clear.call_args.args, ("security.engine_failing", "guardd"))

    def test_an_alert_daemon_that_fails_costs_nothing(self):
        self.engine.alerts.observe.side_effect = OSError("alertd is down")
        self.failing(guardd.ENGINE_FAILING_AFTER)  # does not raise

    def test_every_cycle_reports(self):
        source = (ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py").read_text(encoding="utf-8")
        loop = source.split("    def _run(self) -> None:")[1].split("    def poll(self)")[0]
        self.assertLess(loop.index("self.poll()"), loop.index("self.report_failing()"))
        self.assertLess(loop.index("self.report_failing()"), loop.index("run_maintenance"))


@unittest.skipUnless(shutil.which("tar"), "tar is not installed")
class TheBackup(unittest.TestCase):
    def test_the_archive_carries_the_decisions_and_not_the_request_log(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "gateway"
            state = root / "var/lib/easy-ha-proxy"
            (state / "security").mkdir(parents=True)
            (state / "requests").mkdir(parents=True)
            database = guardd.SecurityDatabase(str(state / "security/security.db"))
            database.record_decision(IP, NOW, "applied", "adaptive", "applied", code=40,
                                     until=NOW + 3600, strike=2, score=95,
                                     reason={"evidence": [{"event_type": "SCANNER_PATH", "points": 60}]})
            database.close()
            (state / "security/ban-policy-u02-1.json").write_text('{"entries": {}}', encoding="utf-8")
            (state / "requests/requests.db").write_bytes(b"every visitor's path")

            # The archive the backup makes, with its own excludes.
            payload = Path(temporary) / "payload.tar.gz"
            full_backup.create_payload(payload, [str(state)])

            copy = Path(temporary) / "copy"
            copy.mkdir()
            with tarfile.open(payload, "r:gz") as archive:
                names = archive.getnames()
                safe = {"filter": "data"} if hasattr(tarfile, "data_filter") else {}
                archive.extractall(copy, **safe)  # noqa: S202 -- our own archive
            self.assertFalse([name for name in names if "/var/lib/easy-ha-proxy/requests" in "/" + name])
            restored_root = copy / str(state).lstrip("/")
            self.assertTrue((restored_root / "security/ban-policy-u02-1.json").exists())

            restored = guardd.SecurityDatabase(str(restored_root / "security/security.db"))
            try:
                [decision] = restored.ban_decisions(IP, limit=5)
            finally:
                restored.close()
            self.assertEqual((decision["strike"], decision["score"], decision["until"]), (2, 95, NOW + 3600))
            self.assertEqual(decision["reason"]["evidence"][0]["event_type"], "SCANNER_PATH")

    def test_the_engine_is_stopped_while_its_database_is_copied(self):
        self.assertIn("easy-ha-proxy-guardd.service", full_backup.QUIESCE_UNITS)
        self.assertIn("/var/lib/easy-ha-proxy", full_backup.CORE_PATHS)
        self.assertIn("var/lib/easy-ha-proxy/requests", full_backup.BACKUP_EXCLUDES)


if __name__ == "__main__":
    unittest.main()
