"""After a restart, the rest of the chosen history is read back in the
background (08).

The latest requests in memory are refilled from the tail of the access log
when guardd starts -- at most 16 MiB of it, a few seconds to parse. With a
memory budget of many hours (07) everything older than that was lost on
every update. The rest is now read back a piece at a time in the background,
older pieces on the left as the first one went, until the horizon (a day
with a budget, the profile's hour without), the start of the file, a full
buffer, or a rotation. Whole lines only, nothing twice.
"""

from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".tests"))

from test_live_activity import guardd, line  # noqa: E402

MIB = guardd.MIB


class ReadingBack(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.log = root / "haproxy.log"
        self.config = guardd.GuardConfig(log_file=str(self.log), whitelist_files=())
        self.database = guardd.SecurityDatabase(str(root / "security.db"))
        self.addCleanup(self.database.close)
        self.now = time.time()
        # Small pieces, so a few hundred lines make many of them.
        for name, value in (("LIVE_REFILL_BYTES", 3000), ("LIVE_REFILL_CHUNK_BYTES", 1700)):
            patcher = mock.patch.object(guardd, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def write(self, ages):
        with self.log.open("w", encoding="utf-8") as handle:
            for index, age in enumerate(ages):
                handle.write(line("203.0.113.9", 200, at=self.now - age,
                                  request=f"GET /p{index} HTTP/1.1") + "\n")

    def engine(self, budget_mib=0):
        engine = guardd.GuardEngine(self.config, self.database)
        if budget_mib:
            engine.live.set_budget(budget_mib * MIB)
        engine._stop.wait = lambda seconds: False  # no pauses in a test
        return engine

    def paths(self, engine):
        return [r[guardd.L_PATH] for r in engine.live._records]

    def test_with_a_budget_a_day_comes_back_in_order_and_once(self):
        ages = [20 * 3600 - i * 120 for i in range(600)]  # 20 hours, oldest first
        self.write(ages)
        engine = self.engine(budget_mib=64)
        first = engine.refill_live(self.now)
        self.assertLess(first, 600)
        self.assertIsNotNone(engine._refill_resume)
        engine.continue_refill()
        self.assertEqual(self.paths(engine), [f"/p{i}" for i in range(600)])
        self.assertIsNone(engine._refill_resume)
        # The live page knows the buffer reaches back that far now.
        self.assertLessEqual(engine.live.started, self.now - 20 * 3600 + 1)

    def test_without_a_budget_it_stops_at_the_profiles_hour(self):
        # Three hours, none exactly on the hour: the boundary is a microsecond.
        ages = [3 * 3600 - i * 30 - 15 for i in range(360)]
        self.write(ages)
        engine = self.engine()
        engine.refill_live(self.now)
        engine.continue_refill()
        times = [r[guardd.L_TS] for r in engine.live._records]
        self.assertGreaterEqual(min(times), self.now - 3600 - 1)
        expected = [f"/p{i}" for i, age in enumerate(ages) if age <= 3600]
        self.assertEqual(self.paths(engine), expected)

    def test_a_full_buffer_stops_it(self):
        self.write([20 * 3600 - i * 120 for i in range(600)])
        engine = self.engine(budget_mib=64)
        engine.refill_live(self.now)
        engine.live.set_budget(16 * 1024)  # the budget is already met
        engine.live.max_bytes = engine.live.status()["bytes"]
        before = engine.live.status()["records"]
        self.assertEqual(engine.continue_refill(), 0)
        self.assertEqual(engine.live.status()["records"], before)

    def test_a_rotated_log_stops_it(self):
        self.write([20 * 3600 - i * 120 for i in range(600)])
        engine = self.engine(budget_mib=64)
        engine.refill_live(self.now)
        inode, offset, horizon = engine._refill_resume
        engine._refill_resume = (inode + 1, offset, horizon)
        self.assertEqual(engine.continue_refill(), 0)

    def test_a_stop_stops_it(self):
        self.write([20 * 3600 - i * 120 for i in range(600)])
        engine = self.engine(budget_mib=64)
        engine.refill_live(self.now)
        engine._stop.set()
        self.assertEqual(engine.continue_refill(), 0)

    def test_nothing_to_do_when_the_tail_reached_back(self):
        self.write([600, 300, 60])
        engine = self.engine(budget_mib=64)
        self.assertEqual(engine.refill_live(self.now), 3)
        self.assertIsNone(engine._refill_resume)
        self.assertEqual(engine.continue_refill(), 0)

    def test_the_collector_starts_it_in_the_background(self):
        source = (ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py").read_text(encoding="utf-8")
        run = source.split("    def _run(self) -> None:")[1].split("while not self._stop.is_set()")[0]
        self.assertIn('name="guardd-refill"', run)
        self.assertIn("daemon=True", run)
        loop = source.split("    def continue_refill(self) -> int:")[1].split("\n    def ")[0]
        # Pauses as long as each piece took: the collector and HAProxy first.
        self.assertIn("self._stop.wait(max(0.05, time.monotonic() - started))", loop)


if __name__ == "__main__":
    unittest.main()
