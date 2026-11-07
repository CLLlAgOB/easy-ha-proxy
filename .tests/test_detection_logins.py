"""Login correlations are warnings from existing failures, never account locks."""
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_guardd import EngineTestCase, guardd  # noqa: E402


class LoginWarnings(EngineTestCase):
    def setUp(self):
        super().setUp()
        self.path = Path(self.directory.name) / "authelia.log"
        self.path.write_text("", encoding="utf-8")
        self.correlation = guardd.LoginCorrelations(str(self.path), self.engine.detection, self.database)
        self.now = int(time.time())

    def failure(self, ip="203.0.113.9", username="operator", **extra):
        return json.dumps({"method": "POST", "path": "/api/firstfactor", "remote_ip": ip,
                           "msg": f"Unsuccessful 1FA authentication attempt by user '{username}'",
                           "time": datetime.fromtimestamp(self.now, timezone.utc).isoformat(), **extra})

    def test_one_ip_many_users_is_a_warning(self):
        for n in range(10):
            self.correlation.observe(self.failure(username=f"user{n}"), self.now, self.engine.exclusions)
        stats = self.engine.detection.summary()["stats"]
        self.assertEqual(stats[0]["id"], "auth:credential-spray")
        self.assertEqual(stats[0]["observe"], 1)
        self.assertFalse(self.events())

    def test_many_ips_one_user_is_a_warning_without_storing_username(self):
        for n in range(10):
            self.correlation.observe(self.failure(ip=f"203.0.113.{n + 1}", username="private-login-name"), self.now, self.engine.exclusions)
        self.assertTrue(any(r["id"] == "auth:distributed-login" for r in self.engine.detection.summary()["stats"]))
        self.correlation.persist(self.now)
        self.assertNotIn("private-login-name", self.database.get_state(self.correlation.KEY, ""))
        self.assertFalse(self.events())

    def test_empty_username_cannot_be_invented_but_burst_is_visible(self):
        for _ in range(20):
            self.correlation.observe(self.failure(username=""), self.now, self.engine.exclusions)
        self.assertEqual([r["id"] for r in self.engine.detection.summary()["stats"]], ["auth:failed-login-burst"])

    def test_mfa_successes_and_detail_lines_are_not_failed_first_factors(self):
        for _ in range(30):
            for line in (self.failure(msg="Successful 1FA authentication"),
                         self.failure(msg="Error occurred getting details for user 'operator'"),
                         self.failure(path="/api/secondfactor/totp"),
                         self.failure(remote_ip="not-an-ip"), "malformed JSON"):
                self.correlation.observe(line, self.now, self.engine.exclusions)
        self.assertFalse(self.engine.detection.summary()["stats"])

    def test_trusted_failures_stay_unscored(self):
        for n in range(20):
            self.correlation.observe(self.failure(ip="198.51.100.7", username=f"u{n}"), self.now, self.engine.exclusions)
        self.assertTrue(all(r["enforce"] == 0 and r["trusted"] > 0 for r in self.engine.detection.summary()["stats"]))
        self.assertFalse(self.events())
        with self.assertRaises(ValueError):
            guardd.validate_detection_config({"version": 1, "modes": {"auth:credential-spray": "enforce"}})

    def test_old_logs_do_not_raise_new_warnings(self):
        for n in range(20):
            self.correlation.observe(self.failure(username=f"u{n}"), self.now + 901, self.engine.exclusions)
        self.assertFalse(self.correlation.entries)

    def test_normal_restart_does_not_replay_log_lines(self):
        self.correlation.poll(self.now, self.engine.exclusions)  # starts at end
        self.path.write_text("\n".join(self.failure(username=f"u{n}") for n in range(9)) + "\n", encoding="utf-8")
        self.correlation.poll(self.now, self.engine.exclusions)
        self.correlation.persist(self.now)
        again = guardd.LoginCorrelations(str(self.path), self.engine.detection, self.database)
        again.poll(self.now, self.engine.exclusions)
        self.assertFalse(self.engine.detection.summary()["stats"])
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(self.failure(username="u9") + "\n")
        again.poll(self.now, self.engine.exclusions)
        self.assertTrue(self.engine.detection.summary()["stats"])

    def test_corrupt_saved_correlation_is_ignored(self):
        for value in ("[]", '{"cursor": []}', '{"entries": [["ip:bad", [[1, 3, [-1]]]]]}'):
            self.database.set_state(self.correlation.KEY, value)
            again = guardd.LoginCorrelations(str(self.path), self.engine.detection, self.database)
            self.assertFalse(again.entries)
