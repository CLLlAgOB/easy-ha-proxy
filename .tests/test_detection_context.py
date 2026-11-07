"""Context, privacy and bounded observations must not weaken trust boundaries."""
import json
import sqlite3
from pathlib import Path
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_guardd import EngineTestCase, guardd  # noqa: E402


def request(path="/.env", host="app.example.test", method="GET", status=404, ip="203.0.113.9"):
    return guardd.ParsedRequest(ip, status, "fe_https", "be_app/srv1", method,
                               guardd.normalize_path(path), host, query_flag=guardd.classify_query(path),
                               path_flag=guardd.classify_raw_path(path), observation_flags=guardd.observation_flags(path))


def settings(**values):
    return {"version": 1, "rules": [], "exceptions": [], "modes": {}, "profiles": {}, **values}


def rule(**values):
    return {"id": "custom:docker-probe", "hosts": ["app.example.test"], "methods": ["GET"],
            "match": "prefix", "value": "/containers", "category": "custom", "mode": "observe", **values}


class ContextRules(EngineTestCase):
    def test_preview_is_pure_and_never_persists_the_query(self):
        before = self.engine.detection.summary()
        payload = self.engine.detection.preview({"host": "app.example.test", "url": "/.env?token=NEVER-STORE"}, self.engine.exclusions, 1000)
        self.assertEqual(payload["matches"][0]["id"], "path:secrets")
        self.assertEqual(payload["nominal_points"], 60)
        self.assertNotIn("NEVER-STORE", json.dumps(payload))
        self.assertEqual(before, self.engine.detection.summary())
        self.assertEqual(self.events(), [])

    def test_host_method_and_route_boundaries(self):
        self.engine.detection.replace(settings(rules=[rule()]))
        context = self.engine.detection
        self.assertEqual(context.inspect(request("/containers/1/json"), 100)[0]["action"], "observe")
        for req in (request("/containers-copy"), request("/containers", method="POST"), request("/containers", host="other.example.test")):
            self.assertFalse(context.inspect(req, 100))

    def test_exception_only_applies_to_one_rule_site_method_and_route(self):
        exception = {"id": "exception:app", "rule": "path:secrets", "hosts": ["app.example.test"],
                     "methods": ["GET"], "match": "exact", "value": "/assets/.env.config.js",
                     "reason": "Public build metadata", "expires": 2000}
        self.engine.detection.replace(settings(exceptions=[exception]))
        self.engine.observe_request(request("/assets/.env.config.js"), 1000)
        self.assertEqual(self.events(), [])
        self.engine.observe_request(request("/assets/.env.config.js", method="POST"), 1001)
        self.assertTrue(self.events())
        self.assertEqual(self.engine.detection.inspect(request("/assets/.env.config.js"), 2001)[0]["action"], "enforce")
        self.assertEqual(self.engine.detection.inspect(request("/assets/.env.config.js", host="b.example.test"), 1000)[0]["action"], "enforce")

    def test_observation_never_backfills_a_score(self):
        self.engine.detection.replace(settings(modes={"path:secrets": "observe"}))
        self.engine.observe_request(request(), 1000)
        self.assertFalse(self.events())
        self.engine.detection.replace(settings(revision=1))
        self.assertFalse(self.events())
        self.engine.observe_request(request(), 1001)
        self.assertEqual(len(self.events()), 1)

    def test_custom_rule_enforcement_requires_explicit_mode(self):
        self.engine.detection.replace(settings(rules=[rule()]))
        self.engine.observe_request(request("/containers/abc/json"), 1000)
        self.assertFalse(self.events())
        self.engine.detection.replace(settings(revision=1, rules=[rule(mode="enforce")]))
        self.engine.observe_request(request("/containers/abc/json"), 1001)
        self.assertTrue(any(e["category"] == "custom" for e in self.events()))

    def test_trusted_findings_are_separate_and_never_replayed(self):
        trusted = request(ip="198.51.100.7")
        self.engine.observe_request(trusted, 1000)
        self.assertFalse(self.events())
        self.assertIsNone(self.engine.memory.get(trusted.client_ip))
        stats = self.engine.detection.summary()["stats"]
        self.assertEqual(stats[0]["trusted"], 1)
        self.assertEqual(stats[0]["enforce"], 0)
        self.engine.detection.persist(1000, force=True)
        self.assertFalse(self.events())

    def test_new_injections_start_in_observation(self):
        for uri in ("/search?q=1%27+OR+1=1", "/api?q=%3Cscript%3Ealert(1)%3C/script%3E", "/%252eenv"):
            req = request(uri, status=200)
            with self.subTest(uri=uri):
                self.assertTrue(req.observation_flags)
                self.engine.observe_request(req, 1000)
        self.assertFalse(self.events())
        self.assertTrue(self.engine.detection.summary()["stats"])

    def test_expected_clients_do_not_trigger_new_injections(self):
        for uri in ("/search?q=how+to+use+curl", "/api?filter=union+of+sets", "/e1cib?cmd=runApp&key=7", "/ocs/v2.php/cloud/users", "/remote.php/dav/files/alex/credentials"):
            self.assertFalse(guardd.observation_flags(uri))

    def test_versioned_service_routes_are_observed_without_scoring(self):
        for uri in ("/v1.47/containers/json", "/v1.47/containers/abcdef/json", "/latest/meta-data/iam/security-credentials/role", "/computeMetadata/v1/instance/service-accounts/default/token", "/actuator/heapdump"):
            self.assertIn("observe:service-api-probe", guardd.observation_flags(uri))
            self.engine.observe_request(request(uri, status=200), 1000)
        self.assertFalse(self.events())
        self.assertFalse(guardd.observation_flags("/v1.47/containers-copy"))

    def test_status_filters_and_user_agent_preview(self):
        context = self.engine.detection
        context.replace(settings(rules=[rule(statuses=[404, 410])]))
        self.assertFalse(context.inspect(request("/containers", status=200), 1000))
        self.assertTrue(context.inspect(request("/containers", status=404), 1000))
        data = context.preview({"host": "app.example.test", "url": "/", "user_agent": "sqlmap/1.9"}, self.engine.exclusions, 1000)
        self.assertTrue(any(row["id"].startswith("ua:") for row in data["matches"]))

    def test_config_and_aggregates_survive_restart_without_enforcing_history(self):
        now = int(time.time())
        self.engine.detection.replace(settings(rules=[rule()]))
        self.engine.observe_request(request("/containers/abc/json"), now)
        self.engine.detection.persist(now, force=True)
        again = guardd.DetectionContext(self.database)
        self.assertEqual(again.config["rules"][0]["mode"], "observe")
        self.assertEqual(again.summary()["stats"][0]["hits"], 1)
        self.assertFalse(self.events())

    def test_stale_editor_cannot_overwrite_a_newer_configuration(self):
        self.engine.detection.replace(settings())
        with self.assertRaises(ValueError):
            self.engine.detection.replace(settings())

    def test_exception_paths_are_case_sensitive(self):
        exception = {"id": "exception:app", "rule": "path:secrets", "hosts": ["app.example.test"],
                     "methods": ["GET"], "match": "exact", "value": "/Public/.env",
                     "reason": "Public metadata", "expires": 0}
        context = self.engine.detection
        context.replace(settings(exceptions=[exception]))
        self.assertEqual(context.inspect(request("/Public/.env"), 1000)[0]["action"], "excepted")
        self.assertEqual(context.inspect(request("/public/.env"), 1000)[0]["action"], "enforce")

    def test_dormant_shipped_rule_settings_survive_catalog_updates(self):
        context = self.engine.detection
        context.replace(settings(modes={"query:retired-rule": "observe"}))
        self.assertEqual(context.config["modes"]["query:retired-rule"], "observe")

    def test_bad_configuration_is_rejected_atomically(self):
        original = self.engine.detection.config
        bad = [settings(version=2), settings(rules=[rule(value="/")]),
               settings(rules=[rule(hosts=["*"])]), settings(rules=[rule(value="/x?token=secret")]),
               settings(rules=[rule(methods=["get"])]), settings(modes={"made-up": "enforce"}),
               settings(rules=[rule(), rule()]), settings(profiles={"app.example.test": "unknown"}),
               settings(profiles={"app.example.test": []}), settings(rules=[rule(category=[])]),
               settings(version=True), settings(modes={"auth:future-rule": "enforce"})]
        for data in bad:
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.engine.detection.replace(data)
        self.assertEqual(self.engine.detection.config, original)

    def test_corrupt_saved_settings_do_not_disable_existing_signatures(self):
        self.database.set_state(guardd.DETECTION_CONFIG_KEY, "not json")
        context = guardd.DetectionContext(self.database)
        self.assertEqual(context.inspect(request(), 1000)[0]["action"], "enforce")

    def test_malformed_saved_aggregates_do_not_stop_collection(self):
        now = int(time.time())
        self.database.set_state(guardd.DETECTION_STATS_KEY, json.dumps([{"id": "path:secrets", "first": now, "last": now, "ips": []}]))
        self.database.set_state(guardd.DETECTION_SLOW_KEY, json.dumps([[['203.0.113.9', 'app.example.test'], now,
                                                                    [[now // 1800, 30, 30, 0, [-1]]]]]))
        context = guardd.DetectionContext(self.database)
        self.assertEqual(context.state_errors, 2)
        context.inspect(request(), now)
        self.assertEqual(context.summary()["stats"][0]["hits"], 1)

    def test_narrow_exception_also_marks_a_trusted_false_positive(self):
        context = self.engine.detection
        exception = {"id": "exception:public", "rule": "path:secrets", "hosts": ["app.example.test"],
                     "methods": ["GET"], "match": "exact", "value": "/.env", "reason": "Public metadata"}
        context.replace(settings(exceptions=[exception]))
        matches = context.inspect(request(ip="198.51.100.7"), 1000, trusted=True)
        self.assertEqual(matches[0]["action"], "excepted")
        self.assertEqual(context.summary()["stats"][0]["trusted"], 0)

    def test_enforced_injection_uses_the_query_event_without_retaining_parameters(self):
        context = self.engine.detection
        context.replace(settings(modes={"observe:sql-injection": "enforce"}))
        req = request("/search?q=1%27+OR+1=1&token=do-not-store", status=200)
        self.engine.observe_request(req, 1000)
        self.assertTrue(any(e["event_type"] == guardd.EVENT_QUERY_INJECTION and e["category"] == "sql-injection" for e in self.events()))
        self.assertNotIn("do-not-store", repr(self.events()))

    def test_overlapping_rules_in_one_category_produce_one_scoring_finding(self):
        rules = [rule(id=f"custom:overlap-{n}", mode="enforce") for n in range(3)]
        self.engine.detection.replace(settings(rules=rules))
        self.engine.observe_request(request("/containers/json"), 1000)
        self.assertEqual(len([e for e in self.events() if e["category"] == "custom"]), 1)
        self.assertEqual(self.engine.memory.get("203.0.113.9").scanner_hits, 1)
        self.assertEqual(len(self.engine.detection.summary()["stats"]), 3)

    def test_preview_uses_policy_weights_without_changing_the_event_type(self):
        context = self.engine.detection
        policy = guardd.ScoringPolicy(weights={guardd.EVENT_SCANNER_DECISIVE: 12})
        result = context.preview({"host": "app.example.test", "url": "/.env"}, self.engine.exclusions, 1000, policy)
        self.assertEqual(result["nominal_points"], 12)
        self.assertEqual(result["matches"][0]["event_type"], guardd.EVENT_SCANNER_DECISIVE)

    def test_related_state_changes_roll_back_together(self):
        self.database.set_state(guardd.DETECTION_CONFIG_KEY, "before")
        with self.database._lock, self.database._conn:
            self.database._conn.execute("CREATE TRIGGER fail_slow BEFORE INSERT ON guard_state "
                                        "WHEN NEW.key = 'detection_slow_v1' "
                                        "BEGIN SELECT RAISE(ABORT, 'test abort'); END")
        with self.assertRaises(sqlite3.Error):
            self.database.set_states({guardd.DETECTION_CONFIG_KEY: "after", guardd.DETECTION_SLOW_KEY: "[]"})
        self.assertEqual(self.database.get_state(guardd.DETECTION_CONFIG_KEY), "before")


class SlowEnumeration(EngineTestCase):
    def scan(self, context, good=False, same=False, start=1_800_000):
        actions = []
        for n in range(240):
            req = request("/unknown" if same else f"/missing-{n}", status=200 if good else 404)
            actions.append(context.observe_slow(req, start + n * 120, False))
        return actions

    def test_eight_hour_unknown_scan_is_observed_without_scoring(self):
        self.assertIn("observe", self.scan(self.engine.detection))
        self.assertFalse(self.events())

    def test_repeated_missing_link_and_useful_traffic_are_not_slow_scans(self):
        self.assertFalse(any(self.scan(self.engine.detection, same=True)))
        self.engine.detection.slow.clear()
        self.assertFalse(any(self.scan(self.engine.detection, good=True)))

    def test_nat_and_identity_refusals(self):
        context = self.engine.detection
        for n in range(120):
            now = 1_800_000 + n * 120
            self.assertEqual(context.observe_slow(request(f"/missing-{n}"), now, True), "")
            context.observe_slow(request(f"/missing-{n}"), now, False)
            self.assertEqual(context.observe_slow(request("/dashboard", status=200), now, False), "")
        self.assertFalse(context.summary()["stats"])

    def test_bounded_churn_and_distinct_sets(self):
        context = self.engine.detection
        for n in range(1000):
            context.observe_slow(request(f"/x-{n}", host=f"h{n}.example.test"), 1000, False)
        self.assertEqual(len(context.slow), guardd.DETECTION_MAX_TRACKED)
        self.assertGreater(context.evictions, 0)
        for n in range(1000):
            context.observe_slow(request(f"/x-{n}"), 1000, False)
        self.assertLessEqual(max(len(b[3]) for e in context.slow.values() for b in e["buckets"].values()), 32)

    def test_persisted_windows_resume_and_expire(self):
        now = int(time.time())
        context = self.engine.detection
        for n in range(30):
            context.observe_slow(request(f"/missing-{n}"), now - 3600 + n * 120, False)
        context.persist(now, force=True)
        again = guardd.DetectionContext(self.database)
        self.assertTrue(again.slow)
        self.assertEqual(again.observe_slow(request("/another-missing"), now, False), "observe")
        again.persist(now + 8 * 3600, force=True)
        self.assertFalse(again.slow)

    def test_enabling_scoring_starts_a_fresh_window(self):
        context = self.engine.detection
        start = int(time.time()) - 8 * 3600
        self.assertIn("observe", self.scan(context, start=start))
        context.replace(settings(modes={"behavior:slow-enumeration": "enforce"}))
        self.assertFalse(context.slow)
        self.assertEqual(self.database.get_state(guardd.DETECTION_SLOW_KEY), "[]")
        self.assertEqual(context.observe_slow(request("/one-new-missing"), start + 8 * 3600, False), "")
        self.assertTrue(all(row["enforce"] == 0 for row in context.summary()["stats"]))

    def test_late_log_line_does_not_delete_a_newer_window(self):
        context = self.engine.detection
        start = 1_800_000
        for n in range(40):
            context.observe_slow(request(f"/missing-{n}"), start + n * 120, False)
        before = set(next(iter(context.slow.values()))["buckets"])
        context.observe_slow(request("/late-missing"), start + 10, False)
        self.assertEqual(set(next(iter(context.slow.values()))["buckets"]), before)


class CandidatesAreScoped(unittest.TestCase):
    def test_served_on_one_host_does_not_hide_another_host(self):
        candidates = guardd.PathCandidates()
        candidates.note("/control", "203.0.113.1", "legit.example.test", 200, True, True, 1000)
        for n in range(3):
            candidates.note("/control", f"203.0.113.{n + 2}", "other.example.test", 404, False, False, 1001)
        rows = candidates.suggestions(set())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["host"], "other.example.test")
        again = guardd.PathCandidates()
        again.restore(candidates.snapshot())
        self.assertEqual(again.suggestions(set()), rows)


if __name__ == "__main__":
    unittest.main()
