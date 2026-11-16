"""Identity belongs to a verified request; an IP grant is not a session."""
from dataclasses import replace
import unittest
import sys
from unittest import mock

from test_request_log import guardd, line, StoreTestCase, ROOT
sys.path.insert(0, str(ROOT / "docker/app"))


class IdentityParsing(unittest.TestCase):
    def test_encoded_identity_survives_without_becoming_log_fields(self):
        req = guardd.parse_access_line(line(extra="host=site.test auth_user=alice%40example.test"))
        self.assertEqual(req.authenticated_user, "alice@example.test")
        req = guardd.parse_access_line(line(extra="auth_user=%D0%90%D0%BD%D0%BD%D0%B0%20Smith"))
        self.assertEqual(req.authenticated_user, "Анна Smith")

    def test_uri_and_earlier_fields_cannot_supply_an_identity(self):
        for extra in ("host=site.test", "auth_user=forged ua=browser auth_user=-"):
            req = guardd.parse_access_line(line(extra=extra, request="GET /?auth_user=forged HTTP/1.1"))
            self.assertEqual(req.authenticated_user, "")

    def test_unknown_old_and_invalid_names_remain_unknown(self):
        for value in ("", "-", "%0Aroot", "%FF", "a" * 129):
            self.assertEqual(guardd.authenticated_username(" auth_user=" + value + " "), "")
        self.assertEqual(guardd.parse_access_line(line()).authenticated_user, "")


class ActivityIdentity(unittest.TestCase):
    def setUp(self):
        self.now = 1800000000
        self.buffer = guardd.LiveBuffer(100, 3600)
        self.req = guardd.parse_access_line(line())

    def record(self, user, ts, ip="203.0.113.9"):
        return guardd.live_record(replace(self.req, authenticated_user=user, client_ip=ip), ts)

    def test_shared_ip_and_guest_request_are_not_attributed_to_one_person(self):
        self.buffer.extend([self.record("alice", self.now - 3), self.record("bob", self.now - 2),
                            self.record("", self.now - 1)])
        users = self.buffer.identities(self.now)["203.0.113.9"]
        self.assertEqual({u["username"] for u in users}, {"alice", "bob"})
        events = self.buffer.snapshot({"window": 60}, now=self.now)["events"]
        self.assertEqual(events[0]["authenticated_user"], "")
        self.assertEqual(events[1]["authenticated_user"], "bob")
        self.assertEqual(self.buffer.identities(self.now + 86401), {})

    def test_refill_never_rewinds_the_last_confirmed_request(self):
        self.buffer.extend([self.record("alice", self.now)])
        self.buffer.refill([self.record("alice", self.now - 100)], self.now - 100)
        self.assertEqual(self.buffer.identities(self.now)["203.0.113.9"][0]["last_seen"], self.now)

    def test_identity_memory_is_bounded_independently(self):
        self.buffer.extend([self.record("alice", self.now, f"198.18.{i // 256}.{i % 256}") for i in range(1100)])
        self.assertEqual(len(self.buffer.identities(self.now)), 1024)
        self.buffer.extend([self.record(f"user{i}", self.now + i) for i in range(10)])
        self.assertEqual(len(self.buffer.identities(self.now + 10)["203.0.113.9"]), 8)


class StoredIdentity(StoreTestCase):
    def test_identity_is_stored_with_the_request_and_old_rows_stay_unknown(self):
        self.ingest(extra="id=named auth_user=alice")
        self.ingest(extra="id=guest")
        rows = {r["request_id"]: r for r in self.store.search()["requests"]}
        self.assertEqual(rows["named"]["authenticated_user"], "alice")
        self.assertEqual(rows["guest"]["authenticated_user"], "")

    def test_v2_migration_adds_unknown_identity_without_retiming_history(self):
        self.ingest(extra="id=old")
        with self.store._conn:
            self.store._conn.execute("ALTER TABLE requests DROP COLUMN authenticated_user")
            self.store._conn.execute("UPDATE schema_version SET version=2")
        self.store._upgrade(self.store._conn.cursor(), 2)
        row = self.store.search()["requests"][0]
        self.assertEqual(row["authenticated_user"], "")
        self.assertEqual(self.store._conn.execute("SELECT version FROM schema_version").fetchone()[0], 3)


class TrustedSource(unittest.TestCase):
    def test_authelia_names_require_success_and_never_use_client_headers(self):
        template = (ROOT / "ansible/roles/haproxy/templates/haproxy.cfg.j2").read_text(encoding="utf-8")
        rules = [r for r in template.splitlines() if "set-var(txn.log_auth_user)" in r]
        self.assertEqual(len(rules), 3)
        for rule in rules[:2]:
            self.assertIn("var(req.auth_response_header.remote_user)", rule)
            self.assertIn("{ var(txn.auth_response_successful) -m bool }", rule)
            self.assertNotIn("req.hdr(", rule)
        self.assertIn("AuthOK !admin_control_plane_probe", rules[2])


@unittest.skipIf(sys.platform == "win32", "the panel needs POSIX")
class PanelIdentity(unittest.TestCase):
    def test_only_current_ip_grants_receive_observed_names(self):
        from haproxy_admin import services, guardd_client
        raw = "# table: tbl_ip_auth, size=10, used=2\nkey=203.0.113.9 exp=60000 gpc0=1\nkey=203.0.113.8 exp=60000 gpc0=0"
        names = {"203.0.113.9": [{"username": "alice", "last_seen": 1}, {"username": "bob", "last_seen": 2}],
                 "203.0.113.8": [{"username": "old", "last_seen": 1}]}
        with mock.patch.object(services, "haproxy_runtime_command", return_value=raw), mock.patch.object(guardd_client, "guardd_identities", return_value={"users_by_ip": names}):
            data = services.get_ip_auth_table()
        self.assertEqual(data["users_by_ip"], {"203.0.113.9": names["203.0.113.9"]})
        self.assertEqual(len(data["rows"]), 2)

    def test_older_or_unavailable_guardd_does_not_remove_ip_grants(self):
        from haproxy_admin import services, guardd_client
        with mock.patch.object(services, "haproxy_runtime_command", return_value="key=203.0.113.9 exp=60000 gpc0=1"), mock.patch.object(guardd_client, "guardd_identities", side_effect=guardd_client.GuarddUnavailable("old daemon")):
            data = services.get_ip_auth_table()
        self.assertEqual(data["rows"], [["203.0.113.9", 1, 60]])
        self.assertEqual(data["users_by_ip"], {"203.0.113.9": []})


if __name__ == "__main__":
    unittest.main()
