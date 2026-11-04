"""One switch for the new ban policy (U02: 04.3a, 04.3c, 04.8, 04.9).

The base rule, set by the operator on 31 October: an ordinary excess is
answered by refusing the excess, never by a ban; bans are for evidence of an
attack, or an operator's decision; the hard floor holds for everyone. Under
the old rules HAProxy banned on its own -- codes 10 and 20 for errors, 30 for
the request rate on a site with rate_ban -- and a signed-in user over a
site's limit got a week-long ban and a kernel drop.

site_defaults.ban_policy chooses, and stays "legacy" until the operator says
otherwise (4 November). The template states the result in a comment; guardd
follows that comment, so the two cannot disagree. On the switch guardd
writes the whole ban table to a file, then lifts the old-rule bans address
by address; switching back restores none of them.
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
sys.path.insert(0, str(ROOT / "docker" / "app"))
sys.path.insert(0, str(ROOT / ".tests"))

from test_site_allow_ips import render, site  # noqa: E402

GUARDD_PATH = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py"


def load_guardd():
    spec = importlib.util.spec_from_file_location("guardd_for_ban_policy", GUARDD_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


guardd = load_guardd()
T0 = 1_786_000_000
SITES = [
    site("shop", "shop.example.test", max_req_rate=200, rate_ban=True),
    site("office", "office.example.test", allow_ips=["203.0.113.7"], max_req_rate=50),
]


def config(policy=None, **extra):
    defaults = {"ban_policy": policy} if policy else {}
    extra.setdefault("admin_ips_enabled", True)
    return render(SITES, site_defaults=defaults, **extra)


def lines_with(text, needle):
    return [line.strip() for line in text.splitlines() if needle in line]


class TheTemplate(unittest.TestCase):
    def test_the_old_rules_stay_until_the_operator_switches(self):
        for text in (config(), config("legacy"), config("yes"), config("U02 later")):
            for code in ("int(10)", "int(20)", "int(30)"):
                self.assertTrue(lines_with(text, f"set-var(txn.ban_code)   {code}"), code)
            self.assertIn("# guardd-ban-policy legacy", text)

    def test_under_u02_haproxy_bans_nobody_itself(self):
        text = config("u02")
        self.assertEqual(lines_with(text, "http-request set-var(txn.ban_code)"), [])
        self.assertIn("# guardd-ban-policy u02", text)
        # Bans that do exist -- adaptive, an operator's -- are still enforced.
        self.assertIn("http-request deny status 423 if already_banned", text)

    def test_a_strangers_rate_excess_is_refused_on_the_site_even_with_rate_ban(self):
        text = config("u02")
        [deny] = lines_with(text, "deny status 429 if host_shop too_fast_shop")
        for trusted in ("!ip_whitelist", "!allowed_admin", "!ip_auth_ok"):
            self.assertIn(trusted, deny)
        # The signed-in are not even counted: a count they ran up must not
        # refuse them the moment the sign-in lapses.
        [track] = lines_with(text, "track-sc3 src table tbl_rate_shop")
        self.assertIn("!ip_auth_ok", track)

    def test_an_error_excess_is_a_cooldown_on_the_site(self):
        text = config("u02")
        [deny] = lines_with(text, "deny status 429 if host_shop too_many_errs_shop")
        for trusted in ("!ip_whitelist", "!allowed_admin", "!ip_auth_ok"):
            self.assertIn(trusted, deny)
        [other] = lines_with(text, "deny status 429 if too_many_errs_other")
        self.assertIn("!ip_auth_ok", other)
        # Its own refusals do not keep it over the limit (F04, again).
        [track] = lines_with(text, "track-sc1 src table tbl_err_shop")
        self.assertIn("!{ src_http_err_rate(tbl_err_shop) gt 20 }", track)
        self.assertIn("!ip_auth_ok", track)
        for line in lines_with(text, "track-sc1 src table tbl_err_other"):
            self.assertIn("!{ src_http_err_rate(tbl_err_other) gt 20 }", line)

    def test_the_old_rules_have_no_cooldown(self):
        text = config("legacy")
        self.assertEqual(lines_with(text, "too_many_errs_shop !ip_whitelist"), [])
        self.assertEqual(lines_with(text, "deny status 429 if host_shop too_fast_shop"), [])

    def test_a_site_open_to_named_addresses_is_left_alone(self):
        text = config("u02")
        self.assertEqual(lines_with(text, "too_many_errs_office"), [])
        self.assertEqual(lines_with(text, "too_fast_office"), [])

    def test_the_hard_floor_is_the_same_under_both(self):
        for name in ("sc0_http_req_rate(fe_https) gt 1000", "guardd-hard-floor table=fe_https"):
            self.assertEqual(lines_with(config("legacy"), name), lines_with(config("u02"), name))

    def test_without_authelia_there_is_no_sign_in_to_name(self):
        text = render(SITES, site_defaults={"ban_policy": "u02"},
                      authelia_enabled=False, admin_ips_enabled=False)
        self.assertNotIn("ip_auth_ok", text)

    def test_rate_errors_is_no_longer_offered_and_is_not_revived(self):
        # No rule ever read it (04.5c): the page offered a "strike threshold"
        # that did nothing. It is not offered or seeded any more, and a value
        # already in vars.yml is left where it is -- the guided save writes
        # only the fields it shows.
        from haproxy_admin import services_haproxy_vars

        self.assertNotIn("rate_errors", (ROOT / "ansible/roles/haproxy/templates/haproxy.cfg.j2").read_text(
            encoding="utf-8"))
        self.assertNotIn("site_defaults.rate_errors", services_haproxy_vars.EDITABLE_FIELDS)
        for path in ("installer/easy_ha_proxy.py", "ansible/roles/haproxy/defaults/main.yml",
                     "docker/app/haproxy_admin/templates/haproxy_sites.html"):
            self.assertNotIn("rate_errors", (ROOT / path).read_text(encoding="utf-8"), path)
        # A value left in vars.yml changes nothing either.
        text = render(SITES, site_defaults={"ban_policy": "u02", "rate_errors": 3}, admin_ips_enabled=True)
        self.assertEqual(text, config("u02"))

    def test_the_settings_page_offers_it(self):
        from haproxy_admin import services_haproxy_vars

        fields = {field["path"]: field for section in services_haproxy_vars.VARS_EDITOR_SECTIONS
                  for field in section["fields"]}
        policy = fields["site_defaults.ban_policy"]
        self.assertEqual((policy["type"], policy["options"], policy["default"]),
                         ("choice", ["legacy", "u02"], "legacy"))
        self.assertIn("u02", fields["site_defaults.rate_ban"]["help"])


class Workspace(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.cfg = self.root / "haproxy.cfg"
        self.write("legacy")
        geo = self.root / "whitelist.geo"
        geo.write_text("192.0.2.0/24\n", encoding="utf-8")
        log = self.root / "haproxy.log"
        log.write_text("", encoding="utf-8")
        self.database = guardd.SecurityDatabase(str(self.root / "security.db"))
        self.addCleanup(self.database.close)
        self.engine = guardd.GuardEngine(
            guardd.GuardConfig(log_file=str(log), whitelist_files=(str(geo),)), self.database
        )
        self.engine.ban_policy_watch = guardd.BanPolicyWatch(str(self.cfg))
        self.table = {
            "198.51.100.10": {"gpc0": "1", "gpt0": "10"},
            "198.51.100.30": {"gpc0": "1", "gpt0": "30"},
            "198.51.100.40": {"gpc0": "1", "gpt0": "40"},
            "198.51.100.50": {"gpc0": "1", "gpt0": "50"},
        }
        self.commands = []

    def write(self, policy):
        self.cfg.write_text(config(policy), encoding="utf-8")
        # A different size or time each write, as on a real reload.
        stamp = T0 + len(policy)
        import os

        os.utime(self.cfg, (stamp, stamp))

    def runtime(self, socket_path, command):
        self.commands.append(command)
        if command == "show table tbl_ban":
            return self.dump(self.table)
        if command.startswith("show table tbl_ban key "):
            ip = command.rsplit(" ", 1)[1]
            return self.dump({ip: self.table[ip]} if ip in self.table else {})
        if command.startswith("clear table tbl_ban key "):
            self.table.pop(command.rsplit(" ", 1)[1], None)
        return ""

    @staticmethod
    def dump(rows):
        lines = ["# table: tbl_ban, type: ip, size:204800, used:%d" % len(rows)]
        for index, (ip, fields) in enumerate(sorted(rows.items())):
            lines.append(f"0x{index + 1}: key={ip} use=0 exp=1000 gpt0={fields['gpt0']} gpc0={fields['gpc0']}")
        return "\n".join(lines) + "\n"

    def switch(self, policy, now=T0):
        self.write(policy)
        with mock.patch.object(guardd, "runtime_command", side_effect=self.runtime):
            self.engine.refresh_ban_policy(now)
            self.engine.ingest_tables({"tbl_ban": guardd.parse_table(self.dump(self.table)),
                                       "tbl_ip_auth": {}}, now)


class GuarddFollowsHaproxy(Workspace):
    def test_it_reads_what_the_configuration_says(self):
        self.assertEqual(guardd.read_ban_policy(str(self.cfg)), "legacy")
        self.write("u02")
        self.assertEqual(guardd.read_ban_policy(str(self.cfg)), "u02")
        self.assertEqual(guardd.read_ban_policy(str(self.root / "missing.cfg")), "legacy")

    def test_under_u02_ordinary_excess_weighs_nothing(self):
        self.assertEqual(self.engine.scoring_policy().weight(guardd.EVENT_RATE_EXCEEDED), 15)
        self.switch("u02")
        policy = self.engine.scoring_policy()
        self.assertEqual(policy.weight(guardd.EVENT_RATE_EXCEEDED), 0)
        self.assertEqual(policy.weight(guardd.EVENT_HARD_FLOOR), 60)

    def test_the_geoip_whitelist_is_no_exemption_under_u02(self):
        self.engine.refresh_ban_policy(T0)
        self.assertTrue(self.engine.exclusions.verdict("192.0.2.9").excluded)
        self.switch("u02")
        self.assertFalse(self.engine.exclusions.verdict("192.0.2.9").excluded)

    def test_a_sign_in_protects_for_seven_days_not_for_ever(self):
        def blockers(days_ago, policy):
            row = {"excluded": False, "enforceable": True,
                   "authenticated_at": T0 - days_ago * 86400}
            return self.engine.ban_blockers(row, T0, policy)

        self.assertEqual(blockers(300, "legacy"), ["has authenticated before"])
        self.assertEqual(blockers(2, "u02"), ["signed in within the last 7 days"])
        self.assertEqual(blockers(8, "u02"), [])


class TheSwitch(Workspace):
    def test_it_writes_the_table_down_before_lifting_anything(self):
        self.switch("u02")
        state = self.engine.ban_policy_state()
        self.assertEqual((state["policy"], state["previous"]), ("u02", "legacy"))
        snapshot = json.loads(Path(state["snapshot"]).read_text(encoding="utf-8"))
        self.assertEqual(set(snapshot["entries"]), {"198.51.100.10", "198.51.100.30",
                                                    "198.51.100.40", "198.51.100.50"})
        first_clear = next(i for i, c in enumerate(self.commands) if c.startswith("clear"))
        self.assertLess(self.commands.index("show table tbl_ban"), first_clear)

    def test_only_the_old_rules_bans_are_lifted(self):
        self.switch("u02")
        self.assertEqual(sorted(self.table), ["198.51.100.40", "198.51.100.50"])
        [ten] = self.database.events_for("198.51.100.10", 0)[:1]
        self.assertEqual(ten["event_type"], guardd.EVENT_LEGACY_BAN_LIFTED)
        self.assertIn("code=10", ten["detail"])
        self.assertNotIn(guardd.EVENT_LEGACY_BAN_LIFTED, guardd.DEFAULT_WEIGHTS)

    def test_an_operators_ban_placed_meanwhile_stays(self):
        listed = self.dump(self.table)
        self.table["198.51.100.10"]["gpt0"] = "50"  # banned by hand after the read
        self.write("u02")
        with mock.patch.object(guardd, "runtime_command", side_effect=self.runtime):
            self.engine.refresh_ban_policy(T0)
            self.engine.ingest_tables({"tbl_ban": guardd.parse_table(listed), "tbl_ip_auth": {}}, T0)
        self.assertIn("198.51.100.10", self.table)

    def test_nothing_is_lifted_without_the_snapshot(self):
        self.write("u02")

        def broken(socket_path, command):
            if command == "show table tbl_ban":
                raise OSError("socket went away")
            return self.runtime(socket_path, command)

        with mock.patch.object(guardd, "runtime_command", side_effect=broken):
            self.engine.refresh_ban_policy(T0)
            self.engine.ingest_tables({"tbl_ban": guardd.parse_table(self.dump(self.table)),
                                       "tbl_ip_auth": {}}, T0)
        self.assertEqual(len(self.table), 4)
        self.assertNotEqual(self.engine.ban_policy_state().get("policy"), "u02")
        # Scoring follows HAProxy at once all the same.
        self.assertEqual(self.engine.scoring_policy().weight(guardd.EVENT_RATE_EXCEEDED), 0)

    def test_switching_back_restores_nothing_and_lifts_nothing(self):
        self.switch("u02")
        self.table["198.51.100.20"] = {"gpc0": "1", "gpt0": "20"}
        self.switch("legacy", now=T0 + 60)
        self.assertEqual(self.engine.ban_policy_state()["policy"], "legacy")
        self.assertIn("198.51.100.20", self.table)
        self.assertNotIn("198.51.100.10", self.table)

    def test_old_snapshots_are_pruned(self):
        with mock.patch.object(guardd, "runtime_command", side_effect=self.runtime):
            for step in range(guardd.BAN_SNAPSHOTS_KEPT + 2):
                self.engine.snapshot_bans(T0 + step)
        self.assertEqual(len(list(self.root.glob("ban-policy-u02-*.json"))), guardd.BAN_SNAPSHOTS_KEPT)

    def test_the_status_says_which_policy_is_in_force(self):
        self.engine.refresh_ban_policy(T0)
        self.assertEqual(self.engine.health()["ban_policy"]["current"], "legacy")
        self.switch("u02")
        health = self.engine.health()["ban_policy"]
        self.assertEqual((health["current"], health["switch"]["policy"]), ("u02", "u02"))
        self.assertEqual(health["legacy_lifted"], 2)
        self.assertEqual(health["legacy_bans"], {})


if __name__ == "__main__":
    unittest.main()
