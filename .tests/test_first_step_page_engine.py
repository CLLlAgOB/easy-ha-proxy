"""The engine places a first step as a page (code 41) and the next as a cut-off (P7).

Held here:
- the first ban of an address is code 41 while the switch is on, a later
  one 40, and with the switch off every ban is 40;
- an address that goes on to signatures on two different paths while it is
  shown the page is taken to the next step at once; one path tried again --
  a person repeating what they were doing -- is not;
- after a page has run its course, what the address did while it was shown
  is not fresh evidence for the next step;
- a first step put back after a restart of HAProxy is put back as a page;
- switching the page off turns the first steps standing into cut-offs;
- both codes are the engine's own: lifted on expiry, swept when enforcement
  goes off.
"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".tests"))
sys.path.insert(0, str(ROOT / "docker" / "app"))
if sys.platform != "win32":
    import test_guardd as base
    guardd = base.guardd
    import haproxy_admin as panel
    from haproxy_admin import create_app, routes_security, services, services_live
else:
    base = guardd = panel = create_app = routes_security = services = services_live = None

NOW = 1_800_000_000
IP = "203.0.113.9"


# The fixture carries no tests of its own, so inheriting it runs only these.
@unittest.skipUnless(guardd, "Linux engine")
class FirstStep(base.EnforcementTestCase if base else unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.engine.enforcer.mode = guardd.MODE_ENFORCE
        self.sequence = 0

    def finding(self, ts, path="/.env", ip=IP):
        self.sequence += 1
        self.engine._emit(ip, guardd.EVENT_SCANNER_DECISIVE, ts, source="test", category="secrets",
                          detail=path, fingerprint=f"{ip}|{path}|{ts}|{self.sequence}")
        self.engine.enforcement_queue.mark(ip, urgent=True)

    def code(self, ip=IP):
        return int(self.table[ip]["gpt0"]) if ip in self.table else None

    def test_the_first_ban_is_a_page_and_the_next_a_cut_off(self):
        self.finding(NOW)
        self.engine.apply_enforcement(NOW + 1)
        self.assertEqual(self.code(), guardd.ADAPTIVE_PAGE_CODE)
        self.assertEqual(self.database.scheduled_ban_codes()[IP], guardd.ADAPTIVE_PAGE_CODE)
        until = self.database.scheduled_bans()[IP]
        self.engine.apply_enforcement(until + 1)  # served
        self.assertIsNone(self.code())
        self.finding(until + 600, "/.git/config")
        self.engine.apply_enforcement(until + 601)
        self.assertEqual(self.code(), guardd.ADAPTIVE_BAN_CODE)

    def test_with_the_switch_off_the_first_ban_is_a_cut_off(self):
        self.engine.set_first_step_page(False)
        self.finding(NOW)
        self.engine.apply_enforcement(NOW + 1)
        self.assertEqual(self.code(), guardd.ADAPTIVE_BAN_CODE)

    def test_going_on_after_the_page_is_the_next_step_at_once(self):
        self.finding(NOW)
        self.engine.apply_enforcement(NOW + 1)
        first_until = self.database.scheduled_bans()[IP]
        self.finding(NOW + 30, "/.git/config")
        self.finding(NOW + 31, "/backup.sql")
        self.engine.apply_enforcement(NOW + 40)
        self.assertEqual(self.code(), guardd.ADAPTIVE_BAN_CODE)
        self.assertGreater(self.database.scheduled_bans()[IP], first_until)
        decision = self.database.ban_decisions(IP, 5)[0]
        self.assertEqual((decision["code"], decision["strike"]), (guardd.ADAPTIVE_BAN_CODE, 2))
        self.assertIn("after_page", decision["reason"])

    def test_one_path_tried_again_is_not_a_scanner(self):
        self.finding(NOW)
        self.engine.apply_enforcement(NOW + 1)
        self.finding(NOW + 30, "/.env")
        self.engine.apply_enforcement(NOW + 40)
        self.assertEqual(self.code(), guardd.ADAPTIVE_PAGE_CODE)

    def test_what_it_did_during_the_page_is_not_evidence_once_the_page_is_over(self):
        self.finding(NOW)
        self.engine.apply_enforcement(NOW + 1)
        until = self.database.scheduled_bans()[IP]
        self.finding(NOW + 30, "/.env")  # the person tried again
        self.engine.apply_enforcement(until + 1)  # the page runs out
        self.engine.apply_enforcement(until + 60)
        self.assertIsNone(self.code())
        self.assertNotIn(IP, self.database.scheduled_bans())

    def test_a_first_step_put_back_after_a_restart_is_a_page_again(self):
        self.finding(NOW)
        self.engine.apply_enforcement(NOW + 1)
        self.table.clear()  # HAProxy restarted
        self.engine.apply_enforcement(NOW + 20)
        self.assertEqual(self.code(), guardd.ADAPTIVE_PAGE_CODE)

    def test_switching_the_page_off_cuts_the_standing_first_steps_off(self):
        self.finding(NOW)
        self.engine.apply_enforcement(NOW + 1)
        state = self.engine.set_first_step_page(False)
        self.assertEqual(state["changed"], 1)
        self.assertEqual(self.code(), guardd.ADAPTIVE_BAN_CODE)
        self.assertEqual(self.database.scheduled_ban_codes()[IP], guardd.ADAPTIVE_BAN_CODE)
        self.assertEqual(self.engine.first_step_state(), {"enabled": False, "showing_page": 0})
        self.assertEqual(self.database.get_state(guardd.FIRST_STEP_PAGE_KEY, ""), "0")

    def test_the_switch_takes_only_true_or_false(self):
        for value in ("off", 0, None):
            with self.assertRaises(ValueError):
                self.engine.set_first_step_page(value)

    def test_a_page_is_lifted_on_expiry_as_the_engines_own(self):
        self.finding(NOW)
        self.engine.apply_enforcement(NOW + 1)
        until = self.database.scheduled_bans()[IP]
        result = self.engine.apply_enforcement(until + 1)
        self.assertIn(IP, result["lifted"])
        lifted = [d for d in self.database.ban_decisions(IP, 5) if d["action"] == "lifted"][0]
        self.assertEqual(lifted["code"], guardd.ADAPTIVE_PAGE_CODE)

    def test_a_page_left_behind_is_swept_when_enforcement_goes_off(self):
        self.table["198.51.100.4"] = {"gpc0": "1", "gpt0": str(guardd.ADAPTIVE_PAGE_CODE)}
        self.engine.enforcer.mode = guardd.MODE_MONITOR
        self.engine.apply_enforcement(NOW)
        self.assertNotIn("198.51.100.4", self.table)

    def test_health_says_how_many_are_shown_the_page(self):
        self.finding(NOW)
        self.engine.apply_enforcement(NOW + 1)
        self.assertEqual(self.engine.health()["first_step_page"], {"enabled": True, "showing_page": 1})


class TheCodes(unittest.TestCase):
    def test_both_adaptive_codes_are_the_engines_own(self):
        if guardd is None:
            self.skipTest("Linux engine")
        self.assertEqual(guardd.ADAPTIVE_CODES, {40, 41})
        self.assertLessEqual(guardd.ADAPTIVE_CODES, guardd.OWN_BAN_CODES)
        self.assertNotIn(41, guardd.LEGACY_BAN_CODES)


if __name__ == "__main__":
    unittest.main()


@unittest.skipIf(sys.platform == "win32", "the admin package needs fcntl")
class ThePanel(unittest.TestCase):
    def setUp(self):
        import json
        import os
        import tempfile
        from unittest import mock

        self.json = json
        self.mock = mock
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        env = mock.patch.dict(os.environ, {"HAPROXY_ADMIN_PROXY_SECRET": "page-test-proxy",
                                           "HAPROXY_ADMIN_SECRET_KEY": "page-test-session",
                                           "AUDIT_DATABASE": str(Path(folder.name) / "audit.db")})
        env.start()
        self.addCleanup(env.stop)
        with mock.patch.object(panel, "ensure_whitelist_file"):
            app = create_app()
        app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = app.test_client()
        self.superadmin = {"X-Easy-HA-Proxy-Secret": "page-test-proxy", "Remote-User": "root-admin",
                           "Remote-Groups": "superadmin"}
        patcher = mock.patch.object(routes_security.security, "set_first_step_page",
                                    return_value={"ok": True, "first_step_page": {"enabled": False, "changed": 2}})
        self.switch = patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(routes_security, "record_request")
        self.record = patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_superadmin_switches_it_and_the_change_is_recorded(self):
        response = self.client.post("/api/security/adaptive/first-step-page", json={"enabled": False},
                                    headers=self.superadmin)
        self.assertEqual(response.status_code, 200)
        self.switch.assert_called_once_with(False)
        self.assertEqual(self.record.call_args.kwargs["after"], {"enabled": False})
        self.assertIn("2", self.record.call_args.kwargs["detail"])

    def test_an_ordinary_administrator_cannot(self):
        response = self.client.post("/api/security/adaptive/first-step-page", json={"enabled": False},
                                    headers={**self.superadmin, "Remote-Groups": "admins"})
        self.assertEqual(response.status_code, 403)
        self.switch.assert_not_called()

    def test_the_ban_lists_name_the_code(self):
        self.assertIn("41", services_live.BAN_CODE_LABELS)
        self.assertIn("41", services.ADAPTIVE_BAN_CODES)
        dashboard = (ROOT / "docker/app/haproxy_admin/static/js/dashboard.js").read_text(encoding="utf-8")
        self.assertIn("41: 'Adaptive protection: first step, shown a page (ADAPTIVE_PAGE)'", dashboard)

    def test_every_new_sentence_is_translated_whole(self):
        import re

        app = ROOT / "docker/app/haproxy_admin"
        catalogue = {}
        for path in list((app / "translations/ru").glob("*.json")) + [app / "translations/ru.json"]:
            data = self.json.loads(path.read_text(encoding="utf-8"))
            catalogue.update(data.get("messages", data))
        script = (app / "static/js/adaptive_protection.js").read_text(encoding="utf-8")
        block = script[script.index("function renderFirstStep"):script.index("async function toggleFirstStep")]
        sentences = []
        for call in re.findall(r'uiText\(([^)]*)\)', block):
            sentences.extend(re.findall(r'"([^"]+)"', call))
        self.assertGreaterEqual(len(sentences), 4)
        for sentence in sentences:
            self.assertIn(sentence, catalogue, sentence)
        page = (app / "templates/adaptive_protection.html").read_text(encoding="utf-8")
        for sentence in re.findall(r'<h3>(First step[^<]+)</h3>|<p class="mon-sub">(On the first step[^<]+)</p>', page):
            for part in sentence:
                if part:
                    self.assertIn(part, catalogue, part[:60])
        for label in ("Adaptive protection: first step, shown a page",
                      "Adaptive protection: first step, shown a page (ADAPTIVE_PAGE)"):
            self.assertIn(label, catalogue)
