"""The alerts page's settings are not redrawn under the operator's hands (F23).

From the 30 October review, confirmed with the page's own renderConfig: the
20-second refresh redrew the rules and delivery settings every time,
putting back the stored recipient and clearing a webhook URL or secret
being typed -- often just before Save.
"""

from __future__ import annotations

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "docker/app/haproxy_admin/static/js/alerts.js").read_text(encoding="utf-8")


class TheRefresh(unittest.TestCase):
    def body(self):
        return SCRIPT.split("  async function refresh(options) {")[1].split("\n  }\n")[0]

    def test_draws_the_forms_only_when_asked_or_the_first_time(self):
        body = self.body()
        self.assertIn("const drawForm = Boolean(options && options.form) || !formDrawn;", body)
        guarded = body.split("if (drawForm) {")[1].split("}")[0]
        self.assertIn("renderRules(state.catalogue);", guarded)
        self.assertIn("renderConfig(state.config);", guarded)
        self.assertEqual(SCRIPT.count("renderConfig(state.config);"), 1)

    def test_the_timer_and_the_actions_leave_them_alone(self):
        self.assertIn("window.setInterval(refresh, REFRESH_MS);", SCRIPT)
        act = SCRIPT.split("  async function act(path, body) {")[1].split("\n  }\n")[0]
        self.assertIn("await refresh();", act)

    def test_a_save_redraws_them_from_what_is_stored(self):
        save = SCRIPT.split("  async function save(payload, resultId) {")[1].split("\n  }\n")[0]
        self.assertIn("if (ok) await refresh({ form: true });", save)


if __name__ == "__main__":
    unittest.main()
