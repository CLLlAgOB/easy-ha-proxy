"""The panel's side of alerts in the header: what each route forwards, who
may do what, and that every page carries the header's indicator."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest import mock

try:
    import flask
except ImportError:  # pragma: no cover - the web requirements are not installed
    flask = None

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker" / "app" / "haproxy_admin"
sys.path.insert(0, str(ROOT / "docker" / "app"))


@unittest.skipUnless(flask, "Flask is not installed")
class TheRoutes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from haproxy_admin import routes_alerts

        cls.module = routes_alerts

    def setUp(self):
        self.superadmin = False
        app = flask.Flask(__name__)

        @app.before_request
        def who():
            flask.g.remote_user = "anna"
            flask.g.is_superadmin = self.superadmin

        app.add_url_rule("/api/alerts/portal", view_func=self.module.api_alerts_portal)
        app.add_url_rule("/api/alerts/quieten", view_func=self.module.api_alerts_quieten,
                         methods=["POST"])
        app.add_url_rule("/api/alerts/dismiss", view_func=self.module.api_alerts_dismiss,
                         methods=["POST"])
        app.add_url_rule("/api/alerts/history/delete",
                         view_func=self.module.api_alerts_history_delete, methods=["POST"])
        self.client = app.test_client()
        audit = mock.patch.object(self.module, "record_request")
        self.audit = audit.start()
        self.addCleanup(audit.stop)

    def test_the_header_reads_what_the_daemon_says(self):
        answer = {"ok": True, "items": [], "total": 0}
        with mock.patch.object(self.module, "alertd_portal", return_value=answer):
            response = self.client.get("/api/alerts/portal")
        self.assertEqual(response.get_json(), answer)
        with mock.patch.object(self.module, "alertd_portal",
                               side_effect=self.module.AlertdUnavailable("down")):
            response = self.client.get("/api/alerts/portal")
        self.assertEqual(response.status_code, 503)

    def test_any_operator_may_acknowledge_or_mute_and_it_is_written_down(self):
        with mock.patch.object(self.module, "alertd_quieten",
                               return_value={"ok": True}) as quieten:
            response = self.client.post("/api/alerts/quieten", json={
                "rule": "site.down", "subject": "shop", "mode": "mute", "seconds": 3600,
            })
        self.assertEqual(response.status_code, 200)
        quieten.assert_called_once_with(
            {"rule": "site.down", "subject": "shop", "mode": "mute", "by": "anna", "seconds": 3600}
        )
        self.assertEqual(self.audit.call_args.args[0], "alerts.quieten")
        self.assertEqual(self.audit.call_args.kwargs["object_id"], "site.down:shop")

    def test_a_refusal_from_the_daemon_is_a_400_with_its_reason(self):
        with mock.patch.object(self.module, "alertd_dismiss",
                               return_value={"ok": False, "error": "mute it instead"}):
            response = self.client.post("/api/alerts/dismiss",
                                        json={"rule": "site.down", "subject": "shop"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "mute it instead")
        self.assertEqual(self.audit.call_args.kwargs["result"], self.module.RESULT_FAILURE)

    def test_only_a_superadmin_deletes_history(self):
        with mock.patch.object(self.module, "alertd_delete_history") as delete:
            response = self.client.post("/api/alerts/history/delete", json={"all": True})
        self.assertEqual(response.status_code, 403)
        delete.assert_not_called()
        self.assertEqual(self.audit.call_args.kwargs["result"], self.module.RESULT_DENIED)

        self.superadmin = True
        with mock.patch.object(self.module, "alertd_delete_history",
                               return_value={"ok": True, "deleted": 3}) as delete:
            self.client.post("/api/alerts/history/delete", json={"all": True})
            self.client.post("/api/alerts/history/delete", json={"ids": [1, 2]})
            # "all" must be the literal true, not anything truthy.
            self.client.post("/api/alerts/history/delete", json={"all": "yes"})
        self.assertEqual([call.args[0] for call in delete.call_args_list],
                         [{"all": True}, {"ids": [1, 2]}, {}])


class EveryPage(unittest.TestCase):
    def test_the_header_carries_the_indicator_and_its_script(self):
        base = (APP / "templates/base.html").read_text(encoding="utf-8")
        self.assertIn('id="global-alerts"', base)
        self.assertIn("url_for('routes.api_alerts_portal')", base)
        self.assertIn("js/alerts_badge.js", base)
        # Shown to every operator, not only to a superadmin.
        indicator = base.split('<a id="global-alerts"')[0]
        self.assertEqual(indicator.count("{% if g.is_superadmin %}"), indicator.count("{% endif %}"))

    def test_the_script_does_not_cry_wolf(self):
        script = (APP / "static/js/alerts_badge.js").read_text(encoding="utf-8")
        # The alert service restarts with every update: one failed answer is
        # not shown, two in a row are.
        self.assertIn("if (failures >= 2) renderSilent(badge);", script)
        self.assertIn("badge.hidden = total === 0;", script)
        self.assertIn('"easy-ha-proxy:alerts-changed"', script)
        page = (APP / "static/js/alerts.js").read_text(encoding="utf-8")
        self.assertIn('new CustomEvent("easy-ha-proxy:alerts-changed")', page)

    def test_a_refresh_keeps_the_history_the_operator_is_looking_at(self):
        page = (APP / "static/js/alerts.js").read_text(encoding="utf-8")
        refresh = page.split("async function refresh(")[1].split("\n  }\n")[0]
        self.assertIn("if (!historyBusy()) await loadHistory(false);", refresh)
        busy = page.split("function historyBusy(")[1].split("\n  }\n")[0]
        self.assertIn("historyRows.length > HISTORY_PAGE", busy)
        self.assertIn("selectedHistory().length > 0", busy)

    def test_every_word_is_in_russian(self):
        import json

        catalog = {}
        for path in (APP / "translations").rglob("*.json"):
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("meta", {}).get("code") == "ru":
                catalog.update(data["messages"])
        words = {
            "Acknowledge", "Mute", "Unmute", "Undo", "Dismiss", "Muted until", "Acknowledged",
            "1 hour", "8 hours", "1 day", "7 days", "Delete selected", "Clear history",
            "Show more", "All severities", "All conditions", "Delete the selected entries?",
            "Delete the whole alert history?", "The action failed", "Show in the panel from",
            "Alerts: {count}", "The alert service is not answering", "Open alerts",
            "Mail cannot be delivered", "critical", "warning", "info", "fired", "recovered",
            "dismissed", "Actions",
        }
        self.assertEqual(sorted(word for word in words if word not in catalog), [])


if __name__ == "__main__":
    unittest.main()
