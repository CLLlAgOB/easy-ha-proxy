"""Regression checks for Authelia users, ACL, and general settings pages."""

from __future__ import annotations

from pathlib import Path
import unittest


APP = Path(__file__).resolve().parent / "haproxy_admin"
TEMPLATES = APP / "templates"


def read(relative: str) -> str:
    return (APP / relative).read_text(encoding="utf-8")


class AutheliaCsrfTemplateTests(unittest.TestCase):
    def test_user_forms_render_csrf_as_hidden_input_not_text(self) -> None:
        for name in ("authelia_user_new.html", "authelia_user_edit.html"):
            template = (TEMPLATES / name).read_text(encoding="utf-8")
            self.assertNotIn("{{ csrf_token() if csrf_token is defined }}", template)
            self.assertIn(
                '<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">',
                template,
            )

    def test_all_audited_server_forms_have_explicit_csrf_fields(self) -> None:
        expected = {
            "authelia_users.html": 1,
            "authelia_acl_edit.html": 1,
            "authelia_settings.html": 1,
        }
        for name, minimum in expected.items():
            template = (TEMPLATES / name).read_text(encoding="utf-8")
            self.assertGreaterEqual(template.count('name="csrf_token"'), minimum)


class AutheliaRouteSafetyTests(unittest.TestCase):
    def test_user_password_confirmation_is_checked_server_side(self) -> None:
        routes = read("routes.py")
        edit = routes.split("def authelia_user_edit", 1)[1].split(
            "\n@bp.route", 1
        )[0]
        self.assertIn('request.form.get("password2")', edit)
        self.assertIn("password_raw != password_confirmation", edit)
        self.assertNotIn(
            '(request.form.get("password") or "").strip()', edit
        )

    def test_self_delete_is_blocked_and_success_uses_prg(self) -> None:
        routes = read("routes.py")
        delete = routes.split("def authelia_user_delete", 1)[1].split(
            "\n@bp.route", 1
        )[0]
        self.assertIn('getattr(g, "remote_user"', delete)
        self.assertIn("code=303", delete)

    def test_settings_save_uses_prg_and_load_errors_disable_editing(self) -> None:
        routes = read("routes_authelia_settings.py")
        template = (TEMPLATES / "authelia_settings.html").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'return redirect(url_for("authelia_settings.edit_settings"), code=303)',
            routes,
        )
        self.assertIn("settings_load_error", routes)
        self.assertIn("{% if settings_load_error %}", template)
        self.assertIn("Editing is disabled to prevent accidental overwrite.", template)


class AutheliaAclSafetyTests(unittest.TestCase):
    def test_rules_read_failure_is_not_converted_to_an_empty_list(self) -> None:
        source = read("authelia_acl.py")
        loader = source.split("def load_rules_yaml", 1)[1].split(
            "\ndef save_rules_from_yaml", 1
        )[0]
        self.assertIn("raise RuntimeError", loader)
        self.assertNotIn('return "[]\\n"', loader)

    def test_acl_template_disables_editor_after_load_failure(self) -> None:
        template = (TEMPLATES / "authelia_acl_edit.html").read_text(
            encoding="utf-8"
        )
        self.assertIn("{% if acl_load_error %}", template)
        self.assertIn("Editing is disabled to prevent accidental overwrite.", template)


if __name__ == "__main__":
    unittest.main()
