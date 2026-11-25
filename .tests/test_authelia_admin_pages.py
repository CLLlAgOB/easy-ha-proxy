"""Regression checks for Authelia users, ACL, and general settings pages."""

from __future__ import annotations

from pathlib import Path
import unittest


APP = Path(__file__).resolve().parents[1] / "docker" / "app" / "haproxy_admin"
_WEB_DIR = Path(__file__).resolve().parents[1] / "go" / "panel" / "web"
TEMPLATES = _WEB_DIR / "templates"


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


class AutheliaAclSafetyTests(unittest.TestCase):

    def test_acl_template_disables_editor_after_load_failure(self) -> None:
        template = (TEMPLATES / "authelia_acl_edit.html").read_text(
            encoding="utf-8"
        )
        self.assertIn("{% if acl_load_error %}", template)
        self.assertIn("Editing is disabled to prevent accidental overwrite.", template)


if __name__ == "__main__":
    unittest.main()
