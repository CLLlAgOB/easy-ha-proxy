"""Rendered shell: role boundaries, current location and safe account text."""
from pathlib import Path
from types import SimpleNamespace
import unittest

from jinja2 import Environment, FileSystemLoader

TEMPLATES = Path(__file__).resolve().parents[1] / "docker/app/haproxy_admin/templates"


def render(endpoint="routes.index", administrator=True, username="operator", source=None):
    environment = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=True)
    environment.globals["url_for"] = lambda endpoint, **values: "/" + endpoint + ("/" + values["filename"] if "filename" in values else "")
    template = environment.from_string(source) if source else environment.get_template("base.html")
    return template.render(
        g=SimpleNamespace(is_superadmin=administrator, remote_user=username),
        request=SimpleNamespace(endpoint=endpoint, full_path="/"),
        current_language="en", supported_languages=[{"code": "en", "label": "English"}],
        i18n_config={"language": "en", "languages": []}, i18n_messages_url="/messages.js",
        csrf_token=lambda: "test-csrf", csp_nonce="test-nonce", build=None,
        updates_badge=None, debug_routes_enabled=False,
    )


class Shell(unittest.TestCase):
    def test_an_ordinary_user_gets_the_dashboard_without_administration_links(self):
        html = render(administrator=False)
        self.assertIn('href="/routes.index"', html)
        self.assertNotIn('data-nav-endpoint="routes.haproxy_config_page"', html)
        self.assertNotIn('data-nav-endpoint="routes.authelia_users"', html)
        self.assertNotIn('id="global-config-state"', html)

    def test_the_current_section_is_open_and_marked_for_nested_editors(self):
        html = render(endpoint="routes.haproxy_site_edit")
        self.assertIn('data-nav-group="routing" open', html)
        self.assertRegex(html, r'data-nav-endpoint="routes\.haproxy_sites_page"\s+aria-current="page"')

    def test_account_text_is_escaped(self):
        html = render(username='<img src=x onerror="bad()">')
        self.assertNotIn('<img src=x', html)
        self.assertIn('&lt;img', html)

    def test_mobile_controls_and_skip_target_are_present_once(self):
        html = render()
        for target in ("app-sidebar", "nav-toggle", "nav-close", "nav-backdrop", "main-content", "theme-toggle"):
            with self.subTest(target=target):
                self.assertEqual(html.count(f'id="{target}"'), 1)
        self.assertIn('href="#main-content"', html)
        self.assertIn('aria-controls="app-sidebar"', html)

    def test_page_actions_render_inside_the_main_content(self):
        html = render(source='''{% extends "base.html" %}
            {% block header_buttons %}<a href="/new">Create entry</a>{% endblock %}''')
        main = html.split('<main ')[1].split('</main>')[0]
        self.assertIn('class="page-actions"', main)
        self.assertIn('href="/new"', main)
        self.assertNotIn('href="/new"', html.split('<header ')[1].split('</header>')[0])


if __name__ == "__main__":
    unittest.main()
