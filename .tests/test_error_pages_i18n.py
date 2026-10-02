"""The HAProxy static error/access pages follow the admin UI language.

They are raw HTTP errorfiles, so the Jinja setup must never disturb the
status-line / headers / blank-line / body structure.
"""

from __future__ import annotations

import unittest
from pathlib import Path

try:
    import jinja2
except Exception:  # pragma: no cover
    jinja2 = None

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "ansible/roles/haproxy/templates"
PAGES = {
    "access_granted.http.j2": ("HTTP/1.0 200 OK", "Access granted", "Доступ разрешён"),
    "maintenance.http.j2": (
        "HTTP/1.0 503 Service Temporarily Unavailable",
        "Service Temporarily Unavailable",
        "Сервис временно недоступен",
    ),
}


@unittest.skipIf(jinja2 is None, "jinja2 unavailable")
class ErrorPageI18nTests(unittest.TestCase):
    def _render(self, name: str, language: str) -> str:
        # Mirror Ansible's template defaults.
        env = jinja2.Environment(trim_blocks=True, lstrip_blocks=False)
        src = (TEMPLATES / name).read_text(encoding="utf-8")
        return env.from_string(src).render(
            haproxy_admin_default_language=language
        )

    def test_http_structure_is_preserved_for_every_language(self) -> None:
        for name, (status, _en, _ru) in PAGES.items():
            for language in ("ru", "en", "de", ""):
                with self.subTest(page=name, language=language):
                    out = self._render(name, language)
                    self.assertEqual(out.splitlines()[0], status)
                    head, sep, body = out.partition("\n\n")
                    self.assertTrue(sep, "missing header/body separator")
                    # Header block is only the status line plus headers.
                    self.assertLessEqual(len(head.splitlines()), 5)
                    self.assertTrue(body.lstrip().startswith("<"))

    def test_language_selection_and_fallback(self) -> None:
        for name, (_status, en_marker, ru_marker) in PAGES.items():
            with self.subTest(page=name):
                self.assertIn(ru_marker, self._render(name, "ru"))
                self.assertIn(en_marker, self._render(name, "en"))
                # Unknown language and empty fall back to English.
                self.assertIn(en_marker, self._render(name, "de"))
                self.assertIn(en_marker, self._render(name, ""))
                self.assertIn('lang="en"', self._render(name, "xx"))


if __name__ == "__main__":
    unittest.main()
