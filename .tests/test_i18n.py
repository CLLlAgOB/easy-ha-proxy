"""Regression checks for the dependency-free UI translation catalogs."""

from __future__ import annotations

import ast
import importlib.util
import json
from pathlib import Path
import re
import sys
import types
import unittest
from unittest import mock

from jinja2 import Environment, FileSystemLoader


PROJECT_ROOT = Path(__file__).resolve().parents[1]
APP_DIR = PROJECT_ROOT / "docker" / "app" / "haproxy_admin"
CATALOG_DIR = APP_DIR / "translations"
CYRILLIC = re.compile(r"[А-Яа-яЁё]")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key}")
        result[key] = value
    return result


def load_catalog(path: Path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)


def translate_source(value: str, messages: dict[str, str]) -> str:
    translated = messages.get(value, value)
    if translated != value:
        return translated
    for source, target in sorted(messages.items(), key=lambda item: len(item[0]), reverse=True):
        if re.fullmatch(r"[\w-]+", source):
            translated = re.sub(
                rf"(?<![\w=-]){re.escape(source)}(?![\w=-])",
                lambda _match: target,
                translated,
            )
        else:
            translated = translated.replace(source, target)
    return translated


def template_ui_fragments():
    for path in (APP_DIR / "templates").glob("*.html"):
        source = path.read_text(encoding="utf-8")
        source = re.sub(
            r"{#.*?#}|<!--.*?-->|<style.*?</style>|<script.*?</script>",
            "",
            source,
            flags=re.DOTALL,
        )
        fragments = re.findall(r"(?:^|>)([^<>]+)(?=<|$)", source, flags=re.DOTALL)
        fragments += re.findall(
            r'(?:title|placeholder|aria-label|data-confirm)=["\']([^"\']+)',
            source,
        )
        for fragment in fragments:
            fragment = re.sub(
                r"{[{%].*?[}%]}", "", fragment, flags=re.DOTALL
            ).strip()
            if CYRILLIC.search(fragment):
                yield path.name, fragment


def javascript_ui_fragments():
    literal_pattern = re.compile(
        r'(["\'`])((?:\\.|(?!\1).)*?)\1', flags=re.DOTALL
    )
    for path in (APP_DIR / "static" / "js").glob("*.js"):
        source = path.read_text(encoding="utf-8")
        source = re.sub(
            r"/\*.*?\*/|^\s*//[^\n]*$", "", source, flags=re.DOTALL | re.MULTILINE
        )
        for _quote, fragment in literal_pattern.findall(source):
            if CYRILLIC.search(fragment):
                yield path.name, fragment.strip()


def python_runtime_strings():
    for path in APP_DIR.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        docstrings = set()
        for node in ast.walk(tree):
            if not isinstance(
                node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                continue
            if (
                node.body
                and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)
            ):
                docstrings.add(id(node.body[0].value))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and id(node) not in docstrings
                and CYRILLIC.search(node.value)
            ):
                yield path.name, node.lineno, node.value


class TranslationCatalogTests(unittest.TestCase):
    def test_technical_output_is_excluded_from_dom_translation(self):
        javascript = (APP_DIR / "static" / "js" / "i18n.js").read_text(
            encoding="utf-8"
        )
        template = (APP_DIR / "templates" / "haproxy_config.html").read_text(
            encoding="utf-8"
        )
        service = (APP_DIR / "services_haproxy_config.py").read_text(
            encoding="utf-8"
        )

        self.assertIn("function isTranslationSkipped(element)", javascript)
        self.assertIn("current = current.parentElement", javascript)
        self.assertIn('current.hasAttribute("data-i18n-skip")', javascript)
        for element_id in (
            "cfg-diff",
            "check-stdout",
            "check-stderr",
            "apply-stdout",
            "apply-stderr",
        ):
            tag = re.search(rf'<[^>]+id="{element_id}"[^>]*>', template)
            self.assertIsNotNone(tag, element_id)
            self.assertIn("data-i18n-skip", tag.group(0))
            self.assertIn('translate="no"', tag.group(0))
        self.assertIn('class="diff notranslate"', service)
        self.assertIn('translate("/etc/haproxy/haproxy.cfg (on server)")', service)

    def test_apply_result_survives_the_success_reload(self):
        javascript = (APP_DIR / "static" / "js" / "haproxy_config.js").read_text(
            encoding="utf-8"
        )
        template = (APP_DIR / "templates" / "haproxy_config.html").read_text(
            encoding="utf-8"
        )

        self.assertIn("APPLY_RESULT_STORAGE_KEY", javascript)
        self.assertIn("window.sessionStorage.setItem", javascript)
        self.assertIn("function restoreApplyResult()", javascript)
        self.assertIn("renderApplyResult(saved.data, saved.completedAt)", javascript)
        self.assertIn("restoreApplyResult();", javascript)
        self.assertIn("persistApplyResult(data, completedAt);", javascript)
        self.assertIn("function clearDisplayedApplyResult()", javascript)
        self.assertIn('id="apply-result-time"', template)
        self.assertIn("Automatic safety check:", template)

    def test_monitoring_identifiers_and_logs_are_not_translated(self):
        template = (APP_DIR / "templates" / "health.html").read_text(
            encoding="utf-8"
        )
        javascript = (APP_DIR / "static" / "js" / "health.js").read_text(
            encoding="utf-8"
        )

        for element_id in (
            "control-result",
            "logs-title-target",
            "logs-cmd",
            "logs-text",
            "recent-log-body",
        ):
            tag = re.search(rf'<[^>]+id="{element_id}"[^>]*>', template)
            self.assertIsNotNone(tag, element_id)
            self.assertIn("data-i18n-skip", tag.group(0))
            self.assertIn('translate="no"', tag.group(0))

        self.assertIn("function technicalText(value, mono = false)", javascript)
        self.assertIn("function statusIndicator(cls, state, title)", javascript)
        self.assertNotIn('window.t(state)', javascript)
        self.assertIn('return statusIndicator("ok", display ||', javascript)
        self.assertIn('? "loaded" : a), title)', javascript)
        self.assertIn('technicalText(unit, true)', javascript)
        self.assertIn('technicalText(name, true)', javascript)
        self.assertIn('logsTitleTarget.textContent = `${kind} / ${name}`', javascript)
        self.assertIn('new URLSearchParams({ limit: String(limit) })', javascript)
        self.assertIn('query.append("unit", unit)', javascript)
        self.assertIn("if (force) await loadRecentLogs()", javascript)
        self.assertIn('technicalText(e.raw_message || "", true)', javascript)
        self.assertNotIn('technicalText(e.message || "", true)', javascript)
        self.assertIn('uiText("No recent journal entries")', javascript)
        self.assertIn('id="tblRecent"', template)
        self.assertIn('id="recentLimit"', template)
        self.assertIn('id="recentUnitOptions"', template)
        self.assertIn('"haproxy.service"', javascript)
        self.assertIn('"haproxy-healthd.service"', javascript)
        self.assertIn("max-height: 430px", template)
        self.assertIn("scrollbar-gutter: stable", template)

        messages = load_catalog(CATALOG_DIR / "ru.json")["messages"]
        self.assertEqual(
            translate_source("iptables-haproxy-ban.service", messages),
            "iptables-haproxy-ban.service",
        )
        raw_journal = (
            'time="2026-07-14T21:57:23.183669593Z" level=info '
            'msg="stopping restart-manager"'
        )
        self.assertEqual(translate_source(raw_journal, messages), raw_journal)

    def test_authelia_log_rows_are_not_translated(self):
        template = (APP_DIR / "templates" / "authelia_bans.html").read_text(
            encoding="utf-8"
        )

        log_body = re.search(r"<tbody[^>]*>\s*{% for e in logs %}", template)
        self.assertIsNotNone(log_body)
        self.assertIn('class="notranslate"', log_body.group(0))
        self.assertIn('translate="no"', log_body.group(0))
        self.assertIn("data-i18n-skip", log_body.group(0))

    def test_raw_json_messages_bypass_server_localization(self):
        module_path = APP_DIR / "i18n.py"
        fake_flask = types.ModuleType("flask")
        fake_flask.Request = object
        fake_flask.current_app = types.SimpleNamespace(
            json=types.SimpleNamespace(dumps=json.dumps)
        )
        fake_flask.g = types.SimpleNamespace(language="ru")
        fake_flask.has_request_context = lambda: True
        fake_flask.request = types.SimpleNamespace()

        spec = importlib.util.spec_from_file_location(
            "haproxy_admin_i18n_regression", module_path
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)

        with mock.patch.dict(sys.modules, {"flask": fake_flask}):
            spec.loader.exec_module(module)

        raw_message = (
            'time="2026-07-15T01:18:52.473212050+03:00" level=warning '
            'msg="received task-delete event from containerd"'
        )

        class Response:
            is_json = True

            def __init__(self):
                self.payload = {
                    "message": "No recent journal entries",
                    "raw_message": raw_message,
                }
                self.data = ""

            def get_json(self, silent=False):
                return self.payload

            def set_data(self, value):
                self.data = value

        response = module.localize_json_response(Response())
        localized = json.loads(response.data)
        self.assertEqual(localized["message"], "Нет недавних записей журнала")
        self.assertEqual(localized["raw_message"], raw_message)

    def test_haproxy_socket_defaults_never_render_empty(self):
        template_dir = PROJECT_ROOT / "ansible" / "roles" / "haproxy" / "templates"
        environment = Environment(
            loader=FileSystemLoader(str(template_dir)),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        environment.filters["regex_replace"] = (
            lambda value, pattern, replacement: re.sub(
                pattern, replacement, str(value)
            )
        )
        environment.filters["combine"] = (
            lambda value, other, recursive=False: {
                **dict(value or {}),
                **dict(other or {}),
            }
        )

        rendered = environment.get_template("haproxy.cfg.j2").render(
            sites=[], tcp_proxies=[], ansible_processor_vcpus=1
        )

        self.assertIn(
            "stats socket /run/haproxy/admin.sock mode 660 user root "
            "group hadmin level admin expose-fd listeners",
            rendered,
        )

    def test_required_catalogs_are_valid(self):
        for code in ("en", "ru"):
            catalog = load_catalog(CATALOG_DIR / f"{code}.json")
            self.assertEqual(catalog["meta"]["code"], code)
            self.assertTrue(catalog["meta"]["label"])
            self.assertIsInstance(catalog["messages"], dict)
            self.assertTrue(all(
                isinstance(key, str) and isinstance(value, str)
                for key, value in catalog["messages"].items()
            ))

    def test_english_is_the_canonical_source_language(self):
        messages = load_catalog(CATALOG_DIR / "en.json")["messages"]
        self.assertEqual(messages, {})

    def test_russian_catalog_covers_core_navigation(self):
        messages = load_catalog(CATALOG_DIR / "ru.json")["messages"]
        expected = {
            "Home": "Главная",
            "HTTP sites": "HTTP-сайты",
            "TCP proxies": "TCP-прокси",
            "HAProxy configuration": "Конфигурация HAProxy",
            "Certificates": "Сертификаты",
            "Status": "Статус",
            "Interface language": "Язык интерфейса",
        }
        for source, translation in expected.items():
            self.assertEqual(messages[source], translation)

    def test_reserved_domain_error_recommends_internal_ca_in_russian(self):
        messages = load_catalog(CATALOG_DIR / "ru.json")["messages"]
        translated = translate_source(
            "Let's Encrypt cannot issue certificates for reserved/private domains: "
            "app.example.test. Select Internal CA for this site.",
            messages,
        )
        self.assertIn("не может выпускать сертификаты", translated)
        self.assertIn("Выберите Internal CA", translated)

    def test_catalog_metadata_matches_filename(self):
        catalogs = list(CATALOG_DIR.rglob("*.json"))
        self.assertGreaterEqual(len(catalogs), 2)
        for path in catalogs:
            catalog = load_catalog(path)
            expected_code = path.stem if path.parent == CATALOG_DIR else path.parent.name
            self.assertEqual(catalog["meta"]["code"], expected_code)

    def test_catalog_fragments_do_not_duplicate_keys(self):
        keys_by_language = {}
        for path in CATALOG_DIR.rglob("*.json"):
            catalog = load_catalog(path)
            code = catalog["meta"]["code"]
            seen = keys_by_language.setdefault(code, set())
            duplicates = seen & catalog["messages"].keys()
            self.assertEqual(duplicates, set(), f"Duplicate {code} keys in {path}")
            seen.update(catalog["messages"])

    def test_templates_and_browser_messages_use_english_source(self):
        missing = []
        for path, fragment in (*template_ui_fragments(), *javascript_ui_fragments()):
            if CYRILLIC.search(fragment):
                missing.append(f"{path}: {fragment}")
        self.assertEqual(missing, [], "Non-English UI source:\n" + "\n".join(missing))

    def test_python_runtime_messages_use_english_source(self):
        missing = [
            f"{path}:{line}: {value}"
            for path, line, value in python_runtime_strings()
        ]
        self.assertEqual(
            missing, [], "Non-English Python runtime strings:\n" + "\n".join(missing)
        )


class I18nPayloadDeliveryTests(unittest.TestCase):
    """The catalog must ship as a cacheable asset, not inlined on every page."""

    APP_INIT = APP_DIR / "__init__.py"
    BASE_TEMPLATE = APP_DIR / "templates" / "base.html"

    def test_base_template_loads_catalog_as_external_script_before_i18n_js(self):
        html = self.BASE_TEMPLATE.read_text(encoding="utf-8")
        self.assertRegex(html, r'<script src="\{\{\s*i18n_messages_url\s*\}\}"')
        # It must load before i18n.js, which reads HAPROXY_ADMIN_I18N.messages.
        self.assertLess(html.index("i18n_messages_url"), html.index("js/i18n.js"))

    def test_context_processor_no_longer_inlines_the_catalog(self):
        source = self.APP_INIT.read_text(encoding="utf-8")
        self.assertIn('"i18n_config"', source)
        start = source.index('"i18n_config"')
        # The i18n_config dict must no longer carry the heavy messages catalog.
        self.assertNotIn('"messages"', source[start:start + 400])

    def test_catalog_route_is_immutable_utf8_and_gzipped(self):
        source = self.APP_INIT.read_text(encoding="utf-8")
        self.assertIn('"/i18n/messages.js"', source)
        self.assertIn('endpoint="i18n_messages"', source)
        self.assertIn("public, max-age=31536000, immutable", source)
        self.assertIn("ensure_ascii=False", source)
        self.assertIn("gzip.compress", source)


if __name__ == "__main__":
    unittest.main()
