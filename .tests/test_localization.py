"""Regression checks for installer and Authelia notification localization."""

from __future__ import annotations

from pathlib import Path
import re
import tempfile
import unittest
from argparse import Namespace
from unittest import mock

import yaml

from easy_ha_proxy import LANGUAGE_TAGS, command_language


ROOT = Path(__file__).resolve().parents[1]
AUTHELIA_ROLE = ROOT / "ansible" / "roles" / "authelia"
CYRILLIC = re.compile(r"[А-Яа-яЁё]")


class InstallerLocalizationTests(unittest.TestCase):
    def test_argument_free_bootstrap_offers_english_and_russian(self) -> None:
        source = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn('language="${language_from_env:-en}"', source)
        self.assertIn("Select language / Выберите язык:", source)
        self.assertIn('if [[ -z "${mode}" && -z "${language_from_env}" ]]', source)
        self.assertIn("select_language", source)

    def test_installed_menu_prioritizes_update_workflow(self) -> None:
        source = (ROOT / "easy-ha-proxy-helper.sh").read_text(encoding="utf-8")
        main_menu = source.split("menu_installed() {", 1)[1]
        self.assertIn("1) Check for updates and install selected items", main_menu)
        self.assertIn("2) Check for updates only", main_menu)
        self.assertIn("6) Advanced operations", main_menu)
        self.assertIn("1) perform_action smart-update", main_menu)
        self.assertIn("6) menu_installed_advanced", main_menu)

    def test_interrupted_installation_has_resume_and_restart_actions(self) -> None:
        source = (ROOT / "easy-ha-proxy-helper.sh").read_text(encoding="utf-8")
        partial_menu = source.split("menu_partial() {", 1)[1].split(
            "menu_legacy() {", 1
        )[0]

        self.assertIn("installation_complete:", source)
        self.assertIn("configuration_pending:", source)
        self.assertIn(
            "Продолжить установку с сохранённой конфигурацией",
            partial_menu,
        )
        self.assertIn("perform_action install-reset", partial_menu)
        self.assertIn("perform_action install-test-reset", partial_menu)
        self.assertIn("Системные службы (справочно", source)

    def test_test_mode_menu_offers_production_promotion(self) -> None:
        source = (ROOT / "easy-ha-proxy-helper.sh").read_text(encoding="utf-8")
        self.assertIn("promote-production", source)
        self.assertIn(
            "Перевести тестовую установку в production без переустановки",
            source,
        )

    def test_remote_installer_accepts_explicit_language(self) -> None:
        source = (ROOT / "install-remote.sh").read_text(encoding="utf-8")
        self.assertIn("--language CODE", source)
        self.assertIn("configure|language|migrate-domain", source)
        self.assertIn("EASY_HA_PROXY_LANGUAGE=${language}", source)
        self.assertIn("language|promote-production)", source)
        self.assertIn('if [[ "${activate_current_source}" == true ]]', source)
        self.assertIn("source.before-${remote_action}.", source)
        self.assertIn('build_source_archive "${source_root}"', source)

    def test_remote_connection_detects_stale_installer_source(self) -> None:
        remote = (ROOT / "install-remote.sh").read_text(encoding="utf-8")
        helper = (ROOT / "easy-ha-proxy-helper.sh").read_text(encoding="utf-8")

        self.assertIn("installer_fingerprint()", remote)
        self.assertIn("local_installer_fingerprint", remote)
        self.assertIn("remote_installer_fingerprint", remote)
        self.assertIn(
            "Загрузить текущие локальные исходники перед продолжением? [Y/n]",
            remote,
        )
        self.assertIn('source_channel="local"', remote)
        self.assertIn(
            'if [[ "${source_channel}" == "github" ]]',
            helper,
        )
        self.assertIn("Обновляю управляемые исходники из GitHub", helper)

    def test_configuration_wizard_persists_selected_language(self) -> None:
        source = (ROOT / "installer" / "easy_ha_proxy.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'INSTALLER_LANGUAGE = os.environ.get("EASY_HA_PROXY_LANGUAGE", "en")',
            source,
        )
        self.assertIn(
            '"authelia_notification_language": INSTALLER_LANGUAGE', source
        )
        self.assertIn(
            '"haproxy_admin_default_language": INSTALLER_LANGUAGE', source
        )

    def test_authelia_has_complete_english_and_russian_template_sets(self) -> None:
        template_dir = AUTHELIA_ROLE / "templates"
        stems = (
            "Event.html",
            "Event.txt",
            "IdentityVerificationJWT.html",
            "IdentityVerificationJWT.txt",
            "IdentityVerificationOTC.html",
            "IdentityVerificationOTC.txt",
        )
        for stem in stems:
            english = template_dir / f"{stem}.en.j2"
            russian = template_dir / f"{stem}.ru.j2"
            self.assertTrue(english.is_file(), english)
            self.assertTrue(russian.is_file(), russian)
            self.assertNotRegex(english.read_text(encoding="utf-8"), CYRILLIC)
            self.assertRegex(russian.read_text(encoding="utf-8"), CYRILLIC)

    def test_authelia_role_selects_language_dynamically(self) -> None:
        defaults = (AUTHELIA_ROLE / "defaults" / "main.yml").read_text(
            encoding="utf-8"
        )
        tasks = (AUTHELIA_ROLE / "tasks" / "install.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn('authelia_notification_language: "en"', defaults)
        self.assertIn("authelia_notification_language in ['en', 'ru']", tasks)
        self.assertEqual(tasks.count("{{ authelia_notification_language }}.j2"), 6)
        self.assertEqual(tasks.count("authelia_notification_language | upper"), 6)

    def test_language_command_updates_all_stack_preferences(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "vars.yml").write_text(
                "root_domain: example.test\n", encoding="utf-8"
            )
            (directory / "authelia.yml").write_text(
                "authelia_notification_language: en\n", encoding="utf-8"
            )
            (directory / "metadata.yml").write_text(
                "installer_language: en\n", encoding="utf-8"
            )
            with (
                mock.patch("easy_ha_proxy.require_root"),
                mock.patch("easy_ha_proxy.config_dir", return_value=directory),
                mock.patch("easy_ha_proxy.backup_configuration"),
                mock.patch("easy_ha_proxy.syntax_check") as syntax_check,
                mock.patch("easy_ha_proxy.run_playbook") as run_playbook,
            ):
                command_language(Namespace(language="ru", apply=True))

            variables = yaml.safe_load((directory / "vars.yml").read_text())
            authelia = yaml.safe_load((directory / "authelia.yml").read_text())
            metadata = yaml.safe_load((directory / "metadata.yml").read_text())
            self.assertEqual(variables["haproxy_admin_default_language"], "ru")
            self.assertEqual(authelia["authelia_notification_language"], "ru")
            self.assertIn("Уведомление безопасности", authelia["mail_subject"])
            self.assertEqual(metadata["installer_language"], "ru")
            syntax_check.assert_called_once_with(directory)
            self.assertEqual(run_playbook.call_args.args[0], LANGUAGE_TAGS)

    def test_primary_ansible_and_localization_comments_are_english(self) -> None:
        paths = (
            ROOT / "ansible" / "authelia.yml",
            ROOT / "ansible" / "easy-ha-proxy.yml",
            AUTHELIA_ROLE / "defaults" / "main.yml",
            AUTHELIA_ROLE / "tasks" / "install.yml",
            ROOT / "ansible" / "roles" / "haproxy-admin" / "defaults" / "main.yml",
            ROOT / "ansible" / "roles" / "haproxy-admin" / "templates" / "haproxy-admin.env.j2",
            ROOT / "ansible" / "roles" / "haproxy-admin" / "templates" / "docker-compose.yml.j2",
            ROOT / "docker" / "app" / "haproxy_admin" / "i18n.py",
            ROOT / "docker" / "app" / "haproxy_admin" / "__init__.py",
        )
        failures = []
        for path in paths:
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if line.lstrip().startswith("#") and CYRILLIC.search(line):
                    failures.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()}")
        self.assertEqual(failures, [], "Non-English comments:\n" + "\n".join(failures))

    def test_ansible_task_names_are_english(self) -> None:
        failures = []
        ansible_dir = ROOT / "ansible"
        paths = sorted((*ansible_dir.rglob("*.yml"), *ansible_dir.rglob("*.yaml")))
        for path in paths:
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if re.match(r"^\s*-\s+name:\s*", line) and CYRILLIC.search(line):
                    failures.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()}")
        self.assertEqual(
            failures,
            [],
            "Non-English Ansible task names:\n" + "\n".join(failures),
        )


if __name__ == "__main__":
    unittest.main()
