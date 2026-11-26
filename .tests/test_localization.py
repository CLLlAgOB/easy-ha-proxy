"""Regression checks for installer and Authelia notification localization."""

from __future__ import annotations

from pathlib import Path
import re
import unittest


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
        i18n = (ROOT / "go/agent/internal/cli/i18n.go").read_text(encoding="utf-8")
        wizard = (ROOT / "go/agent/internal/cli/wizard.go").read_text(encoding="utf-8")
        self.assertIn('os.Getenv("EASY_HA_PROXY_LANGUAGE")', i18n)
        self.assertIn('"authelia_notification_language", lang', wizard)
        self.assertIn('"haproxy_admin_default_language", lang', wizard)

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
        self.assertIn('authelia_notification_language: "en"', defaults)

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
