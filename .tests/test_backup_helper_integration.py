"""Installer/helper integration regressions for the backup daemon."""

from __future__ import annotations

import ast
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import types
import unittest
from unittest import mock

import yaml

from easy_ha_proxy import (
    command_apply_restored,
    InstallerError,
    offline_restore_image_preflight,
    offline_restore_required_images,
)


ROOT = Path(__file__).resolve().parents[1]
INSTALLER_PATH = ROOT / "installer/easy_ha_proxy.py"
HELPER_PATH = ROOT / "easy-ha-proxy-helper.sh"
BACKUPD_TASK_PATH = ROOT / "ansible/roles/haproxy-admin/tasks/backupd.yml"
BACKUPD_UNIT_PATH = (
    ROOT / "ansible/roles/haproxy-admin/templates/easy-ha-proxy-backupd.service.j2"
)
BACKUPD_DAEMON_PATH = (
    ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-backupd.py"
)
PLAYBOOK_PATH = ROOT / "ansible/easy-ha-proxy.yml"
INSTALL_LOCAL_PATH = ROOT / "install-local.sh"

INSTALLER = INSTALLER_PATH.read_text(encoding="utf-8")
HELPER = HELPER_PATH.read_text(encoding="utf-8")
BACKUPD_TASK = BACKUPD_TASK_PATH.read_text(encoding="utf-8")
BACKUPD_UNIT = BACKUPD_UNIT_PATH.read_text(encoding="utf-8")
BACKUPD_DAEMON = BACKUPD_DAEMON_PATH.read_text(encoding="utf-8")
PLAYBOOK = PLAYBOOK_PATH.read_text(encoding="utf-8")
INSTALL_LOCAL = INSTALL_LOCAL_PATH.read_text(encoding="utf-8")

RESTORE_NETWORK_TASK_FILES = (
    ROOT / "ansible/roles/cert/tasks/install.yml",
    ROOT / "ansible/roles/cert/tasks/hooks.yml",
    ROOT / "ansible/roles/haproxy/tasks/install.yml",
    ROOT / "ansible/roles/haproxy/tasks/apparmor.yml",
    ROOT / "ansible/roles/docker/tasks/main.yml",
    ROOT / "ansible/roles/geoip_acl/tasks/main.yml",
    ROOT / "ansible/roles/authelia/tasks/install.yml",
    ROOT / "ansible/roles/authelia/tasks/fs.yml",
    ROOT / "ansible/roles/authelia/tasks/usersd.yml",
    ROOT / "ansible/roles/haproxy-admin/tasks/install.yml",
    ROOT / "ansible/roles/haproxy-admin/tasks/certd.yml",
    ROOT / "ansible/roles/haproxy-admin/tasks/controld.yml",
    ROOT / "ansible/roles/haproxy-admin/tasks/iptables-ban.yml",
)

RESTORE_REMOTE_COMMAND_FILES = (
    ROOT / "ansible/roles/cert/tasks/install.yml",
    ROOT / "ansible/roles/docker/tasks/main.yml",
    ROOT / "ansible/roles/docker/tasks/mirror.yml",
    ROOT / "ansible/roles/geoip_acl/tasks/main.yml",
    ROOT / "ansible/roles/authelia/tasks/start.yml",
    ROOT / "ansible/roles/haproxy-admin/tasks/start.yml",
)


def task_tags(value: object) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {str(item) for item in value}
    return set()


def walk_tasks(
    tasks: list[object], inherited_tags: frozenset[str] = frozenset()
) -> list[tuple[dict[str, object], frozenset[str]]]:
    walked: list[tuple[dict[str, object], frozenset[str]]] = []
    for raw in tasks:
        if not isinstance(raw, dict):
            continue
        effective = inherited_tags | frozenset(task_tags(raw.get("tags")))
        walked.append((raw, effective))
        for section in ("block", "rescue", "always"):
            nested = raw.get(section)
            if isinstance(nested, list):
                walked.extend(walk_tasks(nested, effective))
    return walked


def loaded_tasks(path: Path) -> list[tuple[dict[str, object], frozenset[str]]]:
    document = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(document, list):
        raise AssertionError(f"expected an Ansible task list: {path}")
    return walk_tasks(document)


def command_text(task: dict[str, object]) -> str:
    for module in (
        "command",
        "ansible.builtin.command",
        "shell",
        "ansible.builtin.shell",
    ):
        value = task.get(module)
        if isinstance(value, str):
            return value
        if not isinstance(value, dict):
            continue
        command = value.get("cmd")
        if isinstance(command, str):
            return command
        argv = value.get("argv")
        if isinstance(argv, list):
            return " ".join(str(item) for item in argv)
    return ""


def bash_array(name: str) -> list[str]:
    match = re.search(
        rf"(?m)^{re.escape(name)}=\(\n(?P<body>.*?)^\)$",
        HELPER,
        re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"missing bash array: {name}")
    return shlex.split(match.group("body"), comments=True, posix=True)


def installer_tag_values() -> dict[str, str]:
    wanted = {
        "INSTALL_TAGS",
        "UPDATE_TAGS",
        "UI_TAGS",
        "DAEMON_TAGS",
        "HOST_SERVICE_TAGS",
        "RESTORE_TAGS",
        "RESTORE_SKIP_TAGS",
    }
    values: dict[str, str] = {}
    tree = ast.parse(INSTALLER)
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or target.id not in wanted:
            continue
        expression = ast.Expression(body=node.value)
        ast.fix_missing_locations(expression)
        values[target.id] = eval(  # noqa: S307 - fixed repository source only
            compile(expression, str(INSTALLER_PATH), "eval"),
            {"__builtins__": {}},
            values,
        )
    missing = wanted - values.keys()
    if missing:
        raise AssertionError(f"missing installer tag assignments: {sorted(missing)}")
    return values


class BackupInstallerTagTests(unittest.TestCase):
    def test_offline_restore_preparation_cannot_run_dependency_managers(self) -> None:
        self.assertIn(
            'die "--skip-bootstrap-dependencies is only valid with --prepare-only"',
            INSTALL_LOCAL,
        )
        self.assertIn(
            'die "--skip-bootstrap-dependencies requires '
            'EASY_HA_PROXY_USE_EXISTING_SOURCE=true"',
            INSTALL_LOCAL,
        )

        apt_gate = 'if [[ "${skip_bootstrap_dependencies}" != "true" ]]; then'
        apt_block = INSTALL_LOCAL.split(apt_gate, maxsplit=1)[1].split(
            "\nfi", maxsplit=1
        )[0]
        self.assertIn("apt-get update", apt_block)
        self.assertIn("apt-get install", apt_block)
        self.assertEqual(INSTALL_LOCAL.count("apt-get update"), 1)
        self.assertEqual(INSTALL_LOCAL.count("apt-get install"), 1)

        controller_gate = (
            'if [[ "${skip_bootstrap_dependencies}" == "true" ]]; then'
        )
        controller_section = INSTALL_LOCAL.split(controller_gate, maxsplit=2)[-1]
        offline_branch, dependency_branch = controller_section.split(
            "\nelse\n", maxsplit=1
        )
        self.assertIn("Reusing the prepared Python and Ansible control plane", offline_branch)
        for command in ("python3 -m venv", "/bin/pip", "ansible-galaxy"):
            with self.subTest(command=command):
                self.assertNotIn(command, offline_branch)
                self.assertIn(command, dependency_branch)

    def test_full_restore_wrapper_requests_exact_managed_replacement(self) -> None:
        tree = ast.parse(INSTALLER)
        function = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "command_restore_full"
        )
        constants = {
            node.value
            for node in ast.walk(function)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        self.assertIn("--replace-managed", constants)

    def test_every_reconciliation_path_deploys_backupd(self) -> None:
        values = installer_tag_values()
        for name in (
            "INSTALL_TAGS",
            "UPDATE_TAGS",
            "UI_TAGS",
            "HOST_SERVICE_TAGS",
            "RESTORE_TAGS",
        ):
            with self.subTest(name=name):
                self.assertIn("ha-adm-backupd", values[name].split(","))

        # The targeted daemon component deliberately retains the aggregate
        # role tag; backupd.yml is imported by that aggregate stage as well.
        self.assertIn("ha-adm-daemons", values["DAEMON_TAGS"].split(","))
        self.assertIn('"daemons": DAEMON_TAGS', INSTALLER)
        self.assertIn('"services": HOST_SERVICE_TAGS', INSTALLER)

    def test_dedicated_playbook_stage_matches_the_installer_tag(self) -> None:
        self.assertRegex(
            PLAYBOOK,
            r"(?s)- role: haproxy-admin\s+task_stage: backupd\s+tags: ha-adm-backupd",
        )

    def test_apply_restored_skips_every_restore_network_task(self) -> None:
        values = installer_tag_values()
        self.assertEqual(values["RESTORE_SKIP_TAGS"], "restore-network")
        restore_block = INSTALLER.split(
            "def command_apply_restored", maxsplit=1
        )[1].split("def command_configure", maxsplit=1)[0]
        self.assertIn("skip_tags=RESTORE_SKIP_TAGS", restore_block)
        self.assertIn(
            'extra_vars["easy_ha_proxy_offline_restore"] = "true"',
            restore_block,
        )
        self.assertIn('command.extend(("--skip-tags", skip_tags))', INSTALLER)

        health_defaults = (
            ROOT / "ansible/roles/healthcheck/defaults/main.yml"
        ).read_text(encoding="utf-8")
        geoip_timer = health_defaults.split(
            '- name: "easy-ha-proxy-geoip-update.timer"', maxsplit=1
        )[1].split('- name:', maxsplit=1)[0]
        self.assertIn("easy_ha_proxy_offline_restore", geoip_timer)
        self.assertIn("if offline:", restore_block)
        self.assertIn(
            "skip_tags=RESTORE_SKIP_TAGS if offline else None",
            restore_block,
        )
        # Both the full and the configuration-scope apply-restored branches
        # must apply the same offline network-skip policy.
        self.assertEqual(
            INSTALLER.count("skip_tags=RESTORE_SKIP_TAGS if offline else None"), 2
        )
        self.assertIn('"EASY_HA_PROXY_OFFLINE_RESTORE": "1"', BACKUPD_DAEMON)

    def test_apply_restored_network_policy_is_explicit_per_caller(self) -> None:
        directory = Path("/etc/easy-ha-proxy")
        with (
            mock.patch("easy_ha_proxy.require_root"),
            mock.patch("easy_ha_proxy.config_dir", return_value=directory),
            mock.patch("easy_ha_proxy.ensure_security_secrets"),
            mock.patch("easy_ha_proxy.syntax_check"),
            mock.patch("easy_ha_proxy.offline_restore_image_preflight") as preflight,
            mock.patch("easy_ha_proxy.run_playbook") as run_playbook,
        ):
            command_apply_restored(types.SimpleNamespace(offline=False))
            online_call = run_playbook.call_args
            run_playbook.reset_mock()
            command_apply_restored(types.SimpleNamespace(offline=True))
            offline_call = run_playbook.call_args

        self.assertEqual(online_call.kwargs["skip_tags"], None)
        self.assertNotIn(
            "easy_ha_proxy_offline_restore",
            online_call.kwargs["extra_vars"],
        )
        preflight.assert_called_once_with(directory=directory)
        self.assertEqual(offline_call.kwargs["skip_tags"], "restore-network")
        self.assertEqual(
            offline_call.kwargs["extra_vars"]["easy_ha_proxy_offline_restore"],
            "true",
        )

    def test_restore_selected_dependency_managers_are_skippable(self) -> None:
        dependency_modules = {
            "apt",
            "package",
            "pip",
            "get_url",
            "ansible.builtin.apt",
            "ansible.builtin.package",
            "ansible.builtin.pip",
            "ansible.builtin.get_url",
        }
        found: list[str] = []
        for path in RESTORE_NETWORK_TASK_FILES:
            for task, effective_tags in loaded_tasks(path):
                module = next(
                    (name for name in dependency_modules if name in task),
                    None,
                )
                if module is None:
                    continue
                label = f"{path.relative_to(ROOT)}: {task.get('name', module)}"
                found.append(label)
                with self.subTest(task=label):
                    self.assertIn("restore-network", effective_tags)
        self.assertGreaterEqual(len(found), 15)

    def test_restore_selected_remote_commands_are_skippable(self) -> None:
        found: list[str] = []
        for path in RESTORE_REMOTE_COMMAND_FILES:
            for task, effective_tags in loaded_tasks(path):
                command = " ".join(command_text(task).lower().split())
                remote = (
                    "snap install" in command
                    or re.search(r"\bdocker(?: compose)? pull\b", command)
                    or (
                        "systemctl start easy-ha-proxy-geoip-update.service"
                        in command
                    )
                )
                if not remote:
                    continue
                label = f"{path.relative_to(ROOT)}: {task.get('name', command)}"
                found.append(label)
                with self.subTest(task=label):
                    self.assertIn("restore-network", effective_tags)
        self.assertGreaterEqual(len(found), 7)

        authelia_install = loaded_tasks(
            ROOT / "ansible/roles/authelia/tasks/install.yml"
        )
        ntp_recovery = next(
            effective_tags
            for task, effective_tags in authelia_install
            if task.get("name")
            == "Synchronize the host clock when it has drifted"
        )
        # Deliberately NOT restore-network: the offline web restore skips that
        # tag, yet the final clock assert still runs and Authelia refuses to
        # start without NTP sync, so the recovery must stay available there.
        self.assertNotIn("restore-network", ntp_recovery)
        geoip_tasks = loaded_tasks(
            ROOT / "ansible/roles/geoip_acl/tasks/main.yml"
        )
        geoip_timer = next(
            effective_tags
            for task, effective_tags in geoip_tasks
            if task.get("name") == "Enable or disable the local GeoIP update timer"
        )
        self.assertIn("restore-network", geoip_timer)

    def test_offline_compose_operations_cannot_pull_implicitly(self) -> None:
        authelia_check = (
            ROOT / "ansible/roles/authelia/tasks/check.yml"
        ).read_text(encoding="utf-8")
        authelia_start = (
            ROOT / "ansible/roles/authelia/tasks/start.yml"
        ).read_text(encoding="utf-8")
        relay_spool = (
            ROOT / "ansible/roles/authelia/tasks/mail_relay_spool.yml"
        ).read_text(encoding="utf-8")
        admin_start = (
            ROOT / "ansible/roles/haproxy-admin/tasks/start.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("easy_ha_proxy_offline_restore", authelia_check)
        self.assertIn("--pull=never", authelia_check)
        for source in (authelia_start, relay_spool, admin_start):
            with self.subTest(source=source[:60]):
                self.assertIn("easy_ha_proxy_offline_restore", source)
                self.assertRegex(source, r"--pull(?:'\s*,\s*'| )never")


class OfflineRestoreImagePreflightTests(unittest.TestCase):
    def test_current_recovery_defaults_drive_the_image_preflight_set(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config"
            source = root / "source"
            admin_role = source / "ansible/roles/haproxy-admin"
            authelia_role = source / "ansible/roles/authelia"
            for role in (admin_role, authelia_role):
                (role / "defaults").mkdir(parents=True)
                (role / "templates").mkdir(parents=True)
            config.mkdir()
            (config / "vars.yml").write_text(
                "haproxy_admin_image: managed/admin:alpha\n"
                "mail_notify_enabled: true\n",
                encoding="utf-8",
            )
            (config / "authelia.yml").write_text(
                "authelia_enabled: true\n",
                encoding="utf-8",
            )
            (admin_role / "defaults/main.yml").write_text(
                "haproxy_admin_use_docker: true\n"
                "haproxy_admin_image: source/admin:latest\n",
                encoding="utf-8",
            )
            (authelia_role / "defaults/main.yml").write_text(
                "authelia_version: '9.9.9'\n"
                "authelia_session_redis_enabled: true\n"
                "authelia_redis_image: redis:9-alpine\n"
                "mail_relay_image: relay:9\n",
                encoding="utf-8",
            )
            (admin_role / "templates/docker-compose.yml.j2").write_text(
                'services:\n  app:\n    image: "{{ haproxy_admin_image }}"\n',
                encoding="utf-8",
            )
            (authelia_role / "templates/docker-compose.yml.j2").write_text(
                "services:\n"
                "  redis:\n"
                "    image: {{ authelia_redis_image }}\n"
                "  relay:\n"
                "    image: {{ mail_relay_image }}\n"
                "  authelia:\n"
                "    image: authelia/authelia:{{ authelia_version }}\n",
                encoding="utf-8",
            )

            images = offline_restore_required_images(
                directory=config,
                controller_source=source,
            )

        self.assertEqual(
            images,
            {
                "managed/admin:alpha",
                "authelia/authelia:9.9.9",
                "redis:9-alpine",
                "relay:9",
            },
        )

    def test_missing_local_image_fails_before_restore_playbook(self) -> None:
        inspect_result = subprocess.CompletedProcess([], 1)
        with (
            mock.patch("easy_ha_proxy.shutil.which", return_value="/usr/bin/docker"),
            mock.patch(
                "easy_ha_proxy.subprocess.run",
                return_value=inspect_result,
            ) as run_command,
            self.assertRaisesRegex(
                InstallerError,
                r"required Docker images are not available locally: "
                r"example/app:restored",
            ),
        ):
            offline_restore_image_preflight(
                required_images={"example/app:restored"}
            )

        self.assertEqual(run_command.call_count, 1)
        self.assertEqual(
            run_command.call_args.args[0],
            ["/usr/bin/docker", "image", "inspect", "example/app:restored"],
        )


class BackupHelperDaemonInventoryTests(unittest.TestCase):
    def test_backupd_unit_can_render_during_standalone_healthcheck(self) -> None:
        """Every role-private backupd setting needs an inline fallback.

        The healthcheck role hashes the rendered unit through the template
        lookup plugin, but haproxy-admin role defaults are not guaranteed to
        be in scope during a standalone status run.
        """
        references = set(re.findall(r"\b(backupd_[a-z0-9_]+)\b", BACKUPD_UNIT))
        self.assertTrue(references)
        for name in sorted(references):
            with self.subTest(variable=name):
                expressions = re.findall(
                    rf"\{{\{{[^}}]*\b{re.escape(name)}\b[^}}]*\}}\}}",
                    BACKUPD_UNIT,
                )
                self.assertTrue(expressions, f"missing Jinja expression for {name}")
                self.assertTrue(
                    all(re.search(r"\|\s*default\s*\(", expr) for expr in expressions),
                    f"{name} must have an inline default in every expression",
                )

    def test_parallel_daemon_arrays_have_matching_backupd_entry(self) -> None:
        units = bash_array("daemon_units")
        labels = bash_array("daemon_labels")
        scripts = bash_array("daemon_scripts")
        sources = bash_array("daemon_sources")
        self.assertEqual(len(units), len(labels))
        self.assertEqual(len(units), len(scripts))
        self.assertEqual(len(units), len(sources))

        index = units.index("easy-ha-proxy-backupd.service")
        self.assertEqual(labels[index], "Full backup and restore daemon")
        self.assertEqual(
            scripts[index],
            "/usr/local/sbin/easy-ha-proxy-backupd.py",
        )
        self.assertEqual(
            sources[index],
            "ansible/roles/haproxy-admin/files/easy-ha-proxy-backupd.py",
        )

        # Assert against the actual Ansible install contract rather than
        # allowing the helper inventory to drift independently.
        self.assertIn("src: easy-ha-proxy-backupd.py", BACKUPD_TASK)
        self.assertIn("dest: /usr/local/sbin/easy-ha-proxy-backupd.py", BACKUPD_TASK)
        self.assertIn("dest: /etc/systemd/system/easy-ha-proxy-backupd.service", BACKUPD_TASK)

    def test_missing_new_daemon_is_update_drift(self) -> None:
        function = HELPER.split("daemon_updates_available() {", maxsplit=1)[1].split(
            "show_daemon_versions() {", maxsplit=1
        )[0]
        source_guard = '[[ -f "${comparison_root}/${daemon_sources[i]}" ]] || continue'
        missing_unit = (
            '! systemctl cat "${daemon_units[i]}" >/dev/null 2>&1; then\n'
            "      return 0"
        )
        self.assertIn(source_guard, function)
        self.assertIn(missing_unit, function)
        self.assertLess(function.index(source_guard), function.index(missing_unit))

    def test_old_install_detection_does_not_require_backupd(self) -> None:
        match = re.search(
            r"(?s)elif \[\[ -e /etc/systemd/system/haproxy-certd\.service &&"
            r"(?P<condition>.*?)\]\]; then\n"
            r"\s+# Backward compatibility for installations created before completion",
            HELPER,
        )
        self.assertIsNotNone(match)
        condition = match.group("condition")
        self.assertIn("haproxy-controld.service", condition)
        self.assertIn("/etc/haproxy/haproxy.cfg", condition)
        self.assertIn("/opt/haproxy-admin/docker-compose.yml", condition)
        self.assertIn("/opt/authelia/docker-compose.yml", condition)
        self.assertNotIn("backupd", condition)


if __name__ == "__main__":
    unittest.main()
