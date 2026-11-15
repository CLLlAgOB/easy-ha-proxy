"""Ordinary APT upgrades cannot bypass HAProxy or unattended runtime guards."""
from __future__ import annotations

import importlib.util
from contextlib import ExitStack
import json
import os
import shlex
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from jinja2 import Environment
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'installer'))
import os_upgrade_guard as guard  # noqa: E402


def installed(package, old, new):
    return f'Inst {package}' + (f' [{old}]' if old else '') + f' ({new} repository [amd64])\n'


class PackageSafety(unittest.TestCase):
    def test_ansible_passes_the_flag_and_state_path_without_shell_splitting(self):
        tasks = yaml.safe_load((ROOT / 'ansible/roles/update_packages/tasks/main.yml').read_text())
        task = next(t for t in tasks if 'ansible.builtin.script' in t)
        environment = Environment()
        environment.filters['quote'] = shlex.quote
        environment.filters['bool'] = bool
        for automatic in (False, True):
            command = environment.from_string(task['ansible.builtin.script']['cmd']).render(
                playbook_dir='/source with spaces/ansible', updated_state_root='/state with spaces',
                easy_ha_proxy_automatic_os_upgrade=automatic)
            argv = shlex.split(command)
            self.assertEqual(argv[0], '/source with spaces/ansible/../installer/os_upgrade_guard.py')
            self.assertEqual('--automatic' in argv, automatic)
            self.assertEqual(argv[-2:], ['--state-root', '/state with spaces/os-security'])

    def test_haproxy_holds_apply_on_every_supported_distribution(self):
        task = yaml.safe_load((ROOT / 'ansible/roles/haproxy/tasks/protection.yml').read_text())[0]
        expression = Environment().compile_expression(task['when'])
        for distro, version in (('Debian', '12'), ('Debian', '13'), ('Ubuntu', '22.04'), ('Ubuntu', '24.04')):
            self.assertTrue(expression(ansible_os_family='Debian', ansible_distribution=distro,
                                       ansible_distribution_version=version))

    def test_unheld_haproxy_is_refused_even_if_not_selected_for_upgrade(self):
        for package in guard.HAPROXY_PACKAGES:
            with self.subTest(package=package), self.assertRaisesRegex(guard.UpgradeRefused, 'protection'):
                guard.validate(f'{package}\tinstall\n', installed('libc6', '2.36', '2.36.1'))

    def test_no_haproxy_candidate_can_escape_through_the_os_component(self):
        for automatic in (False, True):
            for package in guard.HAPROXY_PACKAGES:
                with self.subTest(package=package, automatic=automatic), self.assertRaisesRegex(guard.UpgradeRefused, 'separately'):
                    guard.validate(f'{package}\thold\n', installed(package, '2.6.12', '2.6.13'), automatic=automatic)

    def test_runtime_patches_are_accepted_including_epochs_and_distribution_suffixes(self):
        for package, old, new in (
            ('docker-ce', '5:28.5.1-1~ubuntu.24.04~noble', '5:28.5.2-1~ubuntu.24.04~noble'),
            ('docker.io:amd64', '26.1.3+dfsg1-1', '26.1.4+dfsg1-1'),
            ('containerd.io', '1.7.28-1', '1.7.29-1'), ('runc', '1.2.1-1', '1.2.2-1'),
        ):
            with self.subTest(package=package):
                self.assertEqual(guard.validate('', installed(package, old, new), automatic=True), [package])

    def test_new_release_lines_unknown_versions_and_new_runtimes_need_manual_review(self):
        for package in guard.RUNTIME_PACKAGES:
            for old, new in (('5:28.5.1', '5:29.0.0'), ('1.7.1', '1.8.0'), ('1.7.1', '2.0.0'),
                             ('1.7.1', '1:1.7.2'), ('unreadable', '1.7.2'), ('1.7.1', '1.7.2~rc1'),
                             ('1.7.1', '1.7.2-rc.1'), (None, '1.7.2')):
                simulation = installed(package, old, new)
                with self.subTest(package=package, old=old, new=new):
                    with self.assertRaisesRegex(guard.UpgradeRefused, 'manual review'):
                        guard.validate('', simulation, automatic=True)
                    self.assertEqual(guard.validate('', simulation), [])

    def test_removals_and_malformed_candidates_fail_closed(self):
        for simulation in ('Remv openssh-server [1.0]\n', 'Inst docker-ce unreadable\n'):
            with self.assertRaises(guard.UpgradeRefused):
                guard.validate('', simulation, automatic=True)


@unittest.skipUnless(os.name == 'posix', 'atomic Linux installation record')
class Preflight(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / 'os-security'
        self.record = self.root / 'package-install.json'

    def test_refusal_never_records_an_installation_or_runs_a_mutating_command(self):
        with patch.object(guard, 'run', side_effect=['haproxy\thold\n', installed('docker-ce', '28.5.1', '29.0.0')]) as run:
            with self.assertRaisesRegex(guard.UpgradeRefused, 'manual review'):
                guard.prepare(automatic=True, root=self.root)
        self.assertFalse(self.record.exists())
        self.assertEqual([call.args[0] for call in run.call_args_list], [
            ['/usr/bin/dpkg', '--get-selections'], ['/usr/bin/apt-get', '-s', '--with-new-pkgs', 'upgrade']])

    def test_live_restore_must_be_verified_before_automatic_runtime_updates(self):
        for answer in ('false\n', 'unreadable\n'):
            with patch.object(guard, 'run', side_effect=['', installed('containerd.io', '1.7.1', '1.7.2'), answer]):
                with self.assertRaisesRegex(guard.UpgradeRefused, 'live-restore'):
                    guard.prepare(automatic=True, root=self.root)
            self.assertFalse(self.record.exists())

    def test_patches_record_before_apt_and_do_not_overwrite_security_status(self):
        self.root.mkdir()
        status = self.root / 'status.json'
        status.write_text('{"last_install_at":10}')
        with patch.object(guard, 'run', side_effect=['', installed('docker-ce', '28.5.1', '28.5.2'), 'true\n']):
            with patch.object(guard.time, 'time', return_value=1234):
                guard.prepare(automatic=True, root=self.root)
        self.assertEqual(json.loads(self.record.read_text()), {'last_install_attempt': 1234})
        self.assertEqual(self.record.stat().st_mode & 0o777, 0o600)
        self.assertEqual(status.read_text(), '{"last_install_at":10}')

    def test_manual_upgrade_does_not_require_a_running_docker_daemon(self):
        with patch.object(guard, 'run', side_effect=['', installed('docker-ce', '28.5.1', '29.0.0')]) as run:
            guard.prepare(root=self.root)
        self.assertEqual(run.call_count, 2)
        self.assertTrue(self.record.exists())


@unittest.skipUnless(sys.platform == 'linux', 'Linux update broker')
class ScheduledWorker(unittest.TestCase):
    def test_cli_carries_the_automatic_policy_into_the_os_playbook(self):
        import easy_ha_proxy as cli
        for automatic in (False, True):
            argv = ['update', '--component', 'os', '--source-channel', 'local']
            if automatic:
                argv.append('--automatic-os')
            args = cli.build_parser().parse_args(argv)
            with ExitStack() as stack:
                for name in ('require_root', 'hold_maintenance_lock', 'ensure_security_secrets',
                             'persist_deployment_channels', 'sync_runtime_haproxy_config_to_managed',
                             'sync_runtime_authelia_rules_to_managed', 'syntax_check', 'mark_installation_complete'):
                    stack.enter_context(patch.object(cli, name))
                stack.enter_context(patch.object(cli, 'managed_configuration_is_pending', return_value=False))
                stack.enter_context(patch.object(cli, 'config_dir', return_value=Path('/unused')))
                stack.enter_context(patch.dict(os.environ, {cli.UPDATE_SOURCE_REFRESHED_ENV: ''}))
                playbook = stack.enter_context(patch.object(cli, 'run_playbook'))
                cli.command_update(args)
            playbook.assert_called_once_with('upgrade,status', extra_vars=(
                {'easy_ha_proxy_automatic_os_upgrade': True} if automatic else None))
        args = cli.build_parser().parse_args(['update', '--component', 'all', '--automatic-os'])
        with patch.object(cli, 'require_root'), patch.object(cli, 'hold_maintenance_lock'):
            with self.assertRaisesRegex(cli.InstallerError, 'os component'):
                cli.command_update(args)

    def test_only_scheduled_os_commands_receive_the_automatic_guard(self):
        spec = importlib.util.spec_from_file_location('os_upgrade_guard_broker', ROOT / 'ansible/roles/haproxy-admin/files/easy-ha-proxy-updated.py')
        broker = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = broker
        spec.loader.exec_module(broker)
        for scheduled in (False, True):
            with self.subTest(scheduled=scheduled), tempfile.TemporaryDirectory() as temporary:
                plan = {'source_channel': 'local', 'image_channel': 'latest', 'components': []}
                with patch.object(broker, 'ACTIVE_MARKER', Path(temporary) / 'active'), \
                     patch.object(broker.time, 'sleep'), \
                     patch.object(broker, 'validate_selection'), \
                     patch.object(broker, 'execute_checker', return_value=plan), \
                     patch.object(broker, 'validate_fresh_candidates'), \
                     patch.object(broker, 'validate_reviewed_container_candidates'), \
                     patch.object(broker, 'store_plan', return_value={'id':'a'*32}), \
                     patch.object(broker, 'report_availability'), \
                     patch.object(broker, 'load_job', return_value={'scheduled':scheduled}), \
                     patch.object(broker, 'update_job'), \
                     patch.object(broker, 'release_operation'), \
                     patch.object(broker, 'request_self_restart_if_needed'), \
                     patch.object(broker, 'finish_failed') as failed, \
                     patch.object(broker, 'run_command', return_value=(0, '')) as run:
                    broker.apply_worker('a'*32, 7, plan, ['os'])
                failed.assert_not_called()
                self.assertEqual('--automatic-os' in run.call_args.args[1], scheduled)


if __name__ == '__main__':
    unittest.main()
