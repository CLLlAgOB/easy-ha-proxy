"""Regression tests for scoped Fail2ban configuration and status parsing."""

import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, call, patch

import ssh_protection as ssh


class SshProtectionTests(unittest.TestCase):
    def test_status_reports_only_valid_addresses_from_the_ssh_rule(self):
        output = """Status for the jail: sshd
|- Filter
|  |- Currently failed: 2
|  `- Total failed: 31
`- Actions
   |- Currently banned: 2
   |- Total banned: 4
   `- Banned IP list: 192.0.2.1 2001:db8::1 arbitrary-text
"""
        with patch.object(ssh, 'quick', return_value=(0, output)) as query:
            self.assertEqual(ssh.jail_status(), {'currently_failed': 2, 'total_failed': 31,
                                                'currently_banned': 2, 'total_banned': 4,
                                                'banned': ['192.0.2.1', '2001:db8::1']})
        query.assert_called_once_with(ssh.CLIENT, 'status', 'sshd')

    def test_package_install_stages_disabled_ssh_rule_before_starting_apt(self):
        staged = {'text': ssh.config_text(False), 'enabled': False}
        with (patch.object(ssh, 'platform'), patch.object(ssh, 'external_ssh_config', return_value=False),
              patch.object(ssh, 'managed_config', side_effect=[None, staged]),
              patch.object(ssh, 'maintenance_guard'), patch.object(ssh, 'listening_ports', return_value=[2222, 22022]),
              patch.object(ssh, 'log_backend', return_value='systemd'), patch.object(Path, 'is_file', return_value=False),
              patch.object(ssh, 'atomic') as write, patch.object(ssh, 'quick', return_value=(0, '')),
              patch.object(ssh, 'jail_status', return_value={}), patch.object(ssh, 'command') as command):
            ordered = Mock()
            ordered.attach_mock(write, 'write')
            ordered.attach_mock(command, 'command')
            self.assertEqual(ssh.set_protection('install', ['2001:db8::/64']), 'SSH protection is enabled.')

        self.assertEqual(ordered.mock_calls[0], call.write(ssh.DROP_IN, staged['text']))
        self.assertEqual(ordered.mock_calls[1].args[0][0], '/usr/bin/apt-get')
        config = ordered.mock_calls[2].args[1]
        self.assertIn('port = 2222,22022', config)
        self.assertIn('ignoreip = 127.0.0.0/8 ::1 2001:db8::/64', config)
        self.assertIn(call.command([ssh.CLIENT, 'reload', '--if-exists', 'sshd']), ordered.mock_calls)

    def test_failed_verification_restores_the_prior_rule_and_reloads_only_ssh(self):
        saved = ssh.config_text(True, [22], 'polling', ['192.0.2.1'])
        with (patch.object(ssh, 'platform'), patch.object(ssh, 'external_ssh_config', return_value=False),
              patch.object(ssh, 'managed_config', return_value={'text': saved, 'enabled': True}),
              patch.object(ssh, 'listening_ports', return_value=[22]), patch.object(ssh, 'log_backend', return_value='polling'),
              patch.object(Path, 'is_file', return_value=True), patch.object(ssh, 'atomic') as write,
              patch.object(ssh, 'quick', return_value=(0, '')),
              patch.object(ssh, 'jail_status', side_effect=[{}, None]), patch.object(ssh, 'command') as command):
            with self.assertRaisesRegex(ssh.SecurityError, 'could not be verified'):
                ssh.set_protection('enable', ['192.0.2.44'])
        write.assert_called_with(ssh.DROP_IN, saved)
        command.assert_called_with([ssh.CLIENT, 'reload', '--if-exists', 'sshd'], check=False)

    def test_does_not_take_over_an_administrator_rule(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'jail.d').mkdir()
            custom = root / 'jail.d' / 'admin.local'
            custom.write_text('[remote-access]\nfilter = sshd[mode=aggressive]\nenabled = true\n')
            with (patch.object(ssh, 'CONFIG', root), patch.object(ssh, 'DROP_IN', root / 'jail.d/managed.local'),
                  patch.object(ssh, 'platform'), patch.object(ssh, 'read_config', side_effect=Path.read_text)):
                with self.assertRaisesRegex(ssh.SecurityError, 'outside the panel'):
                    ssh.set_protection('enable', [])

    def test_ubuntu_package_defaults_are_only_accepted_with_the_installed_checksum(self):
        # The Ubuntu Noble package enables sshd and provides global defaults.
        stock = ('[DEFAULT]\nbanaction = nftables\nbanaction_allports = nftables[type=allports]\n'
                 'backend = systemd\n\n[sshd]\nenabled = true\n')
        checksum = hashlib.md5(stock.encode(), usedforsecurity=False).hexdigest()
        with TemporaryDirectory() as directory:
            root = Path(directory)
            defaults = root / 'jail.d/defaults-debian.conf'
            defaults.parent.mkdir()
            defaults.write_bytes(stock.encode())
            drop_in = defaults.with_name('99-easy-ha-proxy-sshd.local')
            drop_in.write_bytes(ssh.config_text(False).encode())
            conffiles = f' {defaults} {checksum}\n'
            with (patch.object(ssh, 'CONFIG', root), patch.object(ssh, 'DROP_IN', drop_in),
                  patch.object(ssh, 'read_config', side_effect=Path.read_text),
                  patch.object(ssh, 'quick', return_value=(0, conffiles)) as query):
                self.assertFalse(ssh.external_ssh_config())
                query.assert_called_once_with('/usr/bin/dpkg-query', '--show', '--showformat=${Conffiles}', 'fail2ban')
                defaults.write_bytes(stock.replace('enabled = true', 'enabled = false').encode())
                self.assertTrue(ssh.external_ssh_config())
                defaults.write_bytes(stock.encode())
                query.return_value = (0, conffiles.rstrip() + ' obsolete\n')
                self.assertTrue(ssh.external_ssh_config())
                query.return_value = (1, '')
                self.assertTrue(ssh.external_ssh_config())

    def test_trusted_addresses_canonicalize_cidrs_and_reject_config_content(self):
        self.assertEqual(ssh.trusted_addresses(['2001:db8::1/64', '2001:db8::/64', '192.0.2.4']),
                         ['2001:db8::/64', '192.0.2.4'])
        for value in ['192.0.2.4\nenabled = false', 'fe80::1%eth0', '--config', '192.0.2.4/33']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                ssh.trusted_addresses([value])
