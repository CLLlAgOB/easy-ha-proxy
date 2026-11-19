"""Regression tests for scoped Fail2ban configuration and status parsing."""

import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, call, patch

import ssh_protection as ssh


class SshProtectionTests(unittest.TestCase):
    def test_firewall_matches_ports_and_active_ips_for_both_families(self):
        hook = '-A INPUT -p tcp -m multiport --dports 22,2222 -j f2b-sshd\n'
        ipv4 = hook + '-A f2b-sshd -s 192.0.2.2/32 -j REJECT --reject-with icmp-port-unreachable\n'
        ipv6 = hook + '-A f2b-sshd -s 2001:db8::2/128 -j REJECT --reject-with icmp6-port-unreachable\n'
        status = {'banned': ['192.0.2.2', '2001:db8::2'], 'currently_banned': 2}
        with patch.object(ssh, 'quick', side_effect=[(0, ipv4), (0, ipv6)]) as query:
            self.assertEqual(ssh.firewall_status([22, 2222], [2222, 22], status),
                             {'state': 'verified', 'families': {'4': 'verified', '6': 'verified'}})
            self.assertEqual(query.call_args_list, [call('/usr/sbin/iptables-save', '-t', 'filter'),
                                                   call('/usr/sbin/ip6tables-save', '-t', 'filter')])
        with patch.object(ssh, 'quick', side_effect=[(0, ipv4), (0, hook)]):
            self.assertEqual(ssh.firewall_status([22, 2222], [22, 2222], status)['state'], 'missing')
        with patch.object(ssh, 'quick') as query:
            self.assertEqual(ssh.firewall_status([22], [2222], status)['state'], 'ports_changed')
            self.assertEqual(ssh.firewall_status([22], [22], {'banned': [], 'currently_banned': 0})['state'], 'idle')
            query.assert_not_called()

    def test_firewall_does_not_claim_rules_below_earlier_verdicts(self):
        hook = '-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd\n'
        block = '-A f2b-sshd -s 192.0.2.2/32 -j DROP\n'
        with patch.object(ssh, 'quick', return_value=(0, '-A INPUT -j ACCEPT\n' + hook + block)):
            self.assertEqual(ssh.firewall_family(4, [22], {'192.0.2.2'}), 'order_unknown')
        with patch.object(ssh, 'quick', return_value=(0, hook + '-A f2b-sshd -j RETURN\n' + block)):
            self.assertEqual(ssh.firewall_family(4, [22], {'192.0.2.2'}), 'missing')

    def test_ban_times_are_taken_from_fail2ban_and_permanent_bans_have_no_expiry(self):
        output = ('192.0.2.1 \t2026-11-19 11:00:00 + 3600 = 2026-11-19 12:00:00\n'
                  '2001:0db8::1 \t2026-11-19 11:10:00 + -1 = 9999-12-31 23:59:59\n'
                  '192.0.2.9 \t2026-11-19 11:10:00 + 3600 = 2026-11-19 12:10:00')
        with patch.object(ssh, 'quick', return_value=(0, output)):
            self.assertEqual(ssh.ban_times(['192.0.2.1', '2001:db8::1']), {
                '192.0.2.1': {'started': '2026-11-19 11:00:00', 'expires': '2026-11-19 12:00:00', 'permanent': False},
                '2001:db8::1': {'started': '2026-11-19 11:10:00', 'expires': None, 'permanent': True},
            })

    def test_connection_check_uses_match_arguments_and_rejects_extra_fields(self):
        with patch.object(ssh, 'quick', return_value=(0, 'passwordauthentication no\nallowusers operator\nallowusers backup\n')) as query:
            self.assertEqual(ssh.check_connection('operator', '2001:0db8::2', 'vpn.example.test', '192.0.2.5', '22'),
                             {'passwordauthentication': 'no', 'allowusers': 'operator backup'})
            with self.assertRaises(ValueError):
                ssh.check_connection('operator,addr=192.0.2.1', '192.0.2.2')
        query.assert_called_once_with('/usr/sbin/sshd', '-T', '-C',
                                      'user=operator,addr=2001:db8::2,host=vpn.example.test,laddr=192.0.2.5,lport=22')

    def test_managed_policy_reads_existing_default_files_and_new_thresholds(self):
        policy = {'maxretry': 8, 'findtime': 900, 'bantime': 7200}
        for settings in [None, policy]:
            config = ssh.config_text(True, [22], 'systemd', [], settings)
            with self.subTest(policy=settings), patch.object(ssh, 'read_config', return_value=config):
                self.assertEqual(ssh.managed_config()['policy'], settings or ssh.DEFAULT_POLICY)
        with self.assertRaises(ValueError):
            ssh.validated_policy(dict(policy, bantime=-1))

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
