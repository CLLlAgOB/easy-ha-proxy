"""Provider changes must fail before an ordinary update can replace HAProxy."""
from __future__ import annotations

from pathlib import Path
import unittest

from jinja2 import Environment
import yaml

try:
    from ansible.parsing.dataloader import DataLoader
    from ansible.playbook.conditional import Conditional
    from ansible.template import Templar
except ImportError:
    Conditional = None

ROOT = Path(__file__).resolve().parents[1]
TASKS = yaml.safe_load((ROOT / 'ansible/roles/haproxy/tasks/package.yml').read_text())


@unittest.skipUnless(Conditional, 'requires Ansible')
class ProviderSafety(unittest.TestCase):
    def allowed(self, task, **overrides):
        context = {
            'haproxy_package_provider': 'haproxy-technologies',
            'haproxy_package_branch': '3.4',
            'ansible_distribution': 'Ubuntu',
            'ansible_distribution_release': 'noble',
            'ansible_architecture': 'x86_64',
            'ansible_facts': {'packages': {}},
        }
        context.update(overrides)
        loader = DataLoader()
        conditional = Conditional(loader=loader)
        conditional.when = task['ansible.builtin.assert']['that']
        return conditional.evaluate_conditional(Templar(loader=loader, variables=context), context)

    def test_only_the_two_explicit_providers_are_accepted(self):
        for provider, expected in [('distribution', True), ('haproxy-technologies', True),
                                   ('latest', False), ('', False)]:
            with self.subTest(provider=provider):
                self.assertEqual(self.allowed(TASKS[0], haproxy_package_provider=provider), expected)

    def test_an_existing_distribution_package_cannot_be_silently_replaced(self):
        self.assertFalse(self.allowed(TASKS[2], ansible_facts={
            'packages': {'haproxy': [{'version': '2.8.30'}]}}))
        self.assertTrue(self.allowed(TASKS[2], haproxy_package_provider='distribution',
                                     ansible_facts={'packages': {'haproxy': [{'version': '2.8.30'}]}}))

    def test_a_missing_provider_setting_cannot_silently_downgrade_vendor_installations(self):
        self.assertFalse(self.allowed(TASKS[2], haproxy_package_provider='distribution',
                                     ansible_facts={'packages': {'haproxy-awslc': [{'version': '3.4.7'}]}}))

    def test_both_native_architectures_are_allowed(self):
        task = TASKS[4]['block'][0]
        for arch in ['aarch64', 'x86_64']:
            with self.subTest(arch=arch):
                self.assertTrue(self.allowed(task, ansible_architecture=arch))

    def test_unsupported_platforms_and_branches_fail_before_repository_changes(self):
        task = TASKS[4]['block'][0]
        for values in [
            {'ansible_architecture': 'armv7l'}, {'ansible_distribution': 'Debian'},
            {'ansible_distribution_release': 'jammy'}, {'ansible_distribution_release': 'resolute'},
            {'haproxy_package_branch': '3.5'},
            {'ansible_facts': {'packages': {'haproxy-awslc': [{'version': '3.2.26'}]}}},
        ]:
            with self.subTest(values=values):
                self.assertFalse(self.allowed(task, **values))

    def test_patch_updates_in_the_qualified_branch_are_allowed(self):
        self.assertTrue(self.allowed(TASKS[4]['block'][0], ansible_facts={
            'packages': {'haproxy-awslc': [{'version': '3.4.6-0+ha34+ubuntu24.04u1'}]}}))


class HealthPackageSelection(unittest.TestCase):
    def test_health_checks_query_the_installed_package_even_with_stale_inventory(self):
        tasks = yaml.safe_load((ROOT / 'ansible/roles/healthcheck/tasks/main.yml').read_text())
        task = next(t for t in tasks if t.get('name') == 'Status check | select the actual HAProxy package name')
        selector = task['ansible.builtin.set_fact']['status_check_haproxy_apt_package']
        for status, expected in [
            ({'rc': 0, 'stdout': 'installed'}, 'haproxy-awslc'),
            ({'rc': 0, 'stdout': 'config-files'}, 'haproxy'),
            ({'rc': 1, 'stdout': ''}, 'haproxy'),
        ]:
            with self.subTest(status=status):
                actual = Environment().from_string(selector).render(status_check_haproxy_provider=status)
                self.assertEqual(actual, expected)


if __name__ == '__main__':
    unittest.main()
