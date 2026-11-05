"""Pair host updates with the running panel, even after a download moved its tag."""
from pathlib import Path
import importlib.util
import json
import sys
import tempfile
import unittest
from unittest import mock

import update_plan
from update_plan import CommandResult

IMAGE = "example/panel:latest"
CONTAINER = "c" * 64
RUNNING = "sha256:" + "1" * 64
DIGEST = "sha256:" + "2" * 64
OLD = "a" * 64
NEW = "b" * 64


class Docker:
    def __init__(self, running_tree=OLD, *, registry_digest=DIGEST, stopped=False, mixed_replicas=False):
        self.running_tree = running_tree
        self.registry_digest = registry_digest
        self.stopped = stopped
        self.mixed_replicas = mixed_replicas

    def run(self, argv, *, timeout):
        args = tuple(argv)
        if args[-2:] == ("config", "--images"):
            return CommandResult(0, IMAGE + "\n")
        if args[-2:] == ("ps", "-q"):
            return CommandResult(0, "" if self.stopped else CONTAINER + "\n")
        if args[:2] == ("docker", "inspect"):
            if self.mixed_replicas:
                return CommandResult(0, f'{json.dumps(IMAGE)} {json.dumps(DIGEST)}\n'
                                     f'{json.dumps("example/panel@" + DIGEST)} {json.dumps(RUNNING)}\n')
            return CommandResult(0, json.dumps(IMAGE) + " " + json.dumps(RUNNING) + "\n")
        if args[:3] == ("docker", "buildx", "imagetools"):
            if args[-1] == "{{json .Image}}":
                return CommandResult(0, json.dumps({"config": {"Labels": {update_plan.WEB_TREE_LABEL: NEW}}}))
            return CommandResult(0, "Digest: " + self.registry_digest)
        if args[:3] == ("docker", "image", "inspect"):
            if args[-1] == "{{json .RepoDigests}}":
                return CommandResult(0, json.dumps(["example/panel@" + DIGEST]))
            if args[-1] == "{{json .Config.Labels}}":
                tree = self.running_tree if args[3] == RUNNING else NEW
                return CommandResult(0, json.dumps({update_plan.WEB_TREE_LABEL: tree} if tree else {}))
            if args[-1] == "{{json .RootFS.Layers}}\t{{json .Config}}":
                layer = (self.running_tree or OLD) if args[3] == RUNNING else NEW
                return CommandResult(0, json.dumps(["sha256:" + layer]) + '\t' + '{}')
        return CommandResult(1, stderr="unexpected probe")


class PanelFixture:
    def probe(self, docker):
        with tempfile.TemporaryDirectory() as directory:
            compose = Path(directory) / "compose.yml"
            compose.write_text("services: {}\n", encoding="utf-8")
            return update_plan._probe_admin_compose(
                compose, docker, configured_image=IMAGE,
                configured_channel="latest", target_channel="latest",
            )


class RunningPanelPairing(PanelFixture, unittest.TestCase):
    def test_downloaded_new_tag_does_not_replace_the_running_fingerprint(self):
        panel = self.probe(Docker())
        self.assertEqual(panel['state'], 'available')
        self.assertEqual(panel['details']['images'][0]['current_source_tree'], OLD)

    def test_host_update_still_requires_recreating_the_old_panel(self):
        panel = self.probe(Docker())
        source = dict(id='all', state='available', actionable=True,
                      details={'scope': {'ready': True}})
        update_plan.link_web_application([source, panel], NEW)
        self.assertEqual(source['details']['scope'].get('requires'), [['admin-container']])

    def test_running_fingerprint_is_read_even_if_the_registry_has_another_update(self):
        panel = self.probe(Docker(registry_digest="sha256:" + '3' * 64))
        self.assertEqual(panel['details']['images'][0]['current_source_tree'], OLD)

    def test_a_running_image_without_a_label_is_not_the_downloaded_image(self):
        panel = self.probe(Docker(running_tree=None))
        self.assertIsNone(panel['details']['images'][0]['current_source_tree'])

    def test_a_stopped_panel_uses_its_installed_tag(self):
        panel = self.probe(Docker(stopped=True))
        self.assertEqual(panel['details']['images'][0]['current_source_tree'], NEW)

    def test_unreadable_running_inventory_never_falls_back_to_a_tag(self):
        runner = mock.Mock()
        self.assertIsNone(update_plan._running_web_tree(IMAGE, None, runner))
        runner.run.assert_not_called()

    def test_running_replicas_must_agree_on_their_build_inputs(self):
        running = {IMAGE: [RUNNING, DIGEST]}
        with mock.patch.object(update_plan, '_local_web_tree', side_effect=[OLD, NEW]):
            self.assertIsNone(update_plan._running_web_tree(IMAGE, running, mock.Mock()))

    def test_running_reference_can_be_pinned_to_a_digest(self):
        running = {'example/panel@' + DIGEST: [RUNNING]}
        self.assertEqual(update_plan._running_web_tree(IMAGE, running, Docker()), OLD)
        detail = {'state': 'current'}
        update_plan._check_running(detail, IMAGE, running, Docker())
        self.assertEqual(detail['state'], 'available')
        self.assertEqual(detail['reason'], 'running-older-image')

    def test_a_new_registry_release_does_not_hide_an_old_running_container(self):
        panel = self.probe(Docker(registry_digest='sha256:' + '3' * 64))
        self.assertEqual(panel['state'], 'available')
        self.assertEqual(panel['details']['images'][0]['running'], 'different-content')

    def test_an_old_replica_is_not_hidden_by_the_new_reference(self):
        panel = self.probe(Docker(mixed_replicas=True))
        image = panel['details']['images'][0]
        self.assertIsNone(image['current_source_tree'])
        self.assertEqual(image['running'], 'different-content')


@unittest.skipIf(sys.platform == 'win32', 'the broker needs fcntl')
class AppliedPanelVerification(PanelFixture, unittest.TestCase):
    def setUp(self):
        path = Path(__file__).resolve().parents[1] / 'ansible/roles/haproxy-admin/files/easy-ha-proxy-updated.py'
        spec = importlib.util.spec_from_file_location('updated_running_pairing_test', path)
        self.broker = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = self.broker
        spec.loader.exec_module(self.broker)

    def test_downloaded_digest_is_not_proof_that_the_container_was_updated(self):
        plan = {'components': [self.probe(Docker())]}
        with self.assertRaises(self.broker.UpdatedError) as failure:
            self.broker.validate_applied_container_digests(plan, plan, ['admin-container'])
        self.assertEqual(failure.exception.code, 'verification_failed')

    def test_a_new_registry_release_cannot_mask_an_unsuccessful_install(self):
        reviewed = {'components': [self.probe(Docker())]}
        observed = {'components': [self.probe(Docker(registry_digest='sha256:' + '3' * 64))]}
        with self.assertRaises(self.broker.UpdatedError):
            self.broker.validate_applied_container_digests(reviewed, observed, ['admin-container'])

    def test_a_correctly_running_reviewed_image_survives_a_newer_release(self):
        reviewed = {'components': [self.probe(Docker())]}
        observed = {'components': [self.probe(Docker(running_tree=NEW, registry_digest='sha256:' + '3' * 64))]}
        self.broker.validate_applied_container_digests(reviewed, observed, ['admin-container'])

    def test_unreadable_running_metadata_is_not_success(self):
        plan = {'components': [self.probe(Docker())]}
        for field, value in [('state', 'unknown'), ('running', 'unchecked'), ('running', 'unreadable')]:
            with self.subTest(field=field, value=value):
                observed = {'components': [self.probe(Docker(running_tree=NEW))]}
                observed['components'][0]['details']['images'][0][field] = value
                with self.assertRaises(self.broker.UpdatedError):
                    self.broker.validate_applied_container_digests(plan, observed, ['admin-container'])


if __name__ == '__main__':
    unittest.main()
