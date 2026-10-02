"""Guards against the "every apply runs a full apt update" slowdown.

Several roles run `apt: update_cache: true` to ensure packages are present. A
play-wide `cache_valid_time` default makes only the first such task refresh the
index; the rest reuse it, turning many minutes of repeated network refreshes
into one. The Docker repository is the single third-party source, so it must
force a refresh when it is newly added, and a deliberate OS upgrade must always
refresh.
"""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / "ansible/easy-ha-proxy.yml"
DOCKER_TASKS = ROOT / "ansible/roles/docker/tasks/main.yml"
UPGRADE_TASKS = ROOT / "ansible/roles/update_packages/tasks/main.yml"


class AptCacheSpeedTests(unittest.TestCase):
    def test_play_sets_a_cache_valid_time_default(self) -> None:
        play = yaml.safe_load(PLAYBOOK.read_text(encoding="utf-8"))[0]
        defaults = play.get("module_defaults", {})
        apt_defaults = defaults.get("ansible.builtin.apt", {})
        self.assertIn("cache_valid_time", apt_defaults)
        # Overridable and non-zero by default.
        self.assertIn("easy_ha_proxy_apt_cache_valid_time", str(apt_defaults))

    def test_docker_forces_refresh_only_when_repository_changed(self) -> None:
        tasks = yaml.safe_load(DOCKER_TASKS.read_text(encoding="utf-8"))
        names = [t.get("name", "") for t in tasks]
        self.assertIn("Refresh APT cache after adding the Docker repository", names)
        refresh = next(
            t for t in tasks
            if t.get("name") == "Refresh APT cache after adding the Docker repository"
        )
        self.assertEqual(refresh["apt"]["cache_valid_time"], 0)
        self.assertIn("docker_repo_added is changed", str(refresh.get("when")))
        # The repository task must register the change it keys off.
        repo = next(t for t in tasks if t.get("name") == "Add Docker APT repository")
        self.assertEqual(repo.get("register"), "docker_repo_added")
        # The refresh must run before the engine install.
        self.assertLess(
            names.index("Refresh APT cache after adding the Docker repository"),
            names.index("Install Docker Engine and plugins"),
        )

    def test_os_upgrade_always_refreshes_the_cache(self) -> None:
        tasks = yaml.safe_load(UPGRADE_TASKS.read_text(encoding="utf-8"))
        upgrade = next(
            t for t in tasks if t.get("name") == "Update and upgrade apt packages"
        )
        self.assertEqual(upgrade["apt"]["cache_valid_time"], 0)
        self.assertTrue(upgrade["apt"]["upgrade"])


if __name__ == "__main__":
    unittest.main()
