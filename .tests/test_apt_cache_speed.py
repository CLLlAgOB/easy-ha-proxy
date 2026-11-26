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


class AptCacheSpeedTests(unittest.TestCase):
    def test_play_sets_a_cache_valid_time_default(self) -> None:
        play = yaml.safe_load(PLAYBOOK.read_text(encoding="utf-8"))[0]
        defaults = play.get("module_defaults", {})
        apt_defaults = defaults.get("ansible.builtin.apt", {})
        self.assertIn("cache_valid_time", apt_defaults)
        # Overridable and non-zero by default.
        self.assertIn("easy_ha_proxy_apt_cache_valid_time", str(apt_defaults))

if __name__ == "__main__":
    unittest.main()
