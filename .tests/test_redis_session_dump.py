"""A Redis that cannot read its session dump does not take the sign-in page down.

Redis keeps only Authelia's sessions, and Redis 8 reads what 7.4 wrote but
7.4 refuses what 8 wrote ("Can't handle RDB format version") and exits. Going
back to an older image would therefore leave the gateway with no login page.
Before the stack is recreated, the Redis image about to run checks the dump
with redis-check-rdb; a dump it cannot read is set aside -- after the running
Redis has stopped, because Redis writes the dump again on the way down.

The guard itself runs against a docker stand-in in
go/agent/internal/apply/stages/redis_guard_test.go; this holds the role's
wiring and the paths it shares with the compose file.
"""

from __future__ import annotations

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible/roles/authelia"


class TheRoleRunsItAtTheRightMoment(unittest.TestCase):
    def test_the_image_checked_is_the_one_the_compose_file_runs(self):
        compose = (ROLE / "templates/docker-compose.yml.j2").read_text(encoding="utf-8")
        self.assertIn("image: {{ authelia_redis_image", compose)
        defaults = yaml.safe_load((ROLE / "defaults/main.yml").read_text(encoding="utf-8"))
        self.assertIn(f"default('{defaults['authelia_redis_image']}')", compose)

    def test_the_dump_lives_where_the_compose_file_mounts_it(self):
        compose = (ROLE / "templates/docker-compose.yml.j2").read_text(encoding="utf-8")
        self.assertIn("- {{ authelia_redis_data_dir }}:/data", compose)


if __name__ == "__main__":
    unittest.main()
