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
GUARD = ROLE / "tasks/redis_dump_guard.yml"


class TheRoleRunsItAtTheRightMoment(unittest.TestCase):
    def test_after_the_pull_and_before_every_reconcile(self):
        for name, reconcile in (
            ("start.yml", "Reconcile the Authelia stack with migration recovery"),
            ("update.yml", "Reconcile the updated Authelia stack with migration recovery"),
        ):
            block = yaml.safe_load((ROLE / "tasks" / name).read_text(encoding="utf-8"))[0]["block"]
            names = [task.get("name") for task in block]
            include = next(
                i for i, task in enumerate(block)
                if task.get("ansible.builtin.include_tasks") == "redis_dump_guard.yml"
            )
            self.assertLess(names.index("Pull Authelia stack images"), include, name)
            self.assertLess(include, names.index(reconcile), name)
            conditions = block[include]["when"]
            conditions = conditions if isinstance(conditions, list) else [conditions]
            self.assertIn("authelia_session_redis_enabled", " ".join(conditions), name)

    def test_the_image_checked_is_the_one_the_compose_file_runs(self):
        compose = (ROLE / "templates/docker-compose.yml.j2").read_text(encoding="utf-8")
        self.assertIn("image: {{ authelia_redis_image", compose)
        self.assertIn("{{ authelia_redis_image }}", GUARD.read_text(encoding="utf-8"))
        defaults = yaml.safe_load((ROLE / "defaults/main.yml").read_text(encoding="utf-8"))
        self.assertIn(f"default('{defaults['authelia_redis_image']}')", compose)

    def test_the_dump_lives_where_the_compose_file_mounts_it(self):
        compose = (ROLE / "templates/docker-compose.yml.j2").read_text(encoding="utf-8")
        self.assertIn("- {{ authelia_redis_data_dir }}:/data", compose)
        self.assertIn('"{{ authelia_redis_data_dir }}/dump.rdb"', GUARD.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
