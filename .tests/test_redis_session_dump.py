"""A Redis that cannot read its session dump does not take the sign-in page down.

Redis keeps only Authelia's sessions, and Redis 8 reads what 7.4 wrote but
7.4 refuses what 8 wrote ("Can't handle RDB format version") and exits. Going
back to an older image would therefore leave the gateway with no login page.
Before the stack is recreated, the Redis image about to run checks the dump
with redis-check-rdb; a dump it cannot read is set aside -- after the running
Redis has stopped, because Redis writes the dump again on the way down.

The playbook runs for real here, against a docker stand-in that answers the
check with the exit code a case needs and records what it was asked.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible/roles/authelia"
GUARD = ROLE / "tasks/redis_dump_guard.yml"
IMAGE = "redis:8.10.3-alpine"

FAKE_DOCKER = """#!/bin/sh
# Records each call with whether the dump was still in place, then answers.
dump="$GUARD_DATA_DIR/dump.rdb"
if [ -e "$dump" ]; then present=dump-present; else present=dump-absent; fi
echo "$present $*" >> "$GUARD_DOCKER_LOG"
case "$1" in
  run) exit "$GUARD_CHECK_RC" ;;
  *) exit 0 ;;
esac
"""

PLAYBOOK = """
- hosts: localhost
  gather_facts: false
  tasks:
    - ansible.builtin.include_tasks: "{guard}"
      vars:
        authelia_redis_image: "{image}"
        authelia_redis_data_dir: "{data}"
        authelia_redis_uid: 19011
        authelia_redis_gid: 19011
"""


@unittest.skipIf(shutil.which("ansible-playbook") is None, "ansible-playbook is not installed")
class TheGuardDecides(unittest.TestCase):
    def run_guard(self, check_rc: int, with_dump: bool = True):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        data = root / "redis"
        data.mkdir()
        if with_dump:
            (data / "dump.rdb").write_bytes(b"REDIS0015 sessions")
        bin_dir = root / "bin"
        bin_dir.mkdir()
        docker = bin_dir / "docker"
        docker.write_text(FAKE_DOCKER, encoding="utf-8")
        docker.chmod(docker.stat().st_mode | stat.S_IXUSR)
        log = root / "docker.log"
        log.touch()
        (root / "pb.yml").write_text(
            PLAYBOOK.format(guard=GUARD, image=IMAGE, data=data), encoding="utf-8"
        )
        environment = {
            **os.environ,
            "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "GUARD_DATA_DIR": str(data),
            "GUARD_DOCKER_LOG": str(log),
            "GUARD_CHECK_RC": str(check_rc),
            "ANSIBLE_CALLBACKS_ENABLED": "",
            "ANSIBLE_LOCAL_TEMP": str(root / "tmp"),
        }
        completed = subprocess.run(
            ["ansible-playbook", "-i", "localhost,", "-c", "local", "pb.yml"],
            cwd=root, env=environment, capture_output=True, text=True, timeout=180,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        calls = log.read_text(encoding="utf-8").splitlines()
        return data, calls, completed.stdout

    def test_a_readable_dump_stays_and_redis_is_left_running(self):
        data, calls, _ = self.run_guard(0)
        self.assertEqual([call.split()[1] for call in calls], ["run"])
        self.assertEqual(sorted(path.name for path in data.iterdir()), ["dump.rdb"])

    def test_the_check_is_the_target_image_reading_a_read_only_copy(self):
        _, calls, _ = self.run_guard(0)
        check = calls[0]
        for part in ("--pull never", "--network none", "--read-only", "--cap-drop ALL",
                     "--user 19011:19011", "/redis:/data:ro", "--entrypoint redis-check-rdb",
                     f"{IMAGE} /data/dump.rdb"):
            self.assertIn(part, check)

    def test_an_unreadable_dump_is_set_aside_after_redis_has_stopped(self):
        data, calls, output = self.run_guard(1)
        self.assertEqual([call.split()[1] for call in calls], ["run", "stop"])
        # Still in place when Redis was stopped: moved only afterwards, so the
        # dump the old Redis writes on its way down is the one set aside.
        self.assertTrue(calls[1].startswith("dump-present stop authelia-redis"))
        names = [path.name for path in data.iterdir()]
        self.assertNotIn("dump.rdb", names)
        self.assertEqual(len(names), 1)
        self.assertTrue(names[0].startswith("dump.rdb.unreadable-"))
        self.assertEqual((data / names[0]).read_bytes(), b"REDIS0015 sessions")
        self.assertIn("Signed-in users have to sign in again", output)

    def test_docker_failing_is_not_a_verdict_on_the_dump(self):
        for rc in (125, 126, 127):
            with self.subTest(rc=rc):
                data, calls, _ = self.run_guard(rc)
                self.assertEqual([call.split()[1] for call in calls], ["run"])
                self.assertEqual(sorted(path.name for path in data.iterdir()), ["dump.rdb"])

    def test_no_dump_no_check(self):
        _, calls, _ = self.run_guard(1, with_dump=False)
        self.assertEqual(calls, [])


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
