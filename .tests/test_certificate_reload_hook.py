"""A renewed certificate that HAProxy never loads is not a renewed certificate.

An incident: a site's certificate renewed on schedule at 01:29, the PFX
reached the remote server that needs the same certificate, every PEM under
/etc/haproxy/certs was rebuilt correctly -- and HAProxy went on presenting
the previous one for another eight hours, until something unrelated
reloaded it. certbot reported "all renewals succeeded" and the notification
mail went out as usual.

The reload was the last line of the deploy hook, guarded by

    if systemctl list-unit-files | grep -q "^haproxy.service"; then

in a script that runs under `set -euo pipefail`. grep -q exits at the first
match, systemctl takes SIGPIPE part-way through writing four hundred more
unit names, pipefail turns the pipeline's status into 141, and the condition
is false. On the gateway it failed twenty times out of twenty. The reload
had simply never been running.

A second fault came out of the same read and is deliberately NOT fixed here.
The role's own certificate-delivery hook is written into renewal-hooks/post,
where certbot sets neither RENEWED_LINEAGE nor RENEWED_DOMAINS, so it exits
at its first test and never fires. Deployed gateways deliver certificates
from an older hand-written copy in deploy/ that the role does not manage --
different remote path, different host-key policy, different PFX password.
Renaming the role's file onto that name would have overwritten a working
script with one that behaves differently, so the role is left alone and the
delivery is being rebuilt as something configurable from the interface.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CERT = ROOT / "ansible" / "roles" / "cert"
HOOK = CERT / "templates" / "905-haproxy-pems-reload.sh.j2"
RDG = CERT / "tasks" / "rdg.yml"


class TheReloadRuns(unittest.TestCase):
    def setUp(self):
        self.source = HOOK.read_text(encoding="utf-8")
        self.tail = self.source.split("# Перезагрузка HAProxy")[1]

    def test_the_script_still_uses_pipefail(self):
        # Not a thing to remove -- the rest of the script wants it. The
        # guard has to stop depending on a pipeline instead.
        self.assertIn("set -euo pipefail", self.source)

    def test_the_reload_is_not_guarded_by_a_pipeline(self):
        code = [
            line for line in self.tail.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        for line in code:
            with self.subTest(line=line.strip()[:60]):
                # A pipe anywhere in the guard reintroduces the fault:
                # under pipefail the status is the last non-zero one, and a
                # short-circuiting reader makes the writer fail.
                self.assertNotIn("|", line)

    def test_it_still_checks_the_unit_exists(self):
        # The check is worth keeping: the same script runs on hosts that
        # have no HAProxy at all.
        self.assertIn("systemctl cat", self.tail)

    def test_it_reloads_and_falls_back_to_restart(self):
        self.assertIn("systemctl reload", self.tail)
        self.assertIn("systemctl restart", self.tail)

    def test_a_reload_that_fails_is_loud(self):
        # The incident was silent. A rebuilt certificate that is not being
        # served has to make the renewal report a failure.
        self.assertIn("ERROR", self.tail)
        self.assertIn("exit 1", self.tail)
        self.assertIn(">&2", self.tail)

    def test_the_reload_comes_after_the_pems_are_built(self):
        self.assertLess(
            self.source.index("build_pem"),
            self.source.index("systemctl reload"),
        )


class NoOtherHookRepeatsTheMistake(unittest.TestCase):
    """The pattern is easy to write and fails only under load."""

    def test_no_shipped_hook_guards_a_command_with_a_short_circuiting_pipe(self):
        offenders = []
        for path in sorted(
            list((CERT / "templates").glob("*.sh.j2"))
            + list((CERT / "tasks").glob("*.yml"))
        ):
            text = path.read_text(encoding="utf-8")
            if "pipefail" not in text:
                continue
            for number, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                # `if <writer> | grep -q ...` is the shape that bites: grep
                # leaves early, the writer dies of SIGPIPE, pipefail reports
                # it, and the branch silently does not run.
                #
                # echo and printf are exempt, and not as a convenience: they
                # write one short string that fits the pipe buffer and are
                # finished before grep is scheduled, so there is no signal to
                # take. What is dangerous is a writer with a lot to say --
                # systemctl, journalctl, find, ss -- which is still going
                # when the reader leaves.
                if not re.search(r"^(if|elif|while)\s+.*\|\s*grep\s+-q",
                                 stripped):
                    continue
                writer = re.sub(r"^(if|elif|while)\s+!?\s*", "", stripped)
                if re.match(r"(echo|printf)[ 	]", writer):
                    continue
                offenders.append(f"{path.name}:{number}")
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
