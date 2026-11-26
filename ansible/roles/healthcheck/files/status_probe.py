"""One pass over everything the status check reads from the host.

The status check used to ask Ansible for each unit, file, package and
container in turn. Every loop item costs a module run -- about 0.4 s on an
ARM gateway -- so the check took close to two minutes after every update,
far longer than the probes themselves. This runs the same probes in one
process and prints one JSON document whose parts have the shape of the
loops' registered results ({"results": [{"item": ..., ...}]}), so the rest
of the role reads exactly what it read before.

Input (argv[1], JSON): units, retries, delay, daemon_files, artifacts, apt,
docker, snaps.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import time


def run(argv):
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, errors="replace", check=False)
    except OSError as exc:
        return {"rc": 2, "stdout": "", "stderr": str(exc)}
    # As Ansible's command module reports them: without the trailing newline.
    return {"rc": proc.returncode, "stdout": proc.stdout.rstrip("\r\n"), "stderr": proc.stderr.rstrip("\r\n")}


def units(items, retries, delay):
    """systemctl is-active, asked again for a unit until it answers active.

    Reconciliation and snapd may restart units moments before the check;
    only a state that survives a few probes counts. The waits are shared:
    every unit still not active is asked again after the same delay. A unit
    in the middle of a reload answers "reloading" with exit code 0, and the
    installer's handlers reload HAProxy right before the check: that is not
    active yet either.
    """
    states = [run(["systemctl", "is-active", str(item["name"])]) for item in items]
    for _ in range(max(0, retries)):
        pending = [i for i, state in enumerate(states) if state["rc"] != 0 or state["stdout"].strip() != "active"]
        if not pending:
            break
        time.sleep(max(0.0, delay))
        for i in pending:
            states[i] = run(["systemctl", "is-active", str(items[i]["name"])])
    return {"results": [dict(state, item=items[i]) for i, state in enumerate(states)]}


def stat(path):
    """The fields of ansible.builtin.stat the role reads."""
    if not os.path.exists(path):
        return {"exists": False}
    if not os.path.isfile(path):
        return {"exists": True}
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(1 << 20), b""):
                digest.update(block)
    except OSError:
        return {"exists": True}
    return {"exists": True, "checksum": digest.hexdigest()}


def stats(items, key):
    return {"results": [{"item": item, "stat": stat(str(item[key]))} for item in items]}


def apt_policy(packages):
    """apt-cache policy for every package in one run, split per package."""
    sections, current = {}, None
    if packages:
        for line in run(["apt-cache", "policy", *packages])["stdout"].splitlines():
            match = re.match(r"^(\S+):$", line)
            if match:
                current = match.group(1)
                sections[current] = [line]
            elif current is not None:
                sections[current].append(line)
    return {"results": [{"item": name, "stdout": "\n".join(sections.get(name, []))} for name in packages]}


def containers(items):
    found = {}
    if items:
        proc = run(["docker", "inspect", "--type", "container", *[str(item["name"]) for item in items]])
        try:
            for container in json.loads(proc["stdout"] or "[]"):
                found[str(container.get("Name", "")).lstrip("/")] = container
        except ValueError:
            pass
    results = []
    for item in items:
        container = found.get(str(item["name"]))
        results.append({"item": item, "exists": container is not None, "container": container or {}})
    return {"results": results}


def snaps(names):
    results = []
    for name in names:
        state = run(["snap", "list", name])
        results.append(dict(state, item=name, stdout_lines=state["stdout"].splitlines()))
    return {"results": results}


def main():
    spec = json.loads(sys.argv[1])
    apt = [str(name) for name in spec.get("apt", [])]
    report = {
        "systemd": units(spec.get("units", []), int(spec.get("retries", 3)), float(spec.get("delay", 4))),
        "daemon_versions": stats(spec.get("daemon_files", []), "version_file"),
        "artifacts": stats(spec.get("artifacts", []), "path"),
        "apt_installed": {"results": [
            dict(run(["dpkg-query", "--show", "--showformat=${Version}", name]), item=name) for name in apt]},
        "apt_candidate": apt_policy(apt),
        "docker": containers(spec.get("docker", [])),
        "snaps": snaps([str(name) for name in spec.get("snaps", [])]),
    }
    json.dump(report, sys.stdout)


if __name__ == "__main__":
    main()
