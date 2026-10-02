#!/usr/bin/env python3
"""Deliver a renewed certificate to the machines that also need it.

A gateway is rarely the only thing holding a certificate. A Remote Desktop
Gateway wants the same one as a PKCS#12 file; a web server on another host
wants the PEM pair; a load balancer wants them concatenated. Until now that
was one hand-written hook per gateway, with the host, the port, the path and
the format baked into the script -- and a second copy of it in the Ansible
role that had drifted out of agreement with the one actually running.

This reads targets from a directory, one JSON file each, exactly the way
off-host backup destinations already work: the private key and the pinned
host key live beside the record as <name>.key and <name>.known_hosts, both
root-only.

Invoked from certbot's deploy hook with the lineage and the renewed domains,
and by certd when the operator asks to test a target from the interface.

Two things it deliberately does not do. It does not reload HAProxy: the hook
before it already did that, and a delivery to an unreachable host must never
be able to leave the local gateway on an old certificate. And it does not
stop at the first failure -- one unreachable machine should not cost the
other targets their certificate.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

LOG = logging.getLogger("cert-deliver")

DESTINATIONS_DIR = Path(
    os.environ.get(
        "CERT_DESTINATIONS_DIR", "/etc/easy-ha-proxy/cert-destinations"
    )
)
SSH_TIMEOUT_SECONDS = int(os.environ.get("CERT_DELIVER_TIMEOUT", "120"))

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")

# What the far side is given.
#   pfx           one PKCS#12 file, optionally passworded -- Windows services
#   pem-pair      fullchain.pem and privkey.pem as two files -- nginx, Apache
#   pem-combined  the two concatenated, which is what HAProxy itself reads
FORMATS = ("pfx", "pem-pair", "pem-combined")

# sftp writes a file; scp does too, over the same transport. They differ in
# what the far end has to run, and some appliances offer only one of them.
TRANSPORTS = ("sftp", "scp")


class DeliveryError(Exception):
    """Something the operator can fix, described in a way that says how."""


# ───────────────────── records ─────────────────────


def destination_path(name: str) -> Path:
    return DESTINATIONS_DIR / f"{name}.json"


def key_path(name: str) -> Path:
    return DESTINATIONS_DIR / f"{name}.key"


def known_hosts_path(name: str) -> Path:
    return DESTINATIONS_DIR / f"{name}.known_hosts"


def valid_name(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not NAME_RE.fullmatch(text):
        raise DeliveryError(
            "name must be 1-40 characters of a-z, 0-9 and -, starting with a "
            "letter or digit"
        )
    return text


def load_destination(name: str) -> Dict[str, Any]:
    path = destination_path(valid_name(name))
    if not path.is_file():
        raise DeliveryError(f"no delivery target named {name}")
    with path.open("r", encoding="utf-8") as handle:
        record = json.load(handle)
    record["name"] = path.stem
    return record


def list_destinations() -> List[Dict[str, Any]]:
    if not DESTINATIONS_DIR.is_dir():
        return []
    found: List[Dict[str, Any]] = []
    for path in sorted(DESTINATIONS_DIR.glob("*.json")):
        try:
            with path.open("r", encoding="utf-8") as handle:
                record = json.load(handle)
        except Exception as exc:  # noqa: BLE001 - one bad file is not fatal
            LOG.warning("cannot read %s (%s); skipping", path, exc)
            continue
        record["name"] = path.stem
        found.append(record)
    return found


def wants_domain(record: Dict[str, Any], domains: List[str]) -> bool:
    """Is this target interested in any of the domains that just renewed?

    Matched whole, never as a substring: a target for example.com must not
    fire for notexample.com.
    """

    wanted = {str(d).strip().lower() for d in record.get("domains") or []}
    wanted.discard("")
    if not wanted:
        return False
    return bool(wanted & {str(d).strip().lower() for d in domains})


# ───────────────────── the artefact ─────────────────────


def build_artefacts(
    lineage: Path, record: Dict[str, Any], workdir: Path
) -> List[Tuple[Path, str]]:
    """Local files to send, paired with the name to give each remotely."""

    fullchain = lineage / "fullchain.pem"
    privkey = lineage / "privkey.pem"
    for required in (fullchain, privkey):
        if not required.is_file():
            raise DeliveryError(f"{required} is missing")

    fmt = str(record.get("format") or "pfx").strip().lower()
    if fmt not in FORMATS:
        raise DeliveryError(f"format must be one of {', '.join(FORMATS)}")

    remote = str(record.get("remote_path") or "").strip()
    if not remote:
        raise DeliveryError("remote_path is required")

    if fmt == "pfx":
        out = workdir / "certificate.pfx"
        password = str(record.get("pfx_password") or "")
        result = subprocess.run(
            [
                "openssl", "pkcs12", "-export",
                "-inkey", str(privkey),
                "-in", str(fullchain),
                "-out", str(out),
                "-passout", f"pass:{password}",
            ],
            capture_output=True, timeout=60, check=False,
        )
        if result.returncode != 0:
            raise DeliveryError(
                "openssl could not build the PKCS#12 file: "
                + result.stderr.decode("utf-8", "replace").strip()
            )
        os.chmod(out, 0o600)
        return [(out, remote)]

    if fmt == "pem-combined":
        out = workdir / "certificate.pem"
        out.write_bytes(fullchain.read_bytes() + privkey.read_bytes())
        os.chmod(out, 0o600)
        return [(out, remote)]

    # pem-pair: remote_path names the directory the two files go into.
    chain_out = workdir / "fullchain.pem"
    key_out = workdir / "privkey.pem"
    shutil.copyfile(fullchain, chain_out)
    shutil.copyfile(privkey, key_out)
    os.chmod(chain_out, 0o644)
    os.chmod(key_out, 0o600)
    base = remote.rstrip("/")
    return [
        (chain_out, f"{base}/fullchain.pem"),
        (key_out, f"{base}/privkey.pem"),
    ]


# ───────────────────── transport ─────────────────────


def ssh_base_command(record: Dict[str, Any], binary: str) -> List[str]:
    """Options shared by every call to the OpenSSH client.

    The host key is pinned to what the operator saved, the same as an
    off-host backup. A private key that opens a shell somewhere else is
    worth as much as the certificate it carries, and accepting whatever
    answers on that address would hand both to it.
    """

    name = record["name"]
    port = str(record.get("port") or 22)
    return [
        binary,
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts_path(name)}",
        "-o", "IdentitiesOnly=yes",
        "-o", "ConnectTimeout=20",
        "-i", str(key_path(name)),
        "-P" if binary.endswith("sftp") else "-p", port,
    ]


def remote_quote(value: str) -> str:
    """Quote a path for the sftp batch language, which splits on whitespace."""

    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def send(record: Dict[str, Any], artefacts: List[Tuple[Path, str]]) -> None:
    transport = str(record.get("transport") or "sftp").strip().lower()
    if transport not in TRANSPORTS:
        raise DeliveryError(f"transport must be one of {', '.join(TRANSPORTS)}")

    target = f"{record['user']}@{record['host']}"

    if transport == "sftp":
        batch = "".join(
            f"put {remote_quote(str(local))} {remote_quote(name)}\n"
            for local, name in artefacts
        ) + "quit\n"
        command = ssh_base_command(record, "/usr/bin/sftp")
        command += ["-b", "-", target]
        result = subprocess.run(
            command, input=batch.encode("utf-8"),
            capture_output=True, timeout=SSH_TIMEOUT_SECONDS, check=False,
        )
    else:
        # scp takes many sources but only one destination. One artefact goes
        # to the exact remote name; a pair has to go into a directory, which
        # for pem-pair is what remote_path already is.
        if len(artefacts) == 1:
            destination = artefacts[0][1]
        else:
            destination = str(record.get("remote_path") or "").rstrip("/") + "/"
        command = ssh_base_command(record, "/usr/bin/scp")
        command += [str(local) for local, _ in artefacts]
        command += [f"{target}:{destination}"]
        result = subprocess.run(
            command, capture_output=True,
            timeout=SSH_TIMEOUT_SECONDS, check=False,
        )

    if result.returncode != 0:
        raise DeliveryError(
            f"{transport} failed: "
            + (result.stderr.decode("utf-8", "replace").strip()
               or f"exit {result.returncode}")
        )


def run_post_command(record: Dict[str, Any]) -> Optional[str]:
    """Whatever the far side needs doing once the file has landed.

    A Windows service has to be told to pick the certificate up; a web
    server needs a reload. Optional, and a failure here is reported without
    undoing the delivery -- the file did arrive.
    """

    command = str(record.get("post_command") or "").strip()
    if not command:
        return None
    full = ssh_base_command(record, "/usr/bin/ssh")
    full += [f"{record['user']}@{record['host']}", "--", command]
    result = subprocess.run(
        full, capture_output=True, timeout=SSH_TIMEOUT_SECONDS, check=False
    )
    if result.returncode != 0:
        return (
            "the file was delivered but the command afterwards failed: "
            + (result.stderr.decode("utf-8", "replace").strip()
               or f"exit {result.returncode}")
        )
    return None


# ───────────────────── one target ─────────────────────


def deliver(record: Dict[str, Any], lineage: Path) -> Dict[str, Any]:
    name = record.get("name", "?")
    if not record.get("enabled", True):
        return {"name": name, "ok": True, "skipped": "disabled"}

    for field in ("host", "user"):
        if not str(record.get(field) or "").strip():
            return {"name": name, "ok": False, "error": f"{field} is not set"}
    if not key_path(name).is_file():
        return {"name": name, "ok": False,
                "error": "no private key saved for this target"}
    if not known_hosts_path(name).is_file():
        return {"name": name, "ok": False,
                "error": "no host key saved for this target"}

    with tempfile.TemporaryDirectory(prefix="cert-deliver-") as tmp:
        workdir = Path(tmp)
        os.chmod(workdir, 0o700)
        try:
            artefacts = build_artefacts(lineage, record, workdir)
            send(record, artefacts)
        except DeliveryError as exc:
            return {"name": name, "ok": False, "error": str(exc)}
        except subprocess.TimeoutExpired:
            return {"name": name, "ok": False,
                    "error": f"timed out after {SSH_TIMEOUT_SECONDS}s"}
        warning = run_post_command(record)

    result: Dict[str, Any] = {"name": name, "ok": True,
                              "files": [remote for _, remote in artefacts]}
    if warning:
        result["warning"] = warning
    return result


def deliver_all(lineage: Path, domains: List[str]) -> List[Dict[str, Any]]:
    """Every target that wants one of these domains, whatever happens to any."""

    results: List[Dict[str, Any]] = []
    for record in list_destinations():
        if not wants_domain(record, domains):
            continue
        outcome = deliver(record, lineage)
        results.append(outcome)
        if outcome.get("ok"):
            LOG.info("delivered to %s", outcome["name"])
            if outcome.get("warning"):
                LOG.warning("%s: %s", outcome["name"], outcome["warning"])
        else:
            # Carrying on is the point: one unreachable machine must not
            # cost the others their certificate.
            LOG.error("delivery to %s failed: %s",
                      outcome["name"], outcome.get("error"))
    return results


def main(argv: Optional[List[str]] = None) -> int:
    logging.basicConfig(
        level=logging.INFO, format="cert-deliver: %(levelname)s %(message)s"
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lineage", default=os.environ.get("RENEWED_LINEAGE", ""))
    parser.add_argument("--domains", default=os.environ.get("RENEWED_DOMAINS", ""))
    args = parser.parse_args(argv)

    if not args.lineage:
        # Not an error: certbot runs deploy hooks only after a renewal, and
        # a manual run with nothing to deliver has nothing to say.
        LOG.info("no lineage given; nothing to deliver")
        return 0

    lineage = Path(args.lineage)
    domains = [d for d in args.domains.replace(",", " ").split() if d]
    if not domains:
        LOG.info("no renewed domains given; nothing to deliver")
        return 0

    results = deliver_all(lineage, domains)
    if not results:
        LOG.info("no delivery target wants %s", " ".join(domains))
        return 0

    failed = [r for r in results if not r.get("ok")]
    LOG.info("%d of %d targets delivered", len(results) - len(failed), len(results))
    # Non-zero so certbot reports it and the notification mail carries it.
    # The local reload already happened in the hook before this one.
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
