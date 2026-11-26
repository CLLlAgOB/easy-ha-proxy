#!/usr/bin/env python3
"""Transitional shim: forwards the easy-ha-proxy CLI to easy-ha-proxy-agent cli.

The installer CLI lives in the Go host agent (go/agent/internal/cli). This
shim remains for callers that invoke installer/easy_ha_proxy.py directly and
for the one-time bootstrap on a fresh host or during an upgrade from an agent
predating "easy-ha-proxy-agent cli".
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys

_INSTALLER_DIR = str(Path(__file__).resolve().parent)
if _INSTALLER_DIR not in sys.path:
    sys.path.insert(0, _INSTALLER_DIR)

AGENT = os.environ.get("EASY_HA_PROXY_AGENT_BIN", "/usr/local/sbin/easy-ha-proxy-agent")
STAGED_AGENT = Path(
    os.environ.get(
        "EASY_HA_PROXY_STAGED_AGENT",
        "/var/lib/easy-ha-proxy/native-staging/bootstrap/easy-ha-proxy-agent",
    )
)
DEFAULT_CONFIG_DIR = Path("/etc/easy-ha-proxy")
SOURCE_REVISION_RE = re.compile(r"^[0-9a-f]{40,64}$")


def _source_dir() -> Path:
    configured = os.environ.get("EASY_HA_PROXY_SOURCE_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(__file__).resolve().parents[1]


def _config_dir() -> Path:
    return Path(
        os.environ.get("EASY_HA_PROXY_CONFIG_DIR", str(DEFAULT_CONFIG_DIR))
    ).expanduser()


def _agent_supports_cli(path: str | Path) -> bool:
    candidate = Path(path)
    if not candidate.is_file():
        return False
    try:
        probe = subprocess.run(
            [str(candidate), "cli", "--probe"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return probe.returncode == 0


def _load_bootstrap_vars(vars_file: Path) -> dict:
    if not vars_file.is_file():
        return {}
    try:
        import yaml  # type: ignore[import-not-found]

        loaded = yaml.safe_load(vars_file.read_text(encoding="utf-8"))
        return loaded if isinstance(loaded, dict) else {}
    except Exception:
        pass
    # Stdlib-only fallback when PyYAML is not installed.
    result: dict = {}
    keys = {
        "haproxy_admin_image",
        "native_local_bundle_dir",
        "native_release_base_url",
        "native_release_image",
        "native_release_pin_revision",
    }
    try:
        for line in vars_file.read_text(encoding="utf-8").splitlines():
            if ":" not in line or line.lstrip().startswith("#"):
                continue
            key, value = line.split(":", 1)
            key = key.strip()
            if key in keys:
                cleaned = value.strip().strip('"').strip("'")
                result[key] = cleaned
    except OSError:
        return {}
    return result


def _bootstrap_cli_agent() -> str:
    import agent_bootstrap

    src = _source_dir()
    rev_proc = subprocess.run(
        ["git", "-c", f"safe.directory={src}", "-C", str(src), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    revision = rev_proc.stdout.strip()
    if not SOURCE_REVISION_RE.fullmatch(revision):
        revision = ""
    variables = _load_bootstrap_vars(_config_dir() / "vars.yml")
    reference = agent_bootstrap.image_reference(variables, revision)
    source = reference or "the configured native bundle"
    try:
        binary = agent_bootstrap.bundle_agent(variables)
        if binary is None and reference is not None:
            binary = agent_bootstrap.docker_agent(reference, revision)
            if binary is None:
                binary = agent_bootstrap.fetch_agent(reference, revision)
        if binary is None:
            raise agent_bootstrap.BootstrapError("no source of the native binaries is configured")
        agent_bootstrap.install_agent(binary, STAGED_AGENT)
    except Exception as exc:
        raise RuntimeError(
            f"Could not get the installer agent from {source}: {exc}. "
            "CI publishes it for each commit of main and alpha a few minutes after the commit."
        ) from exc
    if not _agent_supports_cli(STAGED_AGENT):
        raise RuntimeError(
            f"The agent from {source} does not support 'cli'; it is older than this source."
        )
    return str(STAGED_AGENT)


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else list(argv)
    target: str | None = None
    if _agent_supports_cli(AGENT):
        target = AGENT
    elif _agent_supports_cli(STAGED_AGENT):
        target = str(STAGED_AGENT)
    else:
        try:
            target = _bootstrap_cli_agent()
        except RuntimeError as exc:
            print(f"\nERROR: {exc}", file=sys.stderr)
            return 2
    os.execv(target, [target, "cli", *arguments])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
