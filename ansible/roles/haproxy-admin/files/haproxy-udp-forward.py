#!/usr/bin/env python3
"""Kernel-NAT UDP forwarding for easy-ha-proxy (variant A).

HAProxy speaks only TCP/HTTP, so UDP services are forwarded with plain
iptables (legacy) DNAT instead. This generator reads the managed
``udp.yml`` and programs dedicated ``HP_UDP_*`` chains:

  * raw/PREROUTING  HP_UDP_RAW  — DROP banned sources (ipset ``haproxy_ban``)
                                  on the ORIGINAL listen port, before DNAT,
                                  so the existing ban set also covers UDP.
  * nat/PREROUTING  HP_UDP_PRE  — DNAT udp :listen -> backend:port
  * nat/POSTROUTING HP_UDP_POST — MASQUERADE towards the backend
  * filter/FORWARD  HP_UDP_FWD  — ACCEPT a routed forwarded flow (+ conntrack)

It manages only its own chains (create once, jump once, flush + repopulate
on every run), so it never touches Docker's or the ban loader's rules and
is fully idempotent. ``net.ipv4.ip_forward`` is enabled so DNATed packets
are routed to the backend.

Forwarding permits are mirrored into installed legacy/nft filter backends:
ACCEPT in one cannot override DROP in the other. DOCKER-USER hooks precede
Docker's own forwarding rules; only configured DNAT flows are permitted.

Backends must use a non-loopback IPv4 address and see the proxy address because
their flows are masqueraded. Geo filtering is intentionally out of scope here
— the ban set is reused, but per-country UDP filtering would need a separate
allow ipset.

A forward may name a backup backend. haproxy-controld checks the main one
and, when it stops answering, writes ``udp-failover.json`` and runs this
generator again: the DNAT then points at the backup until the main backend
answers again. Without that file every forward uses its main backend.

Usage:
  haproxy-udp-forward.py                  # generate and apply (root)
  haproxy-udp-forward.py --dry-run        # print the planned iptables commands
  haproxy-udp-forward.py --check          # validate udp.yml only, apply nothing
  haproxy-udp-forward.py --health-targets # what controld checks, as JSON
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import shutil
import subprocess
import sys
import tempfile

try:
    import yaml
except ImportError:  # pragma: no cover - exercised only on hosts without PyYAML
    yaml = None

CONFIG_PATH = os.environ.get("HP_UDP_CONFIG", "/opt/haproxy-admin/config/udp.yml")
IPTABLES = os.environ.get("HP_UDP_IPTABLES", "iptables-legacy")
IPTABLES_RESTORE = os.environ.get(
    "HP_UDP_IPTABLES_RESTORE", "iptables-legacy-restore"
)
BAN_SET = os.environ.get("HP_UDP_BAN_SET", "haproxy_ban")
AUTH_SET = os.environ.get("HP_UDP_AUTH_SET", "haproxy_ip_auth")
STATE_PATH = Path(
    os.environ.get(
        "HP_UDP_STATE",
        "/run/easy-ha-proxy/udp-forward-state.json",
    )
)
FAILOVER_PATH = Path(
    os.environ.get("HP_UDP_FAILOVER", "/run/easy-ha-proxy/udp-failover.json")
)
FAILOVER_MAX_BYTES = 64 * 1024
HEALTH_CHECKS = ("ping", "tcp")
MAX_PORTS_PER_FORWARD = 1024
PORT_RANGE_RE = re.compile(r"^([0-9]{1,5})(?:-([0-9]{1,5}))?$")

RAW_CHAIN = "HP_UDP_RAW"
NAT_PRE = "HP_UDP_PRE"
NAT_POST = "HP_UDP_POST"
FWD_CHAIN = "HP_UDP_FWD"
LEGACY_INPUT_CHAIN = "HP_UDP_IN"

# (table, built-in chain, our custom chain) — jump is inserted at the top of
# the built-in chain so our handling runs before Docker's populated rules.
WIRING = (
    ("raw", "PREROUTING", RAW_CHAIN),
    ("nat", "PREROUTING", NAT_PRE),
    ("nat", "POSTROUTING", NAT_POST),
    ("filter", "FORWARD", FWD_CHAIN),
)


class ConfigError(Exception):
    """A udp.yml entry that must be reported and skipped or aborted."""


def log(message: str) -> None:
    print(f"[easy-ha-proxy-udp] {message}", flush=True)


def _resolve_ipv4(host: str) -> str:
    """Return an IPv4 literal for host (accepts a literal or resolves a name)."""
    try:
        return str(ipaddress.IPv4Address(host))
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
    except OSError as exc:
        raise ConfigError(f"cannot resolve backend host {host!r}: {exc}") from exc
    for info in infos:
        return info[4][0]
    raise ConfigError(f"backend host {host!r} has no IPv4 address")


def _port_range(value: object, field: str) -> tuple[int, int]:
    """Parse ``53`` or an inclusive ``10000-10010`` port range."""

    text = str(value if value is not None else "").strip()
    match = PORT_RANGE_RE.fullmatch(text)
    if not match:
        raise ConfigError(
            f"{field} must be a port or inclusive range such as 51820-51830"
        )
    start = int(match.group(1))
    end = int(match.group(2) or start)
    if not 1 <= start <= 65535 or not 1 <= end <= 65535:
        raise ConfigError(f"{field} must be within 1-65535, got {text!r}")
    if end < start:
        raise ConfigError(f"{field} range end must not be lower than its start")
    if end - start + 1 > MAX_PORTS_PER_FORWARD:
        raise ConfigError(
            f"{field} range may contain at most {MAX_PORTS_PER_FORWARD} ports"
        )
    return start, end


def _format_port_range(start: int, end: int) -> int | str:
    return start if start == end else f"{start}-{end}"


def _dport_tokens(start: int, end: int) -> list[str]:
    value = str(start) if start == end else f"{start}:{end}"
    return ["--dport", value]


def normalize_forward(raw: object) -> dict:
    """Validate one forward entry into primitive, injection-safe fields."""
    if not isinstance(raw, dict):
        raise ConfigError("each UDP forward must be a mapping")
    name = str(raw.get("name") or "").strip()
    listen_start, listen_end = _port_range(
        raw.get("listen_port"), "listen_port"
    )
    backend_host = str(raw.get("backend_host") or "").strip()
    if not backend_host:
        raise ConfigError(
            f"forward {name or _format_port_range(listen_start, listen_end)!r} "
            "is missing backend_host"
        )
    backend_ip = _resolve_ipv4(backend_host)
    if ipaddress.ip_address(backend_ip).is_loopback:
        raise ConfigError(
            "backend_host must not resolve to a loopback address; "
            "use a container or LAN backend"
        )
    backend_start, backend_end = _port_range(
        raw.get("backend_port"), "backend_port"
    )
    listen_count = listen_end - listen_start + 1
    backend_count = backend_end - backend_start + 1
    if listen_count != backend_count:
        raise ConfigError(
            "listen_port and backend_port ranges must contain the same "
            "number of ports"
        )
    backup = _normalize_backup(raw, backend_ip, backend_start, backend_end)
    return {
        "name": name or f"udp{listen_start}",
        "listen_port": _format_port_range(listen_start, listen_end),
        "listen_start": listen_start,
        "listen_end": listen_end,
        "backend_ip": backend_ip,
        "backend_port": _format_port_range(backend_start, backend_end),
        "backend_start": backend_start,
        "backend_end": backend_end,
        "ban_check": bool(raw.get("ban_check", True)),
        "zero_trust": bool(raw.get("zero_trust", False)),
        "backup": backup,
        # Where the DNAT points; set_active() moves it to the backup.
        "active": "primary",
        "target_ip": backend_ip,
        "target_start": backend_start,
    }


def _normalize_backup(raw: dict, backend_ip: str, backend_start: int, backend_end: int) -> dict | None:
    """The backup backend of a forward and how its main backend is checked, or None.

    A backup whose name does not resolve is kept with no address: the forward
    goes on working on its main backend, and controld cannot switch to it.
    """
    host = str(raw.get("backup_host") or "").strip()
    if not host:
        return None
    try:
        ip = _resolve_ipv4(host)
    except ConfigError as exc:
        log(f"backup of forward {raw.get('name')!r} is unavailable: {exc}")
        ip = None
    if ip is not None and ipaddress.ip_address(ip).is_loopback:
        raise ConfigError("backup_host must not resolve to a loopback address")
    if ip is not None and ip == backend_ip:
        raise ConfigError("backup_host must be a different address from backend_host")
    port_value = raw.get("backup_port")
    if port_value in (None, ""):
        port_value = raw.get("backend_port")
    start, end = _port_range(port_value, "backup_port")
    if end - start != backend_end - backend_start:
        raise ConfigError("backup_port must contain as many ports as backend_port")
    check = str(raw.get("health_check") or "ping").strip().lower()
    if check not in HEALTH_CHECKS:
        raise ConfigError("health_check must be ping or tcp")
    health_port = None
    if check == "tcp":
        text = str(raw.get("health_port") or "").strip()
        if not text.isdigit() or not 1 <= int(text) <= 65535:
            raise ConfigError("health_port must be a TCP port (1-65535) for the tcp check")
        health_port = int(text)
    return {
        "host": host,
        "ip": ip,
        "start": start,
        "end": end,
        "port": _format_port_range(start, end),
        "check": check,
        "health_port": health_port,
    }


def load_failover(path: Path | None = None) -> dict[str, str]:
    """Forward name -> "backup" for the forwards controld switched over.

    Anything unreadable is no switch at all: every forward keeps its main
    backend, which is what it had before failover existed.
    """
    path = path or FAILOVER_PATH
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > FAILOVER_MAX_BYTES:
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("active"), dict):
        return {}
    return {str(name): "backup" for name, side in data["active"].items() if side == "backup"}


def set_active(forwards: list[dict], failover: dict[str, str]) -> list[dict]:
    """Point each switched-over forward at its backup, when it has one that resolved."""
    for fwd in forwards:
        backup = fwd.get("backup")
        if failover.get(fwd["name"]) == "backup" and backup and backup.get("ip"):
            fwd.update(active="backup", target_ip=backup["ip"], target_start=backup["start"])
    return forwards


def health_targets(forwards: list[dict]) -> list[dict]:
    """What controld checks: the forwards that have a backup."""
    return [
        {
            "name": fwd["name"],
            "primary": fwd["backend_ip"],
            "backup": fwd["backup"]["ip"],
            "check": fwd["backup"]["check"],
            "health_port": fwd["backup"]["health_port"],
        }
        for fwd in forwards
        if fwd.get("backup")
    ]


def load_forwards(path: str) -> list[dict]:
    """Read udp.yml and return validated, de-duplicated enabled forwards."""
    if yaml is None:
        raise SystemExit("PyYAML is required (install python3-yaml)")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise SystemExit(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"{path}: root must be a mapping")
    entries = data.get("udp_forwards")
    if entries is None:
        entries = data.get("udp")
    if not isinstance(entries, list):
        return []

    forwards: list[dict] = []
    seen_ports: set[int] = set()
    for index, entry in enumerate(entries):
        if isinstance(entry, dict) and entry.get("enabled") is False:
            continue
        try:
            forward = normalize_forward(entry)
        except ConfigError as exc:
            raise SystemExit(f"{path}: udp_forwards[{index}]: {exc}") from exc
        ports = set(
            range(forward["listen_start"], forward["listen_end"] + 1)
        )
        overlap = seen_ports.intersection(ports)
        if overlap:
            first = min(overlap)
            raise SystemExit(
                f"{path}: udp_forwards[{index}]: listen port {first} "
                "is configured more than once"
            )
        seen_ports.update(ports)
        forwards.append(forward)
    return forwards


def build_rule_commands(forwards: list[dict]) -> list[list[str]]:
    """Return the iptables argument lists that populate the custom chains.

    Pure function (no side effects) so it can be unit tested. The returned
    lists exclude the iptables binary itself.
    """
    commands: list[list[str]] = []
    for fwd in forwards:
        listen_start = int(fwd["listen_start"])
        listen_end = int(fwd["listen_end"])
        # The main backend, or the backup while controld has switched over.
        backend_ip = fwd.get("target_ip") or fwd["backend_ip"]
        # The two ranges are the same length (checked when saved), so the
        # backend port is the start plus the listening port's offset.
        backend_start = int(fwd.get("target_start") or fwd["backend_start"])
        listen_tokens = _dport_tokens(listen_start, listen_end)
        if fwd["ban_check"]:
            # DROP in raw/PREROUTING matches every packet on the original port
            # before conntrack/DNAT, so a banned source never reaches DNAT.
            commands.append(
                ["-t", "raw", "-A", RAW_CHAIN, "-p", "udp", *listen_tokens,
                 "-m", "set", "--match-set", BAN_SET, "src", "-j", "DROP"]
            )
        if fwd.get("zero_trust"):
            # Zero-trust: drop everything on this port whose source is NOT in
            # the authorized-IP set (mirrored from tbl_ip_auth by controld),
            # so only visitors who passed the access gate reach the backend.
            commands.append(
                ["-t", "raw", "-A", RAW_CHAIN, "-p", "udp", *listen_tokens,
                 "-m", "set", "!", "--match-set", AUTH_SET, "src", "-j", "DROP"]
            )
        for offset, listen_port in enumerate(
            range(listen_start, listen_end + 1)
        ):
            backend_port = backend_start + offset
            commands.append(
                [
                    "-t", "nat", "-A", NAT_PRE, "-p", "udp",
                    "--dport", str(listen_port), "-j", "DNAT",
                    "--to-destination", f"{backend_ip}:{backend_port}",
                ]
            )
            commands.append(
                [
                    "-t", "nat", "-A", NAT_POST, "-p", "udp",
                    "-d", backend_ip, "--dport", str(backend_port),
                    "-j", "MASQUERADE",
                ]
            )
            commands.append(
                [
                    "-t", "filter", "-A", FWD_CHAIN, "-p", "udp",
                    "-d", backend_ip, "--dport", str(backend_port),
                    "-m", "conntrack", "--ctstate", "DNAT",
                    "--ctdir", "ORIGINAL", "--ctorigdstport", str(listen_port),
                    "-j", "ACCEPT",
                ]
            )
            commands.append(
                ["-t", "filter", "-A", FWD_CHAIN, "-p", "udp",
                 "-s", backend_ip, "--sport", str(backend_port),
                 "-m", "conntrack", "--ctstate", "DNAT",
                 "--ctdir", "REPLY", "--ctorigdstport", str(listen_port),
                 "-j", "ACCEPT"]
            )
    return commands


def _run(args: list[str], *, check: bool = True, binary: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [binary or IPTABLES, "-w", "10", *args],
        check=check,
        capture_output=True,
        text=True,
    )


def _run_restore(commands: list[list[str]], *, binary: str | None = None,
                 tables: tuple[str, ...] = ("raw", "nat", "filter")) -> None:
    """Replace all managed-chain rules with one iptables-restore transaction."""

    lines: list[str] = []
    for table in tables:
        lines.append(f"*{table}")
        for wiring_table, _builtin, chain in WIRING:
            if wiring_table == table:
                lines.append(f"-F {chain}")
        for command in commands:
            if len(command) >= 3 and command[:2] == ["-t", table]:
                lines.append(" ".join(command[2:]))
        lines.append("COMMIT")
    result = subprocess.run(
        [binary or IPTABLES_RESTORE, "--wait", "10", "--noflush"],
        input="\n".join(lines) + "\n",
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "iptables-restore failed: "
            + (result.stderr or result.stdout or "unknown error").strip()
        )


def _ensure_scaffolding() -> None:
    """Create the custom chains and their single jump from the built-in chain."""
    for table, builtin, chain in WIRING:
        # Create the chain if it does not exist yet (ignore "already exists").
        _run(["-t", table, "-N", chain], check=False)
        # Ensure exactly one jump into it, at the top of the built-in chain.
        exists = _run(["-t", table, "-C", builtin, "-j", chain], check=False)
        if exists.returncode != 0:
            _run(["-t", table, "-I", builtin, "1", "-j", chain])
    _docker_user_hook(IPTABLES)


def _docker_user_hook(binary: str) -> None:
    # Docker may prepend its jumps again after a restart. DOCKER-USER is its
    # persistent entry point for operator rules, before Docker's own drops.
    if _run(['-t', 'filter', '-S', 'DOCKER-USER'], binary=binary, check=False).returncode == 0:
        if _run(['-t', 'filter', '-C', 'DOCKER-USER', '-j', FWD_CHAIN], binary=binary, check=False).returncode != 0:
            _run(['-t', 'filter', '-I', 'DOCKER-USER', '1', '-j', FWD_CHAIN], binary=binary)


def _sync_other_forward_filters(commands: list[list[str]]) -> None:
    # ACCEPT in legacy does not bypass nft's FORWARD policy (or vice versa).
    # Mirror only the narrow forwarding rules; NAT/raw/ipsets remain managed
    # by the selected primary backend. Never change Docker chains or policies.
    primary = os.path.realpath(shutil.which(IPTABLES) or IPTABLES)
    for name in ('iptables-legacy', 'iptables-nft'):
        binary = shutil.which(name)
        if not binary or os.path.realpath(binary) == primary:
            continue
        restore = shutil.which(name + '-restore')
        if not restore:
            raise RuntimeError(f'{name}-restore is required for UDP forwarding')
        _run(['-t', 'filter', '-N', FWD_CHAIN], binary=binary, check=False)
        if _run(['-t', 'filter', '-C', 'FORWARD', '-j', FWD_CHAIN], binary=binary, check=False).returncode != 0:
            _run(['-t', 'filter', '-I', 'FORWARD', '1', '-j', FWD_CHAIN], binary=binary)
        _docker_user_hook(binary)
        _run_restore(commands, binary=restore, tables=('filter',))


def _remove_legacy_loopback_scaffolding() -> None:
    """Remove the INPUT chain used by the retired loopback-backend mode."""

    while True:
        exists = _run(
            ["-t", "filter", "-C", "INPUT", "-j", LEGACY_INPUT_CHAIN],
            check=False,
        )
        if exists.returncode != 0:
            break
        _run(["-t", "filter", "-D", "INPUT", "-j", LEGACY_INPUT_CHAIN])
    _run(["-t", "filter", "-F", LEGACY_INPUT_CHAIN], check=False)
    _run(["-t", "filter", "-X", LEGACY_INPUT_CHAIN], check=False)


def _write_sysctl(path: str, value: str = "1") -> None:
    try:
        with open(path, "r+", encoding="ascii") as handle:
            if handle.read().strip() != value:
                handle.seek(0)
                handle.write(value + "\n")
                handle.truncate()
    except OSError as exc:
        raise RuntimeError(f"could not set {path}={value}: {exc}") from exc


def enable_forwarding() -> None:
    _write_sysctl("/proc/sys/net/ipv4/ip_forward")
    _write_sysctl("/proc/sys/net/ipv4/conf/all/route_localnet", "0")
    _write_sysctl("/proc/sys/net/ipv4/conf/default/route_localnet", "0")


def _state_payload(forwards: list[dict]) -> dict[str, object]:
    return {
        "version": 1,
        "applied_at": datetime.now(timezone.utc).isoformat(),
        "forwards": len(forwards),
        "ports": sum(
            int(item["listen_end"]) - int(item["listen_start"]) + 1
            for item in forwards
        ),
        # Kept in the version-1 state schema for compatibility with an
        # already-running controller/UI during rolling updates.
        "local_backends": 0,
    }


def _write_state(state: dict[str, object]) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            delete=False,
            dir=STATE_PATH.parent,
            prefix=f".{STATE_PATH.name}.",
        ) as handle:
            json.dump(state, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
            temporary = handle.name
        os.chmod(temporary, 0o644)
        os.replace(temporary, STATE_PATH)
        temporary = None
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def apply_forwards(forwards: list[dict]) -> None:
    enable_forwarding()
    _remove_legacy_loopback_scaffolding()
    _ensure_scaffolding()
    commands = build_rule_commands(forwards)
    _run_restore(commands)
    _sync_other_forward_filters(commands)
    state = _state_payload(forwards)
    _write_state(state)
    switched = [fwd["name"] for fwd in forwards if fwd.get("active") == "backup"]
    log(
        "applied "
        f"{state['forwards']} UDP forward(s), {state['ports']} port(s)"
        + (f"; on their backup: {', '.join(switched)}" if switched else "")
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="easy-ha-proxy UDP forwarding")
    parser.add_argument("--config", default=CONFIG_PATH)
    parser.add_argument("--dry-run", action="store_true",
                        help="print the planned iptables commands, change nothing")
    parser.add_argument("--check", action="store_true",
                        help="validate the configuration only")
    parser.add_argument("--health-targets", action="store_true",
                        help="print the forwards with a backup, as JSON, change nothing")
    args = parser.parse_args(argv)

    forwards = load_forwards(args.config)

    if args.health_targets:
        print(json.dumps(health_targets(forwards), sort_keys=True))
        return 0

    set_active(forwards, load_failover())

    if args.check:
        state = _state_payload(forwards)
        log(
            f"{state['forwards']} valid UDP forward(s), "
            f"{state['ports']} port(s)"
        )
        return 0

    if args.dry_run:
        for table, builtin, chain in WIRING:
            print(f"{IPTABLES} -t {table} -N {chain}")
            print(f"{IPTABLES} -t {table} -C {builtin} -j {chain} "
                  f"|| {IPTABLES} -t {table} -I {builtin} 1 -j {chain}")
            print(f"{IPTABLES} -t {table} -F {chain}")
        for command in build_rule_commands(forwards):
            print(IPTABLES + " " + " ".join(command))
        return 0

    apply_forwards(forwards)
    return 0


if __name__ == "__main__":
    sys.exit(main())
