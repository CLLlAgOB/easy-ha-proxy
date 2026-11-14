"""Keep administrative server state without overriding a new HAProxy config.

Shared by the regular state dumper and package migration/rollback. HAProxy's
required v1 fields include cached addresses and ports as well as administrative
state; copying a runtime dump verbatim is therefore not a configuration backup.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import ipaddress
from pathlib import Path
import shlex
import sys


FIELDS = tuple("be_id be_name srv_id srv_name srv_addr srv_op_state srv_admin_state "
               "srv_uweight srv_iweight srv_time_since_last_change srv_check_status "
               "srv_check_result srv_check_health srv_check_state srv_agent_state "
               "bk_f_forced_id srv_f_forced_id srv_fqdn srv_port srvrecord".split())
OPTIONAL = tuple("srv_use_ssl srv_check_port srv_check_addr srv_agent_addr srv_agent_port".split())
SECTIONS = frozenset("global defaults frontend backend listen peers resolvers userlist mailers "
                     "cache program ring crt-store http-errors log-forward fcgi-app log-profile acme".split())


@dataclass(frozen=True)
class Server:
    host: str
    port: int | None
    check: bool
    agent: bool


def endpoint(value: str) -> tuple[str, int | None]:
    for prefix in ("ipv4@", "ipv6@"):
        if value.startswith(prefix):
            value = value[len(prefix):]
    if value.startswith("["):
        host, separator, suffix = value[1:].partition("]")
        if not separator:
            raise ValueError("Invalid bracketed server address")
        port = suffix[1:] if suffix.startswith(":") else ""
    elif value.count(":") == 1:
        host, port = value.rsplit(":", 1)
    else:
        # An unbracketed IPv6 literal without a port is not a port suffix.
        host, port = value, ""
    absolute_port = int(port) if port.isdecimal() else None
    if absolute_port is not None and not 0 <= absolute_port <= 65535:
        raise ValueError("Invalid server port")
    return host, absolute_port


def check_options(words: list[str], check: bool, agent: bool) -> tuple[bool, bool]:
    for word in words:
        if word == "check":
            check = True
        elif word == "no-check":
            check = False
        elif word == "agent-check":
            agent = True
        elif word == "no-agent-check":
            agent = False
    return check, agent


def configured_servers(config: str) -> dict[tuple[str, str], Server]:
    result = {}
    section, backend = "", ""
    defaults = check = agent = False
    default_agent = False
    for line in config.splitlines():
        first = line.lstrip().split(maxsplit=1)
        if not first or first[0] not in SECTIONS | {"default-server", "server"}:
            continue
        words = shlex.split(line, comments=True)
        if not words:
            continue
        keyword = words[0]
        if keyword in SECTIONS:
            section = keyword
            backend = words[1] if keyword in ("backend", "listen") and len(words) > 1 else ""
            if keyword == "defaults":
                defaults = default_agent = False
            check, agent = defaults, default_agent
        elif keyword == "default-server":
            check, agent = check_options(words[1:], check, agent)
            if section == "defaults":
                defaults, default_agent = check, agent
        elif keyword == "server" and backend and len(words) >= 3:
            host, port = endpoint(words[2])
            server_check, server_agent = check_options(words[3:], check, agent)
            result[backend, words[1]] = Server(host, port, server_check, server_agent)
    return result


def normalize_state(text: str, config: str | None) -> str:
    lines = text.splitlines()
    if not lines or lines[0] != "1":
        raise ValueError("Unsupported HAProxy server-state version")
    servers = configured_servers(config) if config is not None else {}
    output = ["1"]
    header = None
    for line in lines[1:]:
        if not line.strip():
            continue
        if line.startswith("#"):
            if not line.startswith("# be_id "):
                continue
            header = tuple(line[2:].split())
            if header[:len(FIELDS)] != FIELDS or header[len(FIELDS):] != OPTIONAL[:len(header) - len(FIELDS)]:
                raise ValueError("Unsupported HAProxy server-state header")
            output.append("# " + " ".join(FIELDS))
            continue
        row = line.split()
        if header is None or len(row) != len(header):
            raise ValueError("Incomplete HAProxy server-state row")
        values = dict(zip(FIELDS, row[:len(FIELDS)], strict=True))
        # Reject malformed state before writing any output, including rows that
        # HAProxy would otherwise partly apply and only warn about.
        for field in FIELDS:
            if field not in {"be_name", "srv_name", "srv_addr", "srv_fqdn", "srvrecord"}:
                if not values[field].isdecimal():
                    raise ValueError("Invalid numeric HAProxy server-state field: " + field)
        spec = servers.get((values["be_name"], values["srv_name"]))
        if spec is not None:
            # FQDN_CHANGED (0x40) is a runtime address override, not maintenance
            # or drain. A configured hostname must always take precedence.
            values["srv_admin_state"] = str(int(values["srv_admin_state"]) & ~0x40)
            if spec.port is not None:
                values["srv_port"] = str(spec.port)
            try:
                address = str(ipaddress.ip_address(spec.host))
            except ValueError:
                address = None
            if address is not None:
                values.update(srv_addr=address, srv_fqdn="-", srvrecord="-")
            elif spec.host.startswith("_"):
                # Keep DNS SRV discovery only while it belongs to this record.
                if values["srvrecord"] != spec.host:
                    values.update(srv_addr="-", srv_fqdn="-", srvrecord="-")
                    if spec.port is None:
                        values["srv_port"] = "0"
            elif spec.host and not spec.host.startswith(("/", "unix@", "abns@", "fd@")):
                hostname = spec.host.lower().rstrip(".")
                if values["srv_fqdn"].lower().rstrip(".") != hostname or values["srvrecord"] != "-":
                    values["srv_addr"] = "-"
                values.update(srv_fqdn=hostname, srvrecord="-")
            if not spec.check and not spec.agent:
                # With no checks left, an old health failure can never recover.
                # Administrative MAINT/DRAIN is still handled by HAProxy itself.
                values.update(srv_op_state="2", srv_check_status="0", srv_check_result="0",
                              srv_check_health="0", srv_check_state="0", srv_agent_state="0")
        output.append(" ".join(values[field] for field in FIELDS))
    return "\n".join(output) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    try:
        config = args.config.read_text() if args.config.exists() else None
        result = normalize_state(args.state.read_text(), config)
    except (OSError, ValueError) as error:
        print("Cannot normalize HAProxy state: " + str(error), file=sys.stderr)
        return 1
    sys.stdout.write(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
