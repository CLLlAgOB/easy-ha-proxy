"""HAProxy runtime PathShield and tbl_ban enforcement primitives."""

from __future__ import annotations

import pathlib
import re
from typing import Any, Dict, Iterable, Optional, Set

from . import constants as _constants
from .constants import (
    ADAPTIVE_BAN_CODE,
    ADAPTIVE_CODES,
    LOG,
    MODE_ENFORCE,
    _safe_int,
    category_is_decisive,
    enforceable,
)
from .runtime import (
    GuardConfig,
    RuntimeAnswerTooLarge,
    TableUnreadable,
    read_table,
    runtime_command,
)
from .scoring import HAPROXY_CONFIG_PATH
from .watchers import LEGACY_BAN_CODES

# ---------------------------------------------------------------------------
# Enforcement primitives (unused while mode is monitor)
# ---------------------------------------------------------------------------


class LiftRefused(OSError):
    """HAProxy refused to remove a ban table entry: the ban still stands."""


# What leaves a ban's state unknown: a lift HAProxy refused, a table read
# that was not the table, an answer too large to have been read whole. The
# ban is kept on the schedule and tried again, never taken for gone (R01/R10).
BAN_TABLE_UNSURE = (LiftRefused, TableUnreadable, RuntimeAnswerTooLarge)


# ---------------------------------------------------------------------------
# The path shield
#
# A ban follows the log: by the time it lands, the request that earned it has
# been answered. For a decisive category that is the one request that
# matters -- if a site really does serve its .env, the first probe has it.
# HAProxy therefore refuses the decisive signatures itself, from three lists
# it reads at request time, and this class keeps those lists equal to what
# the engine would ban for: the shipped and operator's decisive signatures
# whose rule is enforcing, and nothing at all unless the mode is enforce.
#
# The lists live in HAProxy's memory. The files the configuration names stay
# empty on disk -- this daemon cannot write under /etc/haproxy and does not
# need to: a reloaded HAProxy starts with empty lists and is filled again on
# the next cycle, and until then the ban still follows as it always did.
SHIELD_ENABLED_KEY = "path_shield_enabled"
SHIELD_MARKER = re.compile(
    r"^\s*# guardd-shield segments=(?P<segments>\S+) paths=(?P<paths>\S+) exempt=(?P<exempt>\S+)\s*$",
    re.M,
)
# One word, and none of the characters the runtime socket reads as its own:
# a space ends the pattern, a semicolon ends the command.
_SHIELD_SEGMENT = re.compile(r"^[A-Za-z0-9._~+@%=,:!$()\[\]-]{1,128}$")
_SHIELD_PATH = re.compile(r"^/[A-Za-z0-9._~+@%=,:!$()\[\]/-]{1,199}$")
_SHIELD_HOST = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
SHIELD_MAX_ENTRIES = 2000


def read_shield_files(path: str = "") -> Dict[str, str]:
    """The three list names the running configuration declares, or {}."""
    try:
        text = pathlib.Path(path or HAPROXY_CONFIG_PATH).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    match = SHIELD_MARKER.search(text)
    return match.groupdict() if match else {}


def shield_entries(mode: str, enabled: bool, modes: Dict[str, str],
                   exceptions: Iterable[Dict[str, Any]], now: int) -> Dict[str, Any]:
    """What HAProxy should refuse by itself right now.

    Only what a single request is banned for anyway: decisive categories
    whose rule is enforcing. A wildcard signature is left to the engine --
    the lists match whole segments and whole paths. A site with an exception
    for a decisive rule is left out as a whole: the exception is narrower
    than a host, and the engine applies it exactly, so the shield stands
    back there rather than guess.
    """
    result: Dict[str, Any] = {"segments": set(), "paths": set(), "exempt": set(), "skipped": []}
    if mode != MODE_ENFORCE or not enabled:
        return result

    def enforcing(category: str) -> bool:
        return category_is_decisive(category) and modes.get("path:" + category, "enforce") == "enforce"

    for token, category in _constants.SCANNER_SEGMENTS.items():
        if not enforcing(category) or token.endswith("*"):
            continue
        value = token.lower()
        (result["segments"].add(value) if _SHIELD_SEGMENT.fullmatch(value) else result["skipped"].append(token))
    for token, category in _constants.SCANNER_PATHS.items():
        if not enforcing(category):
            continue
        (result["paths"].add(token) if _SHIELD_PATH.fullmatch(token) else result["skipped"].append(token))
    for row in exceptions:
        rule = str(row.get("rule") or "")
        if not rule.startswith("path:") or not category_is_decisive(rule[5:]):
            continue
        if row.get("expires") and int(row["expires"]) <= now:
            continue
        result["exempt"].update(h for h in row.get("hosts") or [] if _SHIELD_HOST.fullmatch(str(h)))
    for key in ("segments", "paths", "exempt"):
        if len(result[key]) > SHIELD_MAX_ENTRIES:
            raise ValueError(f"the path shield would hold {len(result[key])} {key}; refusing a list that large")
    result["skipped"] = sorted(set(result["skipped"]))[:20]
    return result


class PathShield:
    """Keeps HAProxy's three shield lists equal to the engine's decisive rules.

    The only place that changes an HAProxy list, as Enforcer is the only
    place that changes the ban table. A list is replaced whole and at once
    (prepare, add, commit), so HAProxy never refuses by half a list.
    """

    def __init__(self, config: GuardConfig, config_path: str = "") -> None:
        self.config = config
        self.config_path = config_path
        self.status: Dict[str, Any] = {"configured": False, "active": False, "segments": 0, "paths": 0,
                                       "exempt_hosts": 0, "synced_at": 0, "replaced": 0, "error": None,
                                       "skipped": []}

    def _command(self, command: str) -> str:
        return runtime_command(self.config.haproxy_socket, command)

    def current(self, name: str) -> Set[str]:
        """The patterns HAProxy holds for one list."""
        answer = self._command(f"show acl {name}")
        values: Set[str] = set()
        for line in answer.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[0].startswith("0x"):
                values.add(parts[1].strip())
            elif line.strip() and not line.startswith("#"):
                # "Unknown ACL identifier" and the like: not a list at all.
                raise OSError(f"HAProxy did not return the list {name}: {line.strip()[:120]!r}")
        return values

    def replace(self, name: str, values: Set[str]) -> None:
        answer = self._command(f"prepare acl {name}")
        found = re.search(r"New version created:\s*(\d+)", answer)
        if not found:
            raise OSError(f"HAProxy did not prepare the list {name}: {answer.strip()[:120]!r}")
        version = found.group(1)
        for value in sorted(values):
            refused = self._command(f"add acl @{version} {name} {value}").strip()
            if refused:
                raise OSError(f"HAProxy refused {value!r} for {name}: {refused[:120]}")
        refused = self._command(f"commit acl @{version} {name}").strip()
        if refused:
            raise OSError(f"HAProxy did not commit the list {name}: {refused[:120]}")

    def sync(self, wanted: Dict[str, Any], now: int) -> Dict[str, Any]:
        files = read_shield_files(self.config_path)
        status = {"configured": bool(files), "active": False, "segments": 0, "paths": 0, "exempt_hosts": 0,
                  "synced_at": self.status.get("synced_at", 0), "replaced": self.status.get("replaced", 0),
                  "error": None, "skipped": list(wanted.get("skipped") or [])}
        if not files:
            # A configuration from before the shield, or one rendered without
            # it: nothing to keep in step.
            self.status = status
            return status
        try:
            for key, name in (("exempt", files["exempt"]), ("segments", files["segments"]), ("paths", files["paths"])):
                # The exemptions first when filling, so no site is refused
                # for the moment its exception has not arrived yet.
                if self.current(name) != wanted[key]:
                    self.replace(name, wanted[key])
                    status["replaced"] += 1
            status.update(active=bool(wanted["segments"] or wanted["paths"]), segments=len(wanted["segments"]),
                          paths=len(wanted["paths"]), exempt_hosts=len(wanted["exempt"]), synced_at=now)
        except (OSError, ValueError) as exc:
            status["error"] = str(exc)[:300]
        self.status = status
        return status


class Enforcer:
    """The ban path, isolated so the monitor guarantee stays checkable.

    Applying a ban is refused unless the active mode is `enforce`, so a
    detection rule cannot reach HAProxy by accident. The commands are the ones
    the HAProxy configuration already uses -- gpc0 as the ban flag, gpt0 as the
    reason code -- which keeps adaptive bans visible in the existing ban list
    and removable by the existing unban button.

    Lifting is deliberately *not* gated on the mode: turning enforcement off
    has to be able to undo what it did.
    """

    def __init__(self, config: GuardConfig, mode: Optional[str] = None) -> None:
        self.config = config
        self.mode = mode or config.mode
        self.refused = 0
        self.applied = 0
        self.failed = 0
        self.lifted = 0

    @property
    def allowed(self) -> bool:
        return self.mode == MODE_ENFORCE

    def ban(self, ip: str, *, code: int = ADAPTIVE_BAN_CODE) -> bool:
        if not self.allowed:
            self.refused += 1
            return False
        if not enforceable(ip):
            return False
        answer = runtime_command(
            self.config.haproxy_socket,
            f"set table tbl_ban key {ip} data.gpc0 1 data.gpt0 {int(code)}",
        )
        # HAProxy answers a successful `set table` with an empty line; any
        # text is its refusal ("No such table"). A ban it refused is not a
        # ban: no schedule, no BAN_APPLIED, and the next cycle tries again.
        if answer.strip():
            self.failed += 1
            LOG.warning("HAProxy refused the ban on %s: %s", ip, answer.strip()[:200])
            return False
        self.applied += 1
        return True

    def active_bans(self) -> Dict[str, int]:
        """Every ban standing in the table, with its reason code."""

        rows = read_table(self.config.haproxy_socket, "tbl_ban")
        return {
            ip: _safe_int(fields.get("gpt0"))
            for ip, fields in rows.items()
            if _safe_int(fields.get("gpc0")) > 0
        }

    def adaptive_bans(self) -> Dict[str, Dict[str, str]]:
        """Only the entries this daemon owns, identified by their reason code."""

        rows = read_table(self.config.haproxy_socket, "tbl_ban")
        return {
            ip: fields
            for ip, fields in rows.items()
            if _safe_int(fields.get("gpt0")) in ADAPTIVE_CODES
            and _safe_int(fields.get("gpc0")) > 0
        }

    def lift(self, ip: str) -> bool:
        """Clear an adaptive ban, and only an adaptive one.

        `clear table` would happily remove a ban HAProxy placed itself under
        its own rules, so the entry is re-read and its reason code checked
        before anything is removed.
        """

        rows = read_table(self.config.haproxy_socket, "tbl_ban", f"key {ip}")
        fields = rows.get(ip)
        if fields is None:
            return False
        if _safe_int(fields.get("gpt0")) not in ADAPTIVE_CODES:
            LOG.info(
                "Leaving the ban on %s alone: reason code %s is not ours",
                ip,
                fields.get("gpt0"),
            )
            return False
        self._clear(ip)
        self.lifted += 1
        return True

    def _clear(self, ip: str) -> None:
        """Remove the entry, or raise LiftRefused with HAProxy's words.

        HAProxy answers a successful `clear table` with nothing. Any text is
        its refusal, and it used to be taken for a lift: the schedule was
        dropped and the history said "lifted" while the entry stayed, for as
        long as the table keeps it (R01).
        """
        answer = runtime_command(self.config.haproxy_socket, f"clear table tbl_ban key {ip}")
        if answer.strip():
            self.failed += 1
            raise LiftRefused(f"HAProxy refused to lift the ban on {ip}: {answer.strip()[:200]}")

    def restore(self, ip: str, code: int) -> bool:
        """Put an entry back as it was, whatever the mode.

        Not a decision of this daemon's -- the operator's ban a restart of
        HAProxy dropped -- so neither monitor mode nor the kill switch stops it.
        """
        if not enforceable(ip):
            return False
        answer = runtime_command(
            self.config.haproxy_socket,
            f"set table tbl_ban key {ip} data.gpc0 1 data.gpt0 {int(code)}",
        )
        if answer.strip():
            LOG.warning("HAProxy refused to restore the ban on %s: %s", ip, answer.strip()[:200])
            return False
        return True

    def lift_code(self, ip: str, code: int) -> bool:
        """Clear the entry only while it still carries this code (re-read first)."""
        rows = read_table(self.config.haproxy_socket, "tbl_ban", f"key {ip}")
        fields = rows.get(ip)
        if fields is None or _safe_int(fields.get("gpt0")) != code:
            return False
        self._clear(ip)
        return True

    def started_at(self) -> int:
        """When the running HAProxy process started; 0 if it cannot be told."""
        try:
            info = runtime_command(self.config.haproxy_socket, "show info")
        except OSError:
            return 0
        found = re.search(r"^Start_time_sec:\s*(\d+)", info, re.MULTILINE)
        return int(found.group(1)) if found else 0

    def lift_legacy(self, ip: str) -> int:
        """Clear a ban HAProxy wrote under the old rules; 0 if it is not one.

        Re-read first, like lift(): an operator may have banned the same
        address since the table was last read, and that ban stays.
        """

        rows = read_table(self.config.haproxy_socket, "tbl_ban", f"key {ip}")
        fields = rows.get(ip)
        if fields is None or _safe_int(fields.get("gpc0")) <= 0:
            return 0
        code = _safe_int(fields.get("gpt0"))
        if code not in LEGACY_BAN_CODES:
            return 0
        self._clear(ip)
        return code

    def release(self, ip: str) -> bool:
        """Take whatever ban stands on this address off, whoever placed it:
        an operator's unban, done here and under the engine's lock rather than
        by the panel after it (R09). The entry stays with its code and loses
        its flag, as the panel's own unban always left it. Re-read first;
        False when nothing flagged stands, LiftRefused when HAProxy refuses."""
        rows = read_table(self.config.haproxy_socket, "tbl_ban", f"key {ip}")
        fields = rows.get(ip)
        if fields is None or _safe_int(fields.get("gpc0")) <= 0:
            return False
        code = _safe_int(fields.get("gpt0"))
        answer = runtime_command(
            self.config.haproxy_socket, f"set table tbl_ban key {ip} data.gpc0 0 data.gpt0 {code}"
        )
        if answer.strip():
            self.failed += 1
            raise LiftRefused(f"HAProxy refused to lift the ban on {ip}: {answer.strip()[:200]}")
        return True
