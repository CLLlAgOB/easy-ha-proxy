"""Kernel ipset synchronization, ban expiry, log search, and server state."""

from __future__ import annotations

import contextlib
import ipaddress
import os
import re
import subprocess
import time
from collections import defaultdict
from datetime import datetime
from typing import Dict, Set

from .constants import (
    AUTH_IPSET,
    AUTH_TABLE,
    BAN_DELTA_SECONDS,
    BAN_TABLE,
    BAN_TTL_CACHE_SECONDS,
    BAN_TTL_OVERRIDE_SECONDS,
    DEBUG_ON_EMPTY,
    FIRST_STEP_PAGE_CODE,
    HAPADM_LOG_TIME_ORDER,
    INTERVAL,
    IPSET_NAME,
    IPSET_TIMEOUT_SECONDS,
    JOURNAL_LINES_MULT,
    JOURNAL_PER_SOURCE_TIMEOUT,
    JOURNAL_SOURCES,
    JOURNAL_TOTAL_TIMEOUT,
    JOURNAL_USE_GREP,
    LOG,
    LOGS_IP_CACHE_SECONDS,
    LOG_FILE,
    LOG_FILE_TAIL_CHUNK,
    LOG_FILE_TAIL_MAX_BYTES,
    LOG_LIMIT,
    PAGE_IPSET,
    SOCKET_PATH,
    _BAN_TTL_CACHE_LOCK,
    _BAN_TTL_CACHE_TS,
    _BAN_TTL_CACHE_VALUE,
    _LOGS_IP_CACHE,
    _LOGS_IP_CACHE_LOCK,
    _LOG_SCANS,
    _line_has_ip,
    run_cmd,
)

# ───── ipset/bans ─────

def ensure_ipset() -> None:
    """
    Makes sure IPSET_NAME and PAGE_IPSET exist.
    """
    for name in (IPSET_NAME, PAGE_IPSET):
        try:
            run_cmd(
                ["ipset", "create", name, "hash:ip", "family", "inet", "-exist"],
                timeout=IPSET_TIMEOUT_SECONDS,
            )
            LOG.info("Ensured ipset %s exists", name)
        except Exception as e:
            LOG.error("Failed to ensure ipset %s: %s", name, e)
            raise


# 0x7e27...: key=192.0.2.83 use=0 exp=... gpt0=20 gpc0=1
_TABLE_ROW_RE = re.compile(r"key=(?P<ip>\d+\.\d+\.\d+\.\d+).*?\bgpc0=(?P<gpc0>\d+)")


_EXP_RE = re.compile(r"\bexp=(?P<exp>\d+)")


def _read_flagged_addresses(table: str) -> "Set[str] | None":
    """Addresses whose gpc0 > 0 in a stick table, or None when it was not read."""
    flagged = _read_flagged(table)
    return None if flagged is None else set(flagged)


def _read_flagged(table: str) -> "Dict[str, int] | None":
    """Addresses whose gpc0 > 0, with the seconds their entry has left."""
    rows = _read_flagged_rows(table)
    return None if rows is None else {ip: left for ip, (left, _code) in rows.items()}


_GPT0_RE = re.compile(r"\bgpt0=(?P<gpt0>\d+)")


def _read_flagged_rows(table: str) -> "Dict[str, tuple[int, int]] | None":
    """Addresses whose gpc0 > 0, with the seconds their entry has left and its gpt0.

    None when the table was not read.

    None is not "nobody". HAProxy answers a table it does not have with "No
    such table" and a socket that worked; taken for an empty table, that --
    like a read that failed -- would lift every ban, or every authorisation,
    until the next pass. Only an answer that opens with the table's own
    header says who is in it.
    """
    try:
        proc = run_cmd(
            ["socat", SOCKET_PATH, "stdio"],
            input_data=f"show table {table}\n",
            timeout=5,
        )
    except Exception as e:
        LOG.warning("Failed to fetch table %s from HAProxy: %s", table, e)
        return None
    lines = (proc.stdout or "").splitlines()
    if not lines or not lines[0].startswith(f"# table: {table},"):
        LOG.warning(
            "HAProxy did not return table %s: %r",
            table, (lines[0] if lines else "")[:120],
        )
        return None
    flagged: Dict[str, tuple[int, int]] = {}
    for line in lines[1:]:
        m = _TABLE_ROW_RE.search(line)
        if m and int(m.group("gpc0")) > 0:
            expiry = _EXP_RE.search(line)
            code = _GPT0_RE.search(line)
            flagged[m.group("ip")] = (
                int(expiry.group("exp")) // 1000 if expiry else 0,
                int(code.group("gpt0")) if code else 0,
            )
    return flagged


def get_banned_ips_from_haproxy() -> "Set[str] | None":
    """Banned addresses (gpc0 > 0) in BAN_TABLE, or None when not read."""
    return _read_flagged_addresses(BAN_TABLE)


def get_ban_codes_from_haproxy() -> "Dict[str, int] | None":
    """Banned addresses in BAN_TABLE with their reason code, or None when not read."""
    rows = _read_flagged_rows(BAN_TABLE)
    return None if rows is None else {ip: code for ip, (_left, code) in rows.items()}


def _parse_short_iso_ts(line: str) -> datetime | None:
    # expected: "2025-12-15T01:15:56+07:00 ..."
    ts = line.split(" ", 1)[0].strip()
    if not ts:
        return None
    try:
        # journalctl may print Z; normalise it
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def _sort_log_lines_by_time(lines: list[str]) -> list[str]:
    if HAPADM_LOG_TIME_ORDER not in ("asc", "desc"):
        return lines

    with_ts: list[tuple[datetime, int, str]] = []
    no_ts: list[tuple[int, str]] = []

    for i, ln in enumerate(lines):
        dt = _parse_short_iso_ts(ln)
        if dt is None:
            no_ts.append((i, ln))
        else:
            with_ts.append((dt, i, ln))

    with_ts.sort(key=lambda x: x[0], reverse=(HAPADM_LOG_TIME_ORDER == "desc"))
    # lines without a timestamp keep their original order
    no_ts.sort(key=lambda x: x[0])

    return [ln for _, _, ln in with_ts] + [ln for _, ln in no_ts]


def get_ipset_members(name: str = "") -> Set[str]:
    """
    Returns the set of addresses currently in an ipset (IPSET_NAME by default).
    """
    name = name or IPSET_NAME
    try:
        proc = run_cmd(["ipset", "list", name], timeout=IPSET_TIMEOUT_SECONDS)
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
        LOG.error("Failed to list ipset %s: %s", name, e)
        return set()

    members: Set[str] = set()
    capture = False

    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("Members:"):
            capture = True
            continue
        if not capture:
            continue

        parts = line.split()
        if not parts:
            continue
        ip = parts[0]
        if ip.count(".") == 3:
            members.add(ip)

    return members


def _ipv4_entries(addresses) -> list[str]:
    entries = []
    for address in addresses:
        try:
            entries.append(str(ipaddress.IPv4Address(address)))
        except ValueError:
            LOG.warning("Not an IPv4 address, left out of the ipset: %r", address)
    return sorted(entries)


def _update_ipset(set_name: str, to_add, to_del, timeouts: "Dict[str, int] | None" = None) -> bool:
    """Apply the whole difference to an ipset with one `ipset restore`.

    One process instead of one per address. Deletions go first, so a full
    set makes room before it takes new entries. ipset drops the whole batch
    when one line does not parse, so only valid IPv4 addresses are sent;
    with -exist, adding a present entry or deleting a missing one is no
    error, and adding one with a timeout sets its timeout anew. Returns
    False, after logging why, when the batch was refused.
    """
    lines = [f"del {set_name} {ip}" for ip in _ipv4_entries(to_del)]
    if timeouts is None:
        lines += [f"add {set_name} {ip}" for ip in _ipv4_entries(to_add)]
    else:
        lines += [
            f"add {set_name} {ip} timeout {int(timeouts.get(ip, 1))}"
            for ip in _ipv4_entries(to_add)
        ]
    if not lines:
        return True
    try:
        run_cmd(
            ["ipset", "-exist", "restore"],
            input_data="\n".join(lines) + "\n",
            timeout=IPSET_TIMEOUT_SECONDS,
        )
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
        LOG.warning(
            "Failed to update ipset %s (+%d, -%d): %s",
            set_name, len(to_add), len(to_del), e,
        )
        return False
    return True


# A restarted HAProxy starts with an empty ban table, and the next pass used
# to take every ban out of the firewall with it -- for the ten seconds or so
# until guardd put its bans back (and the manual ones it remembers), banned
# addresses got through. For this long after HAProxy starts, a pass only
# adds; what is still missing from the table afterwards is taken out by the
# first pass after it. A reload restarts the count too.
BAN_RESTART_GRACE_SECONDS = max(0, int(os.environ.get("HAPADM_BAN_RESTART_GRACE_SECONDS", "60")))


def haproxy_uptime() -> "int | None":
    """Seconds the HAProxy answering on the socket has run; None when not known."""
    try:
        proc = run_cmd(["socat", SOCKET_PATH, "stdio"], input_data="show info\n", timeout=5)
    except Exception as e:  # noqa: BLE001 - not knowing is answered below
        LOG.debug("Failed to read HAProxy's uptime: %s", e)
        return None
    found = re.search(r"^Uptime_sec:\s*(\d+)", proc.stdout or "", re.MULTILINE)
    return int(found.group(1)) if found else None


def sync_bans_once() -> None:
    """
    One synchronisation pass of tbl_ban -> ipset.
    """
    banned = get_ban_codes_from_haproxy()
    if banned is None:
        return  # not read; the bans in force stay until a pass that reads it
    haproxy_banned = set(banned)
    first_steps = {ip for ip, code in banned.items() if code == FIRST_STEP_PAGE_CODE}
    ipset_members = get_ipset_members()
    page_members = get_ipset_members(PAGE_IPSET)

    if not haproxy_banned and not ipset_members and not page_members:
        return

    # A first step enters the page set before the ban set and leaves it after
    # (below): the TCP rule drops what is in the ban set and not in the page
    # set, so the other order would cut a first step off for a moment.
    page_add = first_steps - page_members
    page_del = page_members - first_steps
    if page_add and _update_ipset(PAGE_IPSET, page_add, ()):
        LOG.info("First steps shown a page: +%d", len(page_add))

    to_add = haproxy_banned - ipset_members
    to_del = ipset_members - haproxy_banned
    if to_del and BAN_RESTART_GRACE_SECONDS:
        uptime = haproxy_uptime()
        if uptime is not None and uptime < BAN_RESTART_GRACE_SECONDS:
            LOG.info(
                "HAProxy has run for %ds: %d bans stay in the firewall until its table is filled again",
                uptime, len(to_del),
            )
            to_del = set()

    if _update_ipset(IPSET_NAME, to_add, to_del) and (to_add or to_del):
        LOG.info(
            "Sync done: +%d, -%d (haproxy=%d, ipset=%d)",
            len(to_add),
            len(to_del),
            len(haproxy_banned),
            len(ipset_members),
        )
    # Not held after a restart of HAProxy as the ban set is: a first step
    # that leaves the page set is dropped until it is put back, which errs
    # on the side of the ban.
    if page_del and _update_ipset(PAGE_IPSET, (), page_del):
        LOG.info("First steps no longer shown a page: -%d", len(page_del))


# The authorized set lets a signed-in address through a zero-trust UDP
# forward (U02, 04.4b). Its entries used to carry no timeout, so a stopped
# synchroniser -- or a HAProxy it could not read -- left every address that
# had once signed in trusted by the kernel for good. Each entry now carries
# a timeout, renewed on every pass: never longer than HAProxy's own entry has
# left, and never more than AUTH_IPSET_TTL, so trust the synchroniser stops
# renewing runs out on its own.
AUTH_IPSET_TTL = max(30, int(os.environ.get("HAPADM_AUTH_IPSET_TTL", "900")))


def _auth_ipset_listing() -> "tuple[Set[str], bool] | None":
    """The authorized set's members and whether it keeps per-entry timeouts.

    None when it could not be listed (missing, or ipset failed).
    """
    try:
        proc = run_cmd(["ipset", "list", AUTH_IPSET], timeout=IPSET_TIMEOUT_SECONDS)
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
        LOG.error("Failed to list ipset %s: %s", AUTH_IPSET, e)
        return None
    members: Set[str] = set()
    timeouts = False
    capture = False
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if not capture and line.startswith("Header:"):
            timeouts = " timeout " in f" {line} "
            continue
        if line.startswith("Members:"):
            capture = True
            continue
        if capture:
            parts = line.split()
            if parts and parts[0].count(".") == 3:
                members.add(parts[0])
    return members, timeouts


def ensure_auth_ipset() -> None:
    """Ensure the zero-trust authorized-IP ipset exists, with timeouts.

    A set from before keeps no timeouts and cannot be given them: a new one
    is filled with the same addresses and swapped in under the same name,
    which the UDP rules go on matching without a gap.
    """
    listing = _auth_ipset_listing()
    if listing is None:
        run_cmd(
            ["ipset", "create", AUTH_IPSET, "hash:ip", "family", "inet", "timeout", "0", "-exist"],
            timeout=IPSET_TIMEOUT_SECONDS,
        )
        LOG.info("Ensured ipset %s exists", AUTH_IPSET)
        return
    members, timeouts = listing
    if timeouts:
        return
    temporary = f"{AUTH_IPSET}_t"[:31]
    with contextlib.suppress(RuntimeError, OSError, subprocess.TimeoutExpired):
        run_cmd(["ipset", "destroy", temporary], timeout=IPSET_TIMEOUT_SECONDS)
    run_cmd(
        ["ipset", "create", temporary, "hash:ip", "family", "inet", "timeout", "0"],
        timeout=IPSET_TIMEOUT_SECONDS,
    )
    lines = [f"add {temporary} {ip} timeout {AUTH_IPSET_TTL}" for ip in _ipv4_entries(members)]
    if lines:
        run_cmd(["ipset", "-exist", "restore"], input_data="\n".join(lines) + "\n",
                timeout=IPSET_TIMEOUT_SECONDS)
    run_cmd(["ipset", "swap", AUTH_IPSET, temporary], timeout=IPSET_TIMEOUT_SECONDS)
    run_cmd(["ipset", "destroy", temporary], timeout=IPSET_TIMEOUT_SECONDS)
    LOG.warning("ipset %s now expires its entries (%d moved over)", AUTH_IPSET, len(members))


def get_authorized_ips_from_haproxy() -> "Dict[str, int] | None":
    """Authorized addresses (gpc0 > 0) in AUTH_TABLE with the seconds their
    entry has left, or None when not read."""
    return _read_flagged(AUTH_TABLE)


def get_auth_ipset_members() -> Set[str]:
    """IPs currently in the authorized-IP ipset."""
    listing = _auth_ipset_listing()
    return listing[0] if listing else set()


def sync_auth_once() -> None:
    """One iteration of AUTH_TABLE -> AUTH_IPSET (zero-trust whitelist)."""
    authorized = get_authorized_ips_from_haproxy()
    if authorized is None:
        return  # not read: the entries keep their own timeouts and run out
    listing = _auth_ipset_listing()
    members, timeouts = listing if listing else (set(), False)
    wanted = set(authorized)
    if not wanted and not members:
        return
    if timeouts:
        # Every authorized address is added again: that renews its timeout.
        _update_ipset(AUTH_IPSET, wanted, members - wanted, timeouts={
            ip: min(AUTH_IPSET_TTL, max(1, int(left or 0))) for ip, left in authorized.items()
        })
    else:
        _update_ipset(AUTH_IPSET, wanted - members, members - wanted)


def bans_loop() -> None:
    """
    The background loop that synchronises bans and authorised addresses (zero trust).
    """
    LOG.info("Ban-sync loop started: table=%s, ipset=%s, interval=%ss",
             BAN_TABLE, IPSET_NAME, INTERVAL)
    try:
        ensure_ipset()
    except Exception:
        LOG.error("Ban-sync loop aborted: ipset init failed")
        return
    try:
        ensure_auth_ipset()
    except Exception as e:
        LOG.error("Auth ipset init failed; zero-trust UDP will not update: %s", e)

    while True:
        try:
            sync_bans_once()
        except Exception as e:
            LOG.error("Unexpected ban-sync error: %s", e)
        try:
            sync_auth_once()
        except Exception as e:
            LOG.error("Unexpected auth-sync error: %s", e)
        time.sleep(INTERVAL)


# ───── logs-ip (moved here from utils; times taken from the epoch) ─────

def _is_selfcheck_line(line: str, ip: str) -> bool:
    # leave out the request to /ip/<ip> itself, so the current call is not caught
    return "GET /ip/" in line or f"/ip/{ip}" in line


def _fmt_sec(v: int | None) -> str:
    if v is None:
        return "None"
    if v < 60:
        return f"{v}s"
    if v < 3600:
        return f"{v//60}m{v % 60:02d}s"
    if v < 86400:
        m = (v % 3600) // 60
        s = v % 60
        return f"{v//3600}h{m:02d}m{s:02d}s"
    d = v // 86400
    h = (v % 86400) // 3600
    m = (v % 3600) // 60
    return f"{d}d{h:02d}h{m:02d}m"


def _get_ban_table_ttl_seconds(table: str = BAN_TABLE) -> int:
    """
    The table's TTL (expire) from "show table <table>", in seconds; 7 days if unknown.

    To keep it cheap:
      1) the TTL can be set explicitly with HAPADM_BAN_TTL_SECONDS;
      2) otherwise it is cached for BAN_TTL_CACHE_SECONDS;
      3) a light "show table <table> key 0.0.0.0" is tried first, to avoid dumping the whole table.
    """
    if BAN_TTL_OVERRIDE_SECONDS > 0:
        return BAN_TTL_OVERRIDE_SECONDS

    now = time.time()
    with _BAN_TTL_CACHE_LOCK:
        if (
            _BAN_TTL_CACHE_VALUE is not None
            and (now - _BAN_TTL_CACHE_TS) < max(1, BAN_TTL_CACHE_SECONDS)
        ):
            return _BAN_TTL_CACHE_VALUE

    def _parse_expire_seconds(text: str) -> int | None:
        m = re.search(r'\bexpire\b[^\d]*(\d+)\s*([a-zA-Z]+)?', text or "")
        if not m:
            return None
        val = int(m.group(1))
        unit = (m.group(2) or "").lower()
        # expire without a suffix is usually seconds
        if unit in ("ms", "msec"):
            return max(1, val // 1000)
        if unit in ("", "s", "sec"):
            return val
        if unit in ("m", "min"):
            return val * 60
        if unit == "h":
            return val * 3600
        if unit in ("d", "day", "days"):
            return val * 86400
        return None

    ttl: int | None = None
    try:
        # 1) The light request: the header and, ideally, nothing more
        for cmd in (
            f"show table {table} key 0.0.0.0\n",
            f"show table {table}\n",  # fallback: may be heavy
        ):
            proc = run_cmd(
                ["socat", SOCKET_PATH, "stdio"],
                input_data=cmd,
                timeout=5,
            )
            ttl = _parse_expire_seconds(proc.stdout or "")
            if ttl is not None:
                break
    except Exception as exc:  # pylint: disable=broad-except
        LOG.warning("_get_ban_table_ttl_seconds: %s", exc)

    if ttl is None:
        ttl = 7 * 24 * 3600

    with _BAN_TTL_CACHE_LOCK:
        globals()["_BAN_TTL_CACHE_VALUE"] = ttl
        globals()["_BAN_TTL_CACHE_TS"] = now
    return ttl


def _get_ban_remaining_seconds(ip: str, table: str = BAN_TABLE) -> int | None:
    """The remaining TTL of a key (ip) from "show table <table> key <ip>", in seconds, or None if there is no entry."""
    try:
        proc = run_cmd(
            ["socat", SOCKET_PATH, "stdio"],
            input_data=f"show table {table} key {ip}\n",
            timeout=5,
        )
        out = (proc.stdout or "").strip()
        if not out:
            return None

        # exp/expire: exp WITHOUT a suffix is milliseconds (IMPORTANT)
        m = re.search(r'\bexp(?:ire)?\s*[:=]?\s*(\d+)\s*([a-zA-Z]+)?\b', out)
        if not m:
            m = re.search(r'\bexpires?\s+in\s+(\d+)\s*([a-zA-Z]+)\b', out)
        if not m:
            return None

        val = int(m.group(1))
        unit = (m.group(2) or "").lower()
        if unit in ("", "ms", "msec"):
            return max(1, val // 1000)
        if unit in ("s", "sec"):
            return val
        if unit in ("m", "min"):
            return val * 60
        if unit == "h":
            return val * 3600
        if unit in ("d", "day", "days"):
            return val * 86400
        return val
    except Exception as exc:  # pylint: disable=broad-except
        LOG.warning("_get_ban_remaining_seconds: %s", exc)
    return None


def _normalize_remaining_seconds(rem: int, ttl: int) -> int:
    """
    Brings ban_remaining to seconds:
    - if rem >> ttl (10 times or more), rem is taken to be milliseconds and divided by 1000
    - if after that rem is still > ttl*2, it is cut down to ttl
    - negative or nonsensical values are not let through
    """
    if rem <= 0:
        return 0
    # heuristic: exp is almost always in ms, and ttl in seconds.
    if ttl > 0 and rem > ttl * 10:
        rem = rem // 1000
    if ttl > 0 and rem > ttl * 2:
        rem = ttl
    return max(0, rem)


def _parse_source_to_args(source_flag: str) -> tuple[list[str], list[str]]:
    """
    Returns (opt_args, match_args) for journalctl.
    source_flag accepts the old forms:
      - "-u haproxy"
      - "SYSLOG_IDENTIFIER=haproxy"
      - "-u haproxy.service"
      - "*"
    """
    opt_args: list[str] = []
    match_args: list[str] = []

    src = source_flag.strip()
    if not src or src == "*":
        return opt_args, match_args

    # FIELD=VALUE is a journalctl match argument
    if "=" in src and not src.lstrip().startswith("-"):
        match_args.append(src)
        return opt_args, match_args

    # journalctl does not take a bare word ("haproxy") as a match; old
    # configurations with such a value are read as a syslog identifier
    if not src.lstrip().startswith("-") and " " not in src:
        opt_args.extend(["-t", src])
        return opt_args, match_args

    # otherwise options such as "-u haproxy"
    parts = src.split()
    if parts:
        opt_args.extend(parts)
    return opt_args, match_args


def _journal_window_for_ip(
    ip: str,
    since_epoch: int,
    until_epoch: int,
    limit: int = LOG_LIMIT,
    collect_debug: bool = False,
):
    """
    Searches journald in the given window, filtered by IP, leaving out our own requests.

    To keep it fast:
      • journalctl's output is limited with -n (after filtering);
      • where possible --grep=<ip> is used, so journalctl filters the messages itself;
      • all sources share one time budget (JOURNAL_TOTAL_TIMEOUT).
    """
    started = time.monotonic()
    debug = {
        "since_epoch": since_epoch,
        "until_epoch": until_epoch,
        "sources": [],
        "timeouts": {
            "per_source": JOURNAL_PER_SOURCE_TIMEOUT,
            "total": JOURNAL_TOTAL_TIMEOUT,
        },
        "used_grep": JOURNAL_USE_GREP,
    }

    nlines = max(limit * max(1, JOURNAL_LINES_MULT), limit + 5)

    def _run_one(source_flag: str, use_grep: bool) -> tuple[list[str], dict]:
        opt_args, match_args = _parse_source_to_args(source_flag)

        args = [
            "journalctl",
            "--no-pager",
            "-q",
            "-o", "short-iso",
            "--since", f"@{since_epoch}",
            "--until", f"@{until_epoch}",
            "-n", str(nlines),
        ] + opt_args + match_args

        if use_grep:
            args += ["--grep", re.escape(ip)]

        remaining_total = JOURNAL_TOTAL_TIMEOUT - (time.monotonic() - started)
        timeout = min(JOURNAL_PER_SOURCE_TIMEOUT, max(0.1, remaining_total))

        out = ""
        err = ""
        rc: int | None = None
        t0 = time.monotonic()
        try:
            proc = subprocess.run(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
            )
            rc = proc.returncode
            out = proc.stdout or ""
            err = proc.stderr or ""
        except subprocess.TimeoutExpired:
            err = "TIMEOUT"
        except Exception as exc:  # pylint: disable=broad-except
            err = f"EXC: {exc}"

        dt = time.monotonic() - t0

        # filter and sort (there are few lines by now)
        raw_lines = out.splitlines()
        filtered: list[str] = []
        for ln in raw_lines:
            if _line_has_ip(ln, ip) and not _is_selfcheck_line(ln, ip):
                filtered.append(ln)

        ordered = _sort_log_lines_by_time(filtered)[:limit]

        info = {
            "source": source_flag,
            "args": args,
            "duration_s": round(dt, 3),
            "returncode": rc,
            "found_total": len(filtered),
            "returned": len(ordered),
            "stderr": err[:4000],
            "used_grep": use_grep,
        }
        return ordered, info

    for src in JOURNAL_SOURCES:
        if (time.monotonic() - started) >= JOURNAL_TOTAL_TIMEOUT:
            break

        # 1) try with --grep (faster, less output); 2) if that fails, without it
        lines1, info1 = _run_one(src, use_grep=JOURNAL_USE_GREP)
        debug["sources"].append(info1)
        if lines1:
            return (lines1, debug) if collect_debug else lines1

        if JOURNAL_USE_GREP and info1.get("returncode") not in (0, None) and info1.get("stderr"):
            lines2, info2 = _run_one(src, use_grep=False)
            debug["sources"].append(info2)
            if lines2:
                return (lines2, debug) if collect_debug else lines2

    return ([], debug) if collect_debug else []


def _file_tail_for_ip(ip: str, limit: int = LOG_LIMIT) -> list[str]:
    """
    Quickly finds the last lines for an IP in LOG_FILE.

    It used to be tac|grep|tac (several processes and a shell). Now the file
    is read backwards in blocks, stopping as soon as enough lines are found.
    """
    if not LOG_FILE:
        return []
    if not os.path.exists(LOG_FILE):
        return []

    chunk_size = max(4096, int(LOG_FILE_TAIL_CHUNK))
    max_bytes = int(LOG_FILE_TAIL_MAX_BYTES) if LOG_FILE_TAIL_MAX_BYTES else 0

    with _LOG_SCANS:
        return _file_tail_scan(ip, limit, chunk_size, max_bytes)


def _file_tail_scan(ip: str, limit: int, chunk_size: int, max_bytes: int) -> list[str]:
    try:
        found: list[str] = []
        with open(LOG_FILE, "rb") as f:
            f.seek(0, os.SEEK_END)
            pos = f.tell()
            buf = b""
            scanned = 0

            while pos > 0 and len(found) < limit:
                if max_bytes and scanned >= max_bytes:
                    break

                to_read = min(chunk_size, pos)
                pos -= to_read
                f.seek(pos)
                chunk = f.read(to_read)
                scanned += to_read

                buf = chunk + buf
                parts = buf.split(b"\n")
                buf = parts[0]  # an incomplete line at the start of the buffer

                for raw in reversed(parts[1:]):
                    if len(found) >= limit:
                        break
                    ln = raw.decode("utf-8", "replace")
                    if _line_has_ip(ln, ip) and not _is_selfcheck_line(ln, ip):
                        found.append(ln)

            if pos == 0 and buf and len(found) < limit:
                ln = buf.decode("utf-8", "replace")
                if _line_has_ip(ln, ip) and not _is_selfcheck_line(ln, ip):
                    found.append(ln)

        found.reverse()  # back into natural order
        return found
    except Exception as exc:  # pylint: disable=broad-except
        LOG.warning("_file_tail_for_ip: %s", exc)
        return []


_LOGS_IP_CACHE_MAX = 512
_LOGS_IP_CACHE_MAX_LIMIT = 2000


def _logs_ip_cache_put(key: tuple[str, int], lines: list[str]) -> None:
    now = time.time()
    with _LOGS_IP_CACHE_LOCK:
        if len(_LOGS_IP_CACHE) >= _LOGS_IP_CACHE_MAX:
            expired = [k for k, (exp, _v) in _LOGS_IP_CACHE.items() if exp <= now]
            for k in expired:
                _LOGS_IP_CACHE.pop(k, None)
            while len(_LOGS_IP_CACHE) >= _LOGS_IP_CACHE_MAX:
                oldest = next(iter(_LOGS_IP_CACHE))
                _LOGS_IP_CACHE.pop(oldest, None)
        _LOGS_IP_CACHE[key] = (now + LOGS_IP_CACHE_SECONDS, lines)


def grep_last_logs_for_ip(ip: str, limit: int = LOG_LIMIT) -> list[str]:
    """
    How it works:
      • first a short cache (LOGS_IP_CACHE_SECONDS);
      • then the tail of LOG_FILE (cheap);
      • if the address is in the ban table, ban_start is worked out and journald is read in [ban_start ± DELTA];
      • otherwise, the result from the tail of LOG_FILE.

    When nothing matches (and DEBUG_ON_EMPTY=1), a diagnostic block is returned.
    """
    limit = max(1, min(int(limit), _LOGS_IP_CACHE_MAX_LIMIT))
    # 0) a short cache (useful when the UI or a client repeats the request after a timeout)
    if LOGS_IP_CACHE_SECONDS > 0:
        key = (ip, limit)
        now = time.time()
        with _LOGS_IP_CACHE_LOCK:
            item = _LOGS_IP_CACHE.get(key)
            if item and item[0] > now:
                return item[1]

    # 1) a quick look at the file's tail (often all that is needed, even for a banned address)
    file_lines = _file_tail_for_ip(ip, limit=limit)
    if file_lines:
        if LOGS_IP_CACHE_SECONDS > 0:
            _logs_ip_cache_put((ip, limit), file_lines)
        return file_lines

    # 2) check the ban
    ban_remaining_raw = _get_ban_remaining_seconds(ip)
    if ban_remaining_raw is not None:
        ban_ttl = _get_ban_table_ttl_seconds()
        ban_remaining = _normalize_remaining_seconds(ban_remaining_raw, ban_ttl)
        served = max(ban_ttl - ban_remaining, 0)

        ban_start = int(time.time() - served)
        since_epoch = max(0, ban_start - BAN_DELTA_SECONDS)
        until_epoch = max(0, ban_start + BAN_DELTA_SECONDS)

        # journald (can be fairly heavy)
        if DEBUG_ON_EMPTY:
            j_lines, dbg = _journal_window_for_ip(
                ip=ip,
                since_epoch=since_epoch,
                until_epoch=until_epoch,
                limit=limit,
                collect_debug=True,
            )
        else:
            j_lines = _journal_window_for_ip(
                ip=ip,
                since_epoch=since_epoch,
                until_epoch=until_epoch,
                limit=limit,
                collect_debug=False,
            )
            dbg = None

        if j_lines:
            if LOGS_IP_CACHE_SECONDS > 0:
                _logs_ip_cache_put((ip, limit), j_lines)
            return j_lines

        if DEBUG_ON_EMPTY and dbg:
            def _dbg_block() -> list[str]:
                block = [
                    "[DEBUG] No journal matches for banned IP",
                    f"ip={ip}",
                    f"ban_remaining_raw={ban_remaining_raw}",
                    f"ban_ttl={ban_ttl} ({_fmt_sec(ban_ttl)})",
                    f"ban_remaining_norm={ban_remaining} ({_fmt_sec(ban_remaining)})",
                    f"served={served} ({_fmt_sec(served)})",
                    f"ban_start_epoch={ban_start}",
                    f"window_since_epoch={since_epoch}",
                    f"window_until_epoch={until_epoch}",
                    f"sources_tried={', '.join(s['source'] for s in dbg.get('sources', []))}",
                ]
                for s in dbg.get("sources", []):
                    block.append(
                        "  - {source}: found_total={found_total} returned={returned} dur={duration_s}s "
                        "rc={returncode} used_grep={used_grep} args={args} stderr={stderr}".format(
                            source=s.get("source"),
                            found_total=s.get("found_total"),
                            returned=s.get("returned"),
                            duration_s=s.get("duration_s"),
                            returncode=s.get("returncode"),
                            used_grep=s.get("used_grep"),
                            args=" ".join(s.get("args") or []),
                            stderr=(s.get("stderr") or ""),
                        )
                    )
                return block

            return _dbg_block()

        return []

    # 3) not banned, and nothing in the file either
    if DEBUG_ON_EMPTY:
        try:
            exists = os.path.exists(LOG_FILE)
            size = os.path.getsize(LOG_FILE) if exists else 0
            mtime = datetime.fromtimestamp(os.path.getmtime(LOG_FILE)).strftime(
                "%Y-%m-%d %H:%M:%S") if exists else "n/a"
        except Exception:  # pylint: disable=broad-except
            exists, size, mtime = False, 0, "n/a"

        return [
            "[DEBUG] No file matches for non-banned IP",
            f"ip={ip}",
            f"log_file={LOG_FILE}",
            f"exists={exists} size={size}B mtime_local={mtime}",
            f"limit={limit}",
        ]

    return []


_IP_RE = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')
# The status is the field after the five timers (%TR/%Tw/%Tc/%Tr/%Ta), not any
# " 400 " in the line: a 200 answer of 400 bytes counted as a 400.
_LOG_STATUS_RE = re.compile(r"\s-?\d+/-?\d+/-?\d+/-?\d+/-?\d+\s(\d{3})\s")


def logs_attackers() -> dict:
    """
    Totals for "Threat analytics":
    - the top addresses by HTTP 400
    - the top addresses by HTTP 451 (geo-blocking)
    The status is read from its own field, after the timers.
    """
    if not os.path.exists(LOG_FILE):
        return {
            "error": "Log file not found",
            "diagnostic": {"log_path": LOG_FILE},
        }

    diag = {
        "source": "file",
        "log_path": LOG_FILE,
        "total_lines": 0,
        "lines_with_400": 0,
        "lines_with_451": 0,
        "ip_matches": 0,
    }

    a400 = defaultdict(int)
    a451 = defaultdict(int)

    # The tail, read as a stream: at most LOG_FILE_TAIL_MAX_BYTES of it.
    max_bytes = int(LOG_FILE_TAIL_MAX_BYTES) if LOG_FILE_TAIL_MAX_BYTES else 0
    with _LOG_SCANS, open(LOG_FILE, "rb") as raw_file:
        size = os.fstat(raw_file.fileno()).st_size
        start = max(0, size - max_bytes) if max_bytes else 0
        raw_file.seek(start)
        if start:
            raw_file.readline()  # a line cut by the start of the window
        diag["partial"] = bool(start)
        diag["scanned_bytes"] = size - start
        for raw in raw_file:
            ln = raw.decode("utf-8", "replace")
            diag["total_lines"] += 1

            status = _LOG_STATUS_RE.search(ln)
            code = status.group(1) if status else ""
            has400 = code == "400"
            has451 = code == "451"

            if has400:
                diag["lines_with_400"] += 1
            if has451:
                diag["lines_with_451"] += 1

            if not (has400 or has451):
                continue

            m = _IP_RE.search(ln)
            if not m:
                continue

            ip = m.group(1)
            diag["ip_matches"] += 1
            if has400:
                a400[ip] += 1
            if has451:
                a451[ip] += 1

    def _top(src: dict, n: int = 10):
        return sorted(src.items(), key=lambda x: x[1], reverse=True)[:n]

    return {
        "code_400": [{"ip": ip, "count": cnt} for ip, cnt in _top(a400)],
        "code_451": [{"ip": ip, "count": cnt} for ip, cnt in _top(a451)],
        "diagnostic": diag,
    }


# ───── handling socket commands ─────


STATE_DUMP_CMD = "/usr/local/sbin/haproxy-state-dump"


def dump_server_state() -> None:
    """Save the servers' administrative state before a reload.

    Ready/Drain/Maintenance and the runtime weight live only in the running
    process. Without the dump, saving any site would put a server taken out
    for maintenance back under load. A failed dump must not stop the reload:
    a timer refreshes the same file, so at worst the state is a little
    older.
    """

    if not os.path.exists(STATE_DUMP_CMD):
        return
    try:
        proc = subprocess.run(
            [STATE_DUMP_CMD],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
        if proc.returncode != 0:
            LOG.warning(
                "Server state dump exited with %s: %s",
                proc.returncode,
                (proc.stderr or "").strip()[:200],
            )
    except Exception as exc:  # pylint: disable=broad-except
        LOG.warning("Server state dump failed: %r", exc)
