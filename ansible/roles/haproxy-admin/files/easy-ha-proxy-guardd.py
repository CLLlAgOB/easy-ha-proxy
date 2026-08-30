#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""easy-ha-proxy-guardd — adaptive protection engine (foundation).

This is the plumbing layer: it reads what HAProxy already knows, turns it into
sanitised security events, and remembers who must never be acted upon. It does
not yet contain detection rules, and in this release it cannot ban anything --
`enforce` is rejected by configuration validation.

Design notes that the rest of the phase depends on:

* Events are stored raw and weight-free. The score is computed when it is
  asked for, so weights can be retuned and the whole history re-scored without
  waiting another week for fresh data.
* Exclusions mirror the HAProxy configuration exactly (global whitelist, admin
  allow-list, GeoIP whitelist, and IPs that authenticated through Authelia).
  An engine that flags traffic the gateway already exempts produces a review
  queue nobody can use.
* Enforcement is IPv4-only, because `tbl_ban` is an IPv4 stick table and the
  firewall ruleset is `inet`. Addresses that cannot be acted upon are recorded
  as such rather than silently scored.
"""

from __future__ import annotations

import calendar
import contextlib
import grp
import hmac
import ipaddress
import json
import logging
import os
import pathlib
import pwd
import re
import socket
import sqlite3
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from socketserver import ThreadingMixIn, UnixStreamServer
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qs, unquote, unquote_plus, urlparse

LOG = logging.getLogger("easy-ha-proxy-guardd")


# The alert client lives beside this script in /usr/local/sbin, which is
# sys.path[0] for a daemon started by absolute path. It is optional on
# purpose: a gateway without the alert daemon still defends itself.
try:
    from easy_ha_proxy_alert_client import AlertClient  # type: ignore[import]
except Exception:  # pragma: no cover - the daemon runs without it
    AlertClient = None  # type: ignore[assignment]


def _alert_client():
    """An alert client if one can be built, otherwise nothing."""
    if AlertClient is None:
        return None
    client = AlertClient(source="guardd")
    return client if client.configured else None

SOCKET_PATH = os.environ.get(
    "GUARDD_SOCKET_PATH", "/run/easy-ha-proxy/easy-ha-proxy-guardd.sock"
)
SOCKET_GROUP = os.environ.get("GUARDD_SOCKET_GROUP", "hadmin")
CONFIG_PATH = os.environ.get("GUARDD_CONFIG", "/opt/haproxy-admin/guardd.json")
DATABASE_PATH = os.environ.get(
    "GUARDD_DATABASE", "/var/lib/easy-ha-proxy/security/security.db"
)

SCHEMA_VERSION = 3

MODE_OFF = "off"
MODE_MONITOR = "monitor"
MODE_ENFORCE = "enforce"
SUPPORTED_MODES = (MODE_OFF, MODE_MONITOR, MODE_ENFORCE)

# Changing the mode changes what happens to traffic, so it is the one thing
# this daemon accepts over its socket -- and only with the shared token.
CONTROL_TOKEN = os.environ.get("GUARDD_TOKEN", "").strip()

# Progressive ban durations by strike. Stick-table entries carry the table's
# expiry rather than a per-key one, so the schedule is kept here and enforced
# by lifting the entry when its time is up.
# How long a ban lasts, by how many times the address has been caught inside
# the strike window. The first step is deliberately short: it is the one an
# address reaches on a single reading, so it is the one a false positive
# lands on, and an hour costs a wrongly-judged visitor very little. Every
# step after it assumes the address came back and did it again, which is a
# much harder thing to do by accident.
#
# The operator can replace this list; it is only where a gateway starts.
BAN_DURATIONS: Tuple[int, ...] = (3600, 7 * 86400, 30 * 86400, 90 * 86400)

BAN_DURATIONS_KEY = "ban_durations"
MIN_BAN_SECONDS = 60
MAX_BAN_SECONDS = 365 * 86400
MAX_BAN_STEPS = 6


def validate_ban_durations(data: Any) -> Tuple[int, ...]:
    """Check an operator-supplied ladder before it can ban anyone.

    Rejected rather than repaired, because every repair here would be a
    guess about what someone meant to type in a setting that decides how
    long real visitors stay locked out.
    """

    if not isinstance(data, list) or not data:
        raise ValueError("ban durations must be a non-empty list")
    if len(data) > MAX_BAN_STEPS:
        raise ValueError(f"at most {MAX_BAN_STEPS} steps")

    steps: List[int] = []
    for entry in data:
        if isinstance(entry, bool) or not isinstance(entry, int):
            raise ValueError("each step must be a whole number of seconds")
        if entry < MIN_BAN_SECONDS or entry > MAX_BAN_SECONDS:
            raise ValueError(
                f"each step must be between {MIN_BAN_SECONDS} seconds "
                f"and {MAX_BAN_SECONDS // 86400} days"
            )
        steps.append(entry)

    # A later strike earning a shorter ban is never what anyone meant, and it
    # would quietly reward persistence.
    for earlier, later in zip(steps, steps[1:]):
        if later < earlier:
            raise ValueError("each step must be at least as long as the one before")
    return tuple(steps)


def load_ban_durations(database: "SecurityDatabase") -> Tuple[int, ...]:
    """Read the stored ladder, falling back to the shipped one.

    Kept in guardd's own state rather than in guardd.json for the same reason
    the mode is: that file is a template Ansible owns and rewrites, so a
    choice made in the web interface would not survive the next run.
    """

    raw = database.get_state(BAN_DURATIONS_KEY, "")
    if not raw:
        return BAN_DURATIONS
    try:
        return validate_ban_durations(json.loads(raw))
    except Exception as exc:  # noqa: BLE001 - never stop the daemon for this
        LOG.warning("stored ban durations are unusable (%s); using defaults", exc)
        return BAN_DURATIONS
# How long the record of a ban survives, as a multiple of that ban's own
# length. It has to be more than 1: a locked-out address cannot commit its
# next offence until it is let back in, so a window merely equal to the ban
# would forget the strike at the exact moment the address became able to
# earn the next one. The multiplier grows with the step, so a second offence
# is judged over twice its ban, a third over three times, and so on.
#
# This replaced a flat seven-day window, which worked only while bans were
# minutes long. Once a ban could last a week the record aged out while the
# address was still serving it: every release started again from step one
# and the later rungs could never be reached at all.
STRIKE_RETENTION_BASE_MULTIPLIER = 1

RUNTIME_TIMEOUT_SECONDS = 5
RUNTIME_MAX_BYTES = 8 * 1024 * 1024

# The adaptive reason code written into tbl_ban's gpt0. Codes 10/20/30 already
# belong to the HAProxy rules, so adaptive bans stay distinguishable in the
# existing ban list -- and a kill switch can lift exactly these.
ADAPTIVE_BAN_CODE = 40

# Sanitising limits. A request line is attacker-controlled text.
MAX_PATH_LENGTH = 200
MAX_HOST_LENGTH = 128
MAX_LOG_LINE_BYTES = 8192
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_MULTI_SLASH = re.compile(r"/{2,}")

# Per-IP working memory. The whole point of the log source is remembering what
# an address did hours ago, so this has to be bounded on purpose: a scan from a
# botnet must not be able to grow it without limit. Measured cost on a
# 2-core/2 GiB gateway is 4.3 KiB per address with a full 32-path history.
DEFAULT_MAX_TRACKED_IPS = 5000
DEFAULT_MAX_PATHS_PER_IP = 32

# --- Detection ------------------------------------------------------------
#
# Three tiers of confidence. A single hit on a high-confidence path is a strong
# signal; a scattering of 404s is barely a signal at all. Only combinations of
# different categories are meant to reach a punitive score, which is why the
# contribution of any one category is capped.

# Category -> first path segment. Matching on the first segment is O(1) per
# request and still catches "/phpmyadmin/index.php" from "phpmyadmin".
SCANNER_SEGMENTS: Dict[str, str] = {
    ".env": "secrets",
    ".git": "vcs",
    ".svn": "vcs",
    ".hg": "vcs",
    ".aws": "secrets",
    ".ssh": "secrets",
    ".DS_Store": "secrets",
    "phpmyadmin": "database-admin",
    "pma": "database-admin",
    "myadmin": "database-admin",
    "adminer.php": "database-admin",
    "wp-login.php": "wordpress",
    "wp-admin": "wordpress",
    "wp-content": "wordpress",
    "wp-includes": "wordpress",
    "xmlrpc.php": "wordpress",
    "server-status": "server-info",
    "server-info": "server-info",
    "phpinfo.php": "server-info",
    "actuator": "app-framework",
    "solr": "app-framework",
    "jenkins": "app-framework",
    "struts": "app-framework",
    "cgi-bin": "legacy-cgi",
    "vendor": "dependency",
    "backup.zip": "backup",
    "backup.sql": "backup",
    "backup.tar.gz": "backup",
    "database.sql": "backup",
    "dump.sql": "backup",
    "config.php": "config",
    "configuration.php": "config",
    "web.config": "config",
    "docker-compose.yml": "config",
    "id_rsa": "secrets",
    "credentials": "secrets",
}
# Full paths that only mean something in their entirety.
SCANNER_PATHS: Dict[str, str] = {
    "/.env": "secrets",
    "/.git/config": "vcs",
    "/.aws/credentials": "secrets",
    "/.ssh/id_rsa": "secrets",
}

# Categories no client has any business asking for. There is no browser, no
# framework and no crawler that fetches an .env file, a git object store or a
# database dump: a single request is not a hint, it is the whole answer. The
# rest are only probable, because a site may genuinely run WordPress, publish
# a server-status page or serve something under /vendor -- there, one hit
# means little and it takes a spread across categories to mean anything.
#
# The three tiers this file has always described in its comments were never
# actually built: every category weighed the same, so asking for /.env scored
# what asking for /wp-admin scored.
DECISIVE_CATEGORIES: frozenset = frozenset({"secrets", "vcs", "backup"})

# Nothing above looks at the query string, and one gateway carried 11,413
# requests whose attack lived entirely there. The obvious rule -- treat
# ?cmd= as an attack -- would have been a disaster: 73 of the 74 addresses
# sending ?cmd= on that gateway were 1C Enterprise clients, whose web
# protocol puts cmd= in every single request. The parameter name carries no
# information at all.
#
# So these match the VALUE, and only shapes with no legitimate reading. On
# 837,733 real requests they fired on 17 addresses, none of them a client of
# anything, every one answered 404/451/423, and not one was caught by the
# path signatures: /setup.cgi, /device.rsp, /remote/fgt_lang. The three that
# found nothing in that sample are kept because they are well-known
# injection shapes and were proven not to misfire on 412 query-sending
# addresses -- absence of a hit is still evidence about false positives.
DEFAULT_QUERY_RULES: Dict[str, str] = {
    "fetch-and-run": r"(wget\s|curl\s|tftp\s|\bchmod\s+\+?x|\bbusybox\b)",
    "traversal": r"(\.\./\.\./|%2e%2e[/%])",
    "shell-chaining": r"(;\s*(sh|bash|cat|ls|id|uname|rm)\b|\|\s*(sh|bash)\b)",
    "substitution": r"(\$\(|`[a-z/]{2,})",
    "absolute-binary": r"/(bin|usr/bin|sbin)/(sh|bash|nc|perl|python)",
}
QUERY_RULES: Dict[str, "re.Pattern"] = {
    name: re.compile(pattern, re.I)
    for name, pattern in DEFAULT_QUERY_RULES.items()
}
# The query is decoded twice before matching, because %252e%252e is the
# same attack wearing one more coat. Past that, decoding invents requests
# nobody made.
QUERY_DECODE_PASSES = 2
MAX_QUERY_LENGTH = 2048


def classify_query(uri: str) -> str:
    """Name the injection shape in a request target's query, or "".

    The name is all that ever leaves this function. The value stays here:
    the access log genuinely contains ?token=..., which is why
    normalize_path throws the query away, and a rule that recorded what it
    matched would put the thing back into the security database by the
    back door.
    """

    if not uri or "?" not in uri:
        return ""
    query = uri.split("?", 1)[1][:MAX_QUERY_LENGTH]
    if not query:
        return ""
    for _ in range(QUERY_DECODE_PASSES):
        with contextlib.suppress(Exception):
            query = unquote_plus(query)
    for name, pattern in QUERY_RULES.items():
        if pattern.search(query):
            return name
    return ""


# The tables above are the fallback. The signature file ships beside this
# daemon and can be replaced without rebuilding anything, the way the GeoIP
# database already is: the useful part of this list is the part that keeps up
# with what is actually being probed, and that changes faster than releases.
SIGNATURE_PATH = os.environ.get(
    "GUARDD_SIGNATURES", "/usr/local/sbin/scanner-signatures.json"
)
SIGNATURE_VERSION = "built-in"
# Where the list in force actually came from. Reloading has to go back to
# the same place: re-reading the default path would quietly swap the list
# under a daemon started with GUARDD_SIGNATURES pointing somewhere else.
SIGNATURE_SOURCE = ""
# The shipped list as read from the file, before the operator's rules go
# on top. Kept apart so the two can be merged and published in one step.
_SHIPPED_SEGMENTS: Dict[str, str] = dict(SCANNER_SEGMENTS)
_SHIPPED_PATHS: Dict[str, str] = dict(SCANNER_PATHS)
# A path has few segments, but a hostile one can be made to have many; the
# scan stops well before the cost matters.
MAX_MATCHED_SEGMENTS = 12


def load_signatures(path: str = "") -> bool:
    """Replace the tables from the signature file. False keeps the built-ins.

    A broken or missing file must never stop the daemon: protection that
    fails closed on a bad download is worse than protection that keeps
    yesterday's list.
    """

    global SIGNATURE_VERSION, DECISIVE_CATEGORIES, SIGNATURE_SOURCE
    global _SHIPPED_SEGMENTS, _SHIPPED_PATHS

    source = path or SIGNATURE_PATH
    try:
        with open(source, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        segments = {str(k): str(v) for k, v in dict(data["segments"]).items()}
        paths = {str(k): str(v) for k, v in dict(data["paths"]).items()}
        decisive = {str(name) for name in data["decisive"]}
    except Exception as exc:  # noqa: BLE001 - any breakage keeps the built-ins
        LOG.warning("cannot read %s (%s); using the built-in signatures", source, exc)
        return False

    if not segments or not paths:
        LOG.warning("%s carries no signatures; using the built-in ones", source)
        return False

    # A trap is a path this installation does not serve and never links to,
    # so nothing can reach one by accident.
    for trap in data.get("traps") or []:
        paths[str(trap)] = "trap"

    # A bad regex in a downloaded file must not take the daemon with it, so
    # every rule is compiled before any of them is adopted.
    rules = dict(QUERY_RULES)
    if isinstance(data.get("queries"), dict):
        compiled = {}
        for name, pattern in data["queries"].items():
            try:
                compiled[str(name)] = re.compile(str(pattern), re.I)
            except re.error as exc:
                LOG.warning("query rule %s is not a valid regex (%s); "
                            "keeping the built-in rules", name, exc)
                compiled = {}
                break
        if compiled:
            rules = compiled

    QUERY_RULES.clear()
    QUERY_RULES.update(rules)
    _SHIPPED_SEGMENTS = segments
    _SHIPPED_PATHS = paths
    DECISIVE_CATEGORIES = frozenset(decisive)
    publish_signatures()
    SIGNATURE_VERSION = str(data.get("version") or "unversioned")
    SIGNATURE_SOURCE = source
    LOG.info(
        "Loaded scanner signatures %s: %d segments, %d paths, %d decisive, "
        "%d query rules",
        SIGNATURE_VERSION,
        len(segments),
        len(paths),
        len(decisive),
        len(QUERY_RULES),
    )
    return True


# The operator's own rules. The shipped list is a file Ansible writes on
# every deploy, so a signature typed into it would survive exactly until the
# next one; these live in guardd's state table instead, next to the
# enforcement mode and the request-log switch, for the same reason.
#
# Suppression is by token rather than by deletion, so a shipped signature the
# operator has turned off stays off when the shipped list is updated. That is
# the whole point: the entry that caused a false positive here must not come
# back with the next release.
SIGNATURE_OVERRIDES_KEY = "signature_overrides"
CUSTOM_CATEGORY = "custom"
MAX_CUSTOM_RULES = 200
MAX_TOKEN_LENGTH = 120

# What may be typed into a signature. A token is matched against a path
# segment or a whole path, never interpreted, so this only has to keep out
# the characters that would make one impossible to match or to read back.
_TOKEN_OK = re.compile(r"^[A-Za-z0-9._~/@:+-]{1,%d}$" % MAX_TOKEN_LENGTH)

_overrides: Dict[str, Any] = {"added": {}, "disabled": []}


def validate_token(token: str) -> str:
    """A signature an operator typed, or a ValueError explaining why not."""

    text = (token or "").strip()
    if not text:
        raise ValueError("empty signature")
    if len(text) > MAX_TOKEN_LENGTH:
        raise ValueError(f"longer than {MAX_TOKEN_LENGTH} characters")
    if not _TOKEN_OK.match(text):
        raise ValueError(
            "a signature may hold letters, digits and . _ ~ / @ : + - only"
        )
    if text.startswith("/") and text.strip("/") == "":
        # "/" would classify every request ever made.
        raise ValueError("a signature of / would match everything")
    return text


def validate_overrides(data: Any) -> Dict[str, Any]:
    """Check an override document before anything is allowed to store it."""

    if not isinstance(data, dict):
        raise ValueError("expected an object")
    added_raw = data.get("added") or {}
    disabled_raw = data.get("disabled") or []
    if not isinstance(added_raw, dict) or not isinstance(disabled_raw, list):
        raise ValueError("expected added to be an object and disabled a list")
    if len(added_raw) > MAX_CUSTOM_RULES or len(disabled_raw) > MAX_CUSTOM_RULES:
        raise ValueError(f"at most {MAX_CUSTOM_RULES} rules")

    added: Dict[str, str] = {}
    for token, category in added_raw.items():
        name = str(category or CUSTOM_CATEGORY).strip() or CUSTOM_CATEGORY
        if not re.match(r"^[a-z0-9-]{1,32}$", name):
            raise ValueError(f"{name} is not a usable category name")
        added[validate_token(str(token))] = name

    disabled = sorted({validate_token(str(token)) for token in disabled_raw})
    return {"added": added, "disabled": disabled}


def publish_signatures() -> None:
    """Merge the shipped list with the operator's rules and swap them in.

    One rebinding rather than a clear and a refill: the log reader looks
    these up on another thread, and it must see either the whole old set or
    the whole new one -- never a half-empty table, and never a moment where
    a suppressed signature is live again.
    """

    global SCANNER_SEGMENTS, SCANNER_PATHS

    segments = dict(_SHIPPED_SEGMENTS)
    paths = dict(_SHIPPED_PATHS)
    for token in _overrides.get("disabled") or []:
        paths.pop(token, None)
        segments.pop(token, None)
    for token, category in (_overrides.get("added") or {}).items():
        if token.startswith("/"):
            paths[token] = category
        else:
            segments[token] = category
    SCANNER_SEGMENTS = segments
    SCANNER_PATHS = paths


def apply_overrides(overrides: Optional[Dict[str, Any]] = None) -> None:
    """Adopt a set of operator rules and republish."""

    global _overrides

    if overrides is not None:
        _overrides = overrides
    publish_signatures()


def load_overrides(database: "SecurityDatabase") -> Dict[str, Any]:
    """Read them back at startup. A corrupt document is ignored, not fatal."""

    raw = database.get_state(SIGNATURE_OVERRIDES_KEY, "")
    if not raw:
        return {"added": {}, "disabled": []}
    try:
        return validate_overrides(json.loads(raw))
    except Exception as exc:  # noqa: BLE001 - never stop the daemon for this
        LOG.warning("stored signature overrides are unusable (%s); ignoring", exc)
        return {"added": {}, "disabled": []}


def store_overrides(database: "SecurityDatabase", data: Any) -> Dict[str, Any]:
    """Validate, persist and apply in one step, so the three cannot diverge."""

    checked = validate_overrides(data)
    database.set_state(SIGNATURE_OVERRIDES_KEY, json.dumps(checked))
    # Reload the shipped list first: a signature that was disabled and is now
    # enabled again has to come back, and only the file has it.
    load_signatures(SIGNATURE_SOURCE)
    apply_overrides(checked)
    LOG.info(
        "signature overrides updated: %d added, %d suppressed",
        len(checked["added"]),
        len(checked["disabled"]),
    )
    return checked


def signature_summary() -> Dict[str, Any]:
    """The rules as they are loaded, for the page that has to explain a ban.

    Grouped by category rather than listed flat: forty-seven segments in one
    column is a data dump, and the thing an operator needs to see is which
    categories end an argument on their own.
    """

    grouped: Dict[str, Dict[str, List[str]]] = {}
    for segment, category in SCANNER_SEGMENTS.items():
        grouped.setdefault(category, {"segments": [], "paths": []})
        grouped[category]["segments"].append(segment)
    for path, category in SCANNER_PATHS.items():
        grouped.setdefault(category, {"segments": [], "paths": []})
        grouped[category]["paths"].append(path)

    return {
        "version": SIGNATURE_VERSION,
        "source": SIGNATURE_SOURCE or SIGNATURE_PATH,
        "would_ban_score": WOULD_BAN_SCORE,
        "decisive_weight": DEFAULT_WEIGHTS.get(EVENT_SCANNER_DECISIVE, 0),
        "probable_weight": DEFAULT_WEIGHTS.get(EVENT_SCANNER_PATH, 0),
        "query_weight": DEFAULT_WEIGHTS.get(EVENT_QUERY_INJECTION, 0),
        "categories": [
            {
                "name": category,
                "decisive": category_is_decisive(category),
                "segments": sorted(entries["segments"]),
                "paths": sorted(entries["paths"]),
            }
            for category, entries in sorted(grouped.items())
        ],
        # The names only. The patterns themselves would be a fair thing to
        # show, but they are regular expressions against a query string and
        # the page is not the place to teach anyone to read one.
        "query_rules": sorted(QUERY_RULES),
        # What the operator changed, so the page can offer to change it back.
        "added": dict(_overrides.get("added") or {}),
        "disabled": list(_overrides.get("disabled") or []),
        "custom_category": CUSTOM_CATEGORY,
        "max_rules": MAX_CUSTOM_RULES,
    }


def category_is_decisive(category: str) -> bool:
    return category in DECISIVE_CATEGORIES


def refusal_is_a_shield(request: ParsedRequest, activity: "IpActivity") -> bool:
    """Does the gateway's refusal make scoring this request pointless?

    Only while the address has never been past the gateway on anything.

    "It reaches nothing, so a ban changes nothing" was the original
    reasoning, and on a gateway serving more than one site it is false. The
    refusals are per host -- one rule for each gated site, plus geography
    over a named set of domains -- so an address turned away from one host
    is free to keep walking the others, and the Authelia host cannot be
    gated at all, because the login page has to be reachable to log in.

    Measured on a live gateway: of 173 addresses refused that day, 17 were
    answered on something else. One of them was collecting a 200 for
    /b374k-2.6.php, which is a webshell name. Every one of them sat at score
    0, state NORMAL, recommended action "nothing", and went on probing every
    hour for days.

    A ban is also not the same instrument as a 451. It is applied by
    tcp-request connection reject, across every host and every port, before
    the TLS handshake -- strictly more coverage, and far cheaper, than the
    per-site rule that refused the request.
    """

    return request.denied_by_gateway and not activity.reached_backend


def is_served(status: int) -> bool:
    """The application answered with content, so this path is not a probe.

    A site that really runs WordPress answers /wp-login.php with a login
    page, and every one of its users would otherwise be filed as scanning
    for WordPress.

    2xx only. A redirect is not the application serving the file: plenty of
    sites bounce every unknown path to a login page or a home page, and on
    one gateway 1004 of 1211 scanner-shaped paths that looked "served" were
    301s. Counting those as legitimate would have excused every scanner on
    the host -- the opposite failure from the one this exists to prevent,
    and a quieter one.
    """

    return 200 <= status < 300

# A 404 on one of these is a broken page, not reconnaissance. Without this the
# single largest false-positive source is a front end asking for assets that
# were renamed by a deploy.
ASSET_SUFFIXES: Tuple[str, ...] = (
    ".css", ".js", ".mjs", ".map", ".json", ".xml", ".txt",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
    ".bmp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".webm", ".mp3", ".wav", ".pdf",
)

EVENT_SCANNER_PATH = "SCANNER_PATH"
EVENT_SCANNER_DECISIVE = "SCANNER_PATH_DECISIVE"
EVENT_QUERY_INJECTION = "QUERY_INJECTION"
EVENT_SCANNER_MULTI = "SCANNER_MULTI_CATEGORY"
EVENT_LOW_AND_SLOW = "LOW_AND_SLOW_SCANNER"
EVENT_NOT_FOUND_ENUM = "NOT_FOUND_ENUMERATION"
EVENT_INVALID_HOST = "INVALID_HOST_ACTIVITY"
EVENT_NOSNI_PROBING = "NOSNI_PROBING"
EVENT_RATE_EXCEEDED = "RATE_EXCEEDED"
EVENT_ERROR_RATE_EXCEEDED = "ERROR_RATE_EXCEEDED"
EVENT_LEGACY_BAN = "LEGACY_HAPROXY_BAN"
# Actions rather than findings: they carry no weight and never feed the score.
EVENT_BAN_APPLIED = "BAN_APPLIED"
EVENT_BAN_LIFTED = "BAN_LIFTED"

DEFAULT_WEIGHTS: Dict[str, int] = {
    EVENT_SCANNER_PATH: 25,
    # One request for a file no client ever wants is enough on
    # its own; that is what makes it decisive.
    EVENT_SCANNER_DECISIVE: 60,
    # Same tier, same reason. Nothing legitimate puts a fetch-and-run or a
    # traversal chain in a query string: on 837,733 real requests these
    # fired on 17 addresses, every one answered 4xx, and none of them was a
    # client of anything.
    EVENT_QUERY_INJECTION: 60,
    EVENT_SCANNER_MULTI: 20,
    EVENT_LOW_AND_SLOW: 30,
    EVENT_NOT_FOUND_ENUM: 15,
    EVENT_INVALID_HOST: 10,
    EVENT_NOSNI_PROBING: 10,
    EVENT_RATE_EXCEEDED: 15,
    EVENT_ERROR_RATE_EXCEEDED: 15,
    EVENT_LEGACY_BAN: 30,
}

# One category is one finding. Fifty different /wp-* URLs say "looked for
# WordPress" once, not fifty times.
DEFAULT_CATEGORY_CAP = 25
DEFAULT_SCORE_WINDOW_SECONDS = 24 * 3600
# Contributions fade with age instead of being decremented on a timer: the
# score is derived from the stored events, so it has to be a function of them.
DEFAULT_DECAY_SECONDS = 6 * 3600

DEFAULT_THRESHOLDS: Tuple[Tuple[int, str], ...] = (
    (80, "HOSTILE"),
    (60, "HIGH_RISK"),
    (40, "SUSPICIOUS"),
    (20, "WATCH"),
    (0, "NORMAL"),
)
# The score at which enforcement would act, and the one at which an address is
# interesting enough that authenticating afterwards counts as a warning sign.
WOULD_BAN_SCORE = 60
WATCH_SCORE = 20

RECOMMENDED_ACTIONS: Dict[str, str] = {
    "NORMAL": "none",
    "WATCH": "observe",
    "SUSPICIOUS": "throttle",
    "HIGH_RISK": "temporary_ban",
    "HOSTILE": "long_ban",
}

# Cooldowns keep one continuous incident from scoring on every cycle.
COOLDOWN_SECONDS: Dict[str, int] = {
    EVENT_SCANNER_PATH: 300,
    EVENT_SCANNER_MULTI: 900,
    EVENT_LOW_AND_SLOW: 3600,
    EVENT_NOT_FOUND_ENUM: 900,
    EVENT_INVALID_HOST: 600,
    EVENT_NOSNI_PROBING: 600,
    EVENT_RATE_EXCEEDED: 60,
    EVENT_ERROR_RATE_EXCEEDED: 60,
}

# Thresholds for the derived detections.
MULTI_CATEGORY_MIN = 3
MULTI_CATEGORY_WINDOW = 2 * 3600
LOW_AND_SLOW_MIN_HITS = 5
LOW_AND_SLOW_MIN_CATEGORIES = 3
LOW_AND_SLOW_WINDOW = 6 * 3600
NOT_FOUND_MIN_DISTINCT = 6
NOT_FOUND_WINDOW = 3600
INVALID_HOST_MIN = 5
INVALID_HOST_WINDOW = 6 * 3600

# rsyslog writes "<ts> <host> haproxy[pid]: <log-format>".
_SYSLOG_PREFIX = re.compile(r"^\S+\s+\S+\s+haproxy\[\d+\]:\s*")
# Anchored at both ends: the middle of the line carries an optional ban_log
# fragment with quoted, space-bearing text, so it is never parsed positionally.
_ACCESS_HEAD = re.compile(
    r"^(?P<client>\[[0-9A-Fa-f:]+\]|[0-9.]+):(?P<port>\d+)\s+"
    r"\[(?P<stamp>[^\]]*)\]\s+"
    r"(?P<frontend>\S+)\s+(?P<backend>\S+)\s+"
    r"(?P<times>\S+)\s+"
    r"(?P<status>-|\d{3})\s+"
    r"(?P<bytes>-|\d+)\s+"
)
_ACCESS_TAIL = re.compile(
    r"(?P<method>[A-Z]{3,10})\s+(?P<uri>\S+)\s+(?P<proto>HTTP/[0-9.]+)\s*$"
)
_BAD_REQUEST_TAIL = re.compile(r"<BADREQ>\s*$")
# Labelled fields in the unparsed middle of the record. They are found by name
# rather than by position, which is what keeps the middle free to change.
_ID_FIELD = re.compile(r"(?:^|\s)id=(?P<id>\S+)")
_HOST_FIELD = re.compile(r"(?:^|\s)host=(?P<host>\S+)")
_MONTHS = {
    name: index
    for index, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}
_STAMP = re.compile(
    r"^(?P<day>\d{2})/(?P<month>[A-Za-z]{3})/(?P<year>\d{4}):"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
)


def parse_stamp(value: str) -> int:
    """Turn HAProxy's %t into a unix timestamp.

    strptime costs about ten microseconds a line, which at the measured
    27k lines/s is real work on a two-core gateway; this does the same job
    with arithmetic.
    """
    match = _STAMP.match(value or "")
    if match is None:
        return 0
    month = _MONTHS.get(match.group("month"))
    if month is None:
        return 0
    try:
        return int(
            calendar.timegm(
                (
                    int(match.group("year")),
                    month,
                    int(match.group("day")),
                    int(match.group("hour")),
                    int(match.group("minute")),
                    int(match.group("second")),
                    0,
                    0,
                    0,
                )
            )
        )
    except (ValueError, OverflowError):
        return 0


def _utc_now() -> int:
    return int(time.time())


def _clamp_int(value: Any, *, default: int, min_v: int, max_v: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(min_v, min(max_v, parsed))


# ---------------------------------------------------------------------------
# Request sanitising
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ParsedRequest:
    """One access-log line, reduced to what is safe to keep."""

    client_ip: str
    status: int
    frontend: str
    backend: str
    method: str
    path: str
    host: str
    bad_request: bool = False
    # The NAME of the injection rule the query matched, never the query. The
    # value is dropped for the same reason normalize_path drops it: the
    # access log really does contain ?token=..., and a security database is
    # the last place that belongs.
    query_flag: str = ""
    # Filled in only when the request log is on. They cost a little more
    # parsing per line, so they stay optional rather than always paid for.
    ts: int = 0
    request_id: str = ""
    bytes_out: int = 0
    duration_ms: int = 0

    # A refusal counts as "already handled" only when it was about who the
    # client is, not about what it sent. 451 is a geo block or a failed IP
    # authorisation and 403 a per-site address rule: in both the address can
    # reach nothing, so scoring it further changes nothing.
    IDENTITY_REFUSALS = (403, 451)

    @property
    def denied_by_gateway(self) -> bool:
        """HAProxy refused this one for who the client is, not what it sent.

        400 used to be in this set, and it is the opposite case: the gateway
        rejected one malformed request and carried on serving that same
        address everything else it asked for. Treating it as a shield threw
        away most of the evidence -- on a live gateway 77% of all security
        events scored nothing, including 85% of scanner findings, because a
        scanner's requests are malformed by nature. One address sent 134
        malformed requests while being served 5935 normal ones and scored
        zero for every one of them.
        """

        return self.status in self.IDENTITY_REFUSALS


def normalize_path(value: str) -> str:
    """Reduce a request target to a comparable path, dropping the query.

    The query string is removed before anything is stored: the access log
    genuinely contains things like `?token=...`, and a security database is the
    last place a password-reset token should end up.
    """

    if not value:
        return "/"
    text = value.strip()
    # An HTTP/2 request line carries the absolute form, so the host travels
    # inside the target rather than in a captured header.
    if text.startswith(("http://", "https://")):
        text = urlparse(text).path or "/"
    for separator in ("?", "#"):
        index = text.find(separator)
        if index >= 0:
            text = text[:index]
    with contextlib.suppress(Exception):
        # One decoding pass only: decoding repeatedly invents paths that were
        # never requested.
        text = unquote(text)
    text = _CONTROL_CHARS.sub("", text)
    text = _MULTI_SLASH.sub("/", text)
    if not text.startswith("/"):
        text = "/" + text
    segments: List[str] = []
    for segment in text.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if segments:
                segments.pop()
            continue
        segments.append(segment)
    normalized = "/" + "/".join(segments)
    return normalized[:MAX_PATH_LENGTH]


def is_asset(path: str) -> bool:
    """A missing stylesheet is a deploy artefact, not reconnaissance."""

    lowered = path.lower()
    return lowered.endswith(ASSET_SUFFIXES)


def classify_path(path: str) -> str:
    """Return the scanner category for a normalised path, or "".

    Every segment is checked, not only the first. The most common attack in
    the mined traffic -- CVE-2017-9841, the phpunit eval-stdin.php remote
    execution -- arrives as /laravel/vendor/phpunit/... and /lib/phpunit/...
    far more often than as /vendor/phpunit/..., and first-segment matching
    saw none of those. A path has few segments and the scan is bounded, so
    the cost of running this on every logged line is unchanged in practice.
    """

    if not path or path == "/":
        return ""
    exact = SCANNER_PATHS.get(path)
    if exact:
        return exact
    if is_asset(path):
        # A stylesheet under /vendor/ that a deploy renamed is not a probe,
        # and matching every segment would otherwise make it one.
        return ""
    # The most confident match wins, not the leftmost. /vendor/phpunit/...
    # and /lib/phpunit/... are the same attack, and taking whichever segment
    # came first gave one of them "dependency" and the other "rce-probe".
    probable = ""
    for segment in path.split("/", MAX_MATCHED_SEGMENTS + 1)[1:]:
        if not segment:
            continue
        category = SCANNER_SEGMENTS.get(segment) or SCANNER_SEGMENTS.get(
            segment.lower()
        )
        if not category:
            continue
        if category_is_decisive(category):
            return category
        probable = probable or category
    return probable


def extract_host(value: str) -> str:
    """Host from an absolute-form target, empty when the line has none.

    HTTP/2 requests log the absolute URI, so the host is available; HTTP/1.1
    requests usually log the origin form and simply do not carry it.
    """

    if not value.startswith(("http://", "https://")):
        return ""
    host = (urlparse(value).hostname or "").strip().lower()
    return _CONTROL_CHARS.sub("", host)[:MAX_HOST_LENGTH]


def parse_access_line(line: str) -> Optional[ParsedRequest]:
    """Parse one HAProxy access-log line, or None if it is not one.

    HAProxy also writes health-check and warning lines to the same file; those
    are not access records and must not be mistaken for traffic.
    """

    if not line:
        return None
    text = _SYSLOG_PREFIX.sub("", line.strip())
    head = _ACCESS_HEAD.match(text)
    if head is None:
        return None

    client = head.group("client")
    if client.startswith("["):
        client = client[1:-1]
    status_text = head.group("status")
    status = 0 if status_text == "-" else int(status_text)

    remainder = text[head.end():]
    bytes_text = head.group("bytes")
    bytes_out = 0 if bytes_text == "-" else int(bytes_text)
    stamp = parse_stamp(head.group("stamp"))
    identifier = _ID_FIELD.search(remainder)
    request_id = identifier.group("id") if identifier else ""

    tail = _ACCESS_TAIL.search(remainder)
    if tail is None:
        if _BAD_REQUEST_TAIL.search(remainder):
            return ParsedRequest(
                client_ip=client,
                status=status,
                frontend=head.group("frontend"),
                backend=head.group("backend"),
                method="",
                path="",
                host="",
                bad_request=True,
                ts=stamp,
                request_id=request_id,
                bytes_out=bytes_out,
            )
        return None

    uri = tail.group("uri")
    # The Host header, when the frontend captures it, is a labelled field; the
    # absolute-form URI is the fallback and is rare in practice.
    host_field = _HOST_FIELD.search(remainder)
    host = host_field.group("host") if host_field else extract_host(uri)
    if host in ("-", "{}"):
        host = ""
    return ParsedRequest(
        client_ip=client,
        status=status,
        frontend=head.group("frontend"),
        backend=head.group("backend"),
        method=tail.group("method"),
        path=normalize_path(uri),
        host=extract_host(uri) if not host else host[:MAX_HOST_LENGTH],
        query_flag=classify_query(uri),
        ts=stamp,
        request_id=request_id,
        bytes_out=bytes_out,
        duration_ms=_total_time(head.group("times")),
    )


def _total_time(times: str) -> int:
    """The last field of %TR/%Tw/%Tc/%Tr/%Tt is the total, or -1 when unknown."""
    tail = (times or "").rsplit("/", 1)[-1]
    try:
        value = int(tail)
    except ValueError:
        return 0
    return max(0, value)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GuardConfig:
    mode: str = MODE_MONITOR
    poll_interval_seconds: int = 10
    haproxy_socket: str = "/run/haproxy/admin.sock"
    log_file: str = "/var/log/haproxy.log"
    log_read_bytes_per_cycle: int = 4 * 1024 * 1024
    whitelist_files: Tuple[str, ...] = (
        "/etc/haproxy/whitelist.ip",
        "/etc/haproxy/admin.allow",
        "/etc/haproxy/geoip/whitelist.geo",
    )
    trusted_networks: Tuple[str, ...] = ()
    max_tracked_ips: int = DEFAULT_MAX_TRACKED_IPS
    max_paths_per_ip: int = DEFAULT_MAX_PATHS_PER_IP
    event_retention_days: int = 30
    maintenance_interval_seconds: int = 300
    # The request log is a separate concern that happens to need the same read
    # of the same file. It has its own switch, its own database and its own
    # budget, so turning it on cannot change how the engine scores anything.
    request_log_enabled: bool = False
    request_log_retention_days: int = 3
    request_log_max_bytes: int = 256 * 1024 * 1024
    request_log_reserved_free_bytes: int = 512 * 1024 * 1024


class ConfigError(ValueError):
    """A configuration that must not be silently repaired."""


def load_config(path: str) -> GuardConfig:
    raw: Dict[str, Any] = {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            loaded = json.load(handle)
        if isinstance(loaded, dict):
            raw = loaded
        else:
            LOG.warning("Config %s is not an object; using defaults", path)
    except FileNotFoundError:
        LOG.info("Config %s not found; using defaults", path)
    except (OSError, ValueError) as exc:
        LOG.warning("Cannot read config %s (%s); using defaults", path, exc)

    mode = str(raw.get("mode") or MODE_MONITOR).strip().lower()
    if mode not in SUPPORTED_MODES:
        LOG.warning("Unknown mode %r; falling back to %s", mode, MODE_MONITOR)
        mode = MODE_MONITOR

    limits = raw.get("limits")
    limits = limits if isinstance(limits, dict) else {}
    sources = raw.get("sources")
    sources = sources if isinstance(sources, dict) else {}
    exclusions = raw.get("exclusions")
    exclusions = exclusions if isinstance(exclusions, dict) else {}
    request_log = raw.get("request_log")
    request_log = request_log if isinstance(request_log, dict) else {}

    def _string_tuple(value: Any, fallback: Tuple[str, ...]) -> Tuple[str, ...]:
        if not isinstance(value, list):
            return fallback
        items = tuple(str(item).strip() for item in value if str(item).strip())
        return items if items else fallback

    return GuardConfig(
        mode=mode,
        poll_interval_seconds=_clamp_int(
            raw.get("poll_interval_seconds"), default=10, min_v=5, max_v=60
        ),
        haproxy_socket=str(
            sources.get("haproxy_socket") or "/run/haproxy/admin.sock"
        ).strip(),
        log_file=str(
            sources.get("log_file") or "/var/log/haproxy.log"
        ).strip(),
        log_read_bytes_per_cycle=_clamp_int(
            limits.get("log_read_bytes_per_cycle"),
            default=4 * 1024 * 1024,
            min_v=64 * 1024,
            max_v=64 * 1024 * 1024,
        ),
        whitelist_files=_string_tuple(
            exclusions.get("whitelist_files"),
            GuardConfig.whitelist_files,
        ),
        trusted_networks=_string_tuple(exclusions.get("trusted_networks"), ()),
        max_tracked_ips=_clamp_int(
            limits.get("max_tracked_ips"),
            default=DEFAULT_MAX_TRACKED_IPS,
            min_v=1000,
            max_v=500000,
        ),
        request_log_enabled=bool(request_log.get("enabled")),
        request_log_retention_days=_clamp_int(
            request_log.get("retention_days"), default=3, min_v=1, max_v=30
        ),
        request_log_max_bytes=_clamp_int(
            request_log.get("max_bytes"),
            default=256 * 1024 * 1024,
            min_v=16 * 1024 * 1024,
            max_v=16 * 1024 * 1024 * 1024,
        ),
        request_log_reserved_free_bytes=_clamp_int(
            request_log.get("reserved_free_bytes"),
            default=512 * 1024 * 1024,
            min_v=64 * 1024 * 1024,
            max_v=64 * 1024 * 1024 * 1024,
        ),
        max_paths_per_ip=_clamp_int(
            limits.get("max_paths_per_ip"),
            default=DEFAULT_MAX_PATHS_PER_IP,
            min_v=8,
            max_v=256,
        ),
        event_retention_days=_clamp_int(
            limits.get("event_retention_days"), default=30, min_v=1, max_v=365
        ),
        maintenance_interval_seconds=_clamp_int(
            raw.get("maintenance_interval_seconds"),
            default=300,
            min_v=60,
            max_v=3600,
        ),
    )


# ---------------------------------------------------------------------------
# HAProxy runtime access
# ---------------------------------------------------------------------------


def runtime_command(socket_path: str, command: str) -> str:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(RUNTIME_TIMEOUT_SECONDS)
        sock.connect(socket_path)
        sock.sendall(f"{command}\n".encode("utf-8"))
        chunks: List[bytes] = []
        total = 0
        while total < RUNTIME_MAX_BYTES:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    return b"".join(chunks).decode("utf-8", "replace")


_TABLE_ROW = re.compile(r"^0x[0-9a-f]+:\s+key=(?P<key>\S+)\s+(?P<rest>.*)$")
_TABLE_FIELD = re.compile(r"(?P<name>[a-z_0-9()]+)=(?P<value>\S+)")


def parse_table(payload: str) -> Dict[str, Dict[str, str]]:
    """Parse `show table <name>` into {key: {field: value}}."""

    rows: Dict[str, Dict[str, str]] = {}
    for line in payload.splitlines():
        match = _TABLE_ROW.match(line.strip())
        if match is None:
            continue
        fields = {
            item.group("name"): item.group("value")
            for item in _TABLE_FIELD.finditer(match.group("rest"))
        }
        rows[match.group("key")] = fields
    return rows


def list_tables(payload: str) -> List[str]:
    names: List[str] = []
    for line in payload.splitlines():
        match = re.search(r"\btable:\s*([^\s,]+)", line)
        if match:
            names.append(match.group(1))
    return names


# ---------------------------------------------------------------------------
# Exclusions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScoringPolicy:
    """Everything that turns stored events into a number.

    Kept separate from the events on purpose: retuning any of this re-scores
    the entire history instead of requiring another week of observation.
    """

    weights: Dict[str, int] = field(
        default_factory=lambda: dict(DEFAULT_WEIGHTS)
    )
    category_cap: int = DEFAULT_CATEGORY_CAP
    window_seconds: int = DEFAULT_SCORE_WINDOW_SECONDS
    decay_seconds: int = DEFAULT_DECAY_SECONDS

    def weight(self, event_type: str) -> int:
        return int(self.weights.get(event_type, 0))


def policy_from_query(
    query: Dict[str, List[str]], base: ScoringPolicy
) -> ScoringPolicy:
    """Build a what-if policy from request parameters.

    Every key is an allow-listed event type and every value is clamped, so the
    simulator can only ask "what if this weight were different" -- it cannot
    describe anything the engine would not otherwise compute.
    """

    weights = dict(base.weights)
    for name, values in query.items():
        if not name.startswith("w."):
            continue
        event_type = name[2:]
        if event_type not in DEFAULT_WEIGHTS:
            continue
        weights[event_type] = _clamp_int(
            values[0], default=base.weight(event_type), min_v=0, max_v=100
        )
    return ScoringPolicy(
        weights=weights,
        category_cap=_clamp_int(
            query.get("cap", [None])[0],
            default=base.category_cap,
            min_v=1,
            max_v=100,
        ),
        window_seconds=_clamp_int(
            query.get("window", [None])[0],
            default=base.window_seconds,
            min_v=3600,
            max_v=30 * 86400,
        ),
        decay_seconds=_clamp_int(
            query.get("decay", [None])[0],
            default=base.decay_seconds,
            min_v=0,
            max_v=30 * 86400,
        ),
    )


def state_for(score: int) -> str:
    for threshold, name in DEFAULT_THRESHOLDS:
        if score >= threshold:
            return name
    return "NORMAL"


def score_events(
    events: Iterable[Dict[str, Any]], now: int, policy: ScoringPolicy
) -> Dict[str, Any]:
    """Derive a 0..100 score and its explanation from stored events.

    Contributions fade with age rather than being decremented on a timer, and
    each scanner category is capped, so a bot grinding through fifty WordPress
    URLs counts as one finding rather than fifty.
    """

    total = 0.0
    per_category: Dict[str, float] = {}
    contributions: List[Dict[str, Any]] = []
    counted = 0

    for event in events:
        ts = int(event.get("ts", 0))
        age = max(0, now - ts)
        if age > policy.window_seconds:
            continue
        event_type = str(event.get("event_type", ""))
        base = policy.weight(event_type)
        if base <= 0:
            continue
        if int(event.get("handled", 0)):
            # HAProxy already refused this request; banning on top of a GeoIP
            # denial adds nothing.
            contributions.append(
                {
                    "ts": ts,
                    "event_type": event_type,
                    "category": str(event.get("category", "")),
                    "points": 0,
                    "reason": "already refused by the gateway",
                    "site": str(event.get("site", "")),
                    "detail": str(event.get("detail", "")),
                }
            )
            continue
        decay = 1.0
        if policy.decay_seconds > 0:
            decay = max(0.0, 1.0 - age / policy.decay_seconds)
        points = base * decay
        if points <= 0:
            continue

        category = str(event.get("category", "")) or event_type
        used = per_category.get(category, 0.0)
        # The cap stops repetition from inflating a finding, but it must never
        # clip a single event below its own weight -- otherwise raising a
        # weight above the cap would have no effect at all.
        ceiling = max(policy.category_cap, base)
        allowed = max(0.0, ceiling - used)
        granted = min(points, allowed)
        per_category[category] = used + granted
        total += granted
        counted += 1
        contributions.append(
            {
                "ts": ts,
                "event_type": event_type,
                "category": str(event.get("category", "")),
                "points": round(granted, 2),
                "reason": (
                    "category cap reached"
                    if granted < points
                    else "counted"
                ),
                # What the finding was about, not just that there was one:
                # which site, and the counter reading that triggered it.
                "site": str(event.get("site", "")),
                "detail": str(event.get("detail", "")),
            }
        )

    score = int(min(100.0, round(total)))
    state = state_for(score)
    return {
        "score": score,
        "state": state,
        "recommended_action": RECOMMENDED_ACTIONS.get(state, "none"),
        "events_counted": counted,
        "categories": {
            name: round(value, 2) for name, value in per_category.items()
        },
        "contributions": contributions,
    }


@dataclass
class Verdict:
    excluded: bool
    reason: str


class ExclusionModel:
    """Who guardd must never act on.

    Mirrors the ACLs in the HAProxy configuration: the global whitelist, the
    admin allow-list, the GeoIP whitelist, and -- read live from the runtime --
    the addresses that completed Authelia authentication. HAProxy exempts all
    of these from its own bans, so scoring them would only produce noise.
    """

    def __init__(self, config: GuardConfig) -> None:
        self.config = config
        self._lock = threading.Lock()
        self._networks: List[Any] = []
        self._signatures: Dict[str, Tuple[int, int]] = {}
        self._authenticated: Set[str] = set()
        self.reload_files(force=True)

    # -- static files -----------------------------------------------------

    def reload_files(self, *, force: bool = False) -> bool:
        signatures: Dict[str, Tuple[int, int]] = {}
        for path in self.config.whitelist_files:
            try:
                stat = os.stat(path)
                signatures[path] = (int(stat.st_mtime), int(stat.st_size))
            except OSError:
                signatures[path] = (0, 0)
        if not force and signatures == self._signatures:
            return False

        networks: List[Any] = []
        for path in self.config.whitelist_files:
            networks.extend(self._read_acl_file(path))
        for entry in self.config.trusted_networks:
            network = self._parse_network(entry)
            if network is not None:
                networks.append(network)

        with self._lock:
            self._networks = networks
            self._signatures = signatures
        LOG.info(
            "Exclusion list reloaded: %d networks from %d files",
            len(networks),
            len(self.config.whitelist_files),
        )
        return True

    @staticmethod
    def _parse_network(entry: str) -> Optional[Any]:
        try:
            return ipaddress.ip_network(entry, strict=False)
        except ValueError:
            return None

    def _read_acl_file(self, path: str) -> List[Any]:
        networks: List[Any] = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                for raw in handle:
                    line = raw.split("#", 1)[0].strip()
                    if not line:
                        continue
                    # HAProxy pattern files allow a trailing label after the
                    # pattern; only the first token is the address.
                    network = self._parse_network(line.split()[0])
                    if network is not None:
                        networks.append(network)
        except OSError:
            return []
        return networks

    # -- runtime ----------------------------------------------------------

    def refresh_authenticated(self, rows: Dict[str, Dict[str, str]]) -> None:
        """Addresses currently holding an Authelia authorization."""

        authenticated = {
            key
            for key, fields in rows.items()
            if _safe_int(fields.get("gpc0")) > 0
        }
        with self._lock:
            self._authenticated = authenticated

    # -- queries ----------------------------------------------------------

    def verdict(self, ip: str) -> Verdict:
        with self._lock:
            if ip in self._authenticated:
                return Verdict(True, "authenticated")
            networks = list(self._networks)
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return Verdict(True, "unparsable")
        if address.is_loopback or address.is_link_local:
            return Verdict(True, "local")
        for network in networks:
            if address.version == network.version and address in network:
                return Verdict(True, "whitelisted")
        return Verdict(False, "")

    @property
    def authenticated_count(self) -> int:
        with self._lock:
            return len(self._authenticated)

    @property
    def network_count(self) -> int:
        with self._lock:
            return len(self._networks)


HAPROXY_CONFIG_PATH = os.environ.get("HAPROXY_CFG", "/etc/haproxy/haproxy.cfg")

# The thresholds are written into the generated configuration as ACLs, which
# makes that file the authority on what "exceeded" means. Reading them from
# there keeps one number in one place: change max_req_rate in the interface,
# apply, and the engine agrees without being told separately.
_THRESHOLD_RE = re.compile(
    r"^\s*acl\s+\S+\s+(?:src_http_req_rate|src_http_err_rate|sc0_conn_rate)"
    r"\((?P<table>[A-Za-z0-9_.-]+)\)\s+gt\s+(?P<limit>\d+)\s*$",
    re.MULTILINE,
)


def read_thresholds(path: str = "") -> Dict[str, int]:
    """Map each counter table to the value HAProxy treats as too much."""
    try:
        text = pathlib.Path(path or HAPROXY_CONFIG_PATH).read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError as exc:
        LOG.warning("cannot read %s for thresholds: %s", path or HAPROXY_CONFIG_PATH, exc)
        return {}
    return {
        match.group("table"): int(match.group("limit"))
        for match in _THRESHOLD_RE.finditer(text)
    }


def _safe_int(value: Any) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def enforceable(ip: str) -> bool:
    """Whether a ban could ever be applied to this address.

    `tbl_ban` is an IPv4 stick table and the firewall ruleset is `inet`, so an
    IPv6 client cannot be banned through this path at all. Recording that is
    more honest than accumulating a score nothing can act on.
    """

    try:
        return ipaddress.ip_address(ip).version == 4
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Bounded per-IP memory
# ---------------------------------------------------------------------------


@dataclass
class IpActivity:
    """What one address has been doing, in a fixed amount of space."""

    first_seen: int = 0
    last_seen: int = 0
    requests: int = 0
    errors: int = 0
    not_found: int = 0
    gateway_denied: int = 0
    bad_requests: int = 0
    # Whether any request from this address ever reached a real server. A
    # refusal is only a shield while the answer is no: see reached_a_backend.
    reached_backend: bool = False
    paths: "OrderedDict[int, int]" = field(default_factory=OrderedDict)
    hosts: Set[str] = field(default_factory=set)
    # Detection state, all bounded: category -> last seen, and the distinct
    # 404 paths that were not assets.
    categories: "OrderedDict[str, int]" = field(default_factory=OrderedDict)
    scanner_hits: int = 0
    # How many of those the gateway had already refused. A finding derived
    # from nothing but refused requests must not score when every request it
    # was derived from scored nothing.
    scanner_hits_denied: int = 0
    missing_paths: "OrderedDict[int, int]" = field(default_factory=OrderedDict)
    invalid_host_hits: int = 0
    invalid_host_since: int = 0

    @property
    def scanning_was_all_refused(self) -> bool:
        """Every scanner hit from this address was refused on identity.

        The address reaches nothing, so a ban changes nothing -- the same
        reason a single finding scores zero. Mixed traffic does not count:
        one request that got through is enough for the derived findings to
        be worth their points.
        """

        return (
            self.scanner_hits > 0
            and self.scanner_hits_denied >= self.scanner_hits
        )

    def note_path(self, path: str, ts: int, limit: int) -> bool:
        """Remember a path by hash. True when it had not been seen before."""

        digest = hash(path) & 0xFFFFFFFF
        fresh = digest not in self.paths
        self.paths[digest] = ts
        self.paths.move_to_end(digest)
        while len(self.paths) > limit:
            self.paths.popitem(last=False)
        return fresh

    def note_category(self, category: str, ts: int, limit: int = 16) -> None:
        self.categories[category] = ts
        self.categories.move_to_end(category)
        while len(self.categories) > limit:
            self.categories.popitem(last=False)

    def note_missing(self, path: str, ts: int, limit: int) -> bool:
        digest = hash(path) & 0xFFFFFFFF
        fresh = digest not in self.missing_paths
        self.missing_paths[digest] = ts
        self.missing_paths.move_to_end(digest)
        while len(self.missing_paths) > limit:
            self.missing_paths.popitem(last=False)
        return fresh

    def recent_categories(self, since: int) -> List[str]:
        return [
            name for name, ts in self.categories.items() if ts >= since
        ]

    def distinct_missing(self, since: int) -> int:
        return sum(1 for ts in self.missing_paths.values() if ts >= since)


class IpMemory:
    """LRU over addresses, with a hard ceiling on both dimensions."""

    def __init__(self, max_ips: int, max_paths: int) -> None:
        self.max_ips = max_ips
        self.max_paths = max_paths
        self._entries: "OrderedDict[str, IpActivity]" = OrderedDict()
        self._lock = threading.Lock()
        self.evictions = 0

    def touch(self, ip: str, ts: int) -> IpActivity:
        with self._lock:
            activity = self._entries.get(ip)
            if activity is None:
                activity = IpActivity(first_seen=ts)
                self._entries[ip] = activity
            activity.last_seen = ts
            self._entries.move_to_end(ip)
            while len(self._entries) > self.max_ips:
                self._entries.popitem(last=False)
                self.evictions += 1
            return activity

    def get(self, ip: str) -> Optional[IpActivity]:
        with self._lock:
            return self._entries.get(ip)

    def prune(self, older_than: int) -> int:
        with self._lock:
            stale = [
                ip
                for ip, activity in self._entries.items()
                if activity.last_seen < older_than
            ]
            for ip in stale:
                self._entries.pop(ip, None)
        return len(stale)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


# ---------------------------------------------------------------------------
# Log cursor
# ---------------------------------------------------------------------------


class LogCursor:
    """Incremental reader for a file that rsyslog rotates underneath us.

    Position is (inode, offset): when the inode changes the file was rotated
    and reading restarts at the beginning of the new one; when the file shrinks
    it was truncated in place. Neither case may replay old history, because
    re-importing yesterday's scan would invent events that already happened.
    """

    def __init__(self, path: str, state: Dict[str, Any]) -> None:
        self.path = path
        self.inode = _safe_int(state.get("inode"))
        self.offset = _safe_int(state.get("offset"))
        self.rotations = _safe_int(state.get("rotations"))
        self.lag_bytes = 0
        self.last_error: Optional[str] = None

    def state(self) -> Dict[str, Any]:
        return {
            "inode": self.inode,
            "offset": self.offset,
            "rotations": self.rotations,
        }

    def read(self, max_bytes: int) -> List[str]:
        """Return complete lines, leaving a partial trailing line for later."""

        try:
            stat = os.stat(self.path)
        except OSError as exc:
            self.last_error = str(exc)
            return []
        self.last_error = None

        inode = int(stat.st_ino)
        size = int(stat.st_size)

        if self.inode == 0:
            # First ever start: begin at the end. Importing the existing file
            # would score traffic from before the daemon existed.
            self.inode, self.offset = inode, size
            return []
        if inode != self.inode:
            self.inode, self.offset = inode, 0
            self.rotations += 1
            LOG.info("Log rotated; following the new file from the start")
        elif size < self.offset:
            self.offset = 0
            self.rotations += 1
            LOG.info("Log truncated in place; restarting from the beginning")

        if size <= self.offset:
            self.lag_bytes = 0
            return []

        self.lag_bytes = max(0, size - self.offset - max_bytes)
        lines: List[str] = []
        try:
            with open(self.path, "rb") as handle:
                handle.seek(self.offset)
                data = handle.read(max_bytes)
        except OSError as exc:
            self.last_error = str(exc)
            return []

        consumed = data.rfind(b"\n") + 1
        if consumed <= 0:
            # No complete line yet; wait rather than splitting a record.
            return []
        self.offset += consumed
        for raw in data[:consumed].splitlines():
            if len(raw) > MAX_LOG_LINE_BYTES:
                raw = raw[:MAX_LOG_LINE_BYTES]
            lines.append(raw.decode("utf-8", "replace"))
        return lines


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

_SCHEMA_STATEMENTS: Tuple[str, ...] = (
    "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)",
    """
    CREATE TABLE IF NOT EXISTS ip_state (
        ip               TEXT PRIMARY KEY,
        family           INTEGER NOT NULL,
        enforceable      INTEGER NOT NULL,
        first_seen       INTEGER NOT NULL,
        last_seen        INTEGER NOT NULL,
        excluded         INTEGER NOT NULL DEFAULT 0,
        exclusion_reason TEXT    NOT NULL DEFAULT '',
        banned_until     INTEGER NOT NULL DEFAULT 0,
        ban_code         INTEGER NOT NULL DEFAULT 0,
        authenticated_at INTEGER NOT NULL DEFAULT 0
    ) WITHOUT ROWID
    """,
    # Deliberately weight-free: the score is derived when it is requested, so
    # retuning weights re-scores the whole history instead of starting over.
    # `handled` records that HAProxy already refused the request this event
    # describes -- a GeoIP 451, for instance. It is a fact about what happened,
    # not a weight, so it belongs beside the event rather than in the scoring
    # configuration; the score simply declines to count it.
    """
    CREATE TABLE IF NOT EXISTS security_events (
        id         INTEGER PRIMARY KEY,
        ts         INTEGER NOT NULL,
        ip         TEXT    NOT NULL,
        event_type TEXT    NOT NULL,
        source     TEXT    NOT NULL,
        site       TEXT    NOT NULL DEFAULT '',
        category   TEXT    NOT NULL DEFAULT '',
        detail     TEXT    NOT NULL DEFAULT '',
        handled    INTEGER NOT NULL DEFAULT 0
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_events_ip_ts ON security_events (ip, ts)",
    "CREATE INDEX IF NOT EXISTS idx_events_ts ON security_events (ts)",
    """
    CREATE TABLE IF NOT EXISTS event_cooldowns (
        fingerprint TEXT PRIMARY KEY,
        last_ts     INTEGER NOT NULL
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE IF NOT EXISTS guard_state (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
)

def _add_column_if_missing(
    cursor: sqlite3.Cursor, table: str, column: str, definition: str
) -> None:
    """Add a column unless it is already there.

    The schema statements above create tables in their newest shape, so a
    database can legitimately already have a column that a migration step also
    wants to add. Checking first keeps the ladder safe to re-run instead of
    failing the daemon at startup.
    """

    existing = {row[1] for row in cursor.execute(f"PRAGMA table_info({table})")}
    if column in existing:
        return
    cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


_MIGRATIONS: Dict[int, Callable[[sqlite3.Cursor], None]] = {
    # v1 stored events without knowing whether HAProxy had already refused the
    # request. Existing rows default to "not handled", which is the safe
    # reading: they keep counting exactly as they did before.
    2: lambda cursor: _add_column_if_missing(
        cursor, "security_events", "handled", "INTEGER NOT NULL DEFAULT 0"
    ),
    # The strongest false-positive signal there is: an address the engine
    # scored that later completed Authelia authentication.
    3: lambda cursor: _add_column_if_missing(
        cursor, "ip_state", "authenticated_at", "INTEGER NOT NULL DEFAULT 0"
    ),
}


class SecurityDatabase:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fresh = not self.path.exists()
        self._conn = sqlite3.connect(
            str(self.path), timeout=10, check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        cursor = self._conn.cursor()
        if fresh:
            cursor.execute("PRAGMA auto_vacuum=INCREMENTAL")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()
        self._migrate()

    def _migrate(self) -> None:
        with self._lock, self._conn:
            cursor = self._conn.cursor()
            for statement in _SCHEMA_STATEMENTS:
                cursor.execute(statement)
            row = cursor.execute("SELECT version FROM schema_version").fetchone()
            if row is None:
                cursor.execute(
                    "INSERT INTO schema_version (version) VALUES (?)",
                    (SCHEMA_VERSION,),
                )
                cursor.close()
                return
            current = int(row["version"])
            if current > SCHEMA_VERSION:
                raise RuntimeError(
                    f"security database schema v{current} is newer than the "
                    f"supported v{SCHEMA_VERSION}"
                )
            while current < SCHEMA_VERSION:
                step = _MIGRATIONS.get(current + 1)
                if step is not None:
                    step(cursor)
                current += 1
                LOG.info("Migrated security database to schema v%d", current)
            cursor.execute("UPDATE schema_version SET version = ?", (current,))
            cursor.close()

    def close(self) -> None:
        with self._lock:
            with contextlib.suppress(sqlite3.Error):
                self._conn.close()

    def get_state(self, key: str, default: str = "") -> str:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM guard_state WHERE key = ?", (key,)
            ).fetchone()
        return str(row["value"]) if row else default

    def set_state(self, key: str, value: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO guard_state (key, value) VALUES (?, ?) "
                "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def observe_ip(
        self, ip: str, ts: int, verdict: Verdict
    ) -> None:
        try:
            family = ipaddress.ip_address(ip).version
        except ValueError:
            return
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO ip_state "
                "(ip, family, enforceable, first_seen, last_seen, excluded, "
                " exclusion_reason) VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (ip) DO UPDATE SET last_seen = excluded.last_seen, "
                "excluded = excluded.excluded, "
                "exclusion_reason = excluded.exclusion_reason",
                (
                    ip,
                    family,
                    1 if enforceable(ip) else 0,
                    ts,
                    ts,
                    1 if verdict.excluded else 0,
                    verdict.reason,
                ),
            )

    def record_events(self, events: Iterable[Dict[str, Any]]) -> int:
        payload = [
            (
                int(event["ts"]),
                str(event["ip"]),
                str(event["event_type"]),
                str(event["source"]),
                str(event.get("site", "")),
                str(event.get("category", "")),
                str(event.get("detail", ""))[:MAX_PATH_LENGTH],
                1 if event.get("handled") else 0,
            )
            for event in events
        ]
        if not payload:
            return 0
        with self._lock, self._conn:
            self._conn.executemany(
                "INSERT INTO security_events "
                "(ts, ip, event_type, source, site, category, detail, handled) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                payload,
            )
        return len(payload)

    def record_authenticated(self, ips: Iterable[str], ts: int) -> int:
        """Remember that these addresses hold an Authelia authorization.

        Only addresses the engine has already scored are updated: the point is
        to mark findings that turned out to belong to a real user, not to build
        a second directory of everyone who logged in.
        """

        payload = [(ts, ip) for ip in ips]
        if not payload:
            return 0
        with self._lock, self._conn:
            cursor = self._conn.cursor()
            cursor.executemany(
                "UPDATE ip_state SET authenticated_at = ? WHERE ip = ?", payload
            )
            updated = cursor.rowcount or 0
            cursor.close()
        return updated

    def set_ban(self, ip: str, until: int, code: int, now: int) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE ip_state SET banned_until = ?, ban_code = ?, last_seen = ? "
                "WHERE ip = ?",
                (until, code, now, ip),
            )

    def clear_ban(self, ip: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE ip_state SET banned_until = 0, ban_code = 0 WHERE ip = ?",
                (ip,),
            )

    def scheduled_bans(self) -> Dict[str, int]:
        """Addresses this daemon believes it has banned, and until when."""

        with self._lock:
            rows = self._conn.execute(
                "SELECT ip, banned_until FROM ip_state WHERE banned_until > 0"
            ).fetchall()
        return {str(row["ip"]): int(row["banned_until"]) for row in rows}

    def last_ban_ts(self, ip: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT MAX(ts) AS value FROM security_events "
                "WHERE ip = ? AND event_type = ?",
                (ip, EVENT_BAN_APPLIED),
            ).fetchone()
        return int(row["value"] or 0) if row else 0

    def newest_finding_ts(self, ip: str) -> int:
        """Timestamp of the most recent event that carries weight."""

        with self._lock:
            row = self._conn.execute(
                "SELECT MAX(ts) AS value FROM security_events "
                "WHERE ip = ? AND event_type NOT IN (?, ?)",
                (ip, EVENT_BAN_APPLIED, EVENT_BAN_LIFTED),
            ).fetchone()
        return int(row["value"] or 0) if row else 0

    def ban_timestamps(self, ip: str, limit: int = 100) -> List[int]:
        """When this address was banned, oldest first.

        Capped: an address with more links than the ladder has rungs is
        already at the top of it, so older ones cannot change the answer.
        """

        with self._lock:
            rows = self._conn.execute(
                "SELECT ts FROM security_events "
                "WHERE ip = ? AND event_type = ? ORDER BY ts DESC LIMIT ?",
                (ip, EVENT_BAN_APPLIED, int(limit)),
            ).fetchall()
        return sorted(int(row["ts"]) for row in rows)

    def strike_count(self, ip: str, since: int) -> int:
        """How many times this address has been banned recently."""

        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS value FROM security_events "
                "WHERE ip = ? AND event_type = ? AND ts >= ?",
                (ip, EVENT_BAN_APPLIED, since),
            ).fetchone()
        return int(row["value"]) if row else 0

    def ip_facts(self, ip: str) -> Dict[str, Any]:
        with self._lock:
            row = self._conn.execute(
                "SELECT first_seen, last_seen, excluded, exclusion_reason, "
                "authenticated_at FROM ip_state WHERE ip = ?",
                (ip,),
            ).fetchone()
        return dict(row) if row else {}

    def events_for(
        self, ip: str, since: int, limit: int = 500
    ) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts, event_type, source, site, category, detail, handled "
                "FROM security_events WHERE ip = ? AND ts >= ? "
                "ORDER BY ts DESC, id DESC LIMIT ?",
                (ip, since, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def active_addresses(self, since: int, limit: int = 500) -> List[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT ip, COUNT(*) AS hits FROM security_events "
                "WHERE ts >= ? GROUP BY ip ORDER BY hits DESC LIMIT ?",
                (since, limit),
            ).fetchall()
        return [str(row["ip"]) for row in rows]

    def cooldown_passed(self, fingerprint: str, ts: int, window: int) -> bool:
        """True when this fingerprint may produce an event again."""

        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT last_ts FROM event_cooldowns WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            if row is not None and ts - int(row["last_ts"]) < window:
                return False
            self._conn.execute(
                "INSERT INTO event_cooldowns (fingerprint, last_ts) VALUES (?, ?) "
                "ON CONFLICT (fingerprint) DO UPDATE SET last_ts = excluded.last_ts",
                (fingerprint, ts),
            )
        return True

    def apply_retention(
        self, *, events_before: int, bans_before: Optional[int] = None
    ) -> Dict[str, int]:
        """Sweep old rows.

        Ban records are kept longer than everything else, and deliberately:
        they are what the escalating ladder is counted from. Sweeping them on
        the ordinary schedule would have quietly capped the ladder at
        whatever fits inside the retention period -- the top rungs would have
        existed in the settings and been unreachable in practice.
        """

        if bans_before is None:
            bans_before = events_before
        with self._lock, self._conn:
            cursor = self._conn.cursor()
            cursor.execute(
                "DELETE FROM security_events WHERE ts < ? "
                "AND event_type NOT IN (?, ?)",
                (events_before, EVENT_BAN_APPLIED, EVENT_BAN_LIFTED),
            )
            events = cursor.rowcount or 0
            cursor.execute(
                "DELETE FROM security_events WHERE ts < ? AND event_type IN (?, ?)",
                (bans_before, EVENT_BAN_APPLIED, EVENT_BAN_LIFTED),
            )
            events += cursor.rowcount or 0
            cursor.execute(
                "DELETE FROM event_cooldowns WHERE last_ts < ?", (events_before,)
            )
            cooldowns = cursor.rowcount or 0
            cursor.execute(
                "DELETE FROM ip_state WHERE last_seen < ? AND banned_until = 0",
                (events_before,),
            )
            addresses = cursor.rowcount or 0
            cursor.close()
        return {
            "events": events,
            "cooldowns": cooldowns,
            "addresses": addresses,
        }

    def incremental_vacuum(self, pages: int = 256) -> None:
        with self._lock, self._conn:
            with contextlib.suppress(sqlite3.Error):
                self._conn.execute(f"PRAGMA incremental_vacuum({int(pages)})")

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            cursor = self._conn.cursor()
            version = cursor.execute(
                "SELECT version FROM schema_version"
            ).fetchone()
            events = cursor.execute(
                "SELECT COUNT(*) AS value, MIN(ts) AS oldest, MAX(ts) AS newest "
                "FROM security_events"
            ).fetchone()
            addresses = cursor.execute(
                "SELECT COUNT(*) AS value, "
                "SUM(CASE WHEN excluded = 1 THEN 1 ELSE 0 END) AS excluded, "
                "SUM(CASE WHEN enforceable = 0 THEN 1 ELSE 0 END) AS unenforceable "
                "FROM ip_state"
            ).fetchone()
            by_type = cursor.execute(
                "SELECT event_type, COUNT(*) AS value FROM security_events "
                "GROUP BY event_type ORDER BY value DESC LIMIT 20"
            ).fetchall()
            cursor.close()
        return {
            "schema_version": int(version["version"]) if version else 0,
            "events": {
                "rows": int(events["value"]),
                "oldest_ts": events["oldest"],
                "newest_ts": events["newest"],
                "by_type": {
                    str(row["event_type"]): int(row["value"]) for row in by_type
                },
            },
            "addresses": {
                "rows": int(addresses["value"] or 0),
                "excluded": int(addresses["excluded"] or 0),
                "unenforceable": int(addresses["unenforceable"] or 0),
            },
        }

    def storage(self) -> Dict[str, Any]:
        def size(path: Path) -> int:
            try:
                return path.stat().st_size
            except OSError:
                return 0

        database = size(self.path)
        wal = size(self.path.with_name(self.path.name + "-wal"))
        shm = size(self.path.with_name(self.path.name + "-shm"))
        return {
            "database_bytes": database,
            "wal_bytes": wal,
            "shm_bytes": shm,
            "total_bytes": database + wal + shm,
        }


# ---------------------------------------------------------------------------
# Request log
# ---------------------------------------------------------------------------

REQUEST_LOG_PATH = os.environ.get(
    "GUARDD_REQUEST_LOG", "/var/lib/easy-ha-proxy/requests/requests.db"
)

_REQUEST_SCHEMA: Tuple[str, ...] = (
    "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)",
    """
    CREATE TABLE IF NOT EXISTS requests (
        id          INTEGER PRIMARY KEY,
        ts          INTEGER NOT NULL,
        request_id  TEXT    NOT NULL DEFAULT '',
        client      TEXT    NOT NULL DEFAULT '',
        status      INTEGER NOT NULL DEFAULT 0,
        frontend    TEXT    NOT NULL DEFAULT '',
        backend     TEXT    NOT NULL DEFAULT '',
        server      TEXT    NOT NULL DEFAULT '',
        method      TEXT    NOT NULL DEFAULT '',
        host        TEXT    NOT NULL DEFAULT '',
        path        TEXT    NOT NULL DEFAULT '',
        bytes_out   INTEGER NOT NULL DEFAULT 0,
        duration_ms INTEGER NOT NULL DEFAULT 0,
        bad_request INTEGER NOT NULL DEFAULT 0
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_requests_ts ON requests(ts)",
    "CREATE INDEX IF NOT EXISTS ix_requests_rid ON requests(request_id)",
    "CREATE INDEX IF NOT EXISTS ix_requests_client ON requests(client, ts)",
    "CREATE INDEX IF NOT EXISTS ix_requests_status ON requests(status, ts)",
)

# LIKE needs an escape character so a path containing % or _ is matched
# literally rather than as a wildcard.
_LIKE_ESCAPE = "\\"


class RequestLog:
    """A bounded, searchable window over recent requests.

    Deliberately not a log pipeline. A day of traffic on a small production
    gateway is ~310k records, so the size cap -- not the retention window --
    is what actually holds, and it is enforced by dropping the oldest rows.

    What is stored is what the access log already contains after the engine's
    own normalization: no query string, no headers, no bodies. The query is
    dropped by normalize_path before it ever reaches here, which is why there
    is no list of sensitive parameters to keep up to date.
    """

    def __init__(self, path: str, config: GuardConfig) -> None:
        self.path = Path(path)
        self.config = config
        self._lock = threading.Lock()
        self._pending: List[Tuple[Any, ...]] = []
        self._paused = False
        self._pause_reason = ""
        self._last_maintenance = 0
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fresh = not self.path.exists()
        self._conn = sqlite3.connect(
            str(self.path), timeout=10, check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        cursor = self._conn.cursor()
        if fresh:
            cursor.execute("PRAGMA auto_vacuum=INCREMENTAL")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        for statement in _REQUEST_SCHEMA:
            cursor.execute(statement)
        if cursor.execute("SELECT version FROM schema_version").fetchone() is None:
            cursor.execute("INSERT INTO schema_version (version) VALUES (1)")
        self._conn.commit()
        cursor.close()

    def close(self) -> None:
        with self._lock, contextlib.suppress(Exception):
            self._conn.close()

    # -- ingest ---------------------------------------------------------
    def add(self, record: ParsedRequest) -> None:
        """Queue one record. Writing happens once per cycle, not per line."""
        backend, _, server = (record.backend or "").partition("/")
        self._pending.append(
            (
                record.ts or _utc_now(),
                record.request_id[:64],
                record.client_ip[:45],
                record.status,
                record.frontend[:64],
                backend[:64],
                "" if server in ("", "<NOSRV>") else server[:64],
                record.method[:10],
                record.host[:MAX_HOST_LENGTH],
                record.path[:MAX_PATH_LENGTH],
                record.bytes_out,
                record.duration_ms,
                1 if record.bad_request else 0,
            )
        )

    def flush(self, now: Optional[int] = None) -> int:
        """Write the queued records, then keep the store inside its budget."""
        now = now if now is not None else _utc_now()
        with self._lock:
            pending, self._pending = self._pending, []
            written = 0
            if pending and not self._paused:
                try:
                    with self._conn:
                        self._conn.executemany(
                            "INSERT INTO requests (ts, request_id, client, status,"
                            " frontend, backend, server, method, host, path,"
                            " bytes_out, duration_ms, bad_request) VALUES"
                            " (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            pending,
                        )
                    written = len(pending)
                except sqlite3.Error as exc:
                    LOG.warning("request log write failed: %s", exc)
            if now - self._last_maintenance >= 60:
                self._last_maintenance = now
                self._maintain(now)
            return written

    # -- budget ---------------------------------------------------------
    def _size(self) -> int:
        total = 0
        for suffix in ("", "-wal", "-shm"):
            with contextlib.suppress(OSError):
                total += (self.path.parent / (self.path.name + suffix)).stat().st_size
        return total

    def _free_bytes(self) -> int:
        with contextlib.suppress(OSError, AttributeError):
            usage = os.statvfs(self.path.parent)
            return usage.f_bavail * usage.f_frsize
        return 0

    def _maintain(self, now: int) -> None:
        """Retention first, then the cap, then the filesystem reserve.

        The order matters. Dropping expired rows is free storage, so it runs
        before anything more aggressive. The reserve has the last word:
        diagnostics must never be the reason the gateway runs out of disk,
        which is the same rule the metrics collector follows.
        """
        cutoff = now - self.config.request_log_retention_days * 86400
        with contextlib.suppress(sqlite3.Error):
            with self._conn:
                self._conn.execute("DELETE FROM requests WHERE ts < ?", (cutoff,))

        for _ in range(8):
            if self._size() <= self.config.request_log_max_bytes:
                break
            with contextlib.suppress(sqlite3.Error):
                with self._conn:
                    # A tenth at a time: enough to converge quickly, small
                    # enough that one pass cannot stall the poll cycle.
                    self._conn.execute(
                        "DELETE FROM requests WHERE id IN ("
                        "SELECT id FROM requests ORDER BY id LIMIT"
                        " (SELECT MAX(1, COUNT(*) / 10) FROM requests))"
                    )
                    self._conn.execute("PRAGMA incremental_vacuum")

        free = self._free_bytes()
        reserve = self.config.request_log_reserved_free_bytes
        if free and free < reserve:
            if not self._paused:
                self._paused = True
                self._pause_reason = "the filesystem is below its free-space reserve"
                LOG.warning(
                    "Request log paused: %s. HAProxy traffic is not affected.",
                    self._pause_reason,
                )
        elif self._paused and free > reserve * 1.2:
            self._paused = False
            self._pause_reason = ""
            LOG.info("Request log resumed: free space recovered")

    # -- read -----------------------------------------------------------
    def search(
        self,
        *,
        since: int = 0,
        until: int = 0,
        client: str = "",
        status: str = "",
        host: str = "",
        backend: str = "",
        request_id: str = "",
        method: str = "",
        path: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        clauses: List[str] = []
        parameters: List[Any] = []
        if since:
            clauses.append("ts >= ?")
            parameters.append(int(since))
        if until:
            clauses.append("ts <= ?")
            parameters.append(int(until))
        for column, value in (
            ("client", client),
            ("host", host),
            ("backend", backend),
            ("request_id", request_id),
            ("method", method),
        ):
            if value:
                clauses.append(column + " = ?")
                parameters.append(str(value)[:200])
        if path:
            # A prefix match, so /api finds everything under it. Anchored on
            # purpose: a leading wildcard would scan the whole table.
            escaped = str(path)[:MAX_PATH_LENGTH]
            for character in (_LIKE_ESCAPE, "%", "_"):
                escaped = escaped.replace(character, _LIKE_ESCAPE + character)
            clauses.append("path LIKE ? ESCAPE ?")
            parameters.extend([escaped + "%", _LIKE_ESCAPE])
        if status:
            text = str(status).strip()
            if len(text) == 3 and text.endswith("xx") and text[0].isdigit():
                low = int(text[0]) * 100
                clauses.append("status >= ? AND status < ?")
                parameters.extend([low, low + 100])
            elif text.isdigit():
                clauses.append("status = ?")
                parameters.append(int(text))
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        limit = _clamp_int(limit, default=100, min_v=1, max_v=500)
        offset = _clamp_int(offset, default=0, min_v=0, max_v=100000)
        with self._lock:
            total = int(
                self._conn.execute(
                    "SELECT COUNT(*) FROM requests" + where, parameters
                ).fetchone()[0]
            )
            rows = self._conn.execute(
                "SELECT * FROM requests" + where
                + " ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?",
                parameters + [limit, offset],
            ).fetchall()
        return {"total": total, "requests": [dict(row) for row in rows]}

    def status(self) -> Dict[str, Any]:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS rowcount, MIN(ts) AS oldest, MAX(ts) AS newest"
                " FROM requests"
            ).fetchone()
        return {
            "enabled": True,
            "configured": self.config.request_log_enabled,
            "rows": int(row["rowcount"] or 0),
            "oldest_ts": int(row["oldest"] or 0),
            "newest_ts": int(row["newest"] or 0),
            "database_bytes": self._size(),
            "max_bytes": self.config.request_log_max_bytes,
            "retention_days": self.config.request_log_retention_days,
            "free_bytes": self._free_bytes(),
            "paused": self._paused,
            "pause_reason": self._pause_reason,
        }


# ---------------------------------------------------------------------------
# Enforcement primitives (unused while mode is monitor)
# ---------------------------------------------------------------------------


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
        runtime_command(
            self.config.haproxy_socket,
            f"set table tbl_ban key {ip} data.gpc0 1 data.gpt0 {int(code)}",
        )
        self.applied += 1
        return True

    def adaptive_bans(self) -> Dict[str, Dict[str, str]]:
        """Only the entries this daemon owns, identified by their reason code."""

        rows = parse_table(
            runtime_command(self.config.haproxy_socket, "show table tbl_ban")
        )
        return {
            ip: fields
            for ip, fields in rows.items()
            if _safe_int(fields.get("gpt0")) == ADAPTIVE_BAN_CODE
            and _safe_int(fields.get("gpc0")) > 0
        }

    def lift(self, ip: str) -> bool:
        """Clear an adaptive ban, and only an adaptive one.

        `clear table` would happily remove a ban HAProxy placed itself under
        its own rules, so the entry is re-read and its reason code checked
        before anything is removed.
        """

        rows = parse_table(
            runtime_command(
                self.config.haproxy_socket, f"show table tbl_ban key {ip}"
            )
        )
        fields = rows.get(ip)
        if fields is None:
            return False
        if _safe_int(fields.get("gpt0")) != ADAPTIVE_BAN_CODE:
            LOG.info(
                "Leaving the ban on %s alone: reason code %s is not ours",
                ip,
                fields.get("gpt0"),
            )
            return False
        runtime_command(
            self.config.haproxy_socket, f"clear table tbl_ban key {ip}"
        )
        self.lifted += 1
        return True


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class GuardEngine:
    """Collects from both sources; contains no detection rules yet."""

    def __init__(
        self,
        config: GuardConfig,
        database: SecurityDatabase,
        exclusions: Optional[ExclusionModel] = None,
        alerts: Optional[Any] = None,
        requests: Optional["RequestLog"] = None,
    ) -> None:
        self.config = config
        self.database = database
        self.exclusions = exclusions or ExclusionModel(config)
        self.requests = requests
        # A ban used to be a journal line only. Whether it is worth an email is
        # the alert engine's decision, not this daemon's; here it is only
        # reported.
        self.alerts = alerts
        # The rendered config supplies the default; an operator's choice in the
        # interface overrides it and survives a restart.
        override = database.get_state("mode_override", "")
        self.enforcer = Enforcer(
            config, override if override in SUPPORTED_MODES else config.mode
        )
        self.ban_durations = load_ban_durations(database)
        self.policy = ScoringPolicy()
        self.memory = IpMemory(config.max_tracked_ips, config.max_paths_per_ip)
        cursor_state: Dict[str, Any] = {}
        with contextlib.suppress(ValueError):
            cursor_state = json.loads(
                self.database.get_state("log_cursor", "{}")
            )
        self.cursor = LogCursor(config.log_file, cursor_state)

        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._known_bans: Set[str] = set()

        self.last_poll_ts: Optional[int] = None
        self.last_error: Optional[str] = None
        self.consecutive_failures = 0
        self.polls_total = 0
        self.lines_read = 0
        self.lines_parsed = 0
        self.events_recorded = 0
        self.excluded_observations = 0

    # -- lifecycle --------------------------------------------------------

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, name="guardd-collector", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=10)

    def _run(self) -> None:
        interval = self.config.poll_interval_seconds
        next_maintenance = (
            time.monotonic() + self.config.maintenance_interval_seconds
        )
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                self.poll()
            except Exception as exc:  # pylint: disable=broad-except
                self.consecutive_failures += 1
                self.last_error = str(exc)
                if self.consecutive_failures in (1, 10) or (
                    self.consecutive_failures % 60 == 0
                ):
                    LOG.warning(
                        "Poll failed (%d in a row): %s",
                        self.consecutive_failures,
                        exc,
                    )
            if time.monotonic() >= next_maintenance:
                try:
                    self.run_maintenance()
                except Exception:  # pylint: disable=broad-except
                    LOG.exception("Maintenance pass failed")
                next_maintenance = (
                    time.monotonic() + self.config.maintenance_interval_seconds
                )
            elapsed = time.monotonic() - started
            self._stop.wait(max(0.5, interval - elapsed))

    # -- collection -------------------------------------------------------

    def poll(self) -> Dict[str, int]:
        now = _utc_now()
        self.exclusions.reload_files()
        tables = self.read_tables()
        from_tables = self.ingest_tables(tables, now)
        from_log = self.ingest_log(now)

        # Runs in every mode: expiry and the kill switch have to keep working
        # after enforcement is turned off.
        enforcement = self.apply_enforcement(now)

        self.polls_total += 1
        self.last_poll_ts = now
        self.consecutive_failures = 0
        self.last_error = None
        self.database.set_state("log_cursor", json.dumps(self.cursor.state()))
        return {
            "table_events": from_tables,
            "log_lines": from_log,
            "banned": len(enforcement["applied"]),
            "lifted": len(enforcement["lifted"]),
        }

    def read_tables(self) -> Dict[str, Dict[str, Dict[str, str]]]:
        socket_path = self.config.haproxy_socket
        available = list_tables(runtime_command(socket_path, "show table"))
        # The per-site rate and error tables are generated, so they are matched
        # by prefix rather than listed; tbl_nosni_tcp carries the direct-IP
        # probing signal that never reaches the HTTP log at all.
        wanted = [
            name
            for name in available
            if name in ("tbl_ban", "tbl_ip_auth", "tbl_err_other", "tbl_nosni_tcp")
            or name.startswith(("tbl_err_", "tbl_rate_"))
        ]
        result: Dict[str, Dict[str, Dict[str, str]]] = {}
        for name in wanted:
            result[name] = parse_table(
                runtime_command(socket_path, f"show table {name}")
            )
        return result

    def ingest_tables(
        self, tables: Dict[str, Dict[str, Dict[str, str]]], now: int
    ) -> int:
        auth_rows = tables.get("tbl_ip_auth", {})
        self.exclusions.refresh_authenticated(auth_rows)
        authenticated = [
            ip
            for ip, fields in auth_rows.items()
            if _safe_int(fields.get("gpc0")) > 0
        ]
        if authenticated:
            self.database.record_authenticated(authenticated, now)

        bans = tables.get("tbl_ban", {})
        active = {
            ip for ip, fields in bans.items() if _safe_int(fields.get("gpc0")) > 0
        }
        events: List[Dict[str, Any]] = []
        for ip in sorted(active - self._known_bans):
            # An observation, not a decision: HAProxy banned this address on
            # its own rules and guardd is recording that it happened.
            events.append(
                {
                    "ts": now,
                    "ip": ip,
                    "event_type": "LEGACY_HAPROXY_BAN",
                    "source": "stick-table",
                    "category": "ban",
                    "detail": f"code={_safe_int(bans[ip].get('gpt0'))}",
                }
            )
            self.database.observe_ip(ip, now, self.exclusions.verdict(ip))
        self._known_bans = active
        written = self.database.record_events(events)
        self.events_recorded += written
        return written + self.ingest_rate_tables(tables, now)

    def ingest_rate_tables(
        self, tables: Dict[str, Dict[str, Dict[str, str]]], now: int
    ) -> int:
        """Turn the short-window counters into events, with their site.

        These say how hard an address is pushing right now. On their own they
        duplicate what HAProxy already enforces; their value is combining with
        the slow behavioural signals the log provides.

        A reading only counts when it is over the ceiling the configuration
        sets for that table. It used to count whenever it was non-zero, which
        made "RATE_EXCEEDED" the name for having made one request: on a live
        gateway that was 534 findings across 40 addresses in a day, 497 of
        them at a rate of exactly 1 against limits of 200 and above.
        """

        written = 0
        thresholds = read_thresholds()
        for name, rows in tables.items():
            if name.startswith("tbl_rate_"):
                event_type, field_prefix = EVENT_RATE_EXCEEDED, "http_req_rate"
            elif name.startswith("tbl_err_"):
                event_type, field_prefix = (
                    EVENT_ERROR_RATE_EXCEEDED,
                    "http_err_rate",
                )
            elif name == "tbl_nosni_tcp":
                event_type, field_prefix = EVENT_NOSNI_PROBING, "conn_rate"
            else:
                continue
            site = name.split("_", 2)[-1] if name.count("_") >= 2 else ""
            limit = thresholds.get(name)
            if limit is None:
                # Without the configured ceiling there is no way to tell a
                # busy client from an ordinary one, and guessing produced a
                # finding for every visitor who made a single request.
                LOG.debug("no configured threshold for %s; not scoring it", name)
                continue
            for ip, fields in rows.items():
                value = 0
                for key, raw in fields.items():
                    if key.startswith(field_prefix):
                        value = _safe_int(raw)
                        break
                if value <= limit:
                    continue
                if self.exclusions.verdict(ip).excluded:
                    continue
                if self._emit(
                    ip,
                    event_type,
                    now,
                    source="stick-table",
                    site=site,
                    detail=f"{field_prefix}={value} limit={limit}",
                    fingerprint=f"{ip}|{event_type}|{name}",
                ):
                    written += 1
        return written

    def ingest_log(self, now: int) -> int:
        lines = self.cursor.read(self.config.log_read_bytes_per_cycle)
        if not lines:
            return 0
        self.lines_read += len(lines)
        parsed = 0
        for line in lines:
            request = parse_access_line(line)
            if request is None:
                continue
            parsed += 1
            if self.requests is not None:
                # Diagnostics and scoring are separate concerns that happen to
                # need the same read of the same file. The request log keeps
                # everything, including what the engine excludes: an operator
                # looking for their own failed request must be able to find it.
                self.requests.add(request)
            self.observe_request(request, now)
        self.lines_parsed += parsed
        if self.requests is not None:
            self.requests.flush(now)
        return len(lines)

    def observe_request(self, request: ParsedRequest, now: int) -> None:
        """Fold one request into the address's memory and emit any findings."""

        ip = request.client_ip
        verdict = self.exclusions.verdict(ip)
        if verdict.excluded:
            self.excluded_observations += 1
            return

        activity = self.memory.touch(ip, now)
        activity.requests += 1
        if request.bad_request:
            activity.bad_requests += 1
            self._note_invalid_host(ip, activity, now, request)
            return

        if not request.backend.endswith("/<NOSRV>"):
            # A real server answered, so this address is not walled off.
            activity.reached_backend = True

        handled = refusal_is_a_shield(request, activity)
        if request.status == 404:
            activity.not_found += 1
        elif request.denied_by_gateway:
            # The counter records what the gateway did, not what the engine
            # decided to do about it.
            activity.gateway_denied += 1
        elif request.status >= 400:
            activity.errors += 1

        if request.path:
            activity.note_path(request.path, now, self.config.max_paths_per_ip)
        if request.host and len(activity.hosts) < 16:
            activity.hosts.add(request.host)

        if request.query_flag:
            # Deliberately not gated on is_served. A path the site answers
            # is evidence the path is real; an injection the site answered
            # 200 is evidence it may have worked, which is the opposite of
            # a reason to let the client alone.
            activity.scanner_hits += 1
            if handled:
                activity.scanner_hits_denied += 1
            activity.note_category(request.query_flag, now)
            self._emit(
                ip,
                EVENT_QUERY_INJECTION,
                now,
                source="haproxy-log",
                category=request.query_flag,
                # The path, never the query. The rule name above already
                # says what was in it.
                detail=request.path,
                handled=handled,
                fingerprint=f"{ip}|{EVENT_QUERY_INJECTION}|{request.query_flag}",
            )
            self._check_multi_category(ip, activity, now)

        category = classify_path(request.path)
        if (
            category
            and is_served(request.status)
            and not category_is_decisive(category)
        ):
            # The application answered with content, so this is a path the
            # site actually has. A real WordPress installation would
            # otherwise file every one of its own users as scanning for
            # WordPress.
            #
            # A decisive category is never excused this way. No site serves
            # its own .env, git store or database dump on purpose, so a 200
            # there means one of two things: a catch-all page that answers
            # everything alike -- one gateway returned the same 1477 bytes
            # for /.env, /backup.sql and /phpinfo.php -- or a real leak.
            # Neither is a reason to trust the client asking.
            category = ""
        if category:
            activity.scanner_hits += 1
            if handled:
                activity.scanner_hits_denied += 1
            activity.note_category(category, now)
            event = (
                EVENT_SCANNER_DECISIVE
                if category_is_decisive(category)
                else EVENT_SCANNER_PATH
            )
            self._emit(
                ip,
                event,
                now,
                source="haproxy-log",
                category=category,
                detail=request.path,
                handled=handled,
                fingerprint=f"{ip}|{event}|{category}",
            )
            self._check_multi_category(ip, activity, now)
            self._check_low_and_slow(ip, activity, now)
        elif request.status == 404 and not is_asset(request.path):
            # Enumeration without a known signature: only distinct, non-asset
            # paths count, which is what separates a scanner from a stale link.
            if activity.note_missing(
                request.path, now, self.config.max_paths_per_ip
            ):
                self._check_not_found_enumeration(ip, activity, now)

        if request.status == 400 or request.backend.endswith("/<NOSRV>"):
            self._note_invalid_host(ip, activity, now, request)

    # -- derived detections ----------------------------------------------

    def _emit(
        self,
        ip: str,
        event_type: str,
        now: int,
        *,
        source: str,
        category: str = "",
        site: str = "",
        detail: str = "",
        handled: bool = False,
        fingerprint: Optional[str] = None,
    ) -> bool:
        window = COOLDOWN_SECONDS.get(event_type, 60)
        key = fingerprint or f"{ip}|{event_type}"
        if not self.database.cooldown_passed(key, now, window):
            return False
        self.database.observe_ip(ip, now, self.exclusions.verdict(ip))
        self.database.record_events(
            [
                {
                    "ts": now,
                    "ip": ip,
                    "event_type": event_type,
                    "source": source,
                    "category": category,
                    "site": site,
                    "detail": detail,
                    "handled": handled,
                }
            ]
        )
        self.events_recorded += 1
        return True

    def _check_multi_category(
        self, ip: str, activity: IpActivity, now: int
    ) -> None:
        categories = activity.recent_categories(now - MULTI_CATEGORY_WINDOW)
        if len(categories) < MULTI_CATEGORY_MIN:
            return
        # One host is almost never WordPress and phpMyAdmin and Git at once;
        # several different technologies is a much stronger signal than the
        # same number of hits on one of them.
        self._emit(
            ip,
            EVENT_SCANNER_MULTI,
            now,
            source="haproxy-log",
            detail=f"categories={len(categories)}",
            handled=activity.scanning_was_all_refused,
        )

    def _check_low_and_slow(
        self, ip: str, activity: IpActivity, now: int
    ) -> None:
        since = now - LOW_AND_SLOW_WINDOW
        categories = activity.recent_categories(since)
        if (
            activity.scanner_hits < LOW_AND_SLOW_MIN_HITS
            or len(categories) < LOW_AND_SLOW_MIN_CATEGORIES
        ):
            return
        # Deliberately rate-blind: the slower the scan, the less the existing
        # stick-table limits can see it, and the more this detection matters.
        self._emit(
            ip,
            EVENT_LOW_AND_SLOW,
            now,
            source="haproxy-log",
            detail=f"hits={activity.scanner_hits} categories={len(categories)}",
            handled=activity.scanning_was_all_refused,
        )

    def _check_not_found_enumeration(
        self, ip: str, activity: IpActivity, now: int
    ) -> None:
        distinct = activity.distinct_missing(now - NOT_FOUND_WINDOW)
        if distinct < NOT_FOUND_MIN_DISTINCT:
            return
        self._emit(
            ip,
            EVENT_NOT_FOUND_ENUM,
            now,
            source="haproxy-log",
            detail=f"distinct={distinct}",
        )

    def _note_invalid_host(
        self, ip: str, activity: IpActivity, now: int, request: ParsedRequest
    ) -> None:
        if activity.invalid_host_since < now - INVALID_HOST_WINDOW:
            activity.invalid_host_since = now
            activity.invalid_host_hits = 0
        activity.invalid_host_hits += 1
        if activity.invalid_host_hits < INVALID_HOST_MIN:
            return
        self._emit(
            ip,
            EVENT_INVALID_HOST,
            now,
            source="haproxy-log",
            detail=f"hits={activity.invalid_host_hits}",
            handled=refusal_is_a_shield(request, activity),
        )

    # -- reputation -------------------------------------------------------

    def reputation(
        self,
        ip: str,
        now: Optional[int] = None,
        policy: Optional[ScoringPolicy] = None,
        scheduled: Optional[Dict[str, int]] = None,
    ) -> Dict[str, Any]:
        now = now or _utc_now()
        policy = policy or self.policy
        # Passed in when scoring a whole table, so one query answers for every
        # address instead of one per row.
        if scheduled is None:
            scheduled = self.database.scheduled_bans()
        events = self.database.events_for(ip, now - policy.window_seconds)
        result = score_events(events, now, policy)
        result["ip"] = ip
        result["enforceable"] = enforceable(ip)
        verdict = self.exclusions.verdict(ip)
        result["excluded"] = verdict.excluded
        result["exclusion_reason"] = verdict.reason

        facts = self.database.ip_facts(ip)
        authenticated_at = int(facts.get("authenticated_at") or 0)
        result["authenticated_at"] = authenticated_at
        result["first_seen"] = int(facts.get("first_seen") or 0)
        result["last_seen"] = int(facts.get("last_seen") or 0)
        result["event_count"] = len(events)

        if verdict.excluded:
            # An exempt address is reported with its evidence intact but no
            # standing: HAProxy would not act on it either.
            result["score"] = 0
            result["state"] = "NORMAL"
            result["recommended_action"] = "none"

        result["blockers"] = self.ban_blockers(result)
        result["would_ban"] = (
            result["score"] >= WOULD_BAN_SCORE and not result["blockers"]
        )
        result["banned_until"] = int(scheduled.get(ip, 0))
        # The review question that matters: did an address the engine wanted to
        # act on turn out to belong to somebody who then logged in?
        result["likely_false_positive"] = bool(
            authenticated_at and result["score"] >= WATCH_SCORE
        )
        return result

    def reputation_table(
        self,
        now: Optional[int] = None,
        limit: int = 200,
        policy: Optional[ScoringPolicy] = None,
    ) -> List[Dict[str, Any]]:
        now = now or _utc_now()
        policy = policy or self.policy
        scheduled = self.database.scheduled_bans()
        rows = [
            self.reputation(ip, now, policy, scheduled)
            for ip in self.database.active_addresses(
                now - policy.window_seconds, limit=limit
            )
        ]
        rows.sort(key=lambda item: item["score"], reverse=True)
        return rows

    # -- enforcement ------------------------------------------------------

    def ban_blockers(self, reputation: Dict[str, Any]) -> List[str]:
        """Why this address must not be banned, whatever its score.

        These are not tunable. The first two exist because banning the person
        administering the gateway is the failure this whole phase has to avoid,
        and the third because a ban simply would not work.
        """

        blockers: List[str] = []
        if reputation.get("excluded"):
            blockers.append(f"exempt ({reputation.get('exclusion_reason')})")
        if reputation.get("authenticated_at"):
            # Ever authenticated, not merely authenticated right now: the
            # runtime authorization expires, and a lapsed session must not turn
            # a real user into a ban candidate.
            blockers.append("has authenticated before")
        if not reputation.get("enforceable"):
            blockers.append("IPv4-only ban path")
        return blockers

    def strike_retention(self, level: int) -> int:
        """How long a strike earned at this level stays on the record."""

        ladder = self.ban_durations
        index = min(max(level - 1, 0), len(ladder) - 1)
        return ladder[index] * (level + STRIKE_RETENTION_BASE_MULTIPLIER)

    def longest_strike_retention(self) -> int:
        """The most any strike could be worth keeping, for the sweeper."""

        return max(
            self.strike_retention(level)
            for level in range(1, len(self.ban_durations) + 1)
        )

    def strike_level(self, ip: str, now: int) -> int:
        """How many bans this address has earned that still count.

        Derived from the ban record rather than stored alongside it, so the
        two cannot drift apart. Each link carries its own window, measured
        from the ban that created it, so a long ban keeps its own evidence
        alive instead of outliving it.

        Any fresh activity restarts the countdown from the beginning: an
        address that is still probing has served nothing out, whatever the
        clock says about its last ban.
        """

        stamps = self.database.ban_timestamps(ip)
        if not stamps:
            return 0

        level = 0
        previous = 0
        for ts in stamps:
            if level and ts - previous > self.strike_retention(level):
                # Long enough went by with nothing: the chain lapsed and this
                # ban starts a new one.
                level = 0
            level += 1
            previous = ts

        alive_from = max(previous, self.database.newest_finding_ts(ip))
        if now - alive_from > self.strike_retention(level):
            return 0
        return level

    def ban_duration(self, ip: str, now: int) -> int:
        ladder = self.ban_durations
        index = min(self.strike_level(ip, now), len(ladder) - 1)
        return ladder[index]

    def set_ban_durations(self, data: Any) -> Tuple[int, ...]:
        """Replace the ladder. Bans already placed keep the term they were
        given -- their expiry was written as an absolute time when the ban was
        applied, so changing the rule does not re-sentence anybody.
        """

        checked = validate_ban_durations(data)
        self.database.set_state(BAN_DURATIONS_KEY, json.dumps(list(checked)))
        self.ban_durations = checked
        LOG.warning(
            "Adaptive ban durations changed to %s",
            ", ".join(str(step) for step in checked),
        )
        return checked

    def apply_enforcement(self, now: Optional[int] = None) -> Dict[str, Any]:
        """Ban what qualifies, lift what has served its time.

        Runs on every cycle regardless of mode, because expiry and the kill
        switch have to work even after enforcement has been turned back off.
        """

        now = now or _utc_now()
        applied: List[str] = []
        lifted: List[str] = []

        scheduled = self.database.scheduled_bans()
        enforcing = self.enforcer.allowed
        for ip, until in scheduled.items():
            # Turning enforcement off undoes what it did; leaving addresses
            # banned by a feature that is no longer on would be a trap.
            if enforcing and until > now:
                continue
            if self.enforcer.lift(ip):
                lifted.append(ip)
                self._emit(
                    ip,
                    EVENT_BAN_LIFTED,
                    now,
                    source="guardd",
                    detail="expired" if enforcing else "enforcement disabled",
                    fingerprint=f"{ip}|{EVENT_BAN_LIFTED}|{until}",
                )
            self.database.clear_ban(ip)

        if not enforcing:
            # A ban this daemon placed can outlive it: the stick table keeps the
            # entry for the table's expiry, so anything left over is swept here.
            for ip in self.enforcer.adaptive_bans():
                if ip in scheduled:
                    continue
                if self.enforcer.lift(ip):
                    lifted.append(ip)
            return {"applied": applied, "lifted": lifted, "enforcing": False}

        # A ban longer than the stick table's own expiry would lapse inside
        # HAProxy while the schedule here still called it banned, and the
        # address would be quietly let back in. The same gap opens whenever
        # HAProxy is restarted or the table is cleared by hand. Re-asserting
        # the entries the schedule still wants closes all three: `set table`
        # rewrites the entry and restarts its expiry, so the schedule is the
        # only thing that decides when a ban ends.
        present = set(self.enforcer.adaptive_bans())
        for ip, until in scheduled.items():
            if until <= now or ip in present:
                continue
            if self.enforcer.ban(ip):
                LOG.info("Re-asserted the ban on %s, gone from the table", ip)

        for row in self.reputation_table(now, limit=200):
            ip = row["ip"]
            if row["score"] < WOULD_BAN_SCORE:
                continue
            if scheduled.get(ip, 0) > now:
                continue
            blockers = self.ban_blockers(row)
            if blockers:
                continue
            # Findings decay over hours, so a score that justified one ban is
            # still there when it expires. Requiring fresh evidence keeps the
            # progressive ladder counting repeat incidents rather than simply
            # measuring how long a single scan stays in the window.
            last_ban = self.database.last_ban_ts(ip)
            if last_ban and self.database.newest_finding_ts(ip) <= last_ban:
                continue
            duration = self.ban_duration(ip, now)
            if not self.enforcer.ban(ip):
                continue
            self.database.set_ban(ip, now + duration, ADAPTIVE_BAN_CODE, now)
            applied.append(ip)
            categories = ", ".join(sorted(row.get("categories") or {}))
            self._emit(
                ip,
                EVENT_BAN_APPLIED,
                now,
                source="guardd",
                detail=f"score={row['score']} seconds={duration} [{categories}]",
                fingerprint=f"{ip}|{EVENT_BAN_APPLIED}|{now}",
            )
            LOG.warning(
                "Adaptive ban applied to %s for %ds (score %d)",
                ip,
                duration,
                row["score"],
            )
            self._report_ban(ip, duration, row, categories)
        return {"applied": applied, "lifted": lifted, "enforcing": True}

    def _report_ban(
        self, ip: str, duration: int, row: Dict[str, Any], categories: str
    ) -> None:
        """Tell the alert engine an address was acted upon.

        Best effort by contract: enforcement must not depend on the alert
        daemon being up, so anything that goes wrong here is swallowed.
        """
        if self.alerts is None:
            return
        with contextlib.suppress(Exception):
            self.alerts.observe(
                "security.hostile_ip",
                ip,
                summary=f"Adaptive protection banned {ip} for {duration}s",
                detail=(
                    f"score {row.get('score')} over {categories or 'no category'}; "
                    f"the ban lifts automatically when it expires"
                ),
            )

    def set_mode(self, mode: str, now: Optional[int] = None) -> Dict[str, Any]:
        """Switch between observing and enforcing, and reconcile immediately."""

        mode = str(mode or "").strip().lower()
        if mode not in SUPPORTED_MODES:
            raise ValueError(f"mode must be one of {', '.join(SUPPORTED_MODES)}")
        now = now or _utc_now()
        previous = self.enforcer.mode
        self.database.set_state("mode_override", mode)
        self.enforcer.mode = mode
        LOG.warning("Adaptive protection mode changed: %s -> %s", previous, mode)
        result = self.apply_enforcement(now)
        return {"mode": mode, "previous": previous, **result}

    def shadow_review(
        self,
        now: Optional[int] = None,
        limit: int = 200,
        policy: Optional[ScoringPolicy] = None,
    ) -> Dict[str, Any]:
        """What enforcement would have done, and where it would have been wrong."""

        now = now or _utc_now()
        policy = policy or self.policy
        rows = self.reputation_table(now, limit=limit, policy=policy)
        by_state: Dict[str, int] = {}
        for row in rows:
            by_state[row["state"]] = by_state.get(row["state"], 0) + 1
        return {
            "mode": self.enforcer.mode,
            "configured_mode": self.config.mode,
            "mode_overridden": self.enforcer.mode != self.config.mode,
            "supported_modes": list(SUPPORTED_MODES),
            "enforcement_possible": self.enforcer.allowed,
            "ban_durations_seconds": list(self.ban_durations),
            "policy": {
                "weights": dict(policy.weights),
                "category_cap": policy.category_cap,
                "window_seconds": policy.window_seconds,
                "decay_seconds": policy.decay_seconds,
                # The page said "ban what crosses the threshold" without ever
                # saying what the threshold was, so a score of 43 meant
                # nothing to the person reading it. The bands live here, not
                # in the page, because the daemon is what applies them.
                "bands": [
                    {"from": threshold, "state": name,
                     "bans": threshold >= WOULD_BAN_SCORE}
                    for threshold, name in DEFAULT_THRESHOLDS
                ],
                "would_ban_score": WOULD_BAN_SCORE,
            },
            # The page could show a score of 60 and the word "banned" and
            # never say what the address had actually done to earn it. The
            # rules live in a replaceable file now, so the version matters
            # too: without it nobody can tell which list a gateway is
            # running.
            "signatures": signature_summary(),
            "summary": {
                "scored": len(rows),
                "would_ban": sum(1 for row in rows if row["would_ban"]),
                "likely_false_positive": sum(
                    1 for row in rows if row["likely_false_positive"]
                ),
                "unenforceable": sum(
                    1 for row in rows if not row["enforceable"] and row["score"] > 0
                ),
                "excluded": sum(1 for row in rows if row["excluded"]),
                "banned_now": sum(1 for row in rows if row["banned_until"]),
                "blocked_from_ban": sum(
                    1
                    for row in rows
                    if row["score"] >= WOULD_BAN_SCORE and row["blockers"]
                ),
                "by_state": by_state,
            },
            "addresses": [
                {key: value for key, value in row.items() if key != "contributions"}
                for row in rows
            ],
        }

    # -- maintenance ------------------------------------------------------

    def run_maintenance(self) -> Dict[str, Any]:
        now = _utc_now()
        cutoff = now - self.config.event_retention_days * 86400
        # Ban records outlive ordinary findings by as long as the ladder can
        # still be counting them.
        ban_cutoff = min(cutoff, now - self.longest_strike_retention())
        deleted = self.database.apply_retention(
            events_before=cutoff, bans_before=ban_cutoff
        )
        if any(deleted.values()):
            self.database.incremental_vacuum()
        pruned = self.memory.prune(now - 6 * 3600)
        LOG.info(
            "Maintenance: deleted=%s pruned_ips=%d tracked=%d",
            json.dumps(deleted),
            pruned,
            len(self.memory),
        )
        return {"deleted": deleted, "pruned_ips": pruned}

    # -- reporting --------------------------------------------------------

    def health(self) -> Dict[str, Any]:
        now = _utc_now()
        last_poll = self.last_poll_ts
        stale_after = max(60, self.config.poll_interval_seconds * 6)
        return {
            "mode": self.enforcer.mode,
            "configured_mode": self.config.mode,
            "mode_overridden": self.enforcer.mode != self.config.mode,
            "enforcement_possible": self.enforcer.allowed,
            "enforcement_refusals": self.enforcer.refused,
            "bans_applied": self.enforcer.applied,
            "bans_lifted": self.enforcer.lifted,
            "bans_active": len(self.database.scheduled_bans()),
            "running": bool(self._thread and self._thread.is_alive()),
            "degraded": last_poll is None or (now - last_poll) > stale_after,
            "last_poll_ts": last_poll,
            "polls_total": self.polls_total,
            "consecutive_failures": self.consecutive_failures,
            "last_error": self.last_error,
            "log": {
                "path": self.config.log_file,
                "lines_read": self.lines_read,
                "lines_parsed": self.lines_parsed,
                "lag_bytes": self.cursor.lag_bytes,
                "rotations": self.cursor.rotations,
                "last_error": self.cursor.last_error,
            },
            "memory": {
                "tracked_ips": len(self.memory),
                "max_tracked_ips": self.memory.max_ips,
                "max_paths_per_ip": self.memory.max_paths,
                "evictions": self.memory.evictions,
            },
            "exclusions": {
                "networks": self.exclusions.network_count,
                "authenticated": self.exclusions.authenticated_count,
                "observations_skipped": self.excluded_observations,
            },
            "events_recorded": self.events_recorded,
        }


# ---------------------------------------------------------------------------
# Unix socket API
# ---------------------------------------------------------------------------


class GuardHandler(BaseHTTPRequestHandler):
    server_version = "easy-ha-proxy-guardd/1.0"

    def address_string(self) -> str:  # noqa: N802
        return "unix"

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: N802
        LOG.debug(fmt, *args)

    def _send_json(self, code: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        engine: GuardEngine = self.server.engine  # type: ignore[attr-defined]
        database: SecurityDatabase = self.server.database  # type: ignore[attr-defined]
        path = urlparse(self.path).path

        if path == "/api/v1/guard/health":
            try:
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "ts": _utc_now(),
                        "engine": engine.health(),
                        "database": database.stats(),
                        "storage": database.storage(),
                    },
                )
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/guard/reputation":
            try:
                rows = engine.reputation_table()
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "ts": _utc_now(),
                        "mode": engine.config.mode,
                        "addresses": [
                            {
                                key: value
                                for key, value in row.items()
                                if key != "contributions"
                            }
                            for row in rows
                        ],
                    },
                )
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
            return

        if path in ("/api/v1/guard/requests", "/api/v1/guard/requests/status"):
            requests = getattr(self.server, "requests", None)
            if requests is None:
                self._send_json(
                    404,
                    {"ok": False, "enabled": False, "error": "the request log is off"},
                )
                return
            try:
                if path.endswith("/status"):
                    self._send_json(
                        200, {"ok": True, "ts": _utc_now(), **requests.status()}
                    )
                    return
                query = parse_qs(urlparse(self.path).query or "")

                def one(name: str) -> str:
                    return (query.get(name, [""])[0] or "").strip()

                payload = requests.search(
                    since=_clamp_int(
                        one("since"), default=0, min_v=0, max_v=2_000_000_000
                    ),
                    until=_clamp_int(
                        one("until"), default=0, min_v=0, max_v=2_000_000_000
                    ),
                    client=one("client"),
                    status=one("status"),
                    host=one("host"),
                    backend=one("backend"),
                    request_id=one("request_id"),
                    method=one("method").upper(),
                    path=one("path"),
                    limit=_clamp_int(one("limit"), default=100, min_v=1, max_v=500),
                    offset=_clamp_int(
                        one("offset"), default=0, min_v=0, max_v=100000
                    ),
                )
                self._send_json(200, {"ok": True, "ts": _utc_now(), **payload})
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/guard/signatures":
            self._send_json(200, {"ok": True, **signature_summary()})
            return

        if path == "/api/v1/guard/shadow":
            query = parse_qs(urlparse(self.path).query or "")
            try:
                policy = policy_from_query(query, engine.policy)
                limit = _clamp_int(
                    query.get("limit", [None])[0], default=200, min_v=1, max_v=500
                )
                payload = engine.shadow_review(limit=limit, policy=policy)
                payload["ok"] = True
                payload["ts"] = _utc_now()
                self._send_json(200, payload)
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/guard/ip":
            query = parse_qs(urlparse(self.path).query or "")
            address = (query.get("ip", [""])[0] or "").strip()
            try:
                ipaddress.ip_address(address)
            except ValueError:
                self._send_json(400, {"ok": False, "error": "invalid ip"})
                return
            try:
                now = _utc_now()
                policy = policy_from_query(query, engine.policy)
                payload = engine.reputation(address, now, policy)
                payload["events"] = database.events_for(
                    address, now - policy.window_seconds, limit=200
                )
                payload["ok"] = True
                self._send_json(200, payload)
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
            return

        self._send_json(404, {"ok": False, "error": "not found"})

    def _control_auth_ok(self) -> bool:
        if not CONTROL_TOKEN:
            return False
        supplied = (self.headers.get("X-Guardd-Token", "") or "").strip()
        return hmac.compare_digest(supplied, CONTROL_TOKEN)

    def do_POST(self) -> None:  # noqa: N802
        engine: GuardEngine = self.server.engine  # type: ignore[attr-defined]
        path = urlparse(self.path).path

        if path == "/api/v1/guard/requests/enabled":
            if not self._control_auth_ok():
                self._send_json(403, {"ok": False, "error": "forbidden"})
                return
            try:
                length = int((self.headers.get("Content-Length") or "0").strip() or "0")
                if length <= 0 or length > 4096:
                    raise ValueError("invalid Content-Length")
                payload = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
            except ValueError as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
                return
            try:
                result = _set_request_log(
                    self.server, engine, bool(payload.get("enabled"))
                )
            except Exception as exc:  # pylint: disable=broad-except
                LOG.exception("cannot change the request log")
                self._send_json(500, {"ok": False, "error": str(exc)})
                return
            self._send_json(200, {"ok": True, **result})
            return

        if path == "/api/v1/guard/signatures":
            if not self._control_auth_ok():
                self._send_json(403, {"ok": False, "error": "forbidden"})
                return
            try:
                length = int((self.headers.get("Content-Length") or "0").strip() or "0")
                # Larger than the mode payload: this one carries a rule list.
                if length <= 0 or length > 65536:
                    raise ValueError("invalid Content-Length")
                payload = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
            except ValueError as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
                return
            try:
                store_overrides(engine.database, payload)
            except ValueError as exc:
                # A rejected rule is the operator's typo, not a fault.
                self._send_json(400, {"ok": False, "error": str(exc)})
                return
            except Exception as exc:  # pylint: disable=broad-except
                LOG.exception("cannot store the signature overrides")
                self._send_json(500, {"ok": False, "error": str(exc)})
                return
            self._send_json(200, {"ok": True, **signature_summary()})
            return

        if path == "/api/v1/guard/ban-durations":
            if not self._control_auth_ok():
                self._send_json(403, {"ok": False, "error": "forbidden"})
                return
            try:
                length = int(
                    (self.headers.get("Content-Length") or "0").strip() or "0"
                )
                if length <= 0 or length > 4096:
                    raise ValueError("invalid Content-Length")
                payload = json.loads(
                    self.rfile.read(length).decode("utf-8", "replace")
                )
            except ValueError as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
                return
            try:
                steps = engine.set_ban_durations(payload.get("durations"))
            except ValueError as exc:
                # A rejected ladder is the operator's typo, not a fault.
                self._send_json(400, {"ok": False, "error": str(exc)})
                return
            except Exception as exc:  # pylint: disable=broad-except
                LOG.exception("cannot store the ban durations")
                self._send_json(500, {"ok": False, "error": str(exc)})
                return
            self._send_json(
                200, {"ok": True, "ban_durations_seconds": list(steps)}
            )
            return

        if path != "/api/v1/guard/mode":
            self._send_json(404, {"ok": False, "error": "not found"})
            return
        if not self._control_auth_ok():
            self._send_json(403, {"ok": False, "error": "forbidden"})
            return

        try:
            length = int((self.headers.get("Content-Length") or "0").strip() or "0")
        except ValueError:
            length = 0
        if length <= 0 or length > 4096:
            self._send_json(400, {"ok": False, "error": "invalid Content-Length"})
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
        except ValueError as exc:
            self._send_json(400, {"ok": False, "error": f"bad json: {exc}"})
            return

        try:
            result = engine.set_mode(str(payload.get("mode", "")))
        except ValueError as exc:
            self._send_json(400, {"ok": False, "error": str(exc)})
            return
        except Exception as exc:  # pylint: disable=broad-except
            self._send_json(500, {"ok": False, "error": str(exc)})
            return
        result["ok"] = True
        self._send_json(200, result)


REQUEST_LOG_OVERRIDE_KEY = "request_log_override"


def _request_log_wanted(database: "SecurityDatabase", config: GuardConfig) -> bool:
    """Whether to keep the request store, config plus any operator switch.

    Kept in guardd's own state rather than in guardd.json, exactly like the
    enforcement mode: the file is a template Ansible owns and rewrites, so a
    choice made in the web interface has to live somewhere Ansible does not
    reach.
    """
    override = database.get_state(REQUEST_LOG_OVERRIDE_KEY, "")
    if override in ("on", "off"):
        return override == "on"
    return bool(config.request_log_enabled)


def _set_request_log(server: "GuardServer", engine: "GuardEngine", enabled: bool):
    """Turn the store on or off now, and remember the choice."""
    engine.database.set_state(REQUEST_LOG_OVERRIDE_KEY, "on" if enabled else "off")
    if enabled and server.requests is None:
        store = RequestLog(REQUEST_LOG_PATH, engine.config)
        server.requests = store
        engine.requests = store
        LOG.warning("Request log enabled from the web interface")
    elif not enabled and server.requests is not None:
        store = server.requests
        server.requests = None
        engine.requests = None
        # Anything already queued is written before the handle goes away;
        # dropping it would lose requests the operator can see in the page
        # right now.
        with contextlib.suppress(Exception):
            store.flush()
        with contextlib.suppress(Exception):
            store.close()
        LOG.warning("Request log disabled from the web interface")
    return {
        "enabled": server.requests is not None,
        "configured": bool(engine.config.request_log_enabled),
    }


class GuardServer(ThreadingMixIn, UnixStreamServer):
    daemon_threads = True

    def __init__(
        self,
        socket_path: str,
        handler_cls: type[BaseHTTPRequestHandler],
        engine: GuardEngine,
        database: SecurityDatabase,
    ) -> None:
        super().__init__(socket_path, handler_cls)
        self.engine = engine
        self.database = database
        # Set after construction: the request log is optional and the server
        # answers a "not enabled" 404 for its routes when it is absent.
        self.requests: Optional[RequestLog] = None


def _set_socket_perms(socket_path: str, group_name: str) -> None:
    gid = grp.getgrnam(group_name).gr_gid
    uid = pwd.getpwnam("root").pw_uid
    os.chown(socket_path, uid, gid)
    os.chmod(socket_path, 0o660)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Before anything reads a log line: a signature file that turns out to be
    # unreadable leaves the built-in tables in place and says so.
    load_signatures()

    try:
        config = load_config(CONFIG_PATH)
    except ConfigError as exc:
        LOG.error("%s", exc)
        raise SystemExit(2) from exc

    # The request log rides on the same tail of the same file, so it keeps
    # working with the security engine switched off -- diagnostics should not
    # depend on whether the operator wants scoring.
    # The database first: it holds the operator's switch, and that switch
    # decides whether there is anything to do at all.
    database = SecurityDatabase(DATABASE_PATH)
    # The operator's own rules go on top of the shipped list, which was read
    # above. Order matters: the file first, then what was changed about it.
    apply_overrides(load_overrides(database))
    want_requests = _request_log_wanted(database, config)
    if config.mode == MODE_OFF and not want_requests:
        LOG.info("Adaptive protection is off in %s; idling", CONFIG_PATH)
        stop = threading.Event()
        with contextlib.suppress(KeyboardInterrupt):
            stop.wait()
        return

    requests = RequestLog(REQUEST_LOG_PATH, config) if want_requests else None
    engine = GuardEngine(
        config, database, alerts=_alert_client(), requests=requests
    )

    LOG.info(
        "Starting easy-ha-proxy-guardd: mode=%s socket=%s db=%s log=%s "
        "interval=%ss exclusions=%d networks",
        config.mode,
        SOCKET_PATH,
        DATABASE_PATH,
        config.log_file,
        config.poll_interval_seconds,
        engine.exclusions.network_count,
    )

    engine.start()

    with contextlib.suppress(OSError):
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)

    server = GuardServer(SOCKET_PATH, GuardHandler, engine, database)
    server.requests = requests
    try:
        _set_socket_perms(SOCKET_PATH, SOCKET_GROUP)
    except Exception as exc:  # pylint: disable=broad-except
        LOG.warning("Failed to set socket permissions: %s", exc)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOG.info("Interrupted")
    finally:
        engine.stop()
        with contextlib.suppress(Exception):
            server.server_close()
        if requests is not None:
            requests.close()
        database.close()
        with contextlib.suppress(OSError):
            if os.path.exists(SOCKET_PATH):
                os.unlink(SOCKET_PATH)


if __name__ == "__main__":
    main()
