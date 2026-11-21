"""Constants, scoring defaults, signature loading, and basic helpers for guardd."""

from __future__ import annotations

import calendar
import contextlib
import ipaddress
import itertools
import json
import logging
import os
import re
import threading
import time
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, unquote_plus

if TYPE_CHECKING:
    from .storage import SecurityDatabase

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
# When the ladder was last replaced. Strikes earned before it are not counted
# against the new one: a strike is a position on a scale of punishment, and
# changing the scale changes what the old ones were worth.
#
# Found on a live gateway. An address collected two strikes five minutes
# apart while the first two rungs were five and thirty minutes -- one
# continuous scan, and cheap. The rungs then became a day and a week, those
# two strikes came along, and its next offence started at the third rung: a
# thirty day ban, then ninety. Nobody chose ninety days for it, and by the
# ladder's own arithmetic reaching that rung should take thirty-eight days of
# actually serving the ones below.
BAN_DURATIONS_CHANGED_KEY = "ban_durations_changed_at"
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
    for earlier, later in itertools.pairwise(steps):
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
# Set by an operator from the panel (services_live.MANUAL_BAN_CODE).
MANUAL_BAN_CODE = 50
# A manual ban whose table expiry jumps by more than this was placed again.
MANUAL_BAN_REPLACED_MARGIN = 120
# A manual ban's term before HAProxy has said what its table gives it: the
# table's own default expiry (sd.ban_expire, 168h).
MANUAL_BAN_DEFAULT_SECONDS = 7 * 86400


class ManualBanRefused(RuntimeError):
    """HAProxy refused an operator's ban."""
# Ban decisions (06.1-06.4): how much of the reason is kept, for how many
# rows, and how long a decision may stay pending before a cycle settles it.
DECISION_EVIDENCE_LISTED = 12
DECISION_DETAIL_LENGTH = 240
DECISION_REASON_MAX_BYTES = 8192
DECISIONS_KEEP_ROWS = 20000
DECISION_PENDING_GRACE = 60
# The feed of every address's decisions (06.6): what "bans" and "lifts" are,
# and who writes into the record at all -- so the page can say which sources
# it shows, and that one it does not show is not "no bans".
DECISION_FEED_KINDS: Dict[str, Tuple[str, ...]] = {
    "all": (),
    "bans": ("applied", "restored", "observed"),
    "lifts": ("lifted", "ended"),
}
DECISION_FEED_SOURCES = ("adaptive", "operator", "restart", "haproxy", "policy", "expiry", "mode")
# Bans this daemon or an operator made. Seeing one in the table is seeing the
# gateway's own decision, not something the client did: it must never count
# as a finding (F03 -- an adaptive ban observed as LEGACY_HAPROXY_BAN, worth
# 30, turned a one-hour ban into a week's with no new request).
# The first step of an adaptive ban, when it answers with a page. A dropped
# connection says nothing to the person behind it: a false positive looked
# like "the site is down" and was only ever found by a complaint. HAProxy
# answers this code with a page naming the address and a request code, and
# the firewall leaves it out; from the second step on the address is cut off
# before HAProxy as before.
ADAPTIVE_PAGE_CODE = 41
ADAPTIVE_CODES = frozenset({ADAPTIVE_BAN_CODE, ADAPTIVE_PAGE_CODE})
FIRST_STEP_PAGE_KEY = "first_step_page"
# A person shown the page stops, or tries the one thing again; a scanner goes
# on down its list. Signatures on this many different paths after the page
# was shown take the address to the next step at once rather than when the
# first one ends.
PAGE_ESCALATION_PATHS = 2
OWN_BAN_CODES = frozenset({ADAPTIVE_BAN_CODE, ADAPTIVE_PAGE_CODE, MANUAL_BAN_CODE})
# The bans already seen, kept across restarts: a restart used to observe
# every standing ban again, 30 points each time.
KNOWN_BANS_STATE_KEY = "known_bans"
KNOWN_BANS_MAX = 5000
# HAProxy's own bans (codes 10/20/30) this daemon wrote into the decision
# history when it first saw them, address -> code, so the end of each is
# written once (06.5b). Kept across restarts like the known bans.
LEGACY_OBSERVED_STATE_KEY = "legacy_observed"
# The site counters kept with such a ban: the ones that held the address
# when it was first seen, most telling first.
LEGACY_READINGS_LISTED = 6

# security.burst: this many addresses banned within the window is a wave, not
# the background; reported at most once per gap.
BURST_WINDOW_SECONDS = 300
BURST_MIN_BANS = 15
BURST_REPORT_GAP_SECONDS = 3600
# security.engine_failing: this many failed cycles in a row is no longer a
# hiccup. A cycle that cannot write -- a full disk, a damaged database --
# scores nothing, bans nothing and records no decision, and used to say so
# only in the service journal (06.7).
ENGINE_FAILING_AFTER = 3
ENGINE_FAILING_RULE = "security.engine_failing"

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
    ".env*": "secrets",
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
DECISIVE_CATEGORIES: frozenset = frozenset({"secrets", "vcs", "backup", "scanner-tool"})

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
    "fetch-and-run": r"(?:^|[;&|]\s*)(?:(?:wget|curl)\s+(?=[^;&|\r\n]{0,384}(?:https?|ftp)://)|tftp\s+(?:-g\b|-r\b|[0-9])|chmod\s+\+?x\b|busybox\s+(?:wget|curl|tftp)\b)",
    "traversal": r"(\.\./\.\./|%2e%2e[/%])",
    "shell-chaining": r"(;\s*(sh|bash|cat|ls|id|uname|rm)\b|\|\s*(sh|bash)\b)",
    "substitution": r"(\$\(|`[a-z/]{2,})",
    "absolute-binary": r"/(bin|usr/bin|sbin)/(sh|bash|nc|perl|python)",
}
QUERY_RULES: Dict[str, "re.Pattern"] = {
    name: re.compile(pattern, re.I)
    for name, pattern in DEFAULT_QUERY_RULES.items()
}
# Programs that name themselves in the User-Agent header. The attack tools
# are decisive: nobody runs sqlmap or nikto against a site by accident, and
# the operator who runs one on purpose adds their own address to the
# allow-list first. The internet-wide surveys are only probable -- they ask
# for "/" and leave -- so they count towards a ban but never make one alone.
#
# Generic libraries (curl, python-requests, Go's http client) are left out
# on purpose: plenty of monitors and integrations send exactly those.
#
# Tokens match case-insensitively anywhere in the logged value. HAProxy has
# already reduced that value to one word -- every character outside
# [A-Za-z0-9./;:_-] became "_" -- and the tokens go through the same
# reduction, so they can be written the way the header reads.
DEFAULT_USER_AGENTS: Dict[str, str] = {
    "sqlmap": "scanner-tool",
    "nikto": "scanner-tool",
    "nuclei": "scanner-tool",
    "wpscan": "scanner-tool",
    "gobuster": "scanner-tool",
    "dirbuster": "scanner-tool",
    "feroxbuster": "scanner-tool",
    "dirsearch": "scanner-tool",
    "fuzz faster u fool": "scanner-tool",
    "wfuzz": "scanner-tool",
    "acunetix": "scanner-tool",
    "netsparker": "scanner-tool",
    "openvas": "scanner-tool",
    "w3af": "scanner-tool",
    "nmap scripting engine": "scanner-tool",
    "jorgee": "scanner-tool",
    "zgrab": "survey",
    "masscan": "survey",
    "censysinspect": "survey",
    "expanse, a palo alto": "survey",
    "internet-measurement": "survey",
    "leakix": "survey",
    "l9explore": "survey",
}
MAX_USER_AGENT_RULES = 200
MIN_USER_AGENT_TOKEN = 4
_UA_UNSAFE = re.compile(r"[^a-z0-9./;:_-]")


def user_agent_token(text: str) -> str:
    """A token or a logged value, reduced the way HAProxy reduces the header."""
    return _UA_UNSAFE.sub("_", (text or "").lower())


def _compile_user_agents(table: Dict[str, str]) -> Dict[str, Tuple[str, str]]:
    """token as matched -> (token as written, category)."""
    compiled: Dict[str, Tuple[str, str]] = {}
    for written, category in list(table.items())[:MAX_USER_AGENT_RULES]:
        token = user_agent_token(str(written))
        # Too short a token would match inside ordinary browser strings.
        if len(token.strip("_")) >= MIN_USER_AGENT_TOKEN and str(category):
            compiled[token] = (str(written), str(category))
    return compiled


USER_AGENTS: Dict[str, Tuple[str, str]] = _compile_user_agents(DEFAULT_USER_AGENTS)


def classify_user_agent(value: str) -> Tuple[str, str]:
    """(token as written, category) for a logged User-Agent, or ("", "")."""
    if not value or value == "-":
        return "", ""
    text = value.lower()
    for token, found in USER_AGENTS.items():
        if token in text:
            return found
    return "", ""


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
    for part in query.split("&", 64):
        # Match parameter values, not prose elsewhere in the request or a
        # parameter whose name happens to resemble a program.
        value = part.partition("=")[2] if "=" in part else part
        for name, pattern in QUERY_RULES.items():
            if pattern.search(value.strip()):
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
# Segment tokens ending in "*" match by prefix. Scanners invent file names
# faster than a list can follow -- /.env.anthropic, /.env-example,
# /.env.production.local -- and every one of them is a secrets probe.
SCANNER_PREFIXES: Tuple[Tuple[str, str], ...] = tuple(
    (token[:-1].lower(), category)
    for token, category in SCANNER_SEGMENTS.items()
    if token.endswith("*") and len(token) > 1
)
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

    agents = USER_AGENTS
    if isinstance(data.get("user_agents"), dict):
        agents = _compile_user_agents(
            {str(k): str(v) for k, v in data["user_agents"].items()}
        ) or USER_AGENTS

    QUERY_RULES.clear()
    QUERY_RULES.update(rules)
    if agents is not USER_AGENTS:
        USER_AGENTS.clear()
        USER_AGENTS.update(agents)
    _SHIPPED_SEGMENTS = segments
    _SHIPPED_PATHS = paths
    DECISIVE_CATEGORIES = frozenset(decisive)
    publish_signatures()
    SIGNATURE_VERSION = str(data.get("version") or "unversioned")
    SIGNATURE_SOURCE = source
    LOG.info(
        "Loaded scanner signatures %s: %d segments, %d paths, %d decisive, "
        "%d query rules, %d user agents",
        SIGNATURE_VERSION,
        len(segments),
        len(paths),
        len(decisive),
        len(QUERY_RULES),
        len(USER_AGENTS),
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
    # A trailing * on a segment token matches by prefix (".env*"). Only on a
    # segment, and only after three characters: "a*" would match half of
    # every site's own paths.
    base = text[:-1] if text.endswith("*") else text
    if text.endswith("*"):
        if text.startswith("/"):
            raise ValueError("a prefix (*) works on a path segment, not on a whole path")
        if len(base) < 3:
            raise ValueError("a prefix needs at least three characters before *")
    if not _TOKEN_OK.match(base):
        raise ValueError(
            "a signature may hold letters, digits and . _ ~ / @ : + - only, "
            "with an optional * at the end of a segment"
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

    global SCANNER_SEGMENTS, SCANNER_PATHS, SCANNER_PREFIXES

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
    SCANNER_PREFIXES = tuple(
        (token[:-1].lower(), category)
        for token, category in segments.items()
        if token.endswith("*") and len(token) > 1
    )


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


_OVERRIDES_LOCK = threading.Lock()
_REQUESTS_LOCK = threading.RLock()


def store_overrides(database: "SecurityDatabase", data: Any) -> Dict[str, Any]:
    """Validate, persist and apply in one step, so the three cannot diverge."""

    checked = validate_overrides(data)
    with _OVERRIDES_LOCK:
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


def _dismissed_candidates(database: "SecurityDatabase") -> List[str]:
    with contextlib.suppress(ValueError, TypeError):
        value = json.loads(database.get_state(CANDIDATES_DISMISSED_KEY, "[]") or "[]")
        if isinstance(value, list):
            return [str(item) for item in value]
    return []


def dismiss_candidate(database: "SecurityDatabase", path: str,
                      restore: bool = False, host: str = "") -> Dict[str, Any]:
    """Hide a suggestion for good, or bring a hidden one back."""

    text = (path or "").strip()
    if not text.startswith("/") or len(text) > CANDIDATE_MAX_PATH_LENGTH:
        raise ValueError("expected a path")
    if host:
        text = json.dumps([detection_host(host), text], separators=(",", ":"))
    dismissed = [item for item in _dismissed_candidates(database) if item != text]
    if not restore:
        dismissed.append(text)
    dismissed = dismissed[-CANDIDATES_MAX_DISMISSED:]
    database.set_state(CANDIDATES_DISMISSED_KEY, json.dumps(dismissed))
    return {"dismissed": dismissed}


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
        "user_agents": [
            {"token": written, "category": category,
             "decisive": category_is_decisive(category)}
            for written, category in sorted(USER_AGENTS.values())
        ],
        # What the operator changed, so the page can offer to change it back.
        "added": dict(_overrides.get("added") or {}),
        "disabled": list(_overrides.get("disabled") or []),
        "custom_category": CUSTOM_CATEGORY,
        "max_rules": MAX_CUSTOM_RULES,
    }


def category_is_decisive(category: str) -> bool:
    return category in DECISIVE_CATEGORIES




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
EVENT_WIDE_ENUM = "WIDE_ENUMERATION"
EVENT_MASS_ENUM = "MASS_ENUMERATION"
EVENT_INVALID_HOST = "INVALID_HOST_ACTIVITY"
EVENT_RECURRING = "RECURRING_SCANNER"
EVENT_NOSNI_PROBING = "NOSNI_PROBING"
EVENT_RATE_EXCEEDED = "RATE_EXCEEDED"
EVENT_ERROR_RATE_EXCEEDED = "ERROR_RATE_EXCEEDED"
EVENT_LEGACY_BAN = "LEGACY_HAPROXY_BAN"
# An address that stayed over one of the hard ceilings (U02, 04.7b): far past
# anything a client does, so a flood rather than a busy user.
EVENT_HARD_FLOOR = "HARD_FLOOR_EPISODE"
# The same, by a trusted address: kept as a record, never weighed (a trusted
# address is not punished for load until D09b says how).
EVENT_HARD_FLOOR_TRUSTED = "HARD_FLOOR_TRUSTED"
# Multiple distinct offending IPv4 addresses from the same /24 subnet within a
# short window. Never punishes silent/innocent neighbors in the subnet: it is
# emitted only on an address that already produced its own hostile finding.
EVENT_SUBNET_CAMPAIGN = "SUBNET_CAMPAIGN"
# Actions rather than findings: they carry no weight and never feed the score.
EVENT_BAN_APPLIED = "BAN_APPLIED"
EVENT_BAN_LIFTED = "BAN_LIFTED"
# A ban HAProxy wrote under the old rules, lifted after the switch to U02.
EVENT_LEGACY_BAN_LIFTED = "LEGACY_BAN_LIFTED"

DEFAULT_WEIGHTS: Dict[str, int] = {
    # 25 left a scanner that brought one signature, a sweep by IP and six
    # missing paths to one visit at 50 -- under the line every time. Measured
    # on two gateways over a week: 35 adds only such scanners and no client,
    # because no client in either log ever produced a signature finding.
    EVENT_SCANNER_PATH: 35,
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
    # The low tier above is one category, so the category cap held it at 25
    # however wide the sweep: five hundred random paths in five minutes
    # scored the same as six, and enumeration alone could never reach a ban.
    # Breadth now escalates as findings of their own.
    EVENT_WIDE_ENUM: 30,
    EVENT_MASS_ENUM: 60,
    # A scanner that comes back. Every visit of the slow ones scored the
    # same capped category and faded within six hours, so an address that
    # probed for WordPress eight times in a week never got past 45. Coming
    # back is its own finding, worth a ban together with one signature.
    EVENT_RECURRING: 30,
    EVENT_INVALID_HOST: 10,
    EVENT_NOSNI_PROBING: 10,
    EVENT_RATE_EXCEEDED: 15,
    EVENT_ERROR_RATE_EXCEEDED: 15,
    EVENT_LEGACY_BAN: 30,
    # Recorded under both policies, weighed only under the u02 ban policy
    # (see u02_policy).
    EVENT_HARD_FLOOR: 0,
    # Coordinated /24 campaign boost: combined with a single probable scanner
    # finding (35 + 25 = 60), escalates the third and subsequent hostile IPs in
    # the same /24 straight to the ban threshold without banning the whole /24.
    EVENT_SUBNET_CAMPAIGN: 25,
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
    EVENT_WIDE_ENUM: 900,
    EVENT_MASS_ENUM: 3600,
    EVENT_RECURRING: 6 * 3600,
    EVENT_INVALID_HOST: 600,
    EVENT_NOSNI_PROBING: 600,
    EVENT_RATE_EXCEEDED: 60,
    EVENT_ERROR_RATE_EXCEEDED: 60,
    # One record per ten minutes of a flood, not one per read.
    EVENT_HARD_FLOOR: 600,
    EVENT_HARD_FLOOR_TRUSTED: 600,
    EVENT_SUBNET_CAMPAIGN: 1800,
}

# IPv4 /24 subnet campaign correlation limits (bounded memory, CGNAT-safe).
SUBNET_CAMPAIGN_WINDOW = 1800
SUBNET_CAMPAIGN_MIN_IPS = 3
SUBNET_CAMPAIGN_MAX_SUBNETS = 1024
SUBNET_CAMPAIGN_MAX_IPS_PER_SUBNET = 32
SUBNET_CAMPAIGN_TRIGGERS: frozenset = frozenset({
    EVENT_SCANNER_PATH,
    EVENT_SCANNER_DECISIVE,
    EVENT_QUERY_INJECTION,
    EVENT_WIDE_ENUM,
    EVENT_MASS_ENUM,
    EVENT_LOW_AND_SLOW,
    EVENT_HARD_FLOOR,
})

# Thresholds for the derived detections.
MULTI_CATEGORY_MIN = 3
MULTI_CATEGORY_WINDOW = 2 * 3600
LOW_AND_SLOW_MIN_HITS = 5
LOW_AND_SLOW_MIN_CATEGORIES = 3
LOW_AND_SLOW_WINDOW = 6 * 3600
NOT_FOUND_MIN_DISTINCT = 6
NOT_FOUND_WINDOW = 3600
# Breadth tiers. They count every refusal of a path the address made up --
# 401, 403 and 410 as well as 404 -- because a site behind authorisation
# answers a sweep with 401 or 403 for every path and the 404-only tier never
# saw it. The thresholds are high enough that an application polling its own
# dozen endpoints after a session expired stays below them.
ENUMERATION_STATUSES = frozenset({401, 403, 404, 410})
WIDE_ENUM_MIN = 30
MASS_ENUM_MIN = 100
WIDE_ENUM_WINDOW = 600
# Distinct host-and-path pairs, not hits: a monitor that asks the gateway's
# bare IP for "/" every minute is one pair however long it runs, while a
# sweep of names or paths by IP is many.
INVALID_HOST_MIN = 5
INVALID_HOST_WINDOW = 6 * 3600
# How the protection is doing: the numbers shown on its page and sent once a
# week. "At once" is a ban within this long of the address's first finding.
QUALITY_AT_ONCE_SECONDS = 15
QUALITY_NETWORK_MIN = 3
QUALITY_NETWORKS_SHOWN = 5
QUALITY_CACHE_SECONDS = 300
QUALITY_MAX_DAYS = 30
WEEKLY_SUMMARY_RULE = "security.weekly_summary"
WEEKLY_SUMMARY_KEY = "weekly_summary_sent"
# Monday morning, in the gateway's own time: the week that just ended.
WEEKLY_SUMMARY_WEEKDAY = 0
WEEKLY_SUMMARY_HOUR = 8

# A return visit: a scanner signature now, and another at least two hours
# earlier within thirty days. Only signatures count -- a client with a few
# stale links or odd requests never has one.
#
# The window was a week. On a production gateway 968 addresses in thirty days
# brought one probable signature and were never banned; 90 of them came back
# on other days, half of those more than 7.2 days apart -- one day outside
# the week. Replayed over the stored findings of two gateways, thirty days
# adds 57 and 30 banned addresses, every one a WordPress, AI-endpoint or
# survey prober and none that had ever signed in. Thirty days is also as far
# back as findings are kept by default; a shorter retention shortens it.
RECURRING_WINDOW = 30 * 86400
RECURRING_GAP = 2 * 3600
RECURRING_RECHECK = 600
# A catch-all page answers every path alike: one size, whatever was asked.
# Three different scanner paths answered 2xx with the same size on one host
# are that page, not three things the site really has -- a real WordPress
# answers /wp-login.php, /xmlrpc.php and /wp-admin/ differently.
CATCH_ALL_MIN_PATHS = 3
CATCH_ALL_MAX_HOSTS = 256
CATCH_ALL_MAX_SIZES = 16

# Suggested signatures: paths no rule matched, refused to several different
# addresses and never served to anyone. Only a suggestion -- the operator
# adds one or hides it on the detection rules page.
CANDIDATE_MIN_ADDRESSES = 3
CANDIDATE_MAX_PATHS = 20000
CANDIDATE_MAX_ADDRESSES = 64
CANDIDATE_MAX_SERVED = 50000
CANDIDATE_TTL = 7 * 86400
CANDIDATE_MAX_PATH_LENGTH = 200
CANDIDATES_KEY = "signature_candidates"
CANDIDATES_DISMISSED_KEY = "signature_candidates_dismissed"
CANDIDATES_MAX_DISMISSED = 500

# Trap names: hostnames that point at the gateway but serve no site. Nobody
# with a reason to be here asks for one -- certificate-transparency scanners
# do. The operator chooses them; the engine only lists the names that get
# traffic, with how many of their visitors look like ordinary clients.
TRAP_HOSTS_KEY = "trap_hosts"
UNKNOWN_HOSTS_KEY = "unknown_hosts"
MAX_TRAP_HOSTS = 100
UNKNOWN_HOSTS_MAX = 2000
UNKNOWN_HOSTS_TTL = 7 * 86400
SITE_NAMES_RECHECK = 60
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")

SIGNATURE_EVENTS = frozenset({
    EVENT_SCANNER_PATH, EVENT_SCANNER_DECISIVE, EVENT_QUERY_INJECTION,
})

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
# Already one word: the template replaces anything that could split the line.
_UA_FIELD = re.compile(r"(?:^|\s)ua=(?P<ua>\S*)")
MAX_USER_AGENT_LENGTH = 128
_AUTH_USER_FIELD = re.compile(r"(?:^|\s)auth_user=(?P<user>[A-Za-z0-9_.~%+-]*)\s*$")


def authenticated_username(prefix: str) -> str:
    """Only the labelled field immediately before the request, never its URI."""
    match = _AUTH_USER_FIELD.search(prefix)
    if not match or match.group("user") in ("", "-"):
        return ""
    try:
        user = unquote(match.group("user"), errors="strict")
    except UnicodeError:
        return ""
    return user if len(user) <= 128 and all(c.isprintable() for c in user) else ""

_BAN_REASON_FIELD = re.compile(r'ban_reason="(?P<reason>[^"]*)"')
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


def detection_host(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 253:
        raise ValueError("expected a host name without a port")
    host = value.lower().rstrip(".")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host) or ".." in host:
        raise ValueError("expected a host name without a port")
    return host
