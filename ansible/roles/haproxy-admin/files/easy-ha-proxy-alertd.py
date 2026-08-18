#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""easy-ha-proxy-alertd — one place that decides when to tell the operator.

Before this daemon every feature carried its own notification logic: healthd
mailed about a site being down, the certbot hook mailed about renewals, and
metricsd and guardd only wrote to the journal — so a full metrics disk or the
security engine starting to ban people was something you found out by reading
logs. This daemon owns the decision instead, and the features only report what
they see.

Three ideas hold it together.

**Producers report observations, not notifications.** A daemon says "this
condition is currently true for this subject", repeatedly, and says nothing
about whether that deserves an email. Trigger delay, repetition, recovery and
storm control belong here, where they can be applied consistently and where an
operator can change them in one place.

**A condition is either a level or an event.** A backend being down is a level:
it stays true, it can recover, and a five-minute delay before shouting is
right. A failed backup is an event: it happened, there is no "still failing"
to observe and no recovery to wait for. Conflating them either leaves edge
conditions stuck FIRING forever or turns level conditions into a stream.

**Delivery failure is not a reason to lose the record.** Everything is written
to SQLite first; channels are attempted afterwards and their outcome is stored
alongside. An unreachable SMTP relay costs the email, never the history.
"""

from __future__ import annotations

import contextlib
import fcntl
import grp
import hmac
import ipaddress
import json
import logging
import os
import pwd
import re
import signal
import socket
import sqlite3
import ssl
import subprocess
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from socketserver import ThreadingMixIn, UnixStreamServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

LOG = logging.getLogger("easy-ha-proxy-alertd")

SOCKET_PATH = os.environ.get(
    "ALERTD_SOCKET_PATH", "/run/easy-ha-proxy/easy-ha-proxy-alertd.sock"
)
SOCKET_GROUP = os.environ.get("ALERTD_SOCKET_GROUP", "hadmin")
DATABASE_PATH = os.environ.get(
    "ALERTD_DATABASE", "/var/lib/easy-ha-proxy/alerts/alerts.db"
)
CONFIG_PATH = os.environ.get("ALERTD_CONFIG", "/opt/haproxy-admin/alertd.json")

# Submitting an observation and changing the rules are both privileged: an
# unprivileged process must not be able to invent an outage or silence one.
CONTROL_TOKEN = os.environ.get("ALERTD_TOKEN", "").strip()

# Email goes out exactly the way certificate notifications and the old site
# alerts did: through the mail_relay container, gated by the shared state file
# so alerts stay silent while email delivery is switched off.
MAIL_STATE_PATH = os.environ.get(
    "ALERTD_MAIL_STATE", "/etc/easy-ha-proxy/mail-notify.json"
)
MAIL_LOCK_PATH = os.environ.get(
    "ALERTD_MAIL_LOCK", "/run/easy-ha-proxy/authelia-mail.lock"
)
MAIL_RELAY_CONTAINER = os.environ.get("ALERTD_MAIL_CONTAINER", "mail_relay")
DOCKER_BIN = os.environ.get("ALERTD_DOCKER_BIN", "/usr/bin/docker")
MAIL_TIMEOUT_SECONDS = 30

SCHEMA_VERSION = 1

STATE_OK = "ok"
STATE_PENDING = "pending"
STATE_FIRING = "firing"
STATES = (STATE_OK, STATE_PENDING, STATE_FIRING)

TRANSITION_FIRED = "fired"
TRANSITION_REPEATED = "repeated"
TRANSITION_ESCALATED = "escalated"
TRANSITION_RECOVERED = "recovered"
TRANSITION_SUPPRESSED = "suppressed"

SEVERITY_INFO = "info"
SEVERITY_WARNING = "warning"
SEVERITY_CRITICAL = "critical"
SEVERITIES = (SEVERITY_INFO, SEVERITY_WARNING, SEVERITY_CRITICAL)

KIND_LEVEL = "level"
KIND_EVENT = "event"

EVALUATE_INTERVAL_SECONDS = 15.0
RETENTION_DAYS = 90
MAX_EVENT_ROWS = 50_000
MAX_TEXT_CHARS = 2000
MAX_SUBJECT_CHARS = 200
MAX_STATE_ROWS = 5000

# Storm control. A gateway losing its uplink can turn every site down at once;
# one summary is useful and forty separate emails are not.
STORM_WINDOW_SECONDS = 300
STORM_MAX_NOTIFICATIONS = 8

# --- Webhook -----------------------------------------------------------
# The URL is operator-supplied, but it still must not turn the gateway into a
# request proxy for whatever is reachable from inside the network. The host is
# resolved once and the connection is made to that exact address, so a name
# that answers publicly on one lookup and 127.0.0.1 on the next cannot slip
# past the check.
WEBHOOK_TIMEOUT_SECONDS = 10
WEBHOOK_MAX_RESPONSE_BYTES = 8192
WEBHOOK_USER_AGENT = "easy-ha-proxy-alertd/1.0"

_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,63}$")
_SUBJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/@*-]{0,199}$")
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,253}\.[A-Za-z0-9-]{2,63}$")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _utc_now() -> int:
    return int(time.time())


def _clean_text(value: Any, limit: int = MAX_TEXT_CHARS) -> str:
    """Producer text ends up in an email, so control characters go first."""
    text = _CONTROL_CHARS.sub("", str(value or "")).strip()
    return text[:limit]


def _redact_url(value: str) -> str:
    """Keep the host so an operator can recognise it; drop everything else."""
    if not value:
        return ""
    parsed = urlparse(value)
    if not parsed.hostname:
        return "***"
    return f"{parsed.scheme}://{parsed.hostname}/***"


def _clamp_int(value: Any, *, default: int, min_v: int, max_v: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(min_v, min(max_v, number))


# ---------------------------------------------------------------------------
# Rule catalogue
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    """One condition the gateway knows how to complain about.

    ``trigger_delay`` only applies to levels: an event has already happened by
    the time it is reported. ``auto_clear`` is what stops an event from staying
    FIRING forever, since nothing will ever report it as resolved.
    """

    name: str
    kind: str
    severity: str
    title: str
    trigger_delay: int = 0
    repeat_after: int = 6 * 3600
    auto_clear: int = 3600
    # A level condition that stops being reported is treated as resolved once
    # this long has passed, so a producer that dies does not pin an alert on.
    stale_after: int = 900
    enabled: bool = True


RULES: Tuple[Rule, ...] = (
    Rule("site.down", KIND_LEVEL, SEVERITY_CRITICAL,
         "Site is down", trigger_delay=300),
    Rule("backend.no_servers", KIND_LEVEL, SEVERITY_CRITICAL,
         "No healthy server left in a backend", trigger_delay=120),
    Rule("http.error_ratio", KIND_LEVEL, SEVERITY_WARNING,
         "HTTP 5xx ratio above the threshold", trigger_delay=300),
    Rule("response.slow", KIND_LEVEL, SEVERITY_WARNING,
         "Response time above the threshold", trigger_delay=300),
    Rule("authelia.unavailable", KIND_LEVEL, SEVERITY_CRITICAL,
         "Authelia is not answering", trigger_delay=120),
    Rule("monitoring.storage", KIND_LEVEL, SEVERITY_WARNING,
         "Monitoring storage is under pressure", trigger_delay=0),
    Rule("monitoring.paused", KIND_LEVEL, SEVERITY_WARNING,
         "Historical monitoring is paused", trigger_delay=0),
    Rule("certificate.expiring", KIND_LEVEL, SEVERITY_WARNING,
         "Certificate expires soon", trigger_delay=0, repeat_after=24 * 3600),
    Rule("certificate.renewal_failed", KIND_EVENT, SEVERITY_CRITICAL,
         "Certificate renewal failed", auto_clear=6 * 3600),
    Rule("security.burst", KIND_EVENT, SEVERITY_WARNING,
         "Burst of hostile requests", auto_clear=3600),
    Rule("security.hostile_ip", KIND_EVENT, SEVERITY_INFO,
         "Adaptive protection acted on an address", auto_clear=3600),
    Rule("backup.failed", KIND_EVENT, SEVERITY_CRITICAL,
         "Backup job failed", auto_clear=6 * 3600),
    Rule("restore.failed", KIND_EVENT, SEVERITY_CRITICAL,
         "Restore job failed", auto_clear=6 * 3600),
    Rule("update.failed", KIND_EVENT, SEVERITY_WARNING,
         "Software update failed", auto_clear=6 * 3600),
    Rule("config.apply_failed", KIND_EVENT, SEVERITY_CRITICAL,
         "HAProxy apply or reload failed", auto_clear=3600),
)

RULES_BY_NAME: Dict[str, Rule] = {rule.name: rule for rule in RULES}


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class RuleSettings:
    enabled: bool
    trigger_delay: int
    repeat_after: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "trigger_delay": self.trigger_delay,
            "repeat_after": self.repeat_after,
        }


@dataclass
class AlertConfig:
    """Operator-visible settings. Absent keys keep the catalogue defaults."""

    enabled: bool = True
    email_enabled: bool = True
    recipient: str = ""
    min_severity: str = SEVERITY_INFO
    webhook_url: str = ""
    webhook_header_name: str = ""
    webhook_header_value: str = ""
    webhook_allow_private: bool = False
    rules: Dict[str, RuleSettings] = field(default_factory=dict)

    def settings_for(self, rule: Rule) -> RuleSettings:
        return self.rules.get(
            rule.name,
            RuleSettings(rule.enabled, rule.trigger_delay, rule.repeat_after),
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "email_enabled": self.email_enabled,
            "recipient": self.recipient,
            "min_severity": self.min_severity,
            "webhook_url": self.webhook_url,
            "webhook_header_name": self.webhook_header_name,
            "webhook_header_value": self.webhook_header_value,
            "webhook_allow_private": self.webhook_allow_private,
            "rules": {name: value.as_dict() for name, value in self.rules.items()},
        }

    def redacted(self) -> Dict[str, Any]:
        """The settings as the browser may see them.

        A webhook URL routinely carries a token in its path, and the header
        value is a secret by definition, so neither is ever sent back — only
        whether one is set, the same rule the DNS provider profiles follow.
        """
        payload = self.as_dict()
        payload["webhook_url"] = _redact_url(self.webhook_url)
        payload["webhook_header_value"] = "***" if self.webhook_header_value else ""
        return payload


def load_config(path: str) -> AlertConfig:
    """Read the settings file. A missing or broken file means defaults.

    Alerting that refuses to start because its configuration is unreadable is
    the wrong failure: the operator would lose notifications precisely when
    something is already wrong.
    """
    config = AlertConfig()
    try:
        with open(path, "r", encoding="utf-8") as stream:
            raw = json.load(stream)
    except FileNotFoundError:
        return config
    except Exception as exc:  # pylint: disable=broad-except
        LOG.warning("Cannot read %s (%s); using defaults", path, exc)
        return config
    if not isinstance(raw, dict):
        LOG.warning("%s is not a JSON object; using defaults", path)
        return config

    config.enabled = raw.get("enabled", True) is not False
    config.email_enabled = raw.get("email_enabled", True) is not False
    recipient = str(raw.get("recipient") or "").strip()
    config.recipient = recipient if _EMAIL_RE.fullmatch(recipient) else ""
    severity = str(raw.get("min_severity") or SEVERITY_INFO).strip().lower()
    config.min_severity = severity if severity in SEVERITIES else SEVERITY_INFO
    config.webhook_url = str(raw.get("webhook_url") or "").strip()
    header_name = str(raw.get("webhook_header_name") or "").strip()
    config.webhook_header_name = (
        header_name if _HEADER_NAME_RE.fullmatch(header_name) else ""
    )
    config.webhook_header_value = _CONTROL_CHARS.sub(
        "", str(raw.get("webhook_header_value") or "")
    ).strip()[:4096]
    config.webhook_allow_private = raw.get("webhook_allow_private") is True

    rules = raw.get("rules")
    if isinstance(rules, dict):
        for name, value in rules.items():
            rule = RULES_BY_NAME.get(str(name))
            if rule is None or not isinstance(value, dict):
                continue
            config.rules[rule.name] = RuleSettings(
                enabled=value.get("enabled", rule.enabled) is not False,
                trigger_delay=_clamp_int(
                    value.get("trigger_delay", rule.trigger_delay),
                    default=rule.trigger_delay,
                    min_v=0,
                    max_v=86400,
                ),
                repeat_after=_clamp_int(
                    value.get("repeat_after", rule.repeat_after),
                    default=rule.repeat_after,
                    min_v=300,
                    max_v=7 * 86400,
                ),
            )
    return config


def save_config(path: str, config: AlertConfig) -> None:
    """Write the settings file atomically, root-owned."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    payload = json.dumps(config.as_dict(), ensure_ascii=False, indent=2) + "\n"
    with open(temporary, "w", encoding="utf-8") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, 0o640)
    os.replace(temporary, target)


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

_SCHEMA_STATEMENTS: Tuple[str, ...] = (
    "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)",
    """
    CREATE TABLE IF NOT EXISTS alert_state (
        rule            TEXT    NOT NULL,
        subject         TEXT    NOT NULL,
        state           TEXT    NOT NULL,
        severity        TEXT    NOT NULL DEFAULT 'warning',
        since_ts        INTEGER NOT NULL,
        first_seen_ts   INTEGER NOT NULL,
        last_seen_ts    INTEGER NOT NULL,
        last_notified_ts INTEGER NOT NULL DEFAULT 0,
        notify_count    INTEGER NOT NULL DEFAULT 0,
        summary         TEXT    NOT NULL DEFAULT '',
        detail          TEXT    NOT NULL DEFAULT '',
        -- Per-subject policy the producer carries because it owns the object:
        -- a site's own alert_after and alert_email live in websites.yml.
        trigger_delay   INTEGER,
        recipient       TEXT    NOT NULL DEFAULT '',
        PRIMARY KEY (rule, subject)
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_state_state ON alert_state(state, since_ts)",
    """
    CREATE TABLE IF NOT EXISTS alert_events (
        id          INTEGER PRIMARY KEY,
        ts          INTEGER NOT NULL,
        rule        TEXT    NOT NULL,
        subject     TEXT    NOT NULL,
        transition  TEXT    NOT NULL,
        severity    TEXT    NOT NULL,
        summary     TEXT    NOT NULL DEFAULT '',
        detail      TEXT    NOT NULL DEFAULT '',
        delivered   TEXT    NOT NULL DEFAULT '',
        delivery_error TEXT NOT NULL DEFAULT ''
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_events_ts ON alert_events(ts)",
    "CREATE INDEX IF NOT EXISTS ix_events_rule ON alert_events(rule, ts)",
)


class AlertDatabase:
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

    def close(self) -> None:
        with self._lock, contextlib.suppress(Exception):
            self._conn.close()

    # -- state ---------------------------------------------------------
    def get_state(self, rule: str, subject: str) -> Optional[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM alert_state WHERE rule = ? AND subject = ?",
                (rule, subject),
            ).fetchone()

    def put_state(self, values: Dict[str, Any]) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO alert_state (
                    rule, subject, state, severity, since_ts, first_seen_ts,
                    last_seen_ts, last_notified_ts, notify_count, summary,
                    detail, trigger_delay, recipient
                ) VALUES (
                    :rule, :subject, :state, :severity, :since_ts, :first_seen_ts,
                    :last_seen_ts, :last_notified_ts, :notify_count, :summary,
                    :detail, :trigger_delay, :recipient
                )
                ON CONFLICT(rule, subject) DO UPDATE SET
                    state = excluded.state,
                    severity = excluded.severity,
                    since_ts = excluded.since_ts,
                    last_seen_ts = excluded.last_seen_ts,
                    last_notified_ts = excluded.last_notified_ts,
                    notify_count = excluded.notify_count,
                    summary = excluded.summary,
                    detail = excluded.detail,
                    trigger_delay = excluded.trigger_delay,
                    recipient = excluded.recipient
                """,
                values,
            )

    def drop_state(self, rule: str, subject: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "DELETE FROM alert_state WHERE rule = ? AND subject = ?",
                (rule, subject),
            )

    def open_states(self) -> List[sqlite3.Row]:
        with self._lock:
            return list(
                self._conn.execute(
                    "SELECT * FROM alert_state WHERE state != ? "
                    "ORDER BY since_ts DESC",
                    (STATE_OK,),
                ).fetchall()
            )

    def active_alerts(self) -> List[sqlite3.Row]:
        with self._lock:
            return list(
                self._conn.execute(
                    "SELECT * FROM alert_state WHERE state = ? "
                    "ORDER BY since_ts DESC",
                    (STATE_FIRING,),
                ).fetchall()
            )

    # -- history -------------------------------------------------------
    def add_event(self, values: Dict[str, Any]) -> int:
        with self._lock, self._conn:
            cursor = self._conn.execute(
                """
                INSERT INTO alert_events (
                    ts, rule, subject, transition, severity, summary, detail,
                    delivered, delivery_error
                ) VALUES (
                    :ts, :rule, :subject, :transition, :severity, :summary,
                    :detail, :delivered, :delivery_error
                )
                """,
                values,
            )
            return int(cursor.lastrowid or 0)

    def set_delivery(self, event_id: int, delivered: str, error: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE alert_events SET delivered = ?, delivery_error = ? "
                "WHERE id = ?",
                (delivered, error[:MAX_TEXT_CHARS], event_id),
            )

    def events(
        self,
        *,
        rule: str = "",
        severity: str = "",
        since: int = 0,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        clauses: List[str] = []
        parameters: List[Any] = []
        if rule:
            clauses.append("rule = ?")
            parameters.append(rule)
        if severity in SEVERITIES:
            clauses.append("severity = ?")
            parameters.append(severity)
        if since:
            clauses.append("ts >= ?")
            parameters.append(int(since))
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        limit = _clamp_int(limit, default=100, min_v=1, max_v=500)
        offset = max(0, int(offset or 0))
        with self._lock:
            total = int(
                self._conn.execute(
                    f"SELECT COUNT(*) FROM alert_events{where}", parameters
                ).fetchone()[0]
            )
            rows = self._conn.execute(
                f"SELECT * FROM alert_events{where} ORDER BY ts DESC, id DESC "
                "LIMIT ? OFFSET ?",
                parameters + [limit, offset],
            ).fetchall()
        return {"total": total, "events": [dict(row) for row in rows]}

    def notifications_since(self, since: int) -> int:
        with self._lock:
            return int(
                self._conn.execute(
                    "SELECT COUNT(*) FROM alert_events WHERE ts >= ? "
                    "AND transition IN (?, ?)",
                    (int(since), TRANSITION_FIRED, TRANSITION_REPEATED),
                ).fetchone()[0]
            )

    def prune(self) -> None:
        cutoff = _utc_now() - RETENTION_DAYS * 86400
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM alert_events WHERE ts < ?", (cutoff,))
            self._conn.execute(
                "DELETE FROM alert_events WHERE id NOT IN ("
                "SELECT id FROM alert_events ORDER BY id DESC LIMIT ?)",
                (MAX_EVENT_ROWS,),
            )
            # A resolved subject that nothing has mentioned for a retention
            # period is history, not state.
            self._conn.execute(
                "DELETE FROM alert_state WHERE state = ? AND last_seen_ts < ?",
                (STATE_OK, cutoff),
            )
            self._conn.execute(
                "DELETE FROM alert_state WHERE rowid NOT IN ("
                "SELECT rowid FROM alert_state ORDER BY last_seen_ts DESC LIMIT ?)",
                (MAX_STATE_ROWS,),
            )
            self._conn.execute("PRAGMA incremental_vacuum")

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            firing = int(
                self._conn.execute(
                    "SELECT COUNT(*) FROM alert_state WHERE state = ?",
                    (STATE_FIRING,),
                ).fetchone()[0]
            )
            pending = int(
                self._conn.execute(
                    "SELECT COUNT(*) FROM alert_state WHERE state = ?",
                    (STATE_PENDING,),
                ).fetchone()[0]
            )
            events = int(
                self._conn.execute("SELECT COUNT(*) FROM alert_events").fetchone()[0]
            )
        size = 0
        with contextlib.suppress(OSError):
            size = self.path.stat().st_size
        return {
            "firing": firing,
            "pending": pending,
            "events": events,
            "database_bytes": size,
        }


# ---------------------------------------------------------------------------
# Channels
# ---------------------------------------------------------------------------


class Channel:
    """A way to reach the operator. Never raises; reports its own failure."""

    name = "channel"

    def available(self, config: AlertConfig) -> bool:
        raise NotImplementedError

    def send(self, config: AlertConfig, subject: str, body: str) -> Tuple[bool, str]:
        raise NotImplementedError


class EmailChannel(Channel):
    name = "email"

    def _state(self) -> Optional[Dict[str, str]]:
        try:
            with open(MAIL_STATE_PATH, "r", encoding="utf-8") as stream:
                state = json.load(stream)
        except Exception:  # pylint: disable=broad-except
            return None
        if not isinstance(state, dict) or state.get("enabled") is not True:
            return None
        sender = str(state.get("from") or "")
        if not _EMAIL_RE.fullmatch(sender):
            return None
        return {"from": sender, "to": str(state.get("to") or "")}

    def available(self, config: AlertConfig) -> bool:
        if not config.email_enabled:
            return False
        return self._state() is not None

    def send(self, config: AlertConfig, subject: str, body: str) -> Tuple[bool, str]:
        state = self._state()
        if state is None:
            return False, "email delivery is disabled"
        sender = state["from"]
        recipient = config.recipient or state["to"]
        if not _EMAIL_RE.fullmatch(recipient):
            return False, "no valid recipient configured"

        # A header injected through the subject would let a producer address
        # the message elsewhere, so the subject is a single line by force.
        one_line = subject.replace("\r", " ").replace("\n", " ")[:200]
        message = (
            f"From: {sender}\r\nTo: {recipient}\r\nSubject: {one_line}\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n\r\n"
            + body.replace("\r\n", "\n").replace("\n", "\r\n")
            + "\r\n"
        )
        try:
            os.makedirs(os.path.dirname(MAIL_LOCK_PATH), mode=0o750, exist_ok=True)
            with open(MAIL_LOCK_PATH, "a+b") as lock_file:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_SH)
                proc = subprocess.run(
                    [
                        DOCKER_BIN, "exec", "-i", MAIL_RELAY_CONTAINER,
                        "/usr/sbin/sendmail", "-i", "-f", sender, "--", recipient,
                    ],
                    input=message.encode("utf-8"),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    timeout=MAIL_TIMEOUT_SECONDS,
                    check=False,
                )
        except Exception as exc:  # pylint: disable=broad-except
            return False, f"mail delivery failed: {exc}"
        if proc.returncode != 0:
            detail = (proc.stderr or b"").decode("utf-8", "replace").strip()
            return False, f"mail_relay exit {proc.returncode}: {detail}"[:MAX_TEXT_CHARS]
        return True, ""



def resolve_webhook_target(url: str, *, allow_private: bool) -> Tuple[str, str, int, str]:
    """Validate a webhook URL and pin it to one address.

    Returns ``(hostname, address, port, path)``. Raises ValueError with a
    message meant for the operator.

    The address is resolved here and used for the connection, which is what
    closes the rebinding hole: checking the name and then letting the HTTP
    client resolve it again would validate one answer and connect to another.
    """
    parsed = urlparse((url or "").strip())
    if parsed.scheme != "https":
        raise ValueError("the webhook URL must use https")
    if not parsed.hostname:
        raise ValueError("the webhook URL has no host")
    if parsed.username or parsed.password:
        # Credentials in a URL end up in logs and proxies; a header is the
        # place for a secret.
        raise ValueError("put the secret in the header, not in the URL")
    port = parsed.port or 443
    if not 1 <= port <= 65535:
        raise ValueError("the webhook port is out of range")

    try:
        infos = socket.getaddrinfo(
            parsed.hostname, port, proto=socket.IPPROTO_TCP
        )
    except OSError as exc:
        raise ValueError(f"the webhook host does not resolve: {exc}") from exc

    for info in infos:
        candidate = info[4][0]
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if address.is_loopback or address.is_link_local or address.is_multicast:
            # 169.254.169.254 is the cloud metadata service; loopback is every
            # other daemon on this host.
            raise ValueError(
                "the webhook host resolves to a loopback or link-local address"
            )
        if address.is_reserved or address.is_unspecified:
            raise ValueError("the webhook host resolves to a reserved address")
        if address.is_private and not allow_private:
            raise ValueError(
                "the webhook host resolves to a private address; enable "
                "'allow private destinations' if that is intended"
            )
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        return parsed.hostname, candidate, port, path

    raise ValueError("the webhook host did not resolve to a usable address")


class WebhookChannel(Channel):
    """Posts one JSON object per notification to an operator-chosen URL."""

    name = "webhook"

    def available(self, config: AlertConfig) -> bool:
        return bool(config.webhook_url)

    def send(self, config: AlertConfig, subject: str, body: str) -> Tuple[bool, str]:
        return self.post(config, {"subject": subject, "body": body})

    def post(self, config: AlertConfig, payload: Dict[str, Any]) -> Tuple[bool, str]:
        try:
            hostname, address, port, path = resolve_webhook_target(
                config.webhook_url, allow_private=config.webhook_allow_private
            )
        except ValueError as exc:
            return False, str(exc)

        document = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = [
            f"Host: {hostname}",
            "Content-Type: application/json; charset=utf-8",
            f"Content-Length: {len(document)}",
            f"User-Agent: {WEBHOOK_USER_AGENT}",
            "Connection: close",
        ]
        if config.webhook_header_name and config.webhook_header_value:
            headers.append(
                f"{config.webhook_header_name}: {config.webhook_header_value}"
            )
        head_lines = [f"POST {path} HTTP/1.1"] + headers
        request = (
            "\r\n".join(head_lines) + "\r\n\r\n"
        ).encode("utf-8") + document

        context = ssl.create_default_context()
        try:
            with socket.create_connection(
                (address, port), timeout=WEBHOOK_TIMEOUT_SECONDS
            ) as raw:
                # The certificate is checked against the name the operator
                # typed, not against the address it was pinned to.
                with context.wrap_socket(raw, server_hostname=hostname) as stream:
                    stream.sendall(request)
                    chunks = []
                    received = 0
                    while received < WEBHOOK_MAX_RESPONSE_BYTES:
                        chunk = stream.recv(4096)
                        if not chunk:
                            break
                        chunks.append(chunk)
                        received += len(chunk)
        except ssl.SSLError as exc:
            return False, f"TLS to the webhook failed: {exc}"
        except OSError as exc:
            return False, f"the webhook could not be reached: {exc}"

        head = (
            b"".join(chunks)
            .split(b"\r\n", 1)[0]
            .decode("latin-1", "replace")
        )
        parts = head.split(" ")
        status = parts[1] if len(parts) > 1 else "?"
        if status.startswith("2"):
            return True, ""
        # A redirect is not followed: the destination would not have been
        # validated, which is the whole point of the check above.
        return False, f"the webhook answered {head[:120]}"


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


def _severity_rank(value: str) -> int:
    try:
        return SEVERITIES.index(value)
    except ValueError:
        return 0


class AlertEngine:
    """Turns a stream of observations into a small number of notifications."""

    def __init__(
        self,
        config: AlertConfig,
        database: AlertDatabase,
        channels: Optional[List[Channel]] = None,
    ) -> None:
        self.config = config
        self.database = database
        self.channels: List[Channel] = (
            channels if channels is not None else [EmailChannel(), WebhookChannel()]
        )
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_prune = 0
        # A cloud instance is named something like epdvmcr928c02uk7q8je,
        # which tells the reader of an alert nothing at all. An operator can
        # give the gateway a name they recognise; the machine name is only
        # the fallback.
        self.hostname = (
            os.environ.get("ALERTD_GATEWAY_NAME", "").strip() or os.uname().nodename
        )

    # -- lifecycle ------------------------------------------------------
    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._loop, name="alert-evaluator", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def _loop(self) -> None:
        while not self._stop.wait(EVALUATE_INTERVAL_SECONDS):
            try:
                self.sweep()
            except Exception:  # pylint: disable=broad-except
                LOG.exception("alert sweep failed")

    # -- intake ---------------------------------------------------------
    def observe(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Record one observation and act on it if the rule says so."""
        rule_name = str(payload.get("rule") or "").strip()
        rule = RULES_BY_NAME.get(rule_name)
        if rule is None:
            raise ValueError(f"unknown rule: {rule_name!r}")

        subject = _clean_text(payload.get("subject") or "-", MAX_SUBJECT_CHARS)
        if not _SUBJECT_RE.fullmatch(subject):
            raise ValueError("subject may use letters, digits and . _ : / @ * -")

        active = payload.get("active")
        if rule.kind == KIND_EVENT:
            # An event is by definition something that happened.
            active = True
        elif not isinstance(active, bool):
            raise ValueError("active must be true or false for a level condition")

        severity = str(payload.get("severity") or rule.severity).strip().lower()
        if severity not in SEVERITIES:
            severity = rule.severity
        summary = _clean_text(payload.get("summary") or rule.title)
        detail = _clean_text(payload.get("detail"))

        # Some policy genuinely belongs to the object rather than to the rule:
        # a site carries its own alert_after and alert_email in websites.yml,
        # and moving those into a single global rule would be a regression.
        # The rule's on/off switch and the severity floor still win.
        override_delay: Optional[int] = None
        if payload.get("trigger_delay") is not None and rule.kind == KIND_LEVEL:
            override_delay = _clamp_int(
                payload.get("trigger_delay"),
                default=rule.trigger_delay,
                min_v=0,
                max_v=86400,
            )
        recipient = str(payload.get("recipient") or "").strip()
        if recipient and not _EMAIL_RE.fullmatch(recipient):
            raise ValueError("the recipient is not a valid email address")

        with self._lock:
            return self._apply(
                rule,
                subject,
                bool(active),
                severity,
                summary,
                detail,
                override_delay,
                recipient,
            )

    def _apply(
        self,
        rule: Rule,
        subject: str,
        active: bool,
        severity: str,
        summary: str,
        detail: str,
        override_delay: Optional[int] = None,
        recipient: str = "",
    ) -> Dict[str, Any]:
        now = _utc_now()
        settings = self.config.settings_for(rule)
        delay = settings.trigger_delay if override_delay is None else override_delay
        row = self.database.get_state(rule.name, subject)
        state = str(row["state"]) if row else STATE_OK
        since = int(row["since_ts"]) if row else now
        first_seen = int(row["first_seen_ts"]) if row else now
        last_notified = int(row["last_notified_ts"]) if row else 0
        notify_count = int(row["notify_count"]) if row else 0

        transition = ""

        if not active:
            if state == STATE_FIRING:
                transition = TRANSITION_RECOVERED
                state = STATE_OK
                since = now
            elif state == STATE_PENDING:
                # It never fired, so there is nothing to recover from.
                state = STATE_OK
                since = now
        else:
            if state == STATE_OK:
                state = STATE_PENDING
                since = now
                first_seen = now
                notify_count = 0
            if state == STATE_PENDING and now - since >= delay:
                state = STATE_FIRING
                since = now
                transition = TRANSITION_FIRED
            elif state == STATE_FIRING and _severity_rank(severity) > _severity_rank(
                str(row["severity"]) if row else severity
            ):
                # It got worse. A partial outage becoming a total one is news
                # on its own and should not wait for the repeat window. This
                # cannot loop: the new severity is stored with the state.
                transition = TRANSITION_ESCALATED
            elif state == STATE_FIRING and (
                now - last_notified >= settings.repeat_after
            ):
                transition = TRANSITION_REPEATED

        self.database.put_state(
            {
                "rule": rule.name,
                "subject": subject,
                "state": state,
                "severity": severity,
                "since_ts": since,
                "first_seen_ts": first_seen,
                "last_seen_ts": now,
                "last_notified_ts": last_notified,
                "notify_count": notify_count,
                "summary": summary,
                "detail": detail,
                "trigger_delay": override_delay,
                "recipient": recipient,
            }
        )

        result = {"rule": rule.name, "subject": subject, "state": state}
        if not transition:
            return result

        notified = self._notify(
            rule, subject, transition, severity, summary, detail, now, recipient
        )
        if notified:
            self.database.put_state(
                {
                    "rule": rule.name,
                    "subject": subject,
                    "state": state,
                    "severity": severity,
                    "since_ts": since,
                    "first_seen_ts": first_seen,
                    "last_seen_ts": now,
                    "last_notified_ts": now,
                    "notify_count": notify_count + 1,
                    "summary": summary,
                    "detail": detail,
                    "trigger_delay": override_delay,
                    "recipient": recipient,
                }
            )
        result["transition"] = transition
        result["notified"] = notified
        return result

    # -- notification ---------------------------------------------------
    def _should_notify(self, rule: Rule, severity: str) -> Tuple[bool, str]:
        if not self.config.enabled:
            return False, "alerting is switched off"
        if not self.config.settings_for(rule).enabled:
            return False, "the rule is switched off"
        if _severity_rank(severity) < _severity_rank(self.config.min_severity):
            return False, "below the configured minimum severity"
        return True, ""

    def _notify(
        self,
        rule: Rule,
        subject: str,
        transition: str,
        severity: str,
        summary: str,
        detail: str,
        now: int,
        recipient: str = "",
    ) -> bool:
        allowed, reason = self._should_notify(rule, severity)
        if not allowed:
            self.database.add_event(
                {
                    "ts": now, "rule": rule.name, "subject": subject,
                    "transition": transition, "severity": severity,
                    "summary": summary, "detail": detail,
                    "delivered": "", "delivery_error": reason,
                }
            )
            return False

        # Storm control counts what already went out, so a burst produces the
        # first few notifications and then one line per suppressed alert in the
        # history, which is where an operator can still find them.
        recent = self.database.notifications_since(now - STORM_WINDOW_SECONDS)
        if transition != TRANSITION_RECOVERED and recent >= STORM_MAX_NOTIFICATIONS:
            self.database.add_event(
                {
                    "ts": now, "rule": rule.name, "subject": subject,
                    "transition": TRANSITION_SUPPRESSED, "severity": severity,
                    "summary": summary, "detail": detail, "delivered": "",
                    "delivery_error": (
                        f"more than {STORM_MAX_NOTIFICATIONS} notifications in "
                        f"{STORM_WINDOW_SECONDS // 60} minutes"
                    ),
                }
            )
            return False

        event_id = self.database.add_event(
            {
                "ts": now, "rule": rule.name, "subject": subject,
                "transition": transition, "severity": severity,
                "summary": summary, "detail": detail,
                "delivered": "", "delivery_error": "",
            }
        )
        mail_subject, body = self.render(
            rule, subject, transition, severity, summary, detail, now
        )
        delivered, errors = self.deliver(mail_subject, body, recipient=recipient)
        self.database.set_delivery(event_id, ",".join(delivered), "; ".join(errors))
        return bool(delivered)

    def deliver(
        self, subject: str, body: str, *, recipient: str = ""
    ) -> Tuple[List[str], List[str]]:
        config = self.config
        if recipient:
            # A per-subject recipient replaces the shared one for this message
            # only; nothing about it is persisted into the settings file.
            config = load_config_from_dict(
                {**self.config.as_dict(), "recipient": recipient}
            )
        delivered: List[str] = []
        errors: List[str] = []
        for channel in self.channels:
            # The contract says a channel reports its own failure rather than
            # raising, but a broken one must not cost the delivery record or
            # turn an observation into a 500.
            try:
                if not channel.available(config):
                    continue
                ok, error = channel.send(config, subject, body)
            except Exception as exc:  # pylint: disable=broad-except
                LOG.exception("channel %s raised", channel.name)
                errors.append(f"{channel.name}: {exc}")
                continue
            if ok:
                delivered.append(channel.name)
            else:
                errors.append(f"{channel.name}: {error}")
        if not delivered and not errors:
            errors.append("no channel is configured")
        return delivered, errors

    def render(
        self,
        rule: Rule,
        subject: str,
        transition: str,
        severity: str,
        summary: str,
        detail: str,
        now: int,
    ) -> Tuple[str, str]:
        verb = {
            TRANSITION_FIRED: "ALERT",
            TRANSITION_REPEATED: "STILL",
            TRANSITION_ESCALATED: "WORSE",
            TRANSITION_RECOVERED: "RESOLVED",
        }.get(transition, "ALERT")
        head = f"[{self.hostname}] {verb} {severity}: {rule.title}"
        if subject and subject != "-":
            head += f" ({subject})"
        when = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(now))
        lines = [
            summary or rule.title,
            "",
            f"Condition : {rule.name}",
            f"Subject   : {subject}",
            f"Severity  : {severity}",
            f"State     : {verb.lower()}",
            f"Time      : {when}",
            f"Gateway   : {self.hostname}",
        ]
        if detail:
            lines += ["", detail]
        lines += [
            "",
            "Sent by easy-ha-proxy. Alert settings live on the Alerts page.",
        ]
        return head, "\n".join(lines)

    # -- periodic work --------------------------------------------------
    def sweep(self) -> Dict[str, int]:
        """Resolve what nothing reports any more and clear finished events."""
        now = _utc_now()
        recovered = 0
        cleared = 0
        with self._lock:
            for row in self.database.open_states():
                rule = RULES_BY_NAME.get(str(row["rule"]))
                if rule is None:
                    self.database.drop_state(str(row["rule"]), str(row["subject"]))
                    continue
                age = now - int(row["last_seen_ts"])
                if rule.kind == KIND_EVENT:
                    # Nothing will ever report an event as resolved, so it is
                    # closed on a timer rather than left firing forever.
                    if age >= rule.auto_clear:
                        self.database.drop_state(rule.name, str(row["subject"]))
                        cleared += 1
                    continue
                if age < rule.stale_after:
                    continue
                # A level nobody has reported for a while: the producer either
                # stopped seeing it or stopped running. Both mean this alert
                # can no longer be trusted as active.
                if row["state"] == STATE_FIRING:
                    # The recovery has to reach whoever got the alert, which
                    # for a site is its own alert_email rather than the
                    # shared recipient.
                    self._apply(
                        rule,
                        str(row["subject"]),
                        False,
                        str(row["severity"]),
                        f"{rule.title} is no longer reported",
                        "The condition stopped being reported; treating it as "
                        "resolved.",
                        row["trigger_delay"],
                        str(row["recipient"] or ""),
                    )
                    recovered += 1
                else:
                    self.database.drop_state(rule.name, str(row["subject"]))
                    cleared += 1

            if now - self._last_prune >= 3600:
                self._last_prune = now
                with contextlib.suppress(Exception):
                    self.database.prune()
        return {"recovered": recovered, "cleared": cleared}

    # -- read models ----------------------------------------------------
    def health(self) -> Dict[str, Any]:
        channels = {
            channel.name: channel.available(self.config) for channel in self.channels
        }
        return {
            "enabled": self.config.enabled,
            "hostname": self.hostname,
            "channels": channels,
            "rules": len(RULES),
            **self.database.stats(),
        }

    def snapshot(self, *, limit: int = 100) -> Dict[str, Any]:
        active = [dict(row) for row in self.database.active_alerts()]
        # A condition inside its trigger delay is the most useful thing an
        # operator can see: it is happening now and has not been sent yet.
        pending = [
            dict(row)
            for row in self.database.open_states()
            if str(row["state"]) == STATE_PENDING
        ]
        history = self.database.events(limit=limit)
        return {
            "active": active,
            "pending": pending,
            "history": history["events"],
            "history_total": history["total"],
            "catalogue": [
                {
                    "name": rule.name,
                    "kind": rule.kind,
                    "title": rule.title,
                    "severity": rule.severity,
                    **self.config.settings_for(rule).as_dict(),
                }
                for rule in RULES
            ],
            "config": self.config.redacted(),
        }

    # -- configuration --------------------------------------------------
    def update_config(self, payload: Dict[str, Any]) -> AlertConfig:
        if not isinstance(payload, dict):
            raise ValueError("a JSON object is required")
        merged = self.config.as_dict()
        for key in ("enabled", "email_enabled"):
            if key in payload:
                merged[key] = payload[key] is not False
        if "recipient" in payload:
            recipient = str(payload.get("recipient") or "").strip()
            if recipient and not _EMAIL_RE.fullmatch(recipient):
                raise ValueError("the recipient is not a valid email address")
            merged["recipient"] = recipient
        if "min_severity" in payload:
            severity = str(payload.get("min_severity") or "").strip().lower()
            if severity not in SEVERITIES:
                raise ValueError("min_severity must be info, warning or critical")
            merged["min_severity"] = severity
        if "webhook_allow_private" in payload:
            merged["webhook_allow_private"] = (
                payload["webhook_allow_private"] is True
            )
        if "webhook_url" in payload:
            url = str(payload.get("webhook_url") or "").strip()
            if url:
                # Validated on the way in rather than at the first alert, so a
                # typo is a form error and not a silently missed notification.
                resolve_webhook_target(
                    url, allow_private=bool(merged.get("webhook_allow_private"))
                )
            merged["webhook_url"] = url
        if "webhook_header_name" in payload:
            name = str(payload.get("webhook_header_name") or "").strip()
            if name and not _HEADER_NAME_RE.fullmatch(name):
                raise ValueError("the header name may use letters, digits and -")
            merged["webhook_header_name"] = name
        if "webhook_header_value" in payload:
            # An unchanged secret is never sent back to the browser, so the
            # browser echoes the mask; that must not overwrite the real value.
            value = str(payload.get("webhook_header_value") or "")
            if value != "***":
                merged["webhook_header_value"] = value
        rules = payload.get("rules")
        if rules is not None:
            if not isinstance(rules, dict):
                raise ValueError("rules must be an object")
            for name, value in rules.items():
                if name not in RULES_BY_NAME:
                    raise ValueError(f"unknown rule: {name}")
                if not isinstance(value, dict):
                    raise ValueError(f"rule {name} must be an object")
            merged.setdefault("rules", {}).update(
                {str(name): value for name, value in rules.items()}
            )

        config = load_config_from_dict(merged)
        save_config(CONFIG_PATH, config)
        with self._lock:
            self.config = config
        return config


def load_config_from_dict(raw: Dict[str, Any]) -> AlertConfig:
    """Validate a settings mapping through the same path as the file."""
    import tempfile

    handle, name = tempfile.mkstemp(prefix="alertd-config-")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(raw, stream)
        return load_config(name)
    finally:
        with contextlib.suppress(OSError):
            os.unlink(name)


# ---------------------------------------------------------------------------
# HTTP over a unix socket
# ---------------------------------------------------------------------------


class AlertHandler(BaseHTTPRequestHandler):
    server_version = "easy-ha-proxy-alertd/1.0"

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

    def _auth_ok(self) -> bool:
        if not CONTROL_TOKEN:
            return False
        supplied = (self.headers.get("X-Alertd-Token", "") or "").strip()
        return hmac.compare_digest(supplied, CONTROL_TOKEN)

    def _read_json(self) -> Dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return {}
        if length <= 0 or length > 256 * 1024:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:  # pylint: disable=broad-except
            return {}

    def do_GET(self) -> None:  # noqa: N802
        engine: AlertEngine = self.server.engine  # type: ignore[attr-defined]
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query or "")

        if parsed.path == "/api/v1/alerts/health":
            try:
                self._send_json(200, {"ok": True, "ts": _utc_now(), **engine.health()})
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
            return

        if parsed.path == "/api/v1/alerts/state":
            try:
                limit = _clamp_int(
                    query.get("limit", [None])[0], default=100, min_v=1, max_v=500
                )
                payload = engine.snapshot(limit=limit)
                payload["ok"] = True
                payload["ts"] = _utc_now()
                self._send_json(200, payload)
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
            return

        if parsed.path == "/api/v1/alerts/history":
            try:
                result = engine.database.events(
                    rule=str(query.get("rule", [""])[0] or "").strip(),
                    severity=str(query.get("severity", [""])[0] or "").strip(),
                    since=_clamp_int(
                        query.get("since", [None])[0], default=0, min_v=0,
                        max_v=2_000_000_000,
                    ),
                    limit=_clamp_int(
                        query.get("limit", [None])[0], default=100, min_v=1,
                        max_v=500,
                    ),
                    offset=_clamp_int(
                        query.get("offset", [None])[0], default=0, min_v=0,
                        max_v=1_000_000,
                    ),
                )
                self._send_json(200, {"ok": True, "ts": _utc_now(), **result})
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
            return

        self._send_json(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        engine: AlertEngine = self.server.engine  # type: ignore[attr-defined]
        path = urlparse(self.path).path

        if path not in (
            "/api/v1/alerts/notify",
            "/api/v1/alerts/config",
            "/api/v1/alerts/test",
        ):
            self._send_json(404, {"ok": False, "error": "not found"})
            return

        if not self._auth_ok():
            self._send_json(403, {"ok": False, "error": "forbidden"})
            return

        payload = self._read_json()

        if path == "/api/v1/alerts/notify":
            try:
                result = engine.observe(payload)
            except ValueError as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
                return
            except Exception as exc:  # pylint: disable=broad-except
                LOG.exception("observation failed")
                self._send_json(500, {"ok": False, "error": str(exc)})
                return
            self._send_json(200, {"ok": True, **result})
            return

        if path == "/api/v1/alerts/config":
            try:
                config = engine.update_config(payload)
            except ValueError as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
                return
            except Exception as exc:  # pylint: disable=broad-except
                LOG.exception("configuration update failed")
                self._send_json(500, {"ok": False, "error": str(exc)})
                return
            self._send_json(200, {"ok": True, "config": config.redacted()})
            return

        # A test message proves the channel works without inventing an alert,
        # so it is delivered directly and never touches the state machine.
        try:
            subject = f"[{engine.hostname}] easy-ha-proxy alert test"
            body = (
                "This is a test message from easy-ha-proxy.\n\n"
                "If you received it, alert delivery works.\n"
            )
            delivered, errors = engine.deliver(subject, body)
        except Exception as exc:  # pylint: disable=broad-except
            LOG.exception("test delivery failed")
            self._send_json(500, {"ok": False, "error": str(exc)})
            return
        self._send_json(
            200 if delivered else 502,
            {
                "ok": bool(delivered),
                "delivered": delivered,
                "errors": errors,
            },
        )


class AlertServer(ThreadingMixIn, UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        socket_path: str,
        handler_cls: type[BaseHTTPRequestHandler],
        engine: AlertEngine,
    ) -> None:
        super().__init__(socket_path, handler_cls)
        self.engine = engine


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

    config = load_config(CONFIG_PATH)
    database = AlertDatabase(DATABASE_PATH)
    engine = AlertEngine(config, database)

    LOG.info(
        "Starting easy-ha-proxy-alertd: socket=%s db=%s rules=%d enabled=%s",
        SOCKET_PATH,
        DATABASE_PATH,
        len(RULES),
        config.enabled,
    )

    engine.start()

    with contextlib.suppress(OSError):
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)

    server = AlertServer(SOCKET_PATH, AlertHandler, engine)
    try:
        _set_socket_perms(SOCKET_PATH, SOCKET_GROUP)
    except Exception as exc:  # pylint: disable=broad-except
        LOG.warning("Failed to set socket permissions: %s", exc)

    # Without this, systemd's SIGTERM kills the process outright and leaves the
    # socket file behind: a client connecting during the restart window reaches
    # a path that exists and answers nothing.
    def _shutdown(signum: int, _frame: Any) -> None:
        LOG.info("Received signal %s; shutting down", signum)
        threading.Thread(target=server.shutdown, daemon=True).start()

    for signal_number in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(ValueError, OSError):
            signal.signal(signal_number, _shutdown)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOG.info("Interrupted")
    finally:
        engine.stop()
        with contextlib.suppress(Exception):
            server.server_close()
        database.close()
        with contextlib.suppress(OSError):
            if os.path.exists(SOCKET_PATH):
                os.unlink(SOCKET_PATH)


if __name__ == "__main__":
    main()
