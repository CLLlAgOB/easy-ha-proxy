# services_live.py
#
# The live activity page: who is hitting the gateway right now, what they get
# and what the gateway refuses them.
#
# The requests come from easy-ha-proxy-guardd, which reads every line of the
# access log once anyway and keeps the latest ones in memory: the page costs
# no extra read of the log, however many people have it open and however
# heavy the traffic. What the log cannot show is added here from HAProxy
# itself: an address that is banned, or over the connection limit, is refused
# before HTTP and never reaches the log at all -- the office that lost every
# site for an hour on a connection-rate limit left no line behind.

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Any, Dict, List, Optional

from .cache import get_country_code
from .services import (
    SOCKET,
    WHITELIST_GLOBAL_FILE,
    get_ip_auth_table,
    get_tables,
)
from .services_haproxy_config import CONFIG_YAML, _load_yaml
from .guardd_client import GuarddUnavailable, guardd_live
from .utils import haproxy_runtime_command

LOG = logging.getLogger("haproxy-admin")

WINDOWS = (30, 60, 300, 900)
MAX_WINDOW = 3600
STATUS_CLASSES = ("1xx", "2xx", "3xx", "4xx", "5xx")

# What each ban code in tbl_ban (gpt0) means. 10-30 are HAProxy's own rules,
# 40 the adaptive engine, 50 a ban placed by hand on this page.
BAN_CODE_LABELS = {
    "10": "Too many 4xx errors on a site (ERR_LIMIT_SITE)",
    "20": "Too many 4xx errors on unknown names (ERR_LIMIT_OTHER)",
    "30": "Site request rate exceeded (RATE_LIMIT_SITE)",
    "40": "Adaptive protection: scored as hostile",
    "50": "Banned by hand from the live activity page",
}
MANUAL_BAN_CODE = 50

# Why the gateway refused a request, as the live snapshot names it.
REFUSAL_LABELS = {
    "banned": "Banned",
    "rate-limited": "Request rate limit",
    "geo": "GeoIP",
    "zero-trust": "Zero trust: not signed in",
    "denied": "Address not allowed",
    "invalid-request": "Unknown name or bad request",
    "refused": "Refused by the gateway",
}

_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_CONN_ROW = re.compile(
    r"key=(?P<ip>\S+)\s.*?conn_rate\(\d+\)=(?P<rate>\d+)\s+conn_cur=(?P<cur>\d+)"
)


class LiveUnavailable(RuntimeError):
    """guardd did not answer the snapshot request."""


def normalize_request(args: Dict[str, Any]) -> Dict[str, Any]:
    """The query string, checked, as the snapshot and the enrichment want it."""
    try:
        window = int(args.get("window") or 60)
    except (TypeError, ValueError):
        window = 60
    request: Dict[str, Any] = {"window": max(5, min(MAX_WINDOW, window))}
    ip = str(args.get("ip") or "").strip()
    if ip and re.fullmatch(r"[0-9A-Fa-f:.]{1,45}", ip):
        request["ip"] = ip
    host = str(args.get("host") or "").strip().lower()
    if host and re.fullmatch(r"[a-z0-9.-]{1,253}", host):
        request["host"] = host
    query = str(args.get("q") or "").strip()
    if query:
        request["q"] = query[:120]
    status = str(args.get("status") or "").strip()
    if status in STATUS_CLASSES:
        request["status"] = status
    if str(args.get("blocked") or "").lower() in ("1", "true", "yes", "on"):
        request["blocked"] = True
    if str(args.get("banned") or "").lower() in ("1", "true", "yes", "on"):
        request["banned"] = True
    country = str(args.get("country") or "").strip().upper()
    if re.fullmatch(r"[A-Z]{2}", country):
        request["country"] = country
    # The admin panel's own polling is most of a quiet gateway's traffic:
    # left out unless the page asks for it.
    if str(args.get("hide_admin") or "").lower() in ("1", "true", "yes", "on"):
        request["hide_admin"] = True
    # Part of a client's user agent, as the clients list shows them.
    agent = "".join(ch for ch in str(args.get("agent") or "") if ch.isprintable()).strip()
    if agent:
        request["agent"] = agent[:120]
    return request


def fetch_snapshot(request: Dict[str, Any]) -> Dict[str, Any]:
    params = {key: value for key, value in request.items() if key != "country"}
    for flag in ("blocked", "banned", "hide_admin"):
        if params.get(flag):
            params[flag] = "1"
    try:
        data = guardd_live(params)
    except GuarddUnavailable as exc:
        raise LiveUnavailable(
            "Adaptive protection is not answering. Live activity is read from its "
            "memory, so it needs adaptive protection running in monitor or enforce "
            f"mode ({exc})"
        ) from exc
    if not data.get("ok"):
        raise LiveUnavailable(str(data.get("error") or "guardd refused the request"))
    return data


def _networks(path: str) -> List[ipaddress._BaseNetwork]:
    networks = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                text = line.split("#", 1)[0].strip()
                if not text:
                    continue
                try:
                    networks.append(ipaddress.ip_network(text, strict=False))
                except ValueError:
                    continue
    except OSError:
        pass
    return networks


def _listed(ip: str, networks: List[ipaddress._BaseNetwork]) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in network for network in networks)


def allow_entry(ip: str, networks: List[ipaddress._BaseNetwork]) -> Optional[str]:
    """How an address is allow-listed: "host", "range", or None.

    "host" means a single-host entry exists, which "Drop & ban" can remove.
    "range" means only a broader network covers it; dropping that would
    un-protect everyone else in it, so the page offers no one-click ban.
    """
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    covering = [network for network in networks if address in network]
    if not covering:
        return None
    if any(network.num_addresses == 1 for network in covering):
        return "host"
    return "range"


def address_status(ip: str) -> Dict[str, Any]:
    """What the IP page shows above the log lines: allowed, banned, or neither.

    Read-only and best effort: a runtime socket that does not answer leaves
    the ban unknown rather than taking the log page down with it.
    """
    status: Dict[str, Any] = {
        "ipv4": bool(_IPV4.match(ip or "")),
        "allow_entry": allow_entry(ip, _networks(WHITELIST_GLOBAL_FILE)),
        "ban": None,
        "ban_known": True,
    }
    status["allow_listed"] = status["allow_entry"] is not None
    try:
        status["ban"] = current_bans().get(ip)
    except Exception:  # pylint: disable=broad-except
        LOG.debug("ban state unavailable for %s", ip, exc_info=True)
        status["ban_known"] = False
    return status


def current_bans() -> Dict[str, Dict[str, Any]]:
    """Addresses HAProxy refuses right now, by tbl_ban."""
    table = (get_tables() or {}).get("ban") or {}
    bans = {}
    for row in table.get("rows") or []:
        if len(row) < 4 or str(row[1]) != "Blocked":
            continue
        code = str(row[2])
        try:
            expires = int(row[3])
        except (TypeError, ValueError):
            expires = 0
        bans[str(row[0])] = {
            "code": code,
            "label": BAN_CODE_LABELS.get(code, f"Ban code {code}"),
            "expires_in": expires,
        }
    return bans


def connection_limits() -> Dict[str, int]:
    defaults = (_load_yaml(CONFIG_YAML) or {}).get("site_defaults") or {}

    def number(key: str, fallback: int) -> int:
        try:
            return int(defaults.get(key, fallback))
        except (TypeError, ValueError):
            return fallback

    return {"burst": number("conn_rate_burst", 200), "concurrent": number("conn_cur_limit", 500)}


def connection_table() -> Dict[str, Dict[str, int]]:
    """New-connection rate and open connections per address, from fe_https."""
    try:
        raw = haproxy_runtime_command("show table fe_https", SOCKET, timeout=2)
    except Exception:  # pylint: disable=broad-except
        return {}
    rows = {}
    for line in str(raw).splitlines():
        match = _CONN_ROW.search(line)
        if match:
            rows[match.group("ip")] = {
                "rate": int(match.group("rate")), "cur": int(match.group("cur")),
            }
    return rows


def authorized_addresses() -> set:
    """Addresses signed in through Authelia (zero-trust IP authorization)."""
    try:
        table = get_ip_auth_table()
    except Exception:  # pylint: disable=broad-except
        return set()
    authorized = set()
    for row in table.get("rows") or []:
        try:
            if int(row[1]) > 0:
                authorized.add(str(row[0]))
        except (TypeError, ValueError, IndexError):
            continue
    return authorized


def _country(ip: str, cache: Dict[str, str]) -> str:
    if ip not in cache:
        code = get_country_code(ip) or ""
        cache[ip] = code if re.fullmatch(r"[A-Z]{2}", code) else ""
    return cache[ip]


def live_view(args: Dict[str, Any]) -> Dict[str, Any]:
    request = normalize_request(args)
    snapshot = fetch_snapshot(request)
    bans = current_bans()
    connections = connection_table()
    limits = connection_limits()
    allowed = _networks(WHITELIST_GLOBAL_FILE)
    authorized = authorized_addresses()
    countries: Dict[str, str] = {}

    def state(ip: str) -> Dict[str, Any]:
        connection = connections.get(ip) or {}
        over = bool(connection) and (
            connection["rate"] > limits["burst"] or connection["cur"] > limits["concurrent"]
        )
        entry = allow_entry(ip, allowed)
        allow_listed = entry is not None
        return {
            "country": _country(ip, countries),
            "ban": bans.get(ip),
            "allow_listed": allow_listed,
            "allow_entry": entry,
            "authorized": ip in authorized,
            # The allow list is exempt from the connection limit.
            "connection_limited": over and not allow_listed,
            "connections": connection or None,
        }

    for row in snapshot.get("addresses") or []:
        row.update(state(row["ip"]))
    for key in ("events", "slow"):
        for event in snapshot.get(key) or []:
            event["country"] = _country(event["ip"], countries)

    wanted = request.get("country")
    if wanted:
        snapshot["addresses"] = [
            row for row in snapshot.get("addresses") or [] if row.get("country") == wanted
        ]
        for key in ("events", "slow"):
            snapshot[key] = [
                event for event in snapshot.get(key) or [] if event.get("country") == wanted
            ]

    seen = {row["ip"]: row for row in snapshot.get("addresses") or []}
    banned = []
    for ip, ban in bans.items():
        banned.append({
            "ip": ip, "country": _country(ip, countries), **ban,
            "requests_in_window": (seen.get(ip) or {}).get("requests", 0),
        })
    banned.sort(key=lambda row: row["expires_in"], reverse=True)
    limited = []
    for ip, connection in connections.items():
        if _listed(ip, allowed):
            continue
        if connection["rate"] > limits["burst"] or connection["cur"] > limits["concurrent"]:
            limited.append({"ip": ip, "country": _country(ip, countries), **connection})
    limited.sort(key=lambda row: -row["rate"])

    snapshot.update({
        "request": request,
        "banned": banned,
        "connection_limited": limited,
        "connection_limits": limits,
        "ban_labels": BAN_CODE_LABELS,
        "refusal_labels": REFUSAL_LABELS,
        "countries": sorted({code for code in countries.values() if code}),
        "current_connections": sum(row["cur"] for row in connections.values()),
    })
    snapshot["totals"]["banned_now"] = len(banned)
    snapshot["totals"]["connection_limited_now"] = len(limited)
    return snapshot


def ban_address(ip: str, client_ip: str, drop_allowlist: bool = False) -> Dict[str, Any]:
    """Ban one address by hand, the way HAProxy's own rules do.

    It goes into tbl_ban with its own code, so the ban list, the unban button
    and the firewall mirror all treat it like any other ban; it lasts as long
    as the table keeps its entries. The operator's own address is refused:
    banning it would lock the operator out of the page that lifts the ban.

    An allow-listed address is refused too, because every ban rule carries
    `!ip_whitelist` and the firewall mirror skips the list -- a plain ban on
    such an address does nothing. With ``drop_allowlist`` the one-host entry is
    taken off the global allow list first, so the ban can bite; this is the
    "it's whitelisted but the machine behind it is compromised" case. A host
    that stays covered by a broader allow-listed range afterwards is reported
    rather than banned, because the ban still would not apply.
    """
    if not _IPV4.match(ip or ""):
        return {"ok": False, "error": "Only an IPv4 address can be banned"}
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        return {"ok": False, "error": "Invalid IP"}
    if client_ip and ip == client_ip:
        return {"ok": False, "error": "That is your own address; banning it would lock you out"}

    from . import services

    if _listed(ip, _networks(WHITELIST_GLOBAL_FILE)):
        if not drop_allowlist:
            return {
                "ok": False,
                "allow_listed": True,
                "error": "The address is on the global allow list, so a ban would not apply",
            }
        removed, error = services.remove_host_from_global_whitelist(ip)
        if error:
            return {"ok": False, "error": f"Could not update the allow list: {error}"}
        # A single-host entry is gone now; if the address is still covered it
        # was only ever inside a range, which this must not quietly widen away.
        if _listed(ip, _networks(WHITELIST_GLOBAL_FILE)):
            return {
                "ok": False,
                "error": (
                    "The address is allowed by a network range, not its own entry. "
                    "Remove or narrow that range first, then ban."
                ),
            }
        if not removed:
            return {
                "ok": False,
                "error": "The address was not found as a single allow-list entry",
            }

    answer = haproxy_runtime_command(
        f"set table tbl_ban key {ip} data.gpc0 1 data.gpt0 {MANUAL_BAN_CODE}", SOCKET, timeout=2
    )
    if str(answer).strip():
        return {"ok": False, "error": f"HAProxy refused: {str(answer).strip()[:200]}"}
    # get_tables caches for a few seconds; the page should see the ban now.
    services.cache_time = services.datetime.min
    return {"ok": True, "ip": ip, "code": MANUAL_BAN_CODE, "dropped_from_allowlist": bool(drop_allowlist)}
