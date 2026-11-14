"""Backend sets: named lists of backend addresses, each with a default role.

An operator with two uplinks, or the same pair of servers behind many sites,
used to type the same addresses and roles into every site, TCP proxy and UDP
forward. A set is kept once, in vars.yml under ``backend_presets``, and an
entry names it in ``servers_preset`` (with ``servers_preset_port``).

The reference is expanded when the entry is saved: a site or TCP proxy gets
its own ``servers`` list, a UDP forward its ``backend_host`` and
``backup_host``. HAProxy, the UDP rules and every daemon keep reading what
they always read. Saving a set expands it again in every entry that names it,
so changing an address in one place changes it everywhere once the
configuration is applied. Typing addresses by hand keeps working as before.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple

import yaml

from .services_haproxy_config import (
    CONFIG_YAML,
    TCP_YAML,
    UDP_YAML,
    WEBSITES_YAML,
    StaleEntry,
    _load_yaml,
    check_entry_revision,
    config_transaction_is_pending,
    entry_revision,
    source_lock,
    update_yaml_file,
)
from .validation import validate_config_data, validate_host, validate_port

logger = logging.getLogger(__name__)

PRESETS_KEY = "backend_presets"
PRESET_FIELD = "servers_preset"
PORT_FIELD = "servers_preset_port"
# A UDP forward also keeps the set's id. Its rules are applied at once, while
# vars.yml is rolled back with the HAProxy sources (discarding unapplied
# changes, a transaction that is rolled back, a restored history version);
# by the id a forward still finds its set when that took a rename back.
ID_FIELD = "servers_preset_id"
ID_RE = re.compile(r"^[0-9a-f]{12}$")
# Letters or digits first, then also spaces, dots, dashes and underscores.
# \w is Unicode here, so a name in Cyrillic is fine too.
NAME_RE = re.compile(r"^[^\W_][\w .-]{0,47}$")
NOTE_MAX = 64
MAX_PRESETS = 50
MAX_SERVERS = 16
ROLES = ("primary", "backup")


def _dump(data: Dict[str, Any]) -> str:
    return yaml.safe_dump(data, allow_unicode=True, sort_keys=False, default_flow_style=False)


def presets_from(vars_data: Any) -> List[Dict[str, Any]]:
    """The sets stored in a loaded vars.yml, skipping anything malformed."""
    raw = vars_data.get(PRESETS_KEY) if isinstance(vars_data, dict) else None
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict) and item.get("name")]


def load_presets() -> List[Dict[str, Any]]:
    return presets_from(_load_yaml(CONFIG_YAML))


def find(presets: List[Dict[str, Any]], name: Any) -> Optional[Dict[str, Any]]:
    wanted = str(name or "").strip()
    return next((p for p in presets if str(p.get("name")) == wanted), None)


def effective_id(preset: Dict[str, Any]) -> str:
    """A set's id: the stored one, or for a set saved before ids existed one
    derived from its name.

    A set of the old schema gets that same derived id when it is next saved,
    so an applied snapshot or a history version taken before ids -- which
    holds the set under its old name and without an id -- still matches the
    id a UDP forward was given at the rename.
    """
    stored = str(preset.get("id") or "")
    if ID_RE.fullmatch(stored):
        return stored
    return hashlib.sha256(f"backend-set:{preset.get('name')}".encode("utf-8")).hexdigest()[:12]


def find_by_id(presets: List[Dict[str, Any]], preset_id: Any) -> Optional[Dict[str, Any]]:
    wanted = str(preset_id or "").strip()
    if not ID_RE.fullmatch(wanted):
        return None
    return next((p for p in presets if effective_id(p) == wanted), None)


def new_id() -> str:
    return secrets.token_hex(6)


def preset_revision(preset: Dict[str, Any]) -> str:
    return entry_revision(preset)


def normalize_preset(raw: Any) -> Dict[str, Any]:
    """Validate one set from the form; raises ValueError with the reason."""
    if not isinstance(raw, dict):
        raise ValueError("Invalid backend set (expected an object)")
    name = str(raw.get("name") or "").strip()
    if not NAME_RE.fullmatch(name):
        raise ValueError(
            "Backend set name: up to 48 letters, digits, spaces, dots, dashes or underscores, "
            "starting with a letter or digit"
        )
    servers_in = raw.get("servers")
    if not isinstance(servers_in, list):
        raise ValueError("A backend set needs a list of addresses")
    servers: List[Dict[str, Any]] = []
    seen = set()
    for index, item in enumerate(servers_in, start=1):
        if not isinstance(item, dict):
            continue
        host_text = str(item.get("host") or "").strip()
        if not host_text:
            continue
        host = validate_host(host_text, f"address {index}")
        if host.lower() in seen:
            raise ValueError(f"Address {host} appears twice in the set")
        seen.add(host.lower())
        role = str(item.get("role") or "primary").strip().lower()
        if role not in ROLES:
            raise ValueError(f"Address {index}: role must be primary or backup")
        server: Dict[str, Any] = {"host": host, "role": role}
        weight = item.get("weight")
        if weight not in (None, ""):
            try:
                weight_int = int(weight)
            except (TypeError, ValueError):
                raise ValueError(f"Address {index}: weight must be a number from 1 to 256") from None
            if not 1 <= weight_int <= 256:
                raise ValueError(f"Address {index}: weight must be a number from 1 to 256")
            server["weight"] = weight_int
        note = " ".join(str(item.get("note") or "").split())[:NOTE_MAX]
        if note:
            server["note"] = note
        servers.append(server)
    if not servers:
        raise ValueError("A backend set needs at least one address")
    if len(servers) > MAX_SERVERS:
        raise ValueError(f"A backend set holds at most {MAX_SERVERS} addresses")
    if not any(s["role"] == "primary" for s in servers):
        raise ValueError("A backend set needs at least one primary address")
    return {"name": name, "servers": servers}


def expand_servers(preset: Dict[str, Any], port: int, *, weights: bool = True) -> List[Dict[str, Any]]:
    """The HAProxy server list a set stands for: primaries srvN, backups backupN."""
    out: List[Dict[str, Any]] = []
    primary = backup = 0
    for server in preset.get("servers") or []:
        is_backup = server.get("role") == "backup"
        if is_backup:
            backup += 1
            name = f"backup{backup}"
        else:
            primary += 1
            name = f"srv{primary}"
        entry: Dict[str, Any] = {"name": name, "host": server["host"], "port": port}
        if is_backup:
            entry["backup"] = True
        if weights and server.get("weight"):
            entry["weight"] = server["weight"]
        out.append(entry)
    return out


def _reference(entry: Dict[str, Any], presets: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The set an entry names, or None when it names none; ValueError when it is gone.

    The name decides; a UDP forward's id finds its set under another name,
    when a rollback of vars.yml took a rename back.
    """
    name = str(entry.get(PRESET_FIELD) or "").strip()
    if not name:
        for field in (PRESET_FIELD, PORT_FIELD, ID_FIELD):
            entry.pop(field, None)
        return None
    preset = find(presets, name) or find_by_id(presets, entry.get(ID_FIELD))
    if preset is None:
        raise ValueError(f"Backend set {name!r} does not exist")
    entry[PRESET_FIELD] = preset["name"]
    return preset


def apply_to_site(entry: Dict[str, Any], presets: List[Dict[str, Any]]) -> None:
    """Expand a site's set into its servers (in place)."""
    preset = _reference(entry, presets)
    if preset is None:
        return
    port = validate_port(entry.get(PORT_FIELD), "backend set port")
    entry[PORT_FIELD] = port
    entry["servers"] = expand_servers(preset, port, weights=True)
    entry.pop("backend_ip", None)
    entry.pop("backend_port", None)


def apply_to_tcp(entry: Dict[str, Any], presets: List[Dict[str, Any]]) -> None:
    """Expand a TCP proxy's set into its servers (in place)."""
    preset = _reference(entry, presets)
    if preset is None:
        return
    port = validate_port(entry.get(PORT_FIELD), "backend set port")
    entry[PORT_FIELD] = port
    entry["servers"] = expand_servers(preset, port, weights=False)
    entry.pop("backend_host", None)
    entry.pop("backend_port", None)


def apply_to_udp(entry: Dict[str, Any], presets: List[Dict[str, Any]]) -> None:
    """Fill a UDP forward's main and backup host from its set (in place).

    A forward has one main backend and at most one backup, so it takes the
    set's first primary and first backup; the port stays the forward's own.
    """
    preset = _reference(entry, presets)
    entry.pop(PORT_FIELD, None)
    if preset is None:
        return
    entry[ID_FIELD] = effective_id(preset)
    servers = preset.get("servers") or []
    primary = next((s["host"] for s in servers if s.get("role") != "backup"), "")
    backup = next((s["host"] for s in servers if s.get("role") == "backup"), "")
    entry["backend_host"] = primary
    if backup:
        entry["backup_host"] = backup
    else:
        for field in ("backup_host", "backup_port", "health_check", "health_port"):
            entry.pop(field, None)


def _sites(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    sites = data.get("sites")
    return [s for s in sites if isinstance(s, dict)] if isinstance(sites, list) else []


def _tcp(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    proxies = data.get("tcp_proxies", data.get("tcp"))
    return [p for p in proxies if isinstance(p, dict)] if isinstance(proxies, list) else []


def _udp(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    forwards = data.get("udp_forwards", data.get("udp"))
    return [f for f in forwards if isinstance(f, dict)] if isinstance(forwards, list) else []


def usage(
    websites: Optional[Dict[str, Any]] = None,
    tcp: Optional[Dict[str, Any]] = None,
    udp: Optional[Dict[str, Any]] = None,
    presets: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, List[Dict[str, str]]]:
    """{set name: [{"kind": "site"|"tcp"|"udp", "name": entry}]} for every reference.

    A UDP forward counts for the set its id names, whatever name it still
    carries after a rollback of vars.yml.
    """
    websites = _load_yaml(WEBSITES_YAML) if websites is None else websites
    tcp = _load_yaml(TCP_YAML) if tcp is None else tcp
    udp = _load_yaml(UDP_YAML) if udp is None else udp
    presets = load_presets() if presets is None else presets
    found: Dict[str, List[Dict[str, str]]] = {}
    for kind, entries in (("site", _sites(websites)), ("tcp", _tcp(tcp)), ("udp", _udp(udp))):
        for entry in entries:
            name = str(entry.get(PRESET_FIELD) or "").strip()
            if not name:
                continue
            if kind == "udp":
                by_id = find_by_id(presets, entry.get(ID_FIELD))
                if by_id is not None:
                    name = str(by_id["name"])
            found.setdefault(name, []).append({"kind": kind, "name": str(entry.get("name") or "")})
    return found


def _repoint(entries: List[Dict[str, Any]], old: Optional[str], new: str) -> List[Dict[str, Any]]:
    """Entries that name the set, renamed to its new name where it was renamed."""
    touched = []
    for entry in entries:
        name = str(entry.get(PRESET_FIELD) or "").strip()
        if old and name == old:
            entry[PRESET_FIELD] = new
            touched.append(entry)
        elif name == new:
            touched.append(entry)
    return touched


def _repoint_udp(
    forwards: List[Dict[str, Any]], old: Optional[str], preset: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """Forwards that use the set -- by its old or new name, or by its id."""
    touched = []
    for forward in forwards:
        name = str(forward.get(PRESET_FIELD) or "").strip()
        if not name:
            continue
        same_id = forward.get(ID_FIELD) == effective_id(preset)
        if same_id or name == preset["name"] or (old and name == old):
            forward[PRESET_FIELD] = preset["name"]
            touched.append(forward)
    return touched


def _expand_udp(
    data: Dict[str, Any], touched: List[Dict[str, Any]], presets: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """udp.yml with the touched forwards expanded against ``presets``.

    Raises ValueError naming the forward that the sets no longer fit.
    """
    from .services_haproxy_udp import _normalize_udp_entry

    normalized: List[Dict[str, Any]] = []
    for forward in _udp(data):
        if any(forward is item for item in touched):
            ok, msg, clean = _normalize_udp_entry(forward, presets)
            if not ok or clean is None:
                raise ValueError(f"UDP forward {forward.get('name')}: {msg}")
            normalized.append(clean)
        else:
            normalized.append(forward)
    out = dict(data)
    out.pop("udp", None)
    out["udp_forwards"] = normalized
    return out


def _snapshot(*paths) -> List[Tuple[Any, Optional[bytes], int]]:
    """The bytes and mode of each source, to put them back exactly."""
    taken = []
    for path in paths:
        try:
            taken.append((path, path.read_bytes(), path.stat().st_mode & 0o777))
        except FileNotFoundError:
            taken.append((path, None, 0o640))
    return taken


def _put_back(snapshot: List[Tuple[Any, Optional[bytes], int]]) -> List[str]:
    """Restore a snapshot; the files that could not be restored."""
    from .services_haproxy_config import _atomic_write_snapshot

    failed = []
    for path, raw, mode in snapshot:
        try:
            if raw is None:
                path.unlink(missing_ok=True)
            else:
                _atomic_write_snapshot(path, raw, mode=mode)
        except OSError as exc:
            failed.append(f"{path.name}: {exc}")
    return failed


def save_preset(
    raw: Any, original_name: Optional[str] = None, expected_revision: Optional[str] = None
) -> Tuple[bool, str]:
    """Create or change a set and expand it again everywhere it is named.

    Sites and TCP proxies change in websites.yml and tcp.yml like any other
    edit and take effect when the HAProxy configuration is applied. UDP
    forwards are applied at once, as their own page does.

    All or nothing: every entry is expanded and checked against the new set
    before a file is written, all four sources stay locked to the end, and
    when the UDP rules cannot be applied vars.yml, websites.yml and tcp.yml
    go back to what they were. A rename half done -- the new name in vars.yml,
    the forwards still on the old one -- made the next save of the same form
    fail with "not found".
    """
    from . import services_haproxy_udp as udp_service

    try:
        preset = normalize_preset(raw)
    except ValueError as exc:
        return False, str(exc)
    pending, message = config_transaction_is_pending()
    if pending:
        return False, message
    original = (original_name or "").strip() or None

    try:
        with source_lock("websites"), source_lock("tcp"), source_lock("vars"), source_lock("udp"):
            vars_data = _load_yaml(CONFIG_YAML)
            presets = presets_from(vars_data)
            if original:
                index = next((i for i, p in enumerate(presets) if p.get("name") == original), None)
                if index is None:
                    return False, f"Backend set {original!r} was not found"
                check_entry_revision(presets[index], expected_revision, "This backend set")
                if preset["name"] != original and find(presets, preset["name"]):
                    return False, f"Backend set {preset['name']!r} already exists"
                # Keeps the id, or fixes the derived one of an old-schema set
                # from the name it had until now.
                preset = {"id": effective_id(presets[index]), **preset}
                presets[index] = preset
            else:
                if find(presets, preset["name"]):
                    return False, f"Backend set {preset['name']!r} already exists"
                if len(presets) >= MAX_PRESETS:
                    return False, f"At most {MAX_PRESETS} backend sets"
                preset = {"id": new_id(), **preset}
                presets.append(preset)
            vars_data[PRESETS_KEY] = presets

            websites = _load_yaml(WEBSITES_YAML)
            tcp = _load_yaml(TCP_YAML)
            udp = _load_yaml(UDP_YAML)
            sites = _repoint(_sites(websites), original, preset["name"])
            proxies = _repoint(_tcp(tcp), original, preset["name"])
            forwards = _repoint_udp(_udp(udp), original, preset)
            try:
                for site in sites:
                    apply_to_site(site, presets)
                for proxy in proxies:
                    apply_to_tcp(proxy, presets)
                new_udp = _expand_udp(udp, forwards, presets) if forwards else None
                validate_config_data("vars", vars_data)
                if sites:
                    validate_config_data("websites", websites)
                if proxies:
                    validate_config_data("tcp", tcp)
            except ValueError as exc:
                return False, str(exc)

            before = _snapshot(CONFIG_YAML, WEBSITES_YAML, TCP_YAML)
            writes = [("vars", vars_data)]
            if sites:
                writes.append(("websites", websites))
            if proxies:
                writes.append(("tcp", tcp))
            for kind, data in writes:
                ok, msg = update_yaml_file(kind, _dump(data))
                if not ok:
                    failed = _put_back(before)
                    return False, msg + (f" Restoring failed: {'; '.join(failed)}" if failed else "")
            if new_udp is not None:
                ok, msg = udp_service._write_and_apply(new_udp)
                if not ok:
                    failed = _put_back(before)
                    if failed:
                        return False, (
                            f"The UDP forwards were not updated: {msg} Restoring the other "
                            f"sources also failed: {'; '.join(failed)}"
                        )
                    return False, f"The UDP forwards were not updated, so the set was not saved: {msg}"
    except StaleEntry as exc:
        return False, str(exc)

    parts = [f"Backend set {preset['name']!r} saved."]
    if sites or proxies:
        parts.append(
            f"Updated {len(sites)} site(s) and {len(proxies)} TCP proxy(ies); "
            "validate and apply the HAProxy configuration to put them in effect."
        )
    if forwards:
        parts.append(f"{len(forwards)} UDP forward(s) updated and applied.")
    return True, " ".join(parts)


def reconcile_udp() -> Tuple[bool, int, str]:
    """Bring the UDP forwards back in line with the sets in vars.yml.

    vars.yml goes back with the HAProxy sources -- discarded changes, a
    transaction rolled back, a history version restored -- but the UDP rules
    were applied at once and stay. Each forward finds its set by id (then by
    name), takes its current name and addresses, and is applied again; a
    forward whose set is gone keeps its addresses and loses the reference.
    Nothing is written or applied when everything already agrees.
    """
    from . import services_haproxy_udp as udp_service

    with source_lock("udp"):
        presets = load_presets()
        data = _load_yaml(UDP_YAML)
        forwards = _udp(data)
        touched: List[Dict[str, Any]] = []
        dropped = 0
        for forward in forwards:
            name = str(forward.get(PRESET_FIELD) or "").strip()
            if not name:
                continue
            preset = find_by_id(presets, forward.get(ID_FIELD)) or find(presets, name)
            if preset is None:
                for field in (PRESET_FIELD, ID_FIELD):
                    forward.pop(field, None)
                dropped += 1
                continue
            before = {key: forward.get(key) for key in (PRESET_FIELD, ID_FIELD, "backend_host", "backup_host")}
            candidate = dict(forward, **{PRESET_FIELD: preset["name"]})
            apply_to_udp(candidate, presets)
            after = {key: candidate.get(key) for key in before}
            if after != before:
                forward[PRESET_FIELD] = preset["name"]
                touched.append(forward)
        if not touched and not dropped:
            return True, 0, ""
        try:
            new_udp = _expand_udp(data, touched, presets)
        except ValueError as exc:
            return False, 0, str(exc)
        ok, msg = udp_service._write_and_apply(new_udp)
        return ok, len(touched) + dropped, msg


# A reconciliation owed survives a failed attempt and a restart: the
# HAProxy transaction's own marker is gone by then, and a UDP apply that
# failed once (the rules busy, controld restarting) must be tried again.
FOLLOW_RETRY_SECONDS = 60


def _follow_path():
    return UDP_YAML.parent / ".backend-sets-udp-follow.json"


def _read_follow() -> Dict[str, Any]:
    try:
        value = json.loads(_follow_path().read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _write_follow(state: Dict[str, Any]) -> None:
    path = _follow_path()
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(state), encoding="utf-8")
    os.replace(temporary, path)


def mark_udp_follow(where: str) -> None:
    """Record that the UDP forwards owe a reconciliation.

    Each record gets a fresh token. An attempt clears the record only if it
    is still the one the attempt started from: vars.yml may have moved
    again, and been recorded again, while the attempt was reading it.
    """
    with source_lock("udp"):
        state = _read_follow()
        state.update({
            "where": where,
            "since": state.get("since") or int(time.time()),
            "next": 0,
            "token": secrets.token_hex(8),
        })
        try:
            _write_follow(state)
        except OSError as exc:
            logger.warning("Could not record a pending UDP reconciliation after %s: %s", where, exc)


def follow_udp(*, force: bool = False) -> str:
    """Run the reconciliation owed, if any; a line to report, or ''.

    Cleared only once the forwards agree with the sets and nobody recorded a
    newer debt meanwhile. A failure keeps the record with its error for the
    UDP page and is tried again on a later call, at most once a minute
    unless ``force``.
    """
    state = _read_follow()
    if not state:
        return ""
    if not force and time.time() < float(state.get("next") or 0):
        return f"The UDP forwards have not followed the backend sets yet: {state.get('error') or 'waiting'}"
    token = state.get("token")
    try:
        ok, count, msg = reconcile_udp()
    except Exception as exc:  # noqa: BLE001 -- a status poll or revert must still answer
        ok, count, msg = False, 0, f"{type(exc).__name__}: {exc}"
    with source_lock("udp"):
        current = _read_follow()
        if current.get("token") != token:
            # Recorded again while this attempt ran: the next call goes on.
            return f"{count} UDP forward(s) followed the backend sets and were applied again." if ok and count else ""
        if ok:
            try:
                _follow_path().unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                logger.warning("Could not clear the pending UDP reconciliation: %s", exc)
            return f"{count} UDP forward(s) followed the backend sets and were applied again." if count else ""
        logger.warning("UDP forwards not reconciled with the backend sets after %s: %s", current.get("where"), msg)
        current.update({"error": str(msg)[:500], "next": time.time() + FOLLOW_RETRY_SECONDS})
        try:
            _write_follow(current)
        except OSError:
            pass
    return f"The UDP forwards could not follow the backend sets: {msg}"


def follow_udp_error() -> str:
    """The last error of a reconciliation still owed, for the UDP page; '' when none is owed."""
    state = _read_follow()
    if not state:
        return ""
    return str(state.get("error") or "waiting for the next attempt")


def delete_preset(name: str) -> Tuple[bool, str]:
    """Remove a set nobody names any more.

    udp.yml stays locked from the check to the write: a UDP forward saved
    alongside used to pass the check and keep naming the deleted set.
    """
    name = (name or "").strip()
    pending, message = config_transaction_is_pending()
    if pending:
        return False, message
    with source_lock("websites"), source_lock("tcp"), source_lock("vars"), source_lock("udp"):
        vars_data = _load_yaml(CONFIG_YAML)
        presets = presets_from(vars_data)
        if find(presets, name) is None:
            return False, f"Backend set {name!r} was not found"
        users = usage(presets=presets).get(name) or []
        if users:
            listed = ", ".join(u["name"] for u in users[:5])
            return False, (
                f"Backend set {name!r} is used by {len(users)} entr(ies): {listed}. "
                "Switch them to another set or to manual addresses first."
            )
        vars_data[PRESETS_KEY] = [p for p in presets if p.get("name") != name]
        if not vars_data[PRESETS_KEY]:
            vars_data.pop(PRESETS_KEY)
        return update_yaml_file("vars", _dump(vars_data))
