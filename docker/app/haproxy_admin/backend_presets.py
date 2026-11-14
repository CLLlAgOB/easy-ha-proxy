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

import re
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

PRESETS_KEY = "backend_presets"
PRESET_FIELD = "servers_preset"
PORT_FIELD = "servers_preset_port"
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
    """The set an entry names, or None when it names none; ValueError when it is gone."""
    name = str(entry.get(PRESET_FIELD) or "").strip()
    if not name:
        entry.pop(PRESET_FIELD, None)
        entry.pop(PORT_FIELD, None)
        return None
    preset = find(presets, name)
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
) -> Dict[str, List[Dict[str, str]]]:
    """{set name: [{"kind": "site"|"tcp"|"udp", "name": entry}]} for every reference."""
    websites = _load_yaml(WEBSITES_YAML) if websites is None else websites
    tcp = _load_yaml(TCP_YAML) if tcp is None else tcp
    udp = _load_yaml(UDP_YAML) if udp is None else udp
    found: Dict[str, List[Dict[str, str]]] = {}
    for kind, entries in (("site", _sites(websites)), ("tcp", _tcp(tcp)), ("udp", _udp(udp))):
        for entry in entries:
            name = str(entry.get(PRESET_FIELD) or "").strip()
            if name:
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


def save_preset(
    raw: Any, original_name: Optional[str] = None, expected_revision: Optional[str] = None
) -> Tuple[bool, str]:
    """Create or change a set and expand it again everywhere it is named.

    Sites and TCP proxies change in websites.yml and tcp.yml like any other
    edit and take effect when the HAProxy configuration is applied. UDP
    forwards are applied at once, as their own page does.
    """
    try:
        preset = normalize_preset(raw)
    except ValueError as exc:
        return False, str(exc)
    pending, message = config_transaction_is_pending()
    if pending:
        return False, message
    original = (original_name or "").strip() or None

    try:
        with source_lock("websites"), source_lock("tcp"), source_lock("vars"):
            vars_data = _load_yaml(CONFIG_YAML)
            presets = presets_from(vars_data)
            if original:
                index = next((i for i, p in enumerate(presets) if p.get("name") == original), None)
                if index is None:
                    return False, f"Backend set {original!r} was not found"
                check_entry_revision(presets[index], expected_revision, "This backend set")
                if preset["name"] != original and find(presets, preset["name"]):
                    return False, f"Backend set {preset['name']!r} already exists"
                presets[index] = preset
            else:
                if find(presets, preset["name"]):
                    return False, f"Backend set {preset['name']!r} already exists"
                if len(presets) >= MAX_PRESETS:
                    return False, f"At most {MAX_PRESETS} backend sets"
                presets.append(preset)
            vars_data[PRESETS_KEY] = presets

            websites = _load_yaml(WEBSITES_YAML)
            tcp = _load_yaml(TCP_YAML)
            sites = _repoint(_sites(websites), original, preset["name"])
            proxies = _repoint(_tcp(tcp), original, preset["name"])
            try:
                for site in sites:
                    apply_to_site(site, presets)
                for proxy in proxies:
                    apply_to_tcp(proxy, presets)
                validate_config_data("vars", vars_data)
                if sites:
                    validate_config_data("websites", websites)
                if proxies:
                    validate_config_data("tcp", tcp)
            except ValueError as exc:
                return False, str(exc)

            ok, msg = update_yaml_file("vars", _dump(vars_data))
            if not ok:
                return False, msg
            if sites:
                ok, msg = update_yaml_file("websites", _dump(websites))
                if not ok:
                    return False, msg
            if proxies:
                ok, msg = update_yaml_file("tcp", _dump(tcp))
                if not ok:
                    return False, msg
    except StaleEntry as exc:
        return False, str(exc)

    udp_ok, udp_count, udp_msg = _reapply_udp(original, preset["name"])
    parts = [f"Backend set {preset['name']!r} saved."]
    if sites or proxies:
        parts.append(
            f"Updated {len(sites)} site(s) and {len(proxies)} TCP proxy(ies); "
            "validate and apply the HAProxy configuration to put them in effect."
        )
    if udp_count:
        parts.append(f"{udp_count} UDP forward(s) updated and applied.")
    if not udp_ok:
        return False, " ".join(parts) + f" The UDP forwards were not updated: {udp_msg}"
    return True, " ".join(parts)


def _reapply_udp(original: Optional[str], name: str) -> Tuple[bool, int, str]:
    """Expand the set again in the UDP forwards that name it, and apply them."""
    from .services_haproxy_udp import _normalize_udp_entry, _write_and_apply

    with source_lock("udp"):
        data = _load_yaml(UDP_YAML)
        forwards = _udp(data)
        touched = _repoint(forwards, original, name)
        if not touched:
            return True, 0, ""
        presets = load_presets()
        normalized: List[Dict[str, Any]] = []
        for forward in forwards:
            if any(forward is item for item in touched):
                try:
                    apply_to_udp(forward, presets)
                except ValueError as exc:
                    return False, 0, str(exc)
                ok, msg, clean = _normalize_udp_entry(forward)
                if not ok or clean is None:
                    return False, 0, f"{forward.get('name')}: {msg}"
                normalized.append(clean)
            else:
                normalized.append(forward)
        data.pop("udp", None)
        data["udp_forwards"] = normalized
        ok, msg = _write_and_apply(data)
        return ok, len(touched), msg


def delete_preset(name: str) -> Tuple[bool, str]:
    """Remove a set nobody names any more."""
    name = (name or "").strip()
    pending, message = config_transaction_is_pending()
    if pending:
        return False, message
    with source_lock("websites"), source_lock("tcp"), source_lock("vars"):
        vars_data = _load_yaml(CONFIG_YAML)
        presets = presets_from(vars_data)
        if find(presets, name) is None:
            return False, f"Backend set {name!r} was not found"
        users = usage().get(name) or []
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
