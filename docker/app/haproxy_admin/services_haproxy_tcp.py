# services_haproxy_tcp.py
# Helpers for tcp.yml (the TCP proxies):
# - the list of TCP proxies
# - adding and removing
# - saving one entry from JSON (the edit page)

from typing import Any, Dict, List, Tuple, Optional
import yaml

from . import backend_presets
from .services_haproxy_config import (
    TCP_YAML,
    _load_yaml,
    check_entry_revision,
    entry_revision,
    source_lock,
    update_yaml_file,
)
from .validation import (
    BALANCE_VALUES,
    INTERVAL_RE,
    tcp_identity_conflict,
    validate_host,
    validate_identifier,
    validate_port,
)


def get_tcp_proxies_list() -> List[Dict[str, Any]]:
    """
    Returns the list of TCP proxies from tcp.yml, as it is.

    Both root keys are accepted:
      - tcp_proxies: [...]
      - tcp: [...]
    Saving always writes the key tcp_proxies, so the variants do not multiply.
    """
    data = _load_yaml(TCP_YAML)
    proxies = data.get("tcp_proxies")
    if proxies is None:
        proxies = data.get("tcp")
    if not isinstance(proxies, list):
        return []
    return proxies


def _normalize_tcp_entry(raw: Dict[str, Any]) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Normalises one TCP proxy entry.

    Checks:
      - name (required)
      - bind_port (1-65535)
      - backend_host/backend_port OR a list of servers[{host,port}]
    """
    if not isinstance(raw, dict):
        return False, 'Invalid TCP proxy format (expected a JSON object)', None

    out: Dict[str, Any] = dict(raw)

    # --- the basic fields name / bind_ip / bind_port -----------------------------
    try:
        name = validate_identifier(out.get("name"), "name")
    except ValueError as exc:
        return False, str(exc), None
    out["name"] = name

    try:
        bind_ip = validate_host(out.get("bind_ip") or "0.0.0.0", "bind_ip")
    except ValueError as exc:
        return False, str(exc), None
    out["bind_ip"] = bind_ip

    bind_port = out.get("bind_port")
    try:
        bind_port_int = validate_port(bind_port, "bind_port")
    except ValueError as exc:
        return False, str(exc), None
    out["bind_port"] = bind_port_int

    # --- security flags --------------------------------------------------
    out["zero_trust"] = bool(out.get("zero_trust", False))
    # ban_check is on by default
    out["ban_check"] = bool(out.get("ban_check", True))

    # --- balancing and the health check interval -------------------------------
    balance = str(out.get("balance") or "").strip() or "source"
    if balance not in BALANCE_VALUES:
        return False, 'Unsupported balance algorithm', None
    out["balance"] = balance

    inter = out.get("inter")
    if inter is not None:
        inter_s = str(inter).strip()
        if inter_s:
            if not INTERVAL_RE.fullmatch(inter_s):
                return False, 'inter must look like 500ms, 5s, 2m, or 1h', None
            out["inter"] = inter_s
        else:
            out.pop("inter", None)

    out["ssl_check"] = bool(out.get("ssl_check", False))

    # --- a backend set named instead of addresses ---------------------------
    try:
        backend_presets.apply_to_tcp(out, backend_presets.load_presets())
    except ValueError as exc:
        return False, str(exc), None

    # --- backend servers -----------------------------------------------------
    cleaned_servers: List[Dict[str, Any]] = []
    servers = out.get("servers")

    if isinstance(servers, list):
        for idx, srv in enumerate(servers, start=1):
            if not isinstance(srv, dict):
                continue
            host = str(srv.get("host") or "").strip()
            port = srv.get("port")

            if not host:
                # an empty backend is skipped
                continue

            try:
                host = validate_host(host, f"servers[{idx}].host")
                port_int = validate_port(port, f"servers[{idx}].port")
            except ValueError as exc:
                return False, str(exc), None

            srv_out: Dict[str, Any] = {}

            # The backend server's name
            name_srv = str(srv.get("name") or "").strip()
            if not name_srv:
                name_srv = f"srv{idx}"
            try:
                name_srv = validate_identifier(name_srv, f"servers[{idx}].name")
            except ValueError as exc:
                return False, str(exc), None

            srv_out["name"] = name_srv
            srv_out["host"] = host
            srv_out["port"] = port_int

            # a backup server takes traffic only when no regular server is up
            if bool(srv.get("backup")):
                srv_out["backup"] = True

            cleaned_servers.append(srv_out)

    # Proper servers are written as they are
    if cleaned_servers:
        out["servers"] = cleaned_servers
    else:
        out.pop("servers", None)

    # --- backend_host / backend_port ----------------------------------------
    backend_host = str(out.get("backend_host") or "").strip()
    backend_port = out.get("backend_port")

    if backend_host and backend_port is not None:
        try:
            backend_host = validate_host(backend_host, "backend_host")
            backend_port_int = validate_port(backend_port, "backend_port")
        except ValueError as exc:
            return False, str(exc), None
        out["backend_host"] = backend_host
        out["backend_port"] = backend_port_int
    else:
        # If one of them is empty, drop both
        out.pop("backend_host", None)
        out.pop("backend_port", None)

    # IMPORTANT:
    # With more than one backend in servers, backend_host/backend_port are
    # obsolete and removed, so nothing contradicts.
    if out.get("servers") and isinstance(out["servers"], list) and len(out["servers"]) > 1:
        out.pop("backend_host", None)
        out.pop("backend_port", None)

    return True, "", out


def tcp_revision(name: str) -> Optional[str]:
    """The fingerprint of a stored TCP proxy, for its edit form; None when absent."""

    for proxy in get_tcp_proxies_list():
        if isinstance(proxy, dict) and proxy.get("name") == name:
            return entry_revision(proxy)
    return None


def save_tcp_from_json(
    tcp: Dict[str, Any],
    original_name: Optional[str] = None,
    expected_revision: Optional[str] = None,
) -> Tuple[bool, str]:
    """Save a TCP proxy from its form; raises StaleEntry when expected_revision
    no longer matches the stored proxy. See _save_tcp_from_json."""

    with source_lock("tcp"):
        return _save_tcp_from_json(tcp, original_name, expected_revision)


def _save_tcp_from_json(
    tcp: Dict[str, Any],
    original_name: Optional[str] = None,
    expected_revision: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Saves a TCP proxy from JSON (the edit or create form).

    tcp is what the front end sent, as it is.
    original_name:
      - empty/None  -> create a new one
      - non-empty   -> edit the existing one of this name; it may be renamed
    """
    ok, msg, tcp_out = _normalize_tcp_entry(tcp)
    if not ok or tcp_out is None:
        return False, msg

    data = _load_yaml(TCP_YAML)
    proxies = data.get("tcp_proxies")
    if proxies is None:
        proxies = data.get("tcp")
    if not isinstance(proxies, list):
        proxies = []

    # Editing
    if original_name:
        idx = None
        for i, t in enumerate(proxies):
            if t.get("name") == original_name:
                idx = i
                break
        if idx is None:
            return False, f"TCP proxy with name={original_name!r} not found"
        check_entry_revision(proxies[idx], expected_revision, "This TCP proxy")
        # A rename may not take another proxy's name, nor its port
        conflict = tcp_identity_conflict(tcp_out, proxies[:idx] + proxies[idx + 1:])
        if conflict:
            return False, conflict

        proxies[idx] = tcp_out

    # Creating
    else:
        conflict = tcp_identity_conflict(tcp_out, proxies)
        if conflict:
            return False, conflict
        proxies.append(tcp_out)

    # Saved under the key tcp_proxies
    data["tcp_proxies"] = proxies

    content = yaml.safe_dump(
        data,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )
    ok, msg = update_yaml_file("tcp", content)
    return ok, msg


def delete_tcp_proxy(name: str) -> Tuple[bool, str]:
    """
    Deletes the TCP proxy with this name from tcp.yml.
    """
    with source_lock("tcp"):
        return _delete_tcp_proxy(name)


def _delete_tcp_proxy(name: str) -> Tuple[bool, str]:
    data = _load_yaml(TCP_YAML)
    proxies = data.get("tcp_proxies")
    if proxies is None:
        proxies = data.get("tcp")
    if not isinstance(proxies, list):
        return False, 'Invalid tcp.yml structure (expected a tcp_proxies/tcp list)'

    new_list: List[Dict[str, Any]] = []
    removed = False
    for t in proxies:
        if t.get("name") == name:
            removed = True
            continue
        new_list.append(t)

    if not removed:
        return False, f"TCP proxy with name={name!r} not found"

    data["tcp_proxies"] = new_list

    content = yaml.safe_dump(
        data,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )
    ok, msg = update_yaml_file("tcp", content)
    return ok, msg
