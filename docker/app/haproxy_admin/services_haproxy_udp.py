# services_haproxy_udp.py
# Kernel-NAT UDP forwarding (variant A): read/write udp.yml and ask
# haproxy-controld to reload the iptables DNAT rules. UDP is NOT part of
# haproxy.cfg, so this path is independent of the HAProxy config bundle.

import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple

import yaml

from .services_haproxy_config import (
    UDP_YAML,
    _atomic_write_snapshot,
    _load_yaml,
    apply_udp_forwards,
    get_udp_runtime_status,
    udp_listen_port_conflict,
)
from .validation import (
    validate_host,
    validate_identifier,
)

_MAX_UDP_YAML_BYTES = 512 * 1024
_MAX_PORTS_PER_FORWARD = 1024
_PORT_RANGE_RE = re.compile(r"^([0-9]{1,5})(?:-([0-9]{1,5}))?$")


def get_udp_forwards_list() -> List[Dict[str, Any]]:
    """Return the UDP forwards from udp.yml (supports udp_forwards or udp)."""
    data = _load_yaml(UDP_YAML)
    forwards = data.get("udp_forwards")
    if forwards is None:
        forwards = data.get("udp")
    if not isinstance(forwards, list):
        return []
    return forwards


def get_udp_status() -> Dict[str, Any]:
    return get_udp_runtime_status()


def _parse_port_range(
    value: Any,
    label: str,
) -> Tuple[int, int, int | str]:
    text = str(value if value is not None else "").strip()
    match = _PORT_RANGE_RE.fullmatch(text)
    if not match:
        raise ValueError(
            f"{label} must be a port or inclusive range such as 51820-51830"
        )
    start = int(match.group(1))
    end = int(match.group(2) or start)
    if not 1 <= start <= 65535 or not 1 <= end <= 65535:
        raise ValueError(f"{label} must be between 1 and 65535")
    if end < start:
        raise ValueError(f"{label} range end must not be lower than its start")
    if end - start + 1 > _MAX_PORTS_PER_FORWARD:
        raise ValueError(
            f"{label} range may contain at most {_MAX_PORTS_PER_FORWARD} ports"
        )
    canonical: int | str = start if start == end else f"{start}-{end}"
    return start, end, canonical


def _boolean(raw: Dict[str, Any], field: str, default: bool) -> bool:
    if field not in raw:
        return default
    value = raw[field]
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be true or false")
    return value


def _normalize_udp_entry(
    raw: Dict[str, Any]
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Validate one UDP forward into a normalized, injection-safe record."""
    if not isinstance(raw, dict):
        return False, "Invalid UDP forward format (expected a JSON object)", None

    out: Dict[str, Any] = {}
    try:
        out["name"] = validate_identifier(raw.get("name"), "name")
        listen_start, listen_end, listen_value = _parse_port_range(
            raw.get("listen_port"), "listen_port"
        )
        out["listen_port"] = listen_value
        out["backend_host"] = validate_host(raw.get("backend_host"), "backend_host")
        if out["backend_host"].lower() == "localhost":
            raise ValueError(
                "backend_host must not use a loopback address; "
                "use a container or LAN backend"
            )
        try:
            backend_address = ipaddress.ip_address(out["backend_host"])
        except ValueError:
            backend_address = None
        if backend_address is not None and backend_address.is_loopback:
            raise ValueError(
                "backend_host must not use a loopback address; "
                "use a container or LAN backend"
            )
        backend_start, backend_end, backend_value = _parse_port_range(
            raw.get("backend_port"), "backend_port"
        )
        out["backend_port"] = backend_value
        if listen_end - listen_start != backend_end - backend_start:
            raise ValueError(
                "listen_port and backend_port ranges must contain the same "
                "number of ports"
            )
        out["ban_check"] = _boolean(raw, "ban_check", True)
        out["zero_trust"] = _boolean(raw, "zero_trust", False)
        out["enabled"] = _boolean(raw, "enabled", True)
    except ValueError as exc:
        return False, str(exc), None

    return True, "", out


def _range_for_entry(
    entry: Dict[str, Any],
) -> Tuple[int, int]:
    start, end, _canonical = _parse_port_range(
        entry.get("listen_port"), "existing listen_port"
    )
    return start, end


def _overlapping_forward(
    forwards: List[Dict[str, Any]],
    *,
    start: int,
    end: int,
    skip_index: Optional[int] = None,
) -> Optional[str]:
    for index, current in enumerate(forwards):
        if index == skip_index or current.get("enabled") is False:
            continue
        try:
            current_start, current_end = _range_for_entry(current)
        except ValueError as exc:
            return f"Existing UDP configuration is invalid: {exc}"
        if start <= current_end and current_start <= end:
            return (
                f"UDP listen range {start}-{end} overlaps "
                f"{current.get('name', 'another forward')!r} "
                f"({current_start}-{current_end})"
            )
    return None


def _success_message(state: Dict[str, Any]) -> str:
    return (
        "UDP forwarding applied immediately. "
        f"Active forwards: {int(state.get('forwards', 0))}; "
        f"forwarded ports: {int(state.get('ports', 0))}; "
        f"applied at: {str(state.get('applied_at') or 'unknown')}."
    )


def _write_and_apply(data: Dict[str, Any]) -> Tuple[bool, str]:
    content = yaml.safe_dump(
        data,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )
    raw = content.encode("utf-8")
    if len(raw) > _MAX_UDP_YAML_BYTES:
        return False, "udp.yml exceeds the size limit"
    previous_exists = UDP_YAML.exists()
    try:
        previous_raw = UDP_YAML.read_bytes() if previous_exists else b"udp_forwards: []\n"
        mode = (UDP_YAML.stat().st_mode & 0o777) if previous_exists else 0o640
    except OSError as exc:
        return False, f"Failed to read the previous {UDP_YAML.name}: {exc}"
    try:
        _atomic_write_snapshot(UDP_YAML, raw, mode=mode)
    except OSError as exc:
        return False, f"Failed to write {UDP_YAML.name}: {exc}"

    ok, state, err = apply_udp_forwards()
    if ok:
        return True, _success_message(state)

    try:
        _atomic_write_snapshot(UDP_YAML, previous_raw, mode=mode)
    except OSError as rollback_write_error:
        return (
            False,
            "Applying the UDP rules failed and restoring udp.yml also failed: "
            f"{err}; restore error: {rollback_write_error}",
        )
    rollback_ok, _rollback_state, rollback_error = apply_udp_forwards()
    if rollback_ok:
        return (
            False,
            "Applying the UDP rules failed. The previous configuration and "
            f"rules were restored automatically: {err}",
        )
    return (
        False,
        "Applying the UDP rules failed and automatic rule rollback also "
        f"failed: {err}; rollback error: {rollback_error}",
    )


def save_udp_from_json(
    udp: Dict[str, Any], original_name: Optional[str] = None
) -> Tuple[bool, str]:
    """Create or edit one UDP forward from the edit form JSON."""
    ok, msg, entry = _normalize_udp_entry(udp)
    if not ok or entry is None:
        return False, msg
    name = entry["name"]

    data = _load_yaml(UDP_YAML)
    forwards = data.get("udp_forwards")
    if forwards is None:
        forwards = data.get("udp")
    if not isinstance(forwards, list):
        forwards = []

    try:
        listen_start, listen_end, _listen_value = _parse_port_range(
            entry["listen_port"], "listen_port"
        )
    except ValueError as exc:
        return False, str(exc)
    if original_name:
        idx = next(
            (i for i, f in enumerate(forwards) if f.get("name") == original_name),
            None,
        )
        if idx is None:
            return False, f"UDP forward with name={original_name!r} not found"
        if name != original_name and any(f.get("name") == name for f in forwards):
            return False, f"UDP forward with name={name!r} already exists"
        overlap = _overlapping_forward(
            forwards,
            start=listen_start,
            end=listen_end,
            skip_index=idx,
        )
        if overlap:
            return False, overlap
        if entry["enabled"]:
            conflict = udp_listen_port_conflict(listen_start, listen_end)
            if conflict:
                return False, conflict
        forwards[idx] = entry
    else:
        if any(f.get("name") == name for f in forwards):
            return False, f"UDP forward with name={name!r} already exists"
        overlap = _overlapping_forward(
            forwards,
            start=listen_start,
            end=listen_end,
        )
        if overlap:
            return False, overlap
        if entry["enabled"]:
            conflict = udp_listen_port_conflict(listen_start, listen_end)
            if conflict:
                return False, conflict
        forwards.append(entry)

    data.pop("udp", None)
    data["udp_forwards"] = forwards
    return _write_and_apply(data)


def delete_udp_forward(name: str) -> Tuple[bool, str]:
    """Remove one UDP forward by name and re-apply."""
    data = _load_yaml(UDP_YAML)
    forwards = data.get("udp_forwards")
    if forwards is None:
        forwards = data.get("udp")
    if not isinstance(forwards, list):
        return False, "Invalid udp.yml structure (expected a udp_forwards list)"

    new_list = [f for f in forwards if f.get("name") != name]
    if len(new_list) == len(forwards):
        return False, f"UDP forward with name={name!r} not found"

    data.pop("udp", None)
    data["udp_forwards"] = new_list
    return _write_and_apply(data)
