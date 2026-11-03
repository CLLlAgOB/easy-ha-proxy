# -*- coding: utf-8 -*-
"""Configuration history: the list of versions and a meaningful comparison.

controld writes the versions when a transaction is confirmed; this module
only reads. The comparison is made on the managed model -- the sites, the
TCP proxies and the variables -- rather than on the rendered haproxy.cfg: a
diff of a thousand lines does not answer "what did I change".
"""

from __future__ import annotations

import base64
import contextlib
import logging
import os
import stat
import time
from typing import Any, Dict, List, Optional, Tuple

import yaml

from . import services_haproxy_config as _config
from .services_haproxy_config import (
    CONFIG_SOURCE_ORDER,
    _applied_config_source_paths,
    _controld_json_request,
    _current_config_source_paths,
    _read_config_source_bundle,
    source_lock,
)

LOG = logging.getLogger("haproxy-admin")

# Two "now"s, kept apart: CURRENT is what the editors have saved, which may
# hold changes nobody has applied yet; APPLIED is the last configuration
# confirmed in HAProxy. A save without an apply moves the first only.
CURRENT = "current"
APPLIED = "applied"
MAX_VERSIONS = 200
# A restore over unapplied changes sets them aside first; this many sets.
KEEP_SET_ASIDE = 5


class HistoryUnavailable(RuntimeError):
    """controld does not answer, or the history is unavailable."""


def _request(command: str) -> Dict[str, Any]:
    result = _controld_json_request(command, timeout=20)
    if not result.get("ok"):
        raise HistoryUnavailable(
            str(result.get("failure") or result.get("error") or "history unavailable")
        )
    return result


def list_versions(limit: int = 50) -> List[Dict[str, Any]]:
    limit = max(1, min(int(limit or 50), MAX_VERSIONS))
    return list(_request(f"config-versions {limit}").get("versions") or [])


def _decode(sources: Dict[str, Any]) -> Dict[str, str]:
    decoded: Dict[str, str] = {}
    for name, encoded in (sources or {}).items():
        if name not in CONFIG_SOURCE_ORDER:
            continue
        try:
            decoded[name] = base64.b64decode(str(encoded), validate=True).decode(
                "utf-8", "replace"
            )
        except Exception:  # pylint: disable=broad-except
            decoded[name] = ""
    return decoded


def version_sources(version_id: str) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """The metadata and contents of one version."""

    payload = _request(f"config-version {version_id}").get("version") or {}
    return payload, _decode(payload.get("sources") or {})


def current_sources() -> Dict[str, str]:
    """What the managed configuration holds right now.

    The working files, not `backups/haproxy/last_applied_*.yml`: those are
    the snapshot of the last applied state, the rollback point, and must not
    be written to.
    """

    bundle = _read_config_source_bundle(
        _current_config_source_paths(), label="current"
    )
    return {name: raw.decode("utf-8", "replace") for name, raw in bundle.items()}


def applied_sources() -> Dict[str, str]:
    """What was last confirmed in HAProxy: the applied-state snapshots."""

    try:
        bundle = _read_config_source_bundle(
            _applied_config_source_paths(), label="applied"
        )
    except ValueError as exc:
        raise ValueError("Nothing has been applied on this gateway yet") from exc
    return {name: raw.decode("utf-8", "replace") for name, raw in bundle.items()}


def unapplied_changes() -> Optional[bool]:
    """Whether the saved sources differ from the applied ones; None if unknown."""

    try:
        return current_sources() != applied_sources()
    except Exception:  # pylint: disable=broad-except
        return None


# ---------------------------------------------------------------------------
# Semantic comparison
# ---------------------------------------------------------------------------


def _load(text: str) -> Dict[str, Any]:
    try:
        data = yaml.safe_load(text or "") or {}
    except yaml.YAMLError:
        return {}
    return data if isinstance(data, dict) else {}


def _entries(data: Dict[str, Any], keys: Tuple[str, ...]) -> Dict[str, Dict[str, Any]]:
    """A list of entries -> a mapping by name, so the comparison is about substance.

    The order in the file does not matter: sites that merely swapped places
    are not a change, and showing them as one would be noise.
    """

    items: List[Any] = []
    for key in keys:
        value = data.get(key)
        if isinstance(value, list):
            items = value
            break
    mapping: Dict[str, Dict[str, Any]] = {}
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        name = str(
            item.get("name") or item.get("domain") or item.get("id") or index
        )
        mapping[name] = item
    return mapping


def _field_changes(before: Dict[str, Any], after: Dict[str, Any]) -> List[str]:
    changes: List[str] = []
    for key in sorted(set(before) | set(after)):
        old = before.get(key)
        new = after.get(key)
        if old == new:
            continue
        if key not in before:
            changes.append(f"+{key}: {_short(new)}")
        elif key not in after:
            changes.append(f"-{key}")
        else:
            changes.append(f"{key}: {_short(old)} → {_short(new)}")
    return changes


def _short(value: Any, limit: int = 60) -> str:
    text = str(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _compare_collection(
    before_text: str, after_text: str, keys: Tuple[str, ...], label: str
) -> List[Dict[str, Any]]:
    before = _entries(_load(before_text), keys)
    after = _entries(_load(after_text), keys)
    result: List[Dict[str, Any]] = []
    for name in sorted(set(before) | set(after)):
        if name not in before:
            result.append({"kind": label, "name": name, "change": "added"})
        elif name not in after:
            result.append({"kind": label, "name": name, "change": "removed"})
        else:
            fields = _field_changes(before[name], after[name])
            if fields:
                result.append(
                    {
                        "kind": label,
                        "name": name,
                        "change": "modified",
                        "fields": fields,
                    }
                )
    return result


def _compare_mapping(before_text: str, after_text: str) -> List[Dict[str, Any]]:
    before = _load(before_text)
    after = _load(after_text)
    changes = _field_changes(before, after)
    return [{"kind": "variable", "name": "", "change": "modified", "fields": changes}] \
        if changes else []


def compare(before: Dict[str, str], after: Dict[str, str]) -> Dict[str, Any]:
    """Compare two sets of sources by meaning."""

    changes: List[Dict[str, Any]] = []
    changes.extend(
        _compare_collection(
            before.get("websites.yml", ""),
            after.get("websites.yml", ""),
            ("sites",),
            "site",
        )
    )
    changes.extend(
        _compare_collection(
            before.get("tcp.yml", ""),
            after.get("tcp.yml", ""),
            ("tcp_proxies", "tcp"),
            "tcp",
        )
    )
    changes.extend(
        _compare_mapping(before.get("vars.yml", ""), after.get("vars.yml", ""))
    )
    return {
        "changes": changes,
        "identical": not changes,
        "files_changed": sorted(
            name
            for name in CONFIG_SOURCE_ORDER
            if before.get(name, "") != after.get(name, "")
        ),
    }


def diff(left: str, right: str) -> Dict[str, Any]:
    """Compare two versions; `current` is what is saved, `applied` what runs."""

    def load(identifier: str) -> Tuple[Dict[str, Any], Dict[str, str]]:
        if identifier == CURRENT:
            return {"id": CURRENT}, current_sources()
        if identifier == APPLIED:
            return {"id": APPLIED}, applied_sources()
        return version_sources(identifier)

    left_meta, left_sources = load(left)
    right_meta, right_sources = load(right)
    payload = compare(left_sources, right_sources)
    payload["left"] = left_meta
    payload["right"] = right_meta
    return payload


# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------


class RestoreError(RuntimeError):
    """The restore did not start; the managed configuration is unchanged."""

    def __init__(self, message: str, *, error_code: str = "restore_failed") -> None:
        super().__init__(message)
        self.error_code = error_code


def _write_sources(sources: Dict[str, str]) -> None:
    """Put the managed YAML files in place: all of them or none.

    Every file is written beside its target first; only then are they moved
    in. A failure part way through puts back the ones already moved, so the
    editors never see a mix of two versions.
    """

    paths = _current_config_source_paths()
    staged: List[Tuple[Any, Any]] = []
    try:
        for name in CONFIG_SOURCE_ORDER:
            target = paths[name]
            temporary = target.with_name(f".{target.name}.restore")
            temporary.write_text(sources[name], encoding="utf-8")
            try:
                # Keep whatever ownership and mode the live file already had.
                existing = target.stat()
                os.chmod(temporary, stat.S_IMODE(existing.st_mode))
            except OSError:
                pass
            staged.append((temporary, target))
    except Exception:
        for temporary, _target in staged:
            with contextlib.suppress(OSError):
                temporary.unlink()
        raise

    previous: Dict[Any, Optional[bytes]] = {}
    for _temporary, target in staged:
        try:
            previous[target] = target.read_bytes()
        except FileNotFoundError:
            previous[target] = None
    moved: List[Any] = []
    try:
        for temporary, target in staged:
            os.replace(temporary, target)
            moved.append(target)
    except Exception:
        for target in moved:
            raw = previous[target]
            if raw is None:
                with contextlib.suppress(OSError):
                    target.unlink()
                continue
            back = target.with_name(f".{target.name}.restore-back")
            back.write_bytes(raw)
            os.replace(back, target)
        for temporary, _target in staged:
            with contextlib.suppress(OSError):
                temporary.unlink()
        raise


def _set_aside(sources: Dict[str, str]) -> str:
    """Keep the saved sources a restore is about to replace; say where."""

    folder = _config.BASE_DIR / "backups" / f"before-restore-{time.strftime('%Y%m%d%H%M%S')}"
    folder.mkdir(parents=True, exist_ok=True)
    os.chmod(folder, 0o700)
    for name, text in sources.items():
        path = folder / name
        path.write_text(text, encoding="utf-8")
        os.chmod(path, 0o600)
    kept = sorted(
        (item for item in folder.parent.glob("before-restore-*") if item.is_dir()),
        key=lambda item: item.name,
        reverse=True,
    )
    for old in kept[KEEP_SET_ASIDE:]:
        for item in old.iterdir():
            with contextlib.suppress(OSError):
                item.unlink()
        with contextlib.suppress(OSError):
            old.rmdir()
    return f"backups/{folder.name}"


def restore(version_id: str, *, client_ip: str = "") -> Dict[str, Any]:
    """Put a saved version in place and apply it the usual way.

    No checks of its own: the rendering, `haproxy -c`, the guard against
    locking out the admin, the confirmation window and the automatic
    rollback are those of an ordinary save. Here the sources are only
    swapped in, and swapped back if the transaction could not even start.
    """

    meta, sources = version_sources(version_id)
    missing = [name for name in CONFIG_SOURCE_ORDER if name not in sources]
    if missing:
        raise RestoreError(
            "This version does not contain " + ", ".join(missing),
            error_code="version_incomplete",
        )

    # No editor's save may land between the read of what is there and the
    # transaction: it would be written over, or half of it kept.
    with source_lock("websites"), source_lock("tcp"), source_lock("vars"):
        original = current_sources()
        try:
            unapplied = original != applied_sources()
        except ValueError:
            unapplied = True
        set_aside = ""
        if unapplied:
            # Saved but never applied: neither the history nor the applied
            # snapshot holds it, so it is kept before it is replaced.
            try:
                set_aside = _set_aside(original)
            except OSError as exc:
                raise RestoreError(
                    "The unapplied changes could not be set aside, so nothing "
                    f"was restored: {exc}",
                    error_code="set_aside_failed",
                ) from exc
        try:
            _write_sources(sources)
        except Exception as exc:  # pylint: disable=broad-except
            raise RestoreError(
                f"The version could not be written, so nothing was restored: {exc}",
                error_code="restore_write_failed",
            ) from exc
        result = _apply_restored(original, client_ip)

    result["restored_version"] = meta.get("id") or version_id
    if set_aside:
        result["set_aside"] = set_aside
    return result


def _apply_restored(original: Dict[str, str], client_ip: str) -> Dict[str, Any]:
    """Validate and start the transaction for sources already in place.

    On any failure before the transaction starts the sources go back to
    what they were.
    """

    from .services_haproxy_config import (  # local import: heavy module
        CONFIG_YAML,
        _load_yaml,
        begin_cfg_confirmation,
        preflight_cfg_confirmation,
        render_haproxy_cfg,
    )
    from .services_haproxy_vars import validate_admin_access_for_client

    try:
        cfg_text = render_haproxy_cfg()
        config_vars = _load_yaml(CONFIG_YAML)
        if not isinstance(config_vars, dict):
            raise RestoreError(
                "The restored vars.yml root must be a mapping",
                error_code="version_invalid",
            )
        # An old version may predate the administrator's own address being
        # allow-listed. Restoring it would lock the operator out of the very
        # interface they clicked in, so the same guard the normal apply uses
        # runs here too.
        validate_admin_access_for_client(config_vars, client_ip)

        preflight = preflight_cfg_confirmation(cfg_text)
        if not preflight.get("ok"):
            raise RestoreError(
                str(preflight.get("error") or "the restored configuration was refused"),
                error_code=str(preflight.get("error_code") or "restore_refused"),
            )
        result = begin_cfg_confirmation(cfg_text)
    except Exception as exc:
        # The transaction never started, so nothing was applied; put the
        # managed sources back rather than leaving a surprise draft behind.
        try:
            _write_sources(original)
        except Exception:  # pylint: disable=broad-except
            LOG.exception("could not restore the managed sources after a failed restore")
            raise RestoreError(
                "The restore failed and the managed configuration could not be "
                "returned to its previous state; inspect it on the server",
                error_code="restore_dirty",
            ) from exc
        if isinstance(exc, RestoreError):
            raise
        raise RestoreError(str(exc)) from exc
    return result


def unavailable_payload(exc: Exception) -> Dict[str, Any]:
    LOG.warning("configuration history unavailable: %s", exc)
    return {"ok": False, "unavailable": True, "error": str(exc)}
