# -*- coding: utf-8 -*-
"""История конфигурации: список версий и осмысленное сравнение.

Версии пишет controld в момент подтверждения транзакции; здесь только чтение.
Сравнение делается по управляемой модели — сайтам, TCP-прокси и переменным, —
а не по сгенерированному haproxy.cfg: diff из тысячи строк не отвечает на
вопрос «что я поменял».
"""

from __future__ import annotations

import base64
import logging
import os
import stat
from typing import Any, Dict, List, Optional, Tuple

import yaml

from .services_haproxy_config import (
    CONFIG_SOURCE_ORDER,
    _controld_json_request,
    _current_config_source_paths,
    _read_config_source_bundle,
)

LOG = logging.getLogger("haproxy-admin")

CURRENT = "current"
MAX_VERSIONS = 200


class HistoryUnavailable(RuntimeError):
    """controld не отвечает или история недоступна."""


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
    """Метаданные и содержимое одной версии."""

    payload = _request(f"config-version {version_id}").get("version") or {}
    return payload, _decode(payload.get("sources") or {})


def current_sources() -> Dict[str, str]:
    """То, что лежит в управляемой конфигурации прямо сейчас.

    Именно рабочие файлы, а не `backups/haproxy/last_applied_*.yml`: те —
    снимок последнего применённого состояния, точка отката, и писать в них
    нельзя.
    """

    bundle = _read_config_source_bundle(
        _current_config_source_paths(), label="current"
    )
    return {name: raw.decode("utf-8", "replace") for name, raw in bundle.items()}


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
    """Список записей → отображение по имени, чтобы сравнивать по существу.

    Порядок в файле значения не имеет: переставленные местами сайты — это не
    изменение, и показывать их как изменение было бы шумом.
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
    """Сравнить два набора источников по смыслу."""

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
    """Сравнить две версии; `current` означает то, что применено сейчас."""

    def load(identifier: str) -> Tuple[Dict[str, Any], Dict[str, str]]:
        if identifier == CURRENT:
            return {"id": CURRENT}, current_sources()
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
    """Восстановление не начато; управляемая конфигурация не изменена."""

    def __init__(self, message: str, *, error_code: str = "restore_failed") -> None:
        super().__init__(message)
        self.error_code = error_code


def _write_sources(sources: Dict[str, str]) -> None:
    """Записать управляемые YAML на место, каждый — атомарной заменой."""

    paths = _current_config_source_paths()
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
        os.replace(temporary, target)


def restore(version_id: str, *, client_ip: str = "") -> Dict[str, Any]:
    """Поставить сохранённую версию на место и применить обычным путём.

    Никаких собственных проверок: рендер, `haproxy -c`, защита от блокировки
    админского доступа, окно подтверждения и автооткат — те же, что у обычного
    сохранения. Здесь только подмена источников и возврат их назад, если
    транзакцию не удалось даже начать.
    """

    from .services_haproxy_config import (  # local import: heavy module
        CONFIG_YAML,
        _load_yaml,
        begin_cfg_confirmation,
        preflight_cfg_confirmation,
        render_haproxy_cfg,
    )
    from .services_haproxy_vars import validate_admin_access_for_client

    meta, sources = version_sources(version_id)
    missing = [name for name in CONFIG_SOURCE_ORDER if name not in sources]
    if missing:
        raise RestoreError(
            "This version does not contain " + ", ".join(missing),
            error_code="version_incomplete",
        )

    original = current_sources()
    _write_sources(sources)
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

    result["restored_version"] = meta.get("id") or version_id
    return result


def unavailable_payload(exc: Exception) -> Dict[str, Any]:
    LOG.warning("configuration history unavailable: %s", exc)
    return {"ok": False, "unavailable": True, "error": str(exc)}
