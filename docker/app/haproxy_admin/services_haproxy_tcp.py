# services_haproxy_tcp.py
# Вспомогательные функции для работы с tcp.yml (TCP-прокси):
# - список TCP-прокси
# - добавление/удаление
# - сохранение одной записи из JSON (страница редактирования)

from typing import Any, Dict, List, Tuple, Optional
import yaml

from .services_haproxy_config import (
    TCP_YAML,
    _load_yaml,
    update_yaml_file,
)
from .validation import (
    BALANCE_VALUES,
    INTERVAL_RE,
    validate_host,
    validate_identifier,
    validate_port,
)


def get_tcp_proxies_list() -> List[Dict[str, Any]]:
    """
    Возвращает список TCP-прокси из tcp.yml (как есть).

    Поддерживает оба варианта корня:
      - tcp_proxies: [...]
      - tcp: [...]
    При сохранении мы всегда пишем ключ tcp_proxies,
    чтобы не плодить варианты.
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
    Приводит одну запись TCP-прокси к нормализованному виду.

    Проверяет:
      - name (обязателен)
      - bind_port (1–65535)
      - backend_host/backend_port ИЛИ список servers[{host,port}]
    """
    if not isinstance(raw, dict):
        return False, 'Invalid TCP proxy format (expected a JSON object)', None

    out: Dict[str, Any] = dict(raw)

    # --- базовые поля name / bind_ip / bind_port -----------------------------
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

    # --- флаги безопасности --------------------------------------------------
    out["zero_trust"] = bool(out.get("zero_trust", False))
    # По умолчанию ban_check включён
    out["ban_check"] = bool(out.get("ban_check", True))

    # --- балансировка и health-check интервал -------------------------------
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
                # пустой backend пропускаем
                continue

            try:
                host = validate_host(host, f"servers[{idx}].host")
                port_int = validate_port(port, f"servers[{idx}].port")
            except ValueError as exc:
                return False, str(exc), None

            srv_out: Dict[str, Any] = {}

            # Имя backend-сервера
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

            # флаг backup можно сохранить "про запас", даже если шаблон его не использует
            if bool(srv.get("backup")):
                srv_out["backup"] = True

            cleaned_servers.append(srv_out)

    # Если есть нормальные servers — записываем их
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
        # Если один из них пустой — убираем оба
        out.pop("backend_host", None)
        out.pop("backend_port", None)

    # ВАЖНО:
    # Если backend'ов в списке servers больше одного — backend_host/backend_port
    # считаем устаревшими и убираем, чтобы не было противоречий.
    if out.get("servers") and isinstance(out["servers"], list) and len(out["servers"]) > 1:
        out.pop("backend_host", None)
        out.pop("backend_port", None)

    return True, "", out


def save_tcp_from_json(tcp: Dict[str, Any], original_name: Optional[str] = None) -> Tuple[bool, str]:
    """
    Сохранение TCP-прокси из JSON (форма редактирования/создания).

    tcp — то, что пришло с фронта (как есть).
    original_name:
      - пусто/None  -> создаём новый
      - непустая    -> редактируем существующий (под этим name), можно переименовать
    """
    ok, msg, tcp_out = _normalize_tcp_entry(tcp)
    if not ok or tcp_out is None:
        return False, msg

    name = tcp_out["name"]

    data = _load_yaml(TCP_YAML)
    proxies = data.get("tcp_proxies")
    if proxies is None:
        proxies = data.get("tcp")
    if not isinstance(proxies, list):
        proxies = []

    # Режим редактирования
    if original_name:
        idx = None
        for i, t in enumerate(proxies):
            if t.get("name") == original_name:
                idx = i
                break
        if idx is None:
            return False, f"TCP proxy with name={original_name!r} not found"

        # Проверка на конфликт имени (если переименовали)
        if name != original_name:
            for t in proxies:
                if t.get("name") == name:
                    return False, f"TCP proxy with name={name!r} already exists"

        proxies[idx] = tcp_out

    # Режим createdия
    else:
        for t in proxies:
            if t.get("name") == name:
                return False, f"TCP proxy with name={name!r} already exists"
        proxies.append(tcp_out)

    # Сохраняем под ключом tcp_proxies
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
    Удаляет TCP-прокси по name из tcp.yml.
    """
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
