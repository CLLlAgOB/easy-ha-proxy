# -*- coding: utf-8 -*-

import json
import os
import logging
import socket
import time
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple

import requests
import yaml
from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

logger = logging.getLogger("haproxy-admin.authelia-acl")

bp_authelia_acl = Blueprint(
    "authelia_acl", __name__, url_prefix="/authelia/acl"
)

# Значение по умолчанию — как в authelia-configd
DEFAULT_SOCKET_PATH = "/run/easy-ha-proxy/authelia-configd.sock"


def _configd_socket_path() -> str:
    """Путь к Unix-сокету authelia-configd (можно переопределить через Flask-конфиг)."""
    return current_app.config.get("AUTHELIA_CONFIG_SOCKET", DEFAULT_SOCKET_PATH)


def _configd_request(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Отправляет один JSON-запрос демону authelia-configd и возвращает ответ.
    Протокол — одна строка JSON -> одна строка JSON.
    """
    sock_path = _configd_socket_path()
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8") + b"\n"

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(sock_path)
            s.sendall(data)

            buf = b""
            while b"\n" not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
    except OSError as exc:
        logger.error(
            "Failed to talk to authelia-configd on %s: %s", sock_path, exc
        )
        return {"ok": False, "error": f"socket error: {exc}"}

    if not buf:
        return {"ok": False, "error": "empty response from authelia-configd"}

    line = buf.split(b"\n", 1)[0].decode("utf-8", errors="replace").strip()
    if not line:
        return {"ok": False, "error": "empty JSON line from authelia-configd"}

    try:
        resp = json.loads(line)
    except Exception as exc:  # noqa: BLE001
        logger.error("Invalid JSON from authelia-configd: %r (%s)", line, exc)
        return {"ok": False, "error": f"invalid json from daemon: {exc}"}

    return resp


AUTHELIA_DEFAULT_HEALTH_URL = "http://127.0.0.1:9091/api/health"


def _wait_for_authelia_healthy(timeout: float = 30.0, interval: float = 1.0) -> bool:
    """
    Ждём, пока Authelia начнёт отвечать на health-check.

    Порядок приоритетов:
      1) Переменная окружения AUTHELIA_HEALTHCHECK_URL (Docker/.env, systemd Environment)
      2) Flask-конфиг AUTHELIA_HEALTHCHECK_URL (если где-то выставлен)
      3) Константа AUTHELIA_DEFAULT_HEALTH_URL
    """
    env_url = os.getenv("AUTHELIA_HEALTHCHECK_URL")
    if env_url:
        url = env_url.strip()
    else:
        url = current_app.config.get(
            "AUTHELIA_HEALTHCHECK_URL",
            AUTHELIA_DEFAULT_HEALTH_URL,
        )

    current_app.logger.info("Waiting for Authelia health at %s", url)

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = requests.get(url, timeout=2.0)
            if resp.ok:
                return True
        except Exception:
            time.sleep(interval)
    return False


# ---------------------------------------------------------------------
# Загрузка / сохранение правил через authelia-configd
# ---------------------------------------------------------------------


def load_rules_yaml() -> str:
    """
    Запрашивает у authelia-configd YAML-список access_control.rules.

    Запрос:
      { "action": "rules_get" }

    Ожидаемый ответ:
      { "ok": true, "rules_yaml": "<yaml-список rules>" }
      или (на всякий случай) { "ok": true, "rules": [ ... ] }

    В случае ошибки — возвращаем "[]\\n".
    """
    resp = _configd_request({"action": "rules_get"})

    if not resp.get("ok"):
        logger.error(
            "authelia-configd rules_get failed: %s",
            resp.get("error"),
        )
        return "[]\n"

    rules_yaml = resp.get("rules_yaml")
    if isinstance(rules_yaml, str):
        return rules_yaml

    rules = resp.get("rules")
    if isinstance(rules, list):
        try:
            return yaml.safe_dump(
                rules,
                allow_unicode=True,
                default_flow_style=False,
                sort_keys=False,
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "Failed to dump rules list from configd response: %s", exc)
            return "[]\n"

    return "[]\n"


def save_rules_from_yaml(rules_yaml: str) -> Tuple[bool, str]:
    """
    Передаёт YAML-список rules в authelia-configd для сохранения:

      { "action": "rules_set", "rules_yaml": "<yaml-список rules>" }

    Ожидаемый ответ:
      { "ok": true, "message": "..." }
      или { "ok": false, "error": "..." }

    Возвращает (ok, message) для UI.
    """
    resp = _configd_request(
        {
            "action": "rules_set",
            "rules_yaml": rules_yaml,
        }
    )

    if not resp.get("ok"):
        return (
            False,
            str(resp.get("error")
                or 'Failed to save rules via authelia-configd'),
        )

    msg = str(
        resp.get("message")
        or 'Authelia rules updated successfully via authelia-configd.'
    )
    return True, msg


# ---------------------------------------------------------------------
# Парсинг Authelia rules -> UI-структура
# ---------------------------------------------------------------------


def _normalize_domain(rule: Dict[str, Any]) -> str:
    """
    Приводим поле domain (или domain_regex, если нужно будет) в строку
    вида 'example.com, foo.example.com'.
    Сейчас опираемся только на domain.
    """
    dom = rule.get("domain")
    if isinstance(dom, str):
        return dom
    if isinstance(dom, list):
        return ", ".join(str(d) for d in dom if d)
    # На всякий случай — если вдруг там что-то ещё
    return ""


def _parse_subject_for_ui(
    subject: Any,
) -> Tuple[List[str], List[str], bool, bool]:
    """
    Разбираем subject в формате Authelia в более простой вид для UI:

      groups: список имён групп (без 'group:')
      users:  список имён пользователей (без 'user:')
      flag_authenticated: есть ли 'group:authenticated'
      flag_anonymous:     есть ли 'group:anonymous'
    """
    groups: List[str] = []
    users: List[str] = []
    flag_authenticated = False
    flag_anonymous = False

    intermediate: List[List[str]] = []

    if subject is None:
        return groups, users, flag_authenticated, flag_anonymous

    if isinstance(subject, str):
        intermediate.append([subject])
    elif isinstance(subject, list):
        for item in subject:
            if isinstance(item, str):
                intermediate.append([item])
            elif isinstance(item, list):
                inner = [str(x) for x in item]
                intermediate.append(inner)
            elif isinstance(item, dict):
                tmp: List[str] = []
                for k, v in item.items():
                    v_str = str(v)
                    if k == "group":
                        tmp.append(f"group:{v_str}")
                    elif k == "user":
                        tmp.append(f"user:{v_str}")
                    else:
                        tmp.append(f"{k}:{v_str}")
                if tmp:
                    intermediate.append(tmp)
            else:
                logger.warning(
                    "Unknown subject element type (%r), skipping", type(item)
                )
    elif isinstance(subject, dict):
        tmp: List[str] = []
        for k, v in subject.items():
            v_str = str(v)
            if k == "group":
                tmp.append(f"group:{v_str}")
            elif k == "user":
                tmp.append(f"user:{v_str}")
            else:
                tmp.append(f"{k}:{v_str}")
        if tmp:
            intermediate.append(tmp)
    else:
        logger.warning(
            "Unknown subject type in rule: %r (%r)", type(subject), subject
        )
        return groups, users, flag_authenticated, flag_anonymous

    for and_list in intermediate:
        for s in and_list:
            if not isinstance(s, str):
                s = str(s)

            if s.startswith("group:"):
                g = s.split(":", 1)[1].strip()
                if not g:
                    continue
                if g == "authenticated":
                    flag_authenticated = True
                elif g == "anonymous":
                    flag_anonymous = True
                else:
                    groups.append(g)
            elif s.startswith("user:"):
                u = s.split(":", 1)[1].strip()
                if u:
                    users.append(u)
            else:
                groups.append(s.strip())

    groups = sorted({g for g in groups if g})
    users = sorted({u for u in users if u})

    return groups, users, flag_authenticated, flag_anonymous


def _parse_resources_for_ui(resources: Any) -> str:
    """
    Приводим resources в текстовое поле (textarea): по одному паттерну на строку.
    Если ресурсов нет — возвращаем пустую строку.
    """
    if resources is None:
        return ""
    if isinstance(resources, str):
        return resources.strip()
    if isinstance(resources, list):
        lines = [str(r).strip() for r in resources if str(r).strip()]
        return "\n".join(lines)
    return str(resources).strip()


def _backend_rule_to_ui(rule: Dict[str, Any]) -> Dict[str, Any]:
    """
    Преобразуем исходный rule из configuration.yml в структуру,
    удобную для шаблона authelia_acl_edit.html.
    """
    domains = _normalize_domain(rule)
    policy = str(rule.get("policy") or "").strip()

    subject = rule.get("subject")
    groups, users, flag_auth, flag_anon = _parse_subject_for_ui(subject)

    resources_text = _parse_resources_for_ui(rule.get("resources"))

    return {
        "domains": domains,
        "policy": policy or "one_factor",
        "groups": ", ".join(groups),
        "users": ", ".join(users),
        # флаг authenticated оставляем только для обратной совместимости;
        # в шаблоне он больше не используется
        "flag_authenticated": flag_auth,
        "flag_anonymous": flag_anon,
        "resources": resources_text,
    }


def _empty_ui_rule() -> Dict[str, Any]:
    return {
        "domains": "",
        "policy": "one_factor",
        "groups": "",
        "users": "",
        "flag_authenticated": False,
        "flag_anonymous": False,
        "resources": "",
    }


def _attach_indices(ui_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Проставляем каждому правилу стабильный индекс idx (0..N-1),
    который используется в имени полей формы.
    """
    for idx, rule in enumerate(ui_rules):
        rule["idx"] = idx
    return ui_rules


def _group_ui_rules_by_domain(ui_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Группируем UI-правила по доменам ТОЛЬКО для отображения.

    ВАЖНО: порядок в итоговом YAML не меняется — он всегда определяется
    порядком элементов в списке backend_rules / ui_rules.
    Здесь мы просто раскладываем их по секциям "по доменам" для удобства
    редактирования.
    """
    groups_map: "OrderedDict[str, List[Dict[str, Any]]]" = OrderedDict()

    for rule in ui_rules:
        dom = rule.get("domains") or ""
        groups_map.setdefault(dom, []).append(rule)

    groups: List[Dict[str, Any]] = []
    for dom, rules in groups_map.items():
        groups.append(
            {
                "domain": dom,
                "rules": rules,
            }
        )
    return groups


# ---------------------------------------------------------------------
# Обратное преобразование: UI -> Authelia rule
# ---------------------------------------------------------------------
def _parse_bool(form: Dict[str, Any], field: str) -> bool:
    """Удобный парсер чекбоксов (on/true/1)."""
    val = form.get(field)
    if val is None:
        return False
    return str(val).lower() in ("1", "true", "on", "yes")


def _collect_ui_rules_from_form(form: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Собираем все правила из формы.

    Ожидаем hidden-поле total_rules = N.
    """
    try:
        total = int(form.get("total_rules", "0"))
    except ValueError:
        total = 0

    ui_rules: List[Dict[str, Any]] = []

    for idx in range(total):
        prefix = f"rule-{idx}-"
        # Считаем строку "пустой", если нет доменов / групп / пользователей / ресурсов
        # и не отмечен флаг anonymous. Поле policy игнорируем, чтобы значение
        # по умолчанию one_factor не делало строку "непустой".
        has_any = False
        for key in ("domains", "groups", "users", "resources"):
            if form.get(prefix + key):
                has_any = True
                break
        if not has_any and not _parse_bool(form, prefix + "flag_anonymous"):
            ui_rules.append(_empty_ui_rule())
            continue

        ui_rule = {
            "domains": (form.get(prefix + "domains") or "").strip(),
            "policy": (form.get(prefix + "policy") or "").strip() or "one_factor",
            "groups": (form.get(prefix + "groups") or "").strip(),
            "users": (form.get(prefix + "users") or "").strip(),
            "flag_authenticated": _parse_bool(form, prefix + "flag_authenticated"),
            "flag_anonymous": _parse_bool(form, prefix + "flag_anonymous"),
            "resources": (form.get(prefix + "resources") or "").strip(),
        }
        ui_rules.append(ui_rule)

    return ui_rules


def _convert_form_to_backend_rules(
    form: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    """
    Преобразуем данные формы в backend-правила Authelia.

    Возвращаем (backend_rules, ui_rules, errors), где:
      * backend_rules — список dict для записи в configuration.yml;
      * ui_rules      — список dict для повторного отображения формы
                        (все, включая "пустые" строки);
      * errors        — список строк с сообщениями об ошибках валидации.
    """
    ui_rules = _collect_ui_rules_from_form(form)
    backend_rules: List[Dict[str, Any]] = []
    errors: List[str] = []

    for idx, ui in enumerate(ui_rules):
        domains_raw = (ui.get("domains") or "").strip()
        policy = (ui.get("policy") or "").strip() or "one_factor"
        groups_raw = (ui.get("groups") or "").strip()
        users_raw = (ui.get("users") or "").strip()
        resources_raw = (ui.get("resources") or "").strip()
        flag_anon = bool(ui.get("flag_anonymous"))

        # Полностью пустая строка — игнорируем
        if not (domains_raw or groups_raw or users_raw or resources_raw or flag_anon):
            continue

        # Минимальная валидация: для Authelia в правиле должна быть
        # хотя бы domain (или domain_regex, но мы его пока не поддерживаем) и policy.
        if not domains_raw:
            errors.append(f"Rule #{idx + 1}: the 'Domain(s)' field is empty.")
            continue

        rule: Dict[str, Any] = {}

        domains_list = [d.strip() for d in domains_raw.split(",") if d.strip()]
        if len(domains_list) == 1:
            rule["domain"] = domains_list[0]
        elif len(domains_list) > 1:
            rule["domain"] = domains_list

        rule["policy"] = policy

        subject_items: List[str] = []

        if groups_raw:
            for g in groups_raw.split(","):
                g = g.strip()
                if g:
                    subject_items.append(f"group:{g}")

        if users_raw:
            for u in users_raw.split(","):
                u = u.strip()
                if u:
                    subject_items.append(f"user:{u}")

        if flag_anon:
            subject_items.append("group:anonymous")

        if subject_items:
            rule["subject"] = subject_items

        if resources_raw:
            res_lines = [
                line.strip()
                for line in resources_raw.splitlines()
                if line.strip()
            ]
            if res_lines:
                rule["resources"] = res_lines

        backend_rules.append(rule)

    return backend_rules, ui_rules, errors


def _move_rule(rules: List[Dict[str, Any]], index: int, direction: str) -> None:
    """direction: 'up' или 'down'."""
    if direction == "up" and index > 0:
        rules[index - 1], rules[index] = rules[index], rules[index - 1]
    elif direction == "down" and index < len(rules) - 1:
        rules[index + 1], rules[index] = rules[index], rules[index + 1]


def _render_acl_template(
    ui_rules: List[Dict[str, Any]],
    *,
    active_group_domain: str | None = None,
):
    """
    Единая точка отрисовки шаблона, чтобы везде одинаково считать
    groups / total_rules / active_group_domain.

    ВАЖНО:
      - active_group_domain=None  → выбрать первый домен (поведение по умолчанию);
      - active_group_domain=""    → явно хотим группу "без домена / новые";
      - active_group_domain="foo" → явно хотим домен foo.
    """
    if not ui_rules:
        ui_rules = [_empty_ui_rule()]

    ui_rules = _attach_indices(ui_rules)
    groups = _group_ui_rules_by_domain(ui_rules)
    total_rules = len(ui_rules)

    # Если домен НЕ передали (None) и группы есть — по умолчанию первый домен.
    # Если передали "" или конкретный домен — не трогаем.
    if active_group_domain is None and groups:
        active_group_domain = str(groups[0].get("domain") or "")

    return render_template(
        "authelia_acl_edit.html",
        rules=ui_rules,
        groups=groups,
        total_rules=total_rules,
        active_group_domain=active_group_domain or "",
    )


# ---------------------------------------------------------------------
# Маршрут /authelia/acl/
# ---------------------------------------------------------------------
@bp_authelia_acl.route("/", methods=["GET", "POST"])
def edit_rules():
    form = request.form

    # --- GET: просто показываем правила ---
    if request.method == "GET":
        rules_yaml = load_rules_yaml()

        backend_rules: List[Dict[str, Any]] = []
        if rules_yaml:
            try:
                obj = yaml.safe_load(rules_yaml) or []
            except Exception as exc:  # noqa: BLE001
                current_app.logger.exception(
                    "Failed to parse Authelia rules YAML: %s", exc
                )
                flash(
                    'Failed to parse Authelia rules YAML; showing an empty list.',
                    "danger",
                )
                obj = []
            if isinstance(obj, list):
                backend_rules = [r for r in obj if isinstance(r, dict)]
            else:
                current_app.logger.error(
                    "Authelia rules YAML is not a list: %r", type(obj)
                )
                flash(
                    'Invalid rules format in YAML (expected a list).',
                    "danger",
                )

        ui_rules = [_backend_rule_to_ui(r) for r in backend_rules]
        return _render_acl_template(ui_rules)

    # --- POST: обрабатываем разные действия ---
    active_group_domain = (form.get("active_group_domain") or "").strip()

    # 1) Добавить правило
    if "add_rule" in form:
        ui_rules = _collect_ui_rules_from_form(form)

        # Новое правило всегда без домена → попадает в группу "Новые / без домена"
        new_rule = _empty_ui_rule()
        ui_rules.append(new_rule)

        # Явно просим открыть группу без домена (active_group_domain == "")
        return _render_acl_template(
            ui_rules,
            active_group_domain="",
        )

    # 2) Удалить конкретное правило
    if "delete_rule" in form:
        ui_rules = _collect_ui_rules_from_form(form)
        try:
            del_idx = int(form.get("delete_rule", "-1"))
        except ValueError:
            del_idx = -1

        if 0 <= del_idx < len(ui_rules):
            ui_rules.pop(del_idx)

        return _render_acl_template(ui_rules, active_group_domain=active_group_domain)

    # 3) Переместить вверх/вниз
    if "move_rule_up" in form:
        ui_rules = _collect_ui_rules_from_form(form)
        try:
            idx = int(form.get("move_rule_up", "-1"))
        except ValueError:
            idx = -1
        if 0 <= idx < len(ui_rules):
            _move_rule(ui_rules, idx, "up")

        return _render_acl_template(ui_rules, active_group_domain=active_group_domain)

    if "move_rule_down" in form:
        ui_rules = _collect_ui_rules_from_form(form)
        try:
            idx = int(form.get("move_rule_down", "-1"))
        except ValueError:
            idx = -1
        if 0 <= idx < len(ui_rules):
            _move_rule(ui_rules, idx, "down")

        return _render_acl_template(ui_rules, active_group_domain=active_group_domain)

    # 4) Сохранить (submit_action = save / apply)
    submit_action = form.get("submit_action")
    if submit_action in ("save", "apply"):
        backend_rules, ui_rules, errors = _convert_form_to_backend_rules(form)

        if errors:
            for msg in errors:
                flash(msg, "danger")
            # Просто перерисовываем форму без сохранения
            return _render_acl_template(
                ui_rules,
                active_group_domain=active_group_domain,
            )

        try:
            rules_yaml = yaml.safe_dump(
                backend_rules,
                allow_unicode=True,
                default_flow_style=False,
                sort_keys=False,
            )
        except Exception as exc:  # noqa: BLE001
            current_app.logger.exception(
                "Failed to dump Authelia rules to YAML: %s", exc
            )
            flash(
                f"Failed to serialize rules to YAML: {exc}",
                "danger",
            )
            return _render_acl_template(
                ui_rules,
                active_group_domain=active_group_domain,
            )

        ok, msg = save_rules_from_yaml(rules_yaml)
        flash(msg, "success" if ok else "danger")

        # Пересобираем ui_rules из backend_rules, чтобы отобразить уже то,
        # что реально ушло в конфиг (линейный список без групп)
        ui_rules = [_backend_rule_to_ui(r) for r in backend_rules]

        if not ok:
            return _render_acl_template(
                ui_rules,
                active_group_domain=active_group_domain,
            )

        if submit_action == "apply":
            # Сначала сохранили правила, теперь перезапускаем Authelia через configd
            flash(
                'Authelia rules saved successfully. Restarting Authelia...',
                "success",
            )
            try:
                resp_restart = _configd_request({"action": "restart"})
            except Exception as exc:  # noqa: BLE001
                current_app.logger.exception(
                    "Failed to restart Authelia via configd"
                )
                flash(
                    f"Rules were saved, but Authelia could not be restarted: {exc}",
                    "warning",
                )
            else:
                if not resp_restart.get("ok"):
                    err = resp_restart.get("error") or 'unknown error'
                    flash(
                        f"Rules were saved, but Authelia could not be restarted: {err}",
                        "warning",
                    )
                else:
                    if not _wait_for_authelia_healthy():
                        flash(
                            'Authelia was restarted, but did not become ready before the '
                            'health-check timed out. If the page does not open, refresh it '
                            'in a few seconds.',
                            "warning",
                        )
                    else:
                        flash(
                            'Rules saved and Authelia restarted successfully.',
                            "success",
                        )

        # PRG-паттерн: после успешного сохранения делаем redirect
        return redirect(url_for("authelia_acl.edit_rules"))

    # На всякий случай: просто перерисовать текущую форму
    ui_rules = _collect_ui_rules_from_form(form)
    return _render_acl_template(
        ui_rules,
        active_group_domain=active_group_domain,
    )
