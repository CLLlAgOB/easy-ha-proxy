# -*- coding: utf-8 -*-

import json
import os
import logging
import socket
import time
from collections import OrderedDict
from typing import Any, Dict, List, Tuple

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

# The default, the same as in authelia-configd
DEFAULT_SOCKET_PATH = "/run/easy-ha-proxy/authelia-configd.sock"
CONFIGD_MAX_RESPONSE_BYTES = 2 * 1024 * 1024


def _configd_socket_path() -> str:
    """Path to authelia-configd's Unix socket (can be overridden in the Flask config)."""
    return current_app.config.get("AUTHELIA_CONFIG_SOCKET", DEFAULT_SOCKET_PATH)


def _configd_request(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sends one JSON request to the authelia-configd daemon and returns its answer.
    The protocol is one JSON line in, one JSON line out.
    """
    sock_path = _configd_socket_path()
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8") + b"\n"
    response_timeout = (
        90.0 if payload.get("action") in {"rules_set", "restart"} else 10.0
    )

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(2.0)
            s.connect(sock_path)
            s.settimeout(response_timeout)
            s.sendall(data)

            buf = b""
            while b"\n" not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > CONFIGD_MAX_RESPONSE_BYTES:
                    return {
                        "ok": False,
                        "error": "response from authelia-configd is too large",
                    }
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

    if not isinstance(resp, dict):
        return {"ok": False, "error": "invalid response from authelia-configd"}
    return resp


AUTHELIA_DEFAULT_HEALTH_URL = "http://127.0.0.1:9091/api/health"


def _wait_for_authelia_healthy(timeout: float = 30.0, interval: float = 1.0) -> bool:
    """
    Waits until Authelia answers its health check.

    In order of preference:
      1) the environment variable AUTHELIA_HEALTHCHECK_URL (Docker/.env, systemd Environment)
      2) the Flask config AUTHELIA_HEALTHCHECK_URL (if set anywhere)
      3) the constant AUTHELIA_DEFAULT_HEALTH_URL
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
# Loading and saving the rules through authelia-configd
# ---------------------------------------------------------------------


def load_rules_yaml() -> str:
    """
    Asks authelia-configd for access_control.rules as a YAML list.

    Request:
      { "action": "rules_get" }

    Expected answer:
      { "ok": true, "rules_yaml": "<yaml list of rules>" }
      or, just in case, { "ok": true, "rules": [ ... ] }

    An error raises, so the interface never replaces the real rules with an
    empty editable list.
    """
    resp = _configd_request({"action": "rules_get"})

    if not resp.get("ok"):
        logger.error(
            "authelia-configd rules_get failed: %s",
            resp.get("error"),
        )
        raise RuntimeError(
            str(resp.get("error") or "authelia-configd rules_get failed")
        )

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
            raise RuntimeError(
                "failed to serialize rules from authelia-configd"
            ) from exc

    raise RuntimeError("invalid rules response from authelia-configd")


def save_rules_from_yaml(rules_yaml: str) -> Tuple[bool, str]:
    """
    Hands the YAML list of rules to authelia-configd to save:

      { "action": "rules_set", "rules_yaml": "<yaml list of rules>" }

    Expected answer:
      { "ok": true, "message": "..." }
      or { "ok": false, "error": "..." }

    Returns (ok, message) for the UI.
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
# Parsing Authelia rules into the UI structure
# ---------------------------------------------------------------------


def _normalize_domain(rule: Dict[str, Any]) -> str:
    """
    Turns the domain field (or domain_regex, should it be needed) into a
    string such as 'example.com, foo.example.com'.
    Only domain is used for now.
    """
    dom = rule.get("domain")
    if isinstance(dom, str):
        return dom
    if isinstance(dom, list):
        return ", ".join(str(d) for d in dom if d)
    # Just in case there is something else there
    return ""


def _parse_subject_for_ui(
    subject: Any,
) -> Tuple[List[str], List[str], bool, bool]:
    """
    Breaks an Authelia subject down into a simpler shape for the UI:

      groups: group names (without 'group:')
      users:  user names (without 'user:')
      flag_authenticated: whether 'group:authenticated' is there
      flag_anonymous:     whether 'group:anonymous' is there
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
    Turns resources into a text field (textarea): one pattern per line.
    No resources gives an empty string.
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
    Turns a rule from configuration.yml into the structure
    the authelia_acl_edit.html template uses.
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
        # the authenticated flag is kept only for backward compatibility;
        # the template no longer uses it
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
    Gives each rule a stable index idx (0..N-1),
    used in the names of the form's fields.
    """
    for idx, rule in enumerate(ui_rules):
        rule["idx"] = idx
    return ui_rules


def _group_ui_rules_by_domain(ui_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Groups the UI rules by domain, ONLY for display.

    IMPORTANT: the order in the resulting YAML does not change -- it is always
    the order of the items in backend_rules / ui_rules. They are only laid
    out in per-domain sections here, to make editing easier.
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
# The way back: UI -> Authelia rule
# ---------------------------------------------------------------------
def _parse_bool(form: Dict[str, Any], field: str) -> bool:
    """A forgiving checkbox parser (on/true/1)."""
    val = form.get(field)
    if val is None:
        return False
    return str(val).lower() in ("1", "true", "on", "yes")


def _collect_ui_rules_from_form(form: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Collects every rule from the form.

    Expects the hidden field total_rules = N.
    """
    try:
        total = int(form.get("total_rules", "0"))
    except ValueError:
        total = 0

    ui_rules: List[Dict[str, Any]] = []

    for idx in range(total):
        prefix = f"rule-{idx}-"
        # A row is "empty" if it has no domains, groups, users or resources
        # and the anonymous flag is not set. policy is ignored, so that its
        # default one_factor does not make the row "non-empty".
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
    Turns the form data into Authelia's backend rules.

    Returns (backend_rules, ui_rules, errors), where:
      * backend_rules -- the dicts to write to configuration.yml;
      * ui_rules      -- the dicts to show the form again
                        (all of them, "empty" rows included);
      * errors        -- the validation error messages.
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

        # An entirely empty row is ignored
        if not (domains_raw or groups_raw or users_raw or resources_raw or flag_anon):
            continue

        # Minimal validation: an Authelia rule needs at least a domain
        # (or domain_regex, which is not supported yet) and a policy.
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
    """direction: 'up' or 'down'."""
    if direction == "up" and index > 0:
        rules[index - 1], rules[index] = rules[index], rules[index - 1]
    elif direction == "down" and index < len(rules) - 1:
        rules[index + 1], rules[index] = rules[index], rules[index + 1]


def _render_acl_template(
    ui_rules: List[Dict[str, Any]],
    *,
    active_group_domain: str | None = None,
    load_error: str | None = None,
):
    """
    The one place that renders the template, so groups / total_rules /
    active_group_domain are worked out the same way everywhere.

    IMPORTANT:
      - active_group_domain=None  -> pick the first domain (the default);
      - active_group_domain=""    -> the group "without a domain / new" explicitly;
      - active_group_domain="foo" -> the domain foo explicitly.
    """
    if not ui_rules and not load_error:
        ui_rules = [_empty_ui_rule()]

    ui_rules = _attach_indices(ui_rules)
    groups = _group_ui_rules_by_domain(ui_rules)
    total_rules = len(ui_rules)

    # If no domain was passed (None) and there are groups, the first domain is the default.
    # "" or a specific domain is left as it is.
    if active_group_domain is None and groups:
        active_group_domain = str(groups[0].get("domain") or "")

    return render_template(
        "authelia_acl_edit.html",
        rules=ui_rules,
        groups=groups,
        total_rules=total_rules,
        active_group_domain=active_group_domain or "",
        acl_load_error=load_error,
    )


# ---------------------------------------------------------------------
# The /authelia/acl/ route
# ---------------------------------------------------------------------
@bp_authelia_acl.route("/", methods=["GET", "POST"])
def edit_rules():
    form = request.form

    # --- GET: just show the rules ---
    if request.method == "GET":
        try:
            rules_yaml = load_rules_yaml()
            backend_rules: List[Dict[str, Any]] = []
            obj: Any = []
            if rules_yaml:
                obj = yaml.safe_load(rules_yaml) or []
            if isinstance(obj, list):
                backend_rules = [r for r in obj if isinstance(r, dict)]
            else:
                raise ValueError("Authelia rules YAML is not a list")
        except Exception as exc:  # noqa: BLE001
            current_app.logger.exception("Failed to load Authelia rules")
            return _render_acl_template([], load_error=str(exc))

        ui_rules = [_backend_rule_to_ui(r) for r in backend_rules]
        return _render_acl_template(ui_rules)

    # --- POST: the various actions ---
    active_group_domain = (form.get("active_group_domain") or "").strip()

    # 1) Add a rule
    if "add_rule" in form:
        ui_rules = _collect_ui_rules_from_form(form)

        # A new rule never has a domain, so it lands in the group "New / without a domain"
        new_rule = _empty_ui_rule()
        ui_rules.append(new_rule)

        # Ask for the group without a domain to be open (active_group_domain == "")
        return _render_acl_template(
            ui_rules,
            active_group_domain="",
        )

    # 2) Delete a rule
    if "delete_rule" in form:
        ui_rules = _collect_ui_rules_from_form(form)
        try:
            del_idx = int(form.get("delete_rule", "-1"))
        except ValueError:
            del_idx = -1

        if 0 <= del_idx < len(ui_rules):
            ui_rules.pop(del_idx)

        return _render_acl_template(ui_rules, active_group_domain=active_group_domain)

    # 3) Move up or down
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

    # 4) Save (submit_action = save / apply)
    submit_action = form.get("submit_action")
    if submit_action in ("save", "apply"):
        backend_rules, ui_rules, errors = _convert_form_to_backend_rules(form)

        if errors:
            for msg in errors:
                flash(msg, "danger")
            # Just render the form again, without saving
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

        # Rebuild ui_rules from backend_rules, so what is shown is what
        # actually went into the configuration (a flat list without groups)
        ui_rules = [_backend_rule_to_ui(r) for r in backend_rules]

        if not ok:
            return _render_acl_template(
                ui_rules,
                active_group_domain=active_group_domain,
            )

        if submit_action == "apply":
            # The rules are saved; now restart Authelia through configd
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

        # Post/Redirect/Get: redirect after a successful save
        return redirect(url_for("authelia_acl.edit_rules"))

    # Just in case: render the current form again
    ui_rules = _collect_ui_rules_from_form(form)
    return _render_acl_template(
        ui_rules,
        active_group_domain=active_group_domain,
    )
