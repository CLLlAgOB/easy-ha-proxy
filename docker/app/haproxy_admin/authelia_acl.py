# -*- coding: utf-8 -*-

import json
import hashlib
import os
import logging
import secrets
import socket
import time
from collections import OrderedDict
from copy import deepcopy
from typing import Any, Dict, List, Tuple

import requests
import yaml
from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    g,
    session,
    url_for,
)
from itsdangerous import BadSignature, URLSafeSerializer

from .i18n import translate

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

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            resp = requests.get(url, timeout=2.0)
            if resp.ok:
                return True
        except Exception:
            pass
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


def save_rules_from_yaml(
    rules_yaml: str, *, expected_revision: str | None = None
) -> Tuple[bool, str]:
    """
    Hands the YAML list of rules to authelia-configd to save:

      { "action": "rules_set", "rules_yaml": "<yaml list of rules>" }

    Expected answer:
      { "ok": true, "message": "..." }
      or { "ok": false, "error": "..." }

    Returns (ok, message) for the UI.
    """
    payload = {"action": "rules_set", "rules_yaml": rules_yaml}
    if expected_revision is not None:
        payload["expected_revision"] = expected_revision
    resp = _configd_request(payload)

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


def _rules_revision(rules: List[Dict[str, Any]]) -> str:
    # Keep the serialization in sync with authelia-configd's _rules_revision.
    data = yaml.safe_dump(rules, allow_unicode=True, sort_keys=True)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _load_backend_rules() -> List[Dict[str, Any]]:
    rules_yaml = load_rules_yaml()
    rules = yaml.safe_load(rules_yaml) if rules_yaml else []
    if rules is None:
        rules = []
    if not isinstance(rules, list) or any(not isinstance(r, dict) for r in rules):
        raise ValueError("Authelia rules YAML is not a list of rules")
    return rules


def _snapshot_serializer() -> URLSafeSerializer:
    return URLSafeSerializer(current_app.secret_key, salt="authelia-acl-snapshot")


def _snapshot_token(
    rules: List[Dict[str, Any]], ui_rules: List[Dict[str, Any]]
) -> str:
    nonce = session.setdefault("authelia_acl_nonce", secrets.token_urlsafe(24))
    return _snapshot_serializer().dumps({
        "revision": _rules_revision(rules),
        "nonce": nonce,
        "user": getattr(g, "remote_user", ""),
        "sources": [ui.get("source_index", "") for ui in ui_rules],
    })


def _verify_snapshot(token: str, rules: List[Dict[str, Any]], form: Dict[str, Any]) -> bool:
    try:
        snapshot = _snapshot_serializer().loads(token)
    except BadSignature:
        abort(400, description="Invalid access rules form. Reload the page.")
    if (
        not isinstance(snapshot, dict)
        or not session.get("authelia_acl_nonce")
        or snapshot.get("nonce") != session.get("authelia_acl_nonce")
        or snapshot.get("user") != getattr(g, "remote_user", "")
    ):
        abort(400, description="Invalid access rules form. Reload the page.")
    # Bind each submitted row to its original rule. Removing/changing a hidden
    # reference must never turn a read-only AND rule into a new flat OR rule.
    ui_rules = _collect_ui_rules_from_form(form)
    if snapshot.get("sources") != [ui.get("source_index", "") for ui in ui_rules]:
        abort(400, description="Invalid access rule references. Reload the page.")
    return snapshot.get("revision") == _rules_revision(rules)


def _rule_is_editable(rule: Dict[str, Any]) -> bool:
    """The simple form cannot express AND subjects or advanced restrictions."""
    if set(rule) - {"domain", "policy", "subject", "resources"}:
        return False
    domains = rule.get("domain")
    domains = domains if isinstance(domains, list) else [domains]
    if not domains or any(
        not isinstance(d, str) or not d.strip() or "," in d for d in domains
    ):
        return False
    policy = rule.get("policy")
    if not isinstance(policy, str) or policy not in {"one_factor", "two_factor", "bypass", "deny"}:
        return False
    subject = rule.get("subject")
    subjects = subject if isinstance(subject, list) else [subject]
    for item in subjects:
        if item is None:
            continue
        if not isinstance(item, str) or not item.startswith(("group:", "user:")):
            return False
        name = item.split(":", 1)[1]
        if (
            not name or name != name.strip() or any(c in name for c in ",\r\n")
            or item == "group:authenticated"
        ):
            return False
    resources = rule.get("resources")
    resources = resources if isinstance(resources, list) else [resources]
    return all(r is None or isinstance(r, str) for r in resources)


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


def _backend_rule_to_ui(
    rule: Dict[str, Any], source_index: int | None = None
) -> Dict[str, Any]:
    """
    Turns a rule from configuration.yml into the structure
    the authelia_acl_edit.html template uses.
    """
    domains = _normalize_domain(rule)
    policy = str(rule.get("policy") or "").strip()

    subject = rule.get("subject")
    groups, users, flag_auth, flag_anon = _parse_subject_for_ui(subject)

    resources_text = _parse_resources_for_ui(rule.get("resources"))
    resources_text = resources_text.replace("\r\n", "\n").replace("\r", "\n")

    return {
        "domains": domains.strip(),
        "policy": policy or "one_factor",
        "groups": ", ".join(groups),
        "users": ", ".join(users),
        # the authenticated flag is kept only for backward compatibility;
        # the template no longer uses it
        "flag_authenticated": flag_auth,
        "flag_anonymous": flag_anon,
        "resources": resources_text,
        "source_index": "" if source_index is None else str(source_index),
        "advanced": not _rule_is_editable(rule),
        "original_yaml": yaml.safe_dump(rule, allow_unicode=True, sort_keys=False),
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
        "source_index": "",
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
    except (ValueError, TypeError):
        abort(400, description="Invalid access rules count.")
    if total < 0 or total > 500:
        abort(400, description="At most 500 access rules are allowed.")

    ui_rules: List[Dict[str, Any]] = []

    for idx in range(total):
        prefix = f"rule-{idx}-"
        ui_rule = {
            "domains": (form.get(prefix + "domains") or "").strip(),
            "policy": (form.get(prefix + "policy") or "").strip() or "one_factor",
            "groups": (form.get(prefix + "groups") or "").strip(),
            "users": (form.get(prefix + "users") or "").strip(),
            "flag_authenticated": _parse_bool(form, prefix + "flag_authenticated"),
            "flag_anonymous": _parse_bool(form, prefix + "flag_anonymous"),
            "resources": (form.get(prefix + "resources") or "").strip()
                .replace("\r\n", "\n").replace("\r", "\n"),
            "source_index": form.get(prefix + "source_index", ""),
        }
        ui_rules.append(ui_rule)

    return ui_rules


def _convert_form_to_backend_rules(
    form: Dict[str, Any],
    original_rules: List[Dict[str, Any]] | None = None,
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
    seen_sources: set[int] = set()

    for idx, ui in enumerate(ui_rules):
        original = _original_rule_for_ui(ui, original_rules or [], seen_sources)
        if original is not None:
            original_ui = _backend_rule_to_ui(original)
            fields = ("domains", "policy", "groups", "users", "flag_anonymous", "resources")
            if all(ui.get(key) == original_ui.get(key) for key in fields):
                backend_rules.append(deepcopy(original))
                continue
            if not _rule_is_editable(original):
                errors.append(translate(
                    "Rule #{number}: advanced rules cannot be edited in this form. "
                    "Reload the page and use the configuration file to edit this rule.",
                    number=idx + 1,
                ))
                continue
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

        if original is not None:
            # A policy edit must not rewrite an untouched subject/resources
            # value, even when its scalar/list shape is representable here.
            merged = deepcopy(original)
            field_groups = {
                "domain": ("domains",),
                "policy": ("policy",),
                "subject": ("groups", "users", "flag_anonymous"),
                "resources": ("resources",),
            }
            for backend_key, ui_fields in field_groups.items():
                if any(ui.get(key) != original_ui.get(key) for key in ui_fields):
                    merged.pop(backend_key, None)
                    if backend_key in rule:
                        merged[backend_key] = rule[backend_key]
            rule = merged
        backend_rules.append(rule)

    return backend_rules, ui_rules, errors


def _original_rule_for_ui(
    ui: Dict[str, Any], original_rules: List[Dict[str, Any]], seen: set[int]
) -> Dict[str, Any] | None:
    source = ui.get("source_index", "")
    if source == "":
        return None
    try:
        index = int(source)
    except (ValueError, TypeError):
        abort(400, description="Invalid access rule reference. Reload the page.")
    if index < 0 or index >= len(original_rules) or index in seen:
        abort(400, description="Invalid access rule reference. Reload the page.")
    seen.add(index)
    return original_rules[index]


def _restore_rule_metadata(
    ui_rules: List[Dict[str, Any]], original_rules: List[Dict[str, Any]]
) -> None:
    seen: set[int] = set()
    for ui in ui_rules:
        original = _original_rule_for_ui(ui, original_rules, seen)
        if original is not None:
            ui["advanced"] = not _rule_is_editable(original)
            ui["original_yaml"] = yaml.safe_dump(original, allow_unicode=True, sort_keys=False)


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
    snapshot_token: str = "",
    original_rules: List[Dict[str, Any]] | None = None,
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

    if original_rules is not None:
        _restore_rule_metadata(ui_rules, original_rules)
        snapshot_token = _snapshot_token(original_rules, ui_rules)

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
        acl_snapshot=snapshot_token,
    )


# ---------------------------------------------------------------------
# The /authelia/acl/ route
# ---------------------------------------------------------------------
@bp_authelia_acl.route("/", methods=["GET", "POST"])
def edit_rules():
    form = request.form

    try:
        original_rules = _load_backend_rules()
    except Exception as exc:  # noqa: BLE001
        current_app.logger.exception("Failed to load Authelia rules")
        return _render_acl_template([], load_error=str(exc))

    if request.method == "POST":
        if not _verify_snapshot(form.get("acl_snapshot", ""), original_rules, form):
            return _render_acl_template(
                [], load_error=translate(
                    "Access rules changed since this page was loaded. Reload before editing."
                )
            ), 409

    def render(ui_rules, **kwargs):
        return _render_acl_template(
            ui_rules, original_rules=original_rules, **kwargs
        )

    # --- GET: just show the rules ---
    if request.method == "GET":
        ui_rules = [_backend_rule_to_ui(r, i) for i, r in enumerate(original_rules)]
        return render(ui_rules)

    # --- POST: the various actions ---
    active_group_domain = (form.get("active_group_domain") or "").strip()

    # 1) Add a rule
    if "add_rule" in form:
        ui_rules = _collect_ui_rules_from_form(form)

        if len(ui_rules) >= 500:
            flash(translate("At most 500 access rules are allowed."), "danger")
            return render(ui_rules, active_group_domain=active_group_domain)

        # A new rule never has a domain, so it lands in the group "New / without a domain"
        new_rule = _empty_ui_rule()
        ui_rules.append(new_rule)

        # Ask for the group without a domain to be open (active_group_domain == "")
        return render(
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

        return render(ui_rules, active_group_domain=active_group_domain)

    # 3) Move up or down
    if "move_rule_up" in form:
        ui_rules = _collect_ui_rules_from_form(form)
        try:
            idx = int(form.get("move_rule_up", "-1"))
        except ValueError:
            idx = -1
        if 0 <= idx < len(ui_rules):
            _move_rule(ui_rules, idx, "up")

        return render(ui_rules, active_group_domain=active_group_domain)

    if "move_rule_down" in form:
        ui_rules = _collect_ui_rules_from_form(form)
        try:
            idx = int(form.get("move_rule_down", "-1"))
        except ValueError:
            idx = -1
        if 0 <= idx < len(ui_rules):
            _move_rule(ui_rules, idx, "down")

        return render(ui_rules, active_group_domain=active_group_domain)

    # 4) Save (submit_action = save / apply)
    submit_action = form.get("submit_action")
    if submit_action in ("save", "apply"):
        backend_rules, ui_rules, errors = _convert_form_to_backend_rules(form, original_rules)

        if errors:
            for msg in errors:
                flash(msg, "danger")
            # Just render the form again, without saving
            return render(
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
            return render(
                ui_rules,
                active_group_domain=active_group_domain,
            )

        ok, msg = save_rules_from_yaml(
            rules_yaml, expected_revision=_rules_revision(original_rules)
        )
        flash(translate(msg), "success" if ok else "danger")

        if not ok:
            return render(
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
    return render(
        ui_rules,
        active_group_domain=active_group_domain,
    )
