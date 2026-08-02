"""Superadmin software-update workflow backed by a fixed root broker."""

from __future__ import annotations

import re

from flask import Blueprint, abort, g, jsonify, render_template, request

from .services_haproxy_config import get_haproxy_configuration_state
from .updated_client import UpdatedError, updated_request


bp_system_updates = Blueprint(
    "system_updates",
    __name__,
    url_prefix="/system/updates",
)

IDENTIFIER_RE = re.compile(r"^[a-f0-9]{32}$")
BOOT_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
ACTOR_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")
IMAGE_CHANNELS = frozenset({"latest", "alpha"})
SOURCE_CHANNELS = frozenset({"github", "local"})
RELEASE_CHANNELS = frozenset({"stable", "alpha", "local"})
UPDATE_COMPONENTS = frozenset(
    {
        "all",
        "services",
        "daemons",
        "authelia-container",
        "admin-container",
        "os",
    }
)
CONFIG_SENSITIVE_COMPONENTS = frozenset({"all", "services", "daemons"})


def _daemon_response(result: dict, *, accepted: bool = False):
    if result.get("ok"):
        return jsonify(result), (202 if accepted else 200)
    code = str(result.get("error_code") or "")
    if code in {
        "busy",
        "conflict",
        "config_pending",
        "operation_active",
        "stale_plan",
        "stale_boot",
        "not_required",
    } or result.get("conflict"):
        status_code = 409
    elif code in {"not_found", "missing"}:
        status_code = 404
    elif code in {"invalid", "validation", "bad_request"} or result.get(
        "validation_error"
    ):
        status_code = 400
    else:
        status_code = 502
    return jsonify(result), status_code


def _call_daemon(payload: dict, *, accepted: bool = False):
    try:
        return _daemon_response(updated_request(payload), accepted=accepted)
    except UpdatedError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 503


def _json_payload(required: set[str], optional: set[str] | None = None) -> dict:
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        abort(400, description="a JSON object is required")
    allowed = required | (optional or set())
    if set(payload) - allowed or not required.issubset(payload):
        abort(400, description="invalid request fields")
    return payload


def _identifier(value, label: str) -> str:
    text = str(value or "").strip().lower()
    if not IDENTIFIER_RE.fullmatch(text):
        abort(400, description=f"invalid {label}")
    return text


def _boot_id(value) -> str:
    text = str(value or "").strip().lower()
    if not BOOT_ID_RE.fullmatch(text):
        abort(400, description="invalid boot id")
    return text


def _actor() -> str:
    value = str(getattr(g, "remote_user", "") or "").strip()
    if not ACTOR_RE.fullmatch(value):
        abort(403, description="authenticated actor is unavailable")
    return value


def _components(value) -> list[str]:
    if not isinstance(value, list) or not value:
        abort(400, description="components must be a non-empty list")
    if any(not isinstance(item, str) or item not in UPDATE_COMPONENTS for item in value):
        abort(400, description="unsupported update component")
    if len(value) != len(set(value)):
        abort(400, description="duplicate update component")
    return list(value)


@bp_system_updates.get("/")
def page():
    return render_template("system_updates.html")


@bp_system_updates.get("/api/status")
def status_view():
    payload = {"action": "status"}
    job_id = (request.args.get("job_id") or "").strip().lower()
    if job_id:
        payload["job_id"] = _identifier(job_id, "job id")
    return _call_daemon(payload)


def _channel(payload: dict, key: str, allowed: frozenset) -> str:
    value = payload[key]
    if not isinstance(value, str) or value not in allowed:
        abort(
            400,
            description=f"{key} must be one of: " + ", ".join(sorted(allowed)),
        )
    return value


@bp_system_updates.post("/api/check")
def start_check():
    payload = _json_payload(
        set(), {"image_channel", "source_channel", "release_channel"}
    )
    command = {"action": "start_check"}
    if "release_channel" in payload:
        command["release_channel"] = _channel(
            payload, "release_channel", RELEASE_CHANNELS
        )
    if "image_channel" in payload:
        command["image_channel"] = _channel(payload, "image_channel", IMAGE_CHANNELS)
    if "source_channel" in payload:
        command["source_channel"] = _channel(
            payload, "source_channel", SOURCE_CHANNELS
        )
    return _call_daemon(command, accepted=True)


@bp_system_updates.post("/api/channels")
def save_channels():
    payload = _json_payload(
        set(), {"image_channel", "source_channel", "release_channel"}
    )
    command = {"action": "set_channels"}
    if "release_channel" in payload:
        command["release_channel"] = _channel(
            payload, "release_channel", RELEASE_CHANNELS
        )
    if "image_channel" in payload:
        command["image_channel"] = _channel(payload, "image_channel", IMAGE_CHANNELS)
    if "source_channel" in payload:
        command["source_channel"] = _channel(
            payload, "source_channel", SOURCE_CHANNELS
        )
    if len(command) == 1:
        abort(400, description="select a channel to persist")
    return _call_daemon(command)


@bp_system_updates.post("/api/apply")
def start_apply():
    payload = _json_payload({"plan_id", "components", "confirmation"})
    if payload["confirmation"] != "UPDATE":
        abort(400, description="type UPDATE to confirm software updates")

    plan_id = _identifier(payload["plan_id"], "plan id")
    components = _components(payload["components"])
    sensitive = sorted(CONFIG_SENSITIVE_COMPONENTS.intersection(components))
    if sensitive:
        try:
            config_state = get_haproxy_configuration_state()
        except Exception:  # pylint: disable=broad-except
            return jsonify(
                {
                    "ok": False,
                    "error": (
                        "HAProxy configuration state is unavailable; "
                        "source and host-service updates are blocked"
                    ),
                    "error_code": "configuration_state_unavailable",
                }
            ), 503
        state = str(config_state.get("state") or "unknown")
        if state != "clean":
            return jsonify(
                {
                    "ok": False,
                    "error": (
                        "Resolve pending HAProxy configuration changes before "
                        "updating source or host services"
                    ),
                    "error_code": "configuration_not_clean",
                    "configuration_state": state,
                    "blocked_components": sensitive,
                }
            ), 409

    return _call_daemon(
        {
            "action": "start_apply",
            "plan_id": plan_id,
            "components": components,
            "confirmation": "UPDATE",
        },
        accepted=True,
    )


@bp_system_updates.post("/api/reboot")
def reboot():
    payload = _json_payload({"confirmation", "expected_boot_id"})
    if payload["confirmation"] != "REBOOT":
        abort(400, description="type REBOOT to confirm the server reboot")
    # The broker owns the delayed systemd timer and serializes it with every
    # update/backup operation through the shared maintenance lock.
    return _call_daemon(
        {
            "action": "reboot",
            "confirmation": "REBOOT",
            "expected_boot_id": _boot_id(payload["expected_boot_id"]),
            "actor": _actor(),
        }
    )


@bp_system_updates.post("/api/reboot/cancel")
def cancel_reboot():
    payload = _json_payload({"expected_boot_id"})
    return _call_daemon(
        {
            "action": "cancel_reboot",
            "expected_boot_id": _boot_id(payload["expected_boot_id"]),
            "actor": _actor(),
        }
    )
