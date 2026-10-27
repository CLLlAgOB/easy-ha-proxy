from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from ipaddress import ip_address
from .audit import RESULT_FAILURE, RESULT_SUCCESS, record_request, summarize
from .utils import grep_last_logs_for_ip
from .cache import get_country_code
import os
import traceback

from .services import (
    get_tables,
    get_tables_raw,
    unban_ip,
    add_to_whitelist,
    add_to_global_whitelist,
    get_attackers,
    get_connections,
    get_backends_status,
    get_ip_auth_table,
    get_authelia_bans,
    authelia_unban_user,
    authelia_unban_ip,
    get_authelia_logs,
    get_authelia_users,
    get_authelia_user,
    update_authelia_user,
    create_authelia_user,
    delete_authelia_user,
)


bp = Blueprint(
    "routes",
    __name__,
    template_folder="templates",
    static_folder="static",
)


def _debug_routes_enabled() -> bool:
    return os.environ.get("HAPROXY_ADMIN_DEBUG_ROUTES", "").lower() in {
        "1",
        "true",
        "yes",
    }


# ───────── pages ──────────────────────────────────────────────


@bp.route("/")
def index():
    return render_template(
        "index.html",
        is_superadmin=bool(getattr(g, "is_superadmin", False)),
        debug_routes_enabled=_debug_routes_enabled(),
    )


@bp.route("/debug/headers")
def debug_headers():
    if not _debug_routes_enabled():
        abort(404)
    hidden = {
        "x-easy-ha-proxy-secret",
        "x-easy-haproxy-config-generation",
        "cookie",
        "authorization",
    }
    body = "\n".join(
        f"{key}: {'[redacted]' if key.lower() in hidden else value}"
        for key, value in request.headers.items()
    )
    return Response(body, mimetype="text/plain")


@bp.route("/debug/")
def debug():
    if not _debug_routes_enabled():
        return render_template("debug_disabled.html")
    return render_template("debug.html")


@bp.route("/api/whitelists")
def api_whitelists():
    try:
        from .services import get_whitelists
        return jsonify(get_whitelists())
    except Exception:  # pylint: disable=broad-except
        current_app.logger.exception("Failed to read whitelists")
        return jsonify({"error": 'Failed to read allow list'}), 500

# ───────── API ───────────────────────────────────────────────────


@bp.route("/api/tables")
def api_tables():
    return jsonify(get_tables())


@bp.route("/api/tables_raw")
def api_tables_raw():
    try:
        return jsonify(get_tables_raw())
    except Exception:                 # pylint: disable=broad-except
        current_app.logger.exception("Failed to read raw HAProxy tables")
        return jsonify({"error": 'Failed to read HAProxy tables'}), 500


@bp.route("/api/unban", methods=["POST"])
def api_unban():
    ip = request.form.get("ip", "").strip()
    if not ip:
        return 'IP is required', 400
    try:
        response = unban_ip(ip)
    except Exception as exc:  # pylint: disable=broad-except
        record_request(
            "ban.lift",
            object_type="ip",
            object_id=ip,
            result=RESULT_FAILURE,
            detail=str(exc),
        )
        raise
    record_request("ban.lift", object_type="ip", object_id=ip)
    return response


def _whitelist_api_error(scope: str, exc: Exception):
    current_app.logger.exception("Failed to update %s whitelist", scope)
    return f"Update error: {scope} whitelist: {exc}", 500


@bp.route("/api/whitelist", methods=["POST"])
def api_whitelist():
    ip = request.form.get("ip", "").strip()
    if not ip:
        return 'IP is required', 400
    try:
        response = add_to_whitelist(ip)
    except Exception as exc:  # pylint: disable=broad-except
        record_request(
            "whitelist.add",
            object_type="ip",
            object_id=ip,
            result=RESULT_FAILURE,
            summary="scope: geo",
            detail=str(exc),
        )
        return _whitelist_api_error("GEO", exc)
    record_request(
        "whitelist.add", object_type="ip", object_id=ip, summary="scope: geo"
    )
    return response


@bp.route("/api/whitelist-global", methods=["POST"])
def api_whitelist_global():
    ip = request.form.get("ip", "").strip()
    if not ip:
        return 'IP is required', 400
    try:
        response = add_to_global_whitelist(ip)
    except Exception as exc:  # pylint: disable=broad-except
        record_request(
            "whitelist.add",
            object_type="ip",
            object_id=ip,
            result=RESULT_FAILURE,
            summary="scope: global",
            detail=str(exc),
        )
        return _whitelist_api_error("GLOBAL", exc)
    record_request(
        "whitelist.add", object_type="ip", object_id=ip, summary="scope: global"
    )
    return response


@bp.route("/api/attackers")
def api_attackers():
    try:
        return jsonify(get_attackers())
    except Exception:                 # pylint: disable=broad-except
        current_app.logger.exception("Failed to read attackers")
        return jsonify({"error": 'Failed to load attack statistics'}), 500


@bp.route("/api/connections")
def api_connections():
    try:
        return jsonify(get_connections())
    except Exception:                 # pylint: disable=broad-except
        current_app.logger.exception("Failed to read HAProxy connections")
        return jsonify({"error": 'Failed to load HAProxy connections'}), 500


@bp.route("/ip/<ip>")
def view_ip_logs(ip: str):
    try:
        ip_address(ip)
    except Exception:
        return "Invalid IP", 400

    lines = grep_last_logs_for_ip(ip, limit=30)
    # Whether it is allow-listed or banned, so the page can offer the one
    # action that will actually work. Never worth losing the log lines over.
    try:
        from . import services_live

        status = services_live.address_status(ip)
    except Exception:  # pylint: disable=broad-except
        current_app.logger.exception("Failed to read the state of %s", ip)
        status = None
    return render_template("ip_logs.html", ip=ip, lines=lines, status=status)

# ─────────────────────────────────────────────────────────────────────────────
# Authelia users (managing users_database.yml)
# ─────────────────────────────────────────────────────────────────────────────


@bp.route("/authelia/users")
def authelia_users():
    """The list of Authelia users."""
    message = request.args.get("msg") or ""
    users, all_groups, error = get_authelia_users()
    return render_template(
        "authelia_users.html",
        users=users,
        all_groups=all_groups,
        error=error,
        message=message,
    )


@bp.route("/authelia/users/new", methods=["GET", "POST"])
def authelia_user_new():
    # Take all the groups the same way as the list and the edit page do;
    # get_authelia_users already returns (users, all_groups, error)
    _, all_groups, users_error = get_authelia_users()

    if request.method == "GET":
        # IMPORTANT: pass all_groups itself, because the template
        # authelia_user_new.html reads all_groups
        return render_template(
            "authelia_user_new.html",
            all_groups=all_groups,
            error=users_error,
        )

    # ----- POST -----
    username = (request.form.get("username") or "").strip()
    displayname_raw = (request.form.get("displayname") or "").strip()
    email_raw = (request.form.get("email") or "").strip()

    # the ticked checkboxes
    selected_groups = request.form.getlist("groups")

    # extra groups, comma-separated -- THE FIELD NAME MUST MATCH name="groups_extra" in the HTML
    groups_extra_raw = (request.form.get("groups_extra") or "").strip()
    extra_groups = [g.strip()
                    for g in groups_extra_raw.split(",") if g.strip()]

    # the resulting list of groups
    groups = sorted(set(selected_groups + extra_groups))

    password = request.form.get("password") or ""
    password2 = request.form.get("password2") or ""

    form = {
        "username": username,
        "displayname": displayname_raw,
        "email": email_raw,
        "selected_groups": selected_groups,
        "groups_extra": groups_extra_raw,
    }

    # ---- validating the required fields ----
    if not username:
        return render_template(
            "authelia_user_new.html",
            error='Enter the username',
            form=form,
            all_groups=all_groups,
        )

    if not displayname_raw:
        return render_template(
            "authelia_user_new.html",
            error="Enter the user display name",
            form=form,
            all_groups=all_groups,
        )

    if not email_raw:
        return render_template(
            "authelia_user_new.html",
            error="Enter the user email",
            form=form,
            all_groups=all_groups,
        )

    if not password:
        return render_template(
            "authelia_user_new.html",
            error="Enter a password",
            form=form,
            all_groups=all_groups,
        )

    if password != password2:
        return render_template(
            "authelia_user_new.html",
            error='Password and confirmation do not match',
            form=form,
            all_groups=all_groups,
        )

    # ---- preparing the fields for usersd ----
    displayname = displayname_raw or None
    email = email_raw or None

    fields = {
        "displayname": displayname,
        "email": email,
        "disabled": False,
        "groups": groups,
    }

    try:
        user, error = create_authelia_user(
            username=username,
            fields=fields,
            password_plain=password,
        )
    except Exception as exc:
        current_app.logger.exception("Authelia: cannot create user")
        record_request(
            "user.create",
            object_type="user",
            object_id=username,
            result=RESULT_FAILURE,
            detail=str(exc),
        )
        return render_template(
            "authelia_user_new.html",
            error=f"Creation error: {exc}",
            form=form,
            all_groups=all_groups,
        )

    if error:
        # as when editing: just show the error and the form
        record_request(
            "user.create",
            object_type="user",
            object_id=username,
            result=RESULT_FAILURE,
            detail=str(error),
        )
        return render_template(
            "authelia_user_new.html",
            error=f"Creation error: {error}",
            form=form,
            all_groups=all_groups,
        )

    # The password never reaches the record: only that one was set.
    record_request(
        "user.create",
        object_type="user",
        object_id=username,
        summary=summarize({}, {**fields, "password": "set"}),
    )

    # The user list reads its message from ?msg=,
    # so msg=... must be sent, not message=...
    return redirect(
        url_for("routes.authelia_users", msg=f"User {username} created"),
        code=303,
    )


@bp.route("/authelia/users/<username>", methods=["GET", "POST"])
def authelia_user_edit(username: str):
    """Editing an existing user."""
    username = (username or "").strip()
    if not username:
        return redirect(url_for("routes.authelia_users", msg="Empty username"))

    if request.method == "POST":
        displayname = (request.form.get("displayname") or "").strip()
        email = (request.form.get("email") or "").strip()
        disabled = bool(request.form.get("disabled"))
        groups = request.form.getlist("groups")
        groups_extra_raw = (request.form.get("groups_extra") or "").strip()
        if groups_extra_raw:
            for g in groups_extra_raw.split(","):
                g = g.strip()
                if g and g not in groups:
                    groups.append(g)

        groups = sorted(set(groups))

        # Passwords are opaque values: do not trim leading/trailing spaces.
        # If either password field is used, both values must match exactly.
        password_raw = request.form.get("password") or ""
        password_confirmation = request.form.get("password2") or ""
        password_plain = password_raw or None

        # ---- validating the required fields ----
        required_errors = []
        if not displayname:
            required_errors.append("Enter the user display name.")
        if not email:
            required_errors.append("Enter the user email.")
        if password_raw != password_confirmation:
            required_errors.append("Password and confirmation do not match")

        if required_errors:
            # all_groups must be collected again, so the form renders correctly
            _, all_groups, _ = get_authelia_users()
            for g in groups:
                if g not in all_groups:
                    all_groups.append(g)
            all_groups = sorted(all_groups)

            return render_template(
                "authelia_user_edit.html",
                user={
                    "username": username,
                    "displayname": displayname,
                    "email": email,
                    "groups": groups,
                    "disabled": disabled,
                },
                all_groups=all_groups,
                error=" ".join(required_errors),
                is_new=False,
            )

        fields = {
            "displayname": displayname,
            "email": email,
            "disabled": disabled,
            "groups": groups,
        }

        # Read the stored user first so the record can say what moved. A
        # failure here only costs the before/after detail, never the edit.
        previous, _previous_error = get_authelia_user(username)
        before = {
            key: (previous or {}).get(key)
            for key in ("displayname", "email", "disabled", "groups")
        }
        after = dict(fields)
        if password_plain:
            before["password"] = "kept"
            after["password"] = "changed"

        user, error = update_authelia_user(
            username, fields, password_plain=password_plain)
        if error:
            record_request(
                "user.update",
                object_type="user",
                object_id=username,
                result=RESULT_FAILURE,
                detail=str(error),
            )
            _, all_groups, _ = get_authelia_users()
            for g in groups:
                if g not in all_groups:
                    all_groups.append(g)
            all_groups = sorted(all_groups)
            return render_template(
                "authelia_user_edit.html",
                user={
                    "username": username,
                    "displayname": displayname,
                    "email": email,
                    "groups": groups,
                    "disabled": disabled,
                },
                all_groups=all_groups,
                error=error,
                is_new=False,
            )

        record_request(
            "user.update",
            object_type="user",
            object_id=username,
            summary=summarize(before, after),
        )
        return redirect(
            url_for("routes.authelia_users", msg=f"User {username} updated"),
            code=303,
        )

    # GET
    user, error = get_authelia_user(username)
    if error:
        return redirect(url_for("routes.authelia_users", msg=error))

    _, all_groups, _ = get_authelia_users()
    return render_template(
        "authelia_user_edit.html",
        user=user,
        all_groups=all_groups,
        error=None,
        is_new=False,
    )


@bp.route("/haproxy/stats")
def haproxy_stats_page():
    """
    A wrapper page for HAProxy's stats, so the UI's header stays.
    Inside it is just an iframe on /stats, which HAProxy serves itself.
    """
    return render_template("haproxy_stats.html")


@bp.route("/authelia/users/<username>/delete", methods=["POST"])
def authelia_user_delete(username: str):
    """Deleting a user."""
    username = (username or "").strip()
    if not username:
        return redirect(url_for("routes.authelia_users", msg="Empty username"))

    if username == (getattr(g, "remote_user", "") or "").strip():
        return redirect(
            url_for(
                "routes.authelia_users",
                msg="The currently authenticated user cannot be deleted",
            ),
            code=303,
        )

    ok, error = delete_authelia_user(username)
    if not ok and error:
        record_request(
            "user.delete",
            object_type="user",
            object_id=username,
            result=RESULT_FAILURE,
            detail=str(error),
        )
        return redirect(url_for("routes.authelia_users", msg=f"Deletion error: {username}: {error}"))

    record_request("user.delete", object_type="user", object_id=username)
    return redirect(
        url_for("routes.authelia_users", msg=f"User {username} deleted"),
        code=303,
    )


@bp.route("/authelia/bans", methods=["GET", "POST"])
def authelia_bans():
    """
    The Authelia bans page: unban forms and Authelia's logs.
    """
    log_ip = request.args.get("log_ip", "").strip()[:256]
    log_user = request.args.get("log_user", "").strip()[:256]
    log_level = request.args.get("log_level", "").strip()[:64]

    # Use Post/Redirect/Get so refreshing the result page never repeats a
    # privileged revoke operation. Preserve active log filters across it.
    if request.method == "POST":
        action = request.form.get("action", "")
        target = ""
        try:
            if action == "unban_user":
                username = request.form.get("username", "")
                target = username
                message, code = authelia_unban_user(username)
            elif action == "unban_ip":
                ip = request.form.get("ip", "")
                target = ip
                message, code = authelia_unban_ip(ip)
            else:
                message, code = "Unknown unban action", 400
        except Exception as e:  # pylint: disable=broad-except
            traceback.print_exc()
            message, code = str(e), 500

        if action in ("unban_user", "unban_ip"):
            record_request(
                "authelia_ban.lift",
                object_type="user" if action == "unban_user" else "ip",
                object_id=target,
                result=RESULT_SUCCESS if code == 200 else RESULT_FAILURE,
                detail="" if code == 200 else str(message)[:500],
            )
        flash(message, "success" if code == 200 else "error")
        redirect_args = {
            key: value
            for key, value in {
                "log_ip": log_ip,
                "log_user": log_user,
                "log_level": log_level,
            }.items()
            if value
        }
        return redirect(
            url_for("routes.authelia_bans", **redirect_args),
            code=303,
        )

    # --- bans ---
    bans = get_authelia_bans()
    bans_error = bans.get("error")

    logs, logs_error = get_authelia_logs(
        ip=log_ip or None,
        username=log_user or None,
        level=log_level or None,
    )

    return render_template(
        "authelia_bans.html",
        bans=bans,
        bans_error=bans_error,
        logs=logs,
        logs_error=logs_error,
        log_ip=log_ip,
        log_user=log_user,
        log_level=log_level,
    )


@bp.route("/api/country-batch", methods=["POST"])
def api_country_batch():
    data = request.get_json(silent=True) or {}
    ips = data.get("ips", [])
    if not isinstance(ips, list):
        return jsonify({"error": "ips must be a list"}), 400
    if len(ips) > 512:
        return jsonify({"error": "at most 512 IP addresses are allowed"}), 413
    result = {}
    for value in ips:
        x = str(value).strip()
        if x in result:
            continue
        try:
            ip_address(x)
            result[x] = get_country_code(x) or ""
        except Exception:
            result[x] = ""
    return jsonify(result)


@bp.route('/api/backends')
def api_backends():
    try:
        return jsonify(get_backends_status())
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@bp.route('/api/ip_auth')
def api_ip_auth():
    try:
        return jsonify(get_ip_auth_table())
    except Exception as e:  # pylint: disable=broad-except
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
