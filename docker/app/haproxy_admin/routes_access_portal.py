"""Administration is superadmin-only; downloads require a verified gate login."""
from flask import Blueprint, Response, abort, current_app, flash, g, get_flashed_messages, jsonify, make_response, redirect, render_template, request, send_file, url_for
from . import access_portal as portal
from .audit import RESULT_FAILURE, RESULT_SUCCESS, record_request
from .services_haproxy_sites import add_site_minimal, get_cert_status_for_site, get_site_raw_and_effective, get_sites_and_defaults_for_ui, save_access_site_identity
from .validation import validate_domain
from .i18n import translate
from . import services_haproxy_config as config
import yaml
import os
import threading
import time

bp_access_portal = Blueprint('access_portal', __name__)
_DOWNLOAD_SLOTS = threading.BoundedSemaphore(2)


# Four transfers at once is all the panel gives to downloads (two in each of
# its two workers), so one that never ends, or one visitor taking them all,
# kept everyone else at "downloads are busy". A transfer now has an hour, a
# block the visitor does not take within a minute ends it, and one visitor
# has one transfer at a time. An hour carries the largest attachment allowed
# (128 MiB) over a link of about 0.3 Mbit/s.
DOWNLOAD_SECONDS = 3600
DOWNLOAD_STALL_SECONDS = 60


class _DownloadLease:
    """Keep half the default worker's threads free for administration."""
    def __init__(self, stream, turn=None, sock=None, seconds=DOWNLOAD_SECONDS):
        self.stream = stream
        self.turn = turn
        self.sock = sock
        self.deadline = time.monotonic() + seconds
        self.guard = threading.Lock()
        self.released = False
        self.previous_timeout = None
        if sock is not None:
            try:
                self.previous_timeout = sock.gettimeout()
                sock.settimeout(DOWNLOAD_STALL_SECONDS)
            except OSError:
                self.sock = None

    def __getattr__(self, name):
        # No descriptor is offered: the server would hand the file to the
        # kernel in one call and the time limit below would never be asked.
        if name == 'fileno':
            raise AttributeError(name)
        return getattr(self.stream, name)

    def read(self, size=-1):
        if time.monotonic() > self.deadline:
            raise TimeoutError('The download took longer than it is allowed')
        return self.stream.read(size)

    def close(self):
        with self.guard:
            if self.released:
                return
            self.released = True
        try:
            self.stream.close()
        finally:
            try:
                if self.sock is not None:
                    self.sock.settimeout(self.previous_timeout)
            except OSError:
                pass
            finally:
                if self.turn is not None:
                    try:
                        os.close(self.turn)
                    except OSError:
                        pass
                _DOWNLOAD_SLOTS.release()


@bp_access_portal.get('/api/access-portal-health')
def health():
    return jsonify(ok=True)


def _site(name):
    _, raw, effective = get_site_raw_and_effective(name)
    if raw is None or effective.get('access_gate') is not True:
        abort(404)
    return raw


def set_routing(name, enabled):
    """Opt in this site only; apply remains in the normal guarded workflow."""
    with config.source_lock('websites'):
        data = config._load_yaml(config.WEBSITES_YAML)
        site = next((s for s in data.get('sites', []) if s.get('name') == name), None)
        if site is None:
            raise ValueError('Access page not found')
        if bool(site.get('access_portal_enabled', False)) == enabled:
            return False
        site['access_portal_enabled'] = enabled
        ok, message = config.update_yaml_file('websites', yaml.safe_dump(data, allow_unicode=True, sort_keys=False))
        if not ok:
            raise ValueError(message)
        return True


@bp_access_portal.route('/haproxy/access-sites', methods=['GET', 'POST'])
def sites():
    error = None
    if request.method == 'POST':
        try:
            domain = validate_domain(request.form.get('domain', ''))
            ok, message = add_site_minimal(domain, domain, '', '')
            record_request('site.create', object_type='site', object_id=domain,
                           result=RESULT_SUCCESS if ok else RESULT_FAILURE,
                           detail='Service access site' if ok else str(message)[:500])
            if ok:
                flash(message)
                return redirect(url_for('access_portal.edit', name=domain))
            error = message
        except ValueError as exc:
            error = str(exc)
    _, items = get_sites_and_defaults_for_ui()
    return render_template('access_sites.html', sites=[item for item in items
                           if item['effective'].get('access_gate') is True], error=error)


@bp_access_portal.route('/haproxy/sites/<name>/portal', methods=['GET', 'POST'])
def edit(name):
    site = _site(name)
    error = None
    if request.method == 'POST':
        action = request.form.get('action')
        # The short form takes no proxy fields: a service site has no backend.
        # The one exception is a gate from before the split that already
        # proxies to a single backend of its own -- its address and port.
        allowed = {'action', 'domain', 'paused', 'revision', 'csrf_token'}
        if site.get('backend_ip') and not site.get('servers'):
            allowed |= {'backend_ip', 'backend_port'}
        if (set(request.form) - allowed
                or action not in {'save_identity', 'delete'}
                or request.form.get('paused', 'false') not in {'true', 'false'}):
            abort(400)
        backend = None
        if action == 'save_identity' and ('backend_ip' in request.form or 'backend_port' in request.form):
            backend = (request.form.get('backend_ip', ''), request.form.get('backend_port', ''))
        try:
            ok, message = save_access_site_identity(name, request.form.get('domain', ''),
                request.form.get('paused') == 'true', request.form.get('revision'), delete=action == 'delete',
                backend=backend)
            record_request('site.delete' if action == 'delete' else 'site.update',
                           object_type='site', object_id=name, result=RESULT_SUCCESS if ok else RESULT_FAILURE,
                           detail='' if ok else str(message)[:500])
            if ok:
                flash(message)
                return redirect(url_for('access_portal.sites' if action == 'delete' else 'access_portal.edit',
                                        **({} if action == 'delete' else {'name': name})))
            error = message
        except config.StaleEntry as exc:
            error = str(exc)
        site = _site(name)
    return render_template('access_portal_settings.html', site=site, error=error,
                           messages=get_flashed_messages(), site_revision=config.entry_revision(site),
                           cert=get_cert_status_for_site(site))


@bp_access_portal.route('/haproxy/sites/<name>/portal/settings', methods=['GET', 'POST'])
def settings(name):
    _site(name)
    try:
        if request.method == 'POST':
            changed = []
            value = portal.configure(name, request.get_json(silent=True),
                                     before_save=lambda enabled: changed.append(set_routing(name, enabled)))
            value['routing_changed'] = any(changed)
            record_request("access_portal.settings", object_type='site', object_id=name,
                           detail='Access page instructions and attachment labels updated')
        else:
            value = portal.settings(name)
        return jsonify(ok=True, settings=value)
    except FileExistsError as exc:
        return jsonify(ok=False, error=str(exc)), 409
    except ValueError as exc:
        return jsonify(ok=False, error=str(exc)), 400


@bp_access_portal.post('/haproxy/sites/<name>/portal/files')
def upload(name):
    _site(name)
    if request.mimetype != 'application/octet-stream':
        abort(415)
    try:
        value = portal.upload(name, request.args.get('filename', ''), request.stream)
        record_request("access_portal.upload", object_type='site', object_id=name,
                       detail='Access page attachment uploaded')
        return jsonify(ok=True, settings=value)
    except ValueError as exc:
        return jsonify(ok=False, error=str(exc)), 400


@bp_access_portal.post('/haproxy/sites/<name>/portal/files/<identifier>/delete')
def delete(name, identifier):
    _site(name)
    try:
        value = portal.delete(name, identifier)
        record_request("access_portal.delete", object_type='site', object_id=name,
                       detail='Access page attachment removed')
        return jsonify(ok=True, settings=value)
    except ValueError as exc:
        return jsonify(ok=False, error=str(exc)), 400


def _public_portal():
    if not getattr(g, 'access_portal', False):
        abort(403)
    try:
        site = portal.site_by_host(request.headers.get('X-Easy-HA-Proxy-Portal-Host', ''))
        value = portal.settings(site['name'])
        if value['language'] != 'auto':
            g.language = value['language']
        return site, value
    except (ValueError, FileNotFoundError):
        abort(404)


def _file_size(size):
    if size < 1024:
        return translate('{size} B', size=size)
    if size < 1024 * 1024:
        return translate('{size} KiB', size=f'{size / 1024:.1f}')
    return translate('{size} MiB', size=f'{size / (1024 * 1024):.1f}')


@bp_access_portal.get('/access-portal/')
def page():
    _, value = _public_portal()
    # This small landing page needs no admin badges or daemon status calls.
    response = make_response(current_app.jinja_env.get_template('access_portal.html').render(
        current_language=g.language, portal=value, _=translate, file_size=_file_size))
    response.headers['Content-Language'] = g.language
    return response


@bp_access_portal.get('/access-portal/downloads/<identifier>')
def download(identifier):
    site, _ = _public_portal()

    def refused(message):
        response = Response(translate(message), status=429, mimetype='text/plain')
        response.headers['Retry-After'] = '10'
        return response

    turn = portal.download_turn(g.remote_user)
    if turn is None:
        return refused('You already have a download in progress. Please wait for it to finish.')
    if not _DOWNLOAD_SLOTS.acquire(blocking=False):
        os.close(turn)
        return refused('Downloads are busy. Please try again in 10 seconds.')
    try:
        stream, item = portal.open_download(site['name'], identifier)
    except BaseException as error:
        os.close(turn)
        _DOWNLOAD_SLOTS.release()
        if isinstance(error, FileNotFoundError):
            abort(404)
        raise
    lease = _DownloadLease(stream, turn, request.environ.get('gunicorn.socket'))
    try:
        response = send_file(lease, mimetype='application/octet-stream', as_attachment=True,
                             download_name=item['filename'], conditional=False, max_age=0)
    except BaseException:
        lease.close()
        raise
    response.content_length = item['size']
    response.headers['Cache-Control'] = 'private, no-store'
    response.call_on_close(lease.close)
    return response
