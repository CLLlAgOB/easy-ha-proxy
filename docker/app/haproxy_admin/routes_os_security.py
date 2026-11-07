"""Superadmin controls for the host's distribution security updates."""
from __future__ import annotations

from flask import Blueprint, abort, render_template, request

from .routes_updates import _call_daemon, _identifier, _json_payload, _migration_configuration_error

bp_os_security = Blueprint('os_security', __name__, url_prefix='/system/os-security')


@bp_os_security.get('/')
def page():
    return render_template('os_security.html')


@bp_os_security.get('/api/status')
def status():
    payload = {'action': 'os_security_status'}
    if request.args.get('job_id'):
        payload['job_id'] = _identifier(request.args['job_id'], 'job id')
    return _call_daemon(payload)


@bp_os_security.post('/api/check')
def check():
    _json_payload(set())
    return _call_daemon({'action': 'os_security_check'}, accepted=True)


@bp_os_security.post('/api/policy')
def policy():
    payload = _json_payload({'mode', 'interval', 'start', 'end', 'confirmation'})
    if (not isinstance(payload['mode'], str) or payload['mode'] not in {'system', 'notify', 'auto', 'window'} or type(payload['interval']) is not int
            or payload['interval'] not in (1, 2, 4, 6, 12, 24)
            or any(type(payload[key]) is not int or not 0 <= payload[key] <= 23 for key in ('start', 'end'))
            or payload['start'] == payload['end'] or payload['confirmation'] != 'SECURITY'):
        abort(400, description='Invalid OS security policy or confirmation')
    error = _migration_configuration_error()
    if error is not None:
        return error
    return _call_daemon({'action': 'os_security_configure', **payload}, accepted=True)


@bp_os_security.post('/api/install')
def install():
    payload = _json_payload({'confirmation'})
    if payload['confirmation'] != 'SECURITY':
        abort(400, description='Type SECURITY to confirm OS security management')
    error = _migration_configuration_error()
    if error is not None:
        return error
    return _call_daemon({'action': 'os_security_install', 'confirmation': 'SECURITY'}, accepted=True)
