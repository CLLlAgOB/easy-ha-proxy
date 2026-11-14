"""Superadmin controls for the host's distribution security updates."""
from __future__ import annotations

import re

from flask import Blueprint, abort, render_template, request

from .routes_updates import _call_daemon, _actor, _boot_id, _identifier, _json_payload, _migration_configuration_error

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
    if (not isinstance(payload['mode'], str) or payload['mode'] not in {'system', 'notify', 'auto', 'window', 'daily'} or type(payload['interval']) is not int
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


@bp_os_security.post('/api/automatic-reboot')
def automatic_reboot():
    payload = _json_payload({'enabled', 'time', 'confirmation', 'expected_boot_id'}, {'allow_service_reboot'})
    if (type(payload['enabled']) is not bool or not isinstance(payload['time'], str)
            or not re.fullmatch(r'(?:[01][0-9]|2[0-3]):[0-5][0-9]', payload['time']) or payload['confirmation'] != 'REBOOT'
            or type(payload.get('allow_service_reboot', False)) is not bool):
        abort(400, description='Confirm a valid automatic reboot policy')
    if payload['enabled']:
        error = _migration_configuration_error()
        if error is not None:
            return error
    return _call_daemon({'action': 'set_auto_reboot', 'enabled': payload['enabled'], 'time': payload['time'],
                         **({'allow_service_reboot': payload['allow_service_reboot']} if 'allow_service_reboot' in payload else {}),
                         'confirmation': 'REBOOT', 'expected_boot_id': _boot_id(payload['expected_boot_id']), 'actor': _actor()})


@bp_os_security.post('/api/restart-policy')
def restart_policy():
    payload = _json_payload({'enabled', 'time', 'confirmation', 'expected_boot_id'})
    if (type(payload['enabled']) is not bool or not isinstance(payload['time'], str)
            or not re.fullmatch(r'(?:[01][0-9]|2[0-3]):[0-5][0-9]', payload['time']) or payload['confirmation'] != 'SECURITY'):
        abort(400, description='Confirm a valid service restart policy')
    if payload['enabled']:
        error = _migration_configuration_error()
        if error is not None:
            return error
    return _call_daemon({'action': 'set_service_restarts', **payload,
                         'expected_boot_id': _boot_id(payload['expected_boot_id']), 'actor': _actor()})


@bp_os_security.post('/api/restart-check')
def restart_check():
    _json_payload(set())
    return _call_daemon({'action': 'os_security_restart_check'}, accepted=True)


@bp_os_security.post('/api/restart')
def restart_services():
    payload = _json_payload({'confirmation'})
    if payload['confirmation'] != 'SECURITY':
        abort(400, description='Confirm service restarts')
    error = _migration_configuration_error()
    if error is not None:
        return error
    return _call_daemon({'action': 'os_security_restart', 'confirmation': 'SECURITY'}, accepted=True)
