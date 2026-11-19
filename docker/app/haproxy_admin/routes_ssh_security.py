"""Superadmin controls for protection of the host SSH service."""
from flask import Blueprint, abort, jsonify, render_template, request

from .audit import RESULT_SUCCESS, audit_log
from .routes_updates import _call_daemon, _identifier, _json_payload

bp_ssh_security = Blueprint('ssh_security', __name__, url_prefix='/system/ssh-security')


@bp_ssh_security.get('/')
def page():
    return render_template('ssh_security.html')


@bp_ssh_security.get('/api/status')
def status():
    payload = {'action': 'ssh_protection_status'}
    if request.args.get('job_id'):
        payload['job_id'] = _identifier(request.args['job_id'], 'job id')
    return _call_daemon(payload)


@bp_ssh_security.post('/api/connection')
def connection():
    payload = _json_payload({'user', 'ip'}, {'hostname', 'local_address', 'port'})
    return _call_daemon({'action': 'ssh_protection_connection', **payload})


@bp_ssh_security.get('/api/unblock-history')
def unblock_history():
    history = audit_log().query(action='ssh.unban', result=RESULT_SUCCESS, limit=25)
    return jsonify(ok=True, available=history['available'], events=[
        {key: row[key] for key in ('ts', 'actor', 'summary')} for row in history['events']
    ])


@bp_ssh_security.post('/api/monitoring')
def monitoring():
    payload = _json_payload({'enabled'})
    if type(payload['enabled']) is not bool:
        abort(400, description='Invalid SSH monitoring setting')
    return _call_daemon({'action': 'ssh_protection_monitor', **payload})


@bp_ssh_security.post('/api/protection')
def protection():
    payload = _json_payload({'operation', 'trusted'}, {'policy'})
    if payload['operation'] not in ('install', 'enable', 'disable') or not isinstance(payload['trusted'], list):
        abort(400, description='Invalid SSH protection operation')
    return _call_daemon({'action': 'ssh_protection_configure', **payload}, accepted=True)


@bp_ssh_security.post('/api/unban')
def unban():
    payload = _json_payload({'ip'})
    return _call_daemon({'action': 'ssh_protection_unban', **payload})
