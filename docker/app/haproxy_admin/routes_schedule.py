"""Read-only overview of existing host maintenance schedules."""
from flask import Blueprint, render_template

bp_schedule = Blueprint('schedule', __name__, url_prefix='/system/schedule')


@bp_schedule.get('/')
def page():
    return render_template('system_schedule.html')
