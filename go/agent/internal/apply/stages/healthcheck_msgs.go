package stages

// healthcheckMsgs are the debug and fail tasks' msg: of
// roles/healthcheck/tasks/status.yml, word for word, by task name.
var healthcheckMsgs = map[string]string{
	"Status check | summary for systemd services": `=== SERVICES (systemd) ===
{% if status_check_systemd_result is not defined
      or status_check_systemd_result.results | length == 0 %}
(No services to check; see status_check_systemd_units)
{% else %}
{%   for r in status_check_systemd_result.results %}
{%     set state = ((r.stdout | default('')) | trim) or 'unknown' %}
{%     set prefix = 'OK  ' if state == 'active' else 'FAIL' %}
{%     if r.item.name in (status_check_daemon_versions | default({})) %}
{%       set version = status_check_daemon_versions[r.item.name] %}
{%       set current = version.installed == version.source %}
[{{ prefix }}] {{ r.item.label | default(r.item.name) }} ({{ r.item.name }}): state={{ state }}, installed={{ version.installed[:12] }}, source={{ version.source[:12] }}, {{ 'current' if current else 'UPDATE AVAILABLE' }}
{%     else %}
[{{ prefix }}] {{ r.item.label | default(r.item.name) }} ({{ r.item.name }}): {{ state }}
{%     endif %}
{%   endfor %}
{% endif %}
`,
	"Status check | summary for scheduled oneshot jobs": `=== SCHEDULED ONESHOT JOBS ===
{% if status_check_systemd_jobs_result.results | default([]) | length == 0 %}
(No oneshot jobs enabled)
{% else %}
{%   for r in status_check_systemd_jobs_result.results %}
{%     set timer = status_check_systemd_timer_result.results[loop.index0] %}
[{{ 'FAIL' if r.item.service in status_check_systemd_jobs_failed else ('WAIT' if r.item.service in status_check_systemd_jobs_never_run else 'OK  ') }}] {{ r.item.label }} ({{ r.item.service }}): {{ r.stdout | default('no data') | replace('\n', ', ') }}; {{ timer.stdout | default('no schedule') | replace('\n', ', ') }}
{%   endfor %}
{% endif %}
`,
	"Status check | summary for Docker containers": `=== CONTAINERS (Docker) ===
{% if status_check_docker_enabled | length == 0 %}
(No containers to check; see status_check_docker_containers)
{% elif status_check_docker_result is not defined
        or status_check_docker_result.results | length == 0 %}
(docker_container_info returned nothing -- check that Docker and the community.docker collection are there)
{% else %}
{%   for r in status_check_docker_result.results %}
{%     if not (r.exists | default(false)) %}
[FAIL] {{ r.item.label | default(r.item.name) }} ({{ r.item.name }}): not found
{%     else %}
{%       set st = r.container.State.Status | default('unknown') %}
{%       set health = (r.container.State.Health.Status
                       if r.container.State.Health is defined
                       else 'n/a') %}
{%       set ok = (st == 'running'
                  and (r.container.State.Health is not defined
                       or health == 'healthy')) %}
[{{ 'OK  ' if ok else 'FAIL' }}] {{ r.item.label | default(r.item.name) }} ({{ r.item.name }}): status={{ st }}, health={{ health }}
{%     endif %}
{%   endfor %}
{% endif %}
`,
	"Status check | summary for managed artifacts": `=== MANAGED SCRIPTS / UNIT FILES ===
{% if status_check_managed_artifact_versions | length == 0 %}
(No files enabled for checking)
{% else %}
{%   for name, version in status_check_managed_artifact_versions.items() %}
{%     set current = version.installed == version.source %}
[{{ 'OK  ' if current else 'UPD ' }}] {{ version.label }}: installed={{ version.installed[:12] }}, source={{ version.source[:12] }}, {{ 'current' if current else 'UPDATE AVAILABLE' }}
{%   endfor %}
{% endif %}
`,
	"Status check | summary for APT package versions": `=== APT PACKAGE VERSIONS OF THE SERVICES ===
{% for r in status_check_apt_installed_result.results | default([]) %}
{%   set policy = status_check_apt_candidate_result.results[loop.index0].stdout | default('') %}
{%   set candidate = (policy | regex_findall('Candidate:\\s*(\\S+)') | first | default('unknown')) %}
[{{ 'FAIL' if r.rc != 0 else ('UPD ' if r.stdout != candidate and candidate not in ['unknown', '(none)'] else 'OK  ') }}] {{ r.item }}: installed={{ r.stdout | default('missing', true) }}, candidate={{ candidate }}
{% endfor %}
`,
	"Status check | summary for snap package versions": `=== SNAP PACKAGE VERSIONS OF THE SERVICES ===
{% for r in status_check_snap_result.results | default([]) %}
[{{ 'OK  ' if (r.rc | default(1)) == 0 else 'FAIL' }}] {{ r.item }}: {{ (r.stdout_lines | default([]) | last) if (r.rc | default(1)) == 0 else (r.stderr | default('not installed', true)) }}
{% endfor %}
`,
	"Status check | final summary": `=== SUMMARY ===
systemd services:
  failing: {{ status_check_systemd_failed_unique | join(', ') | default('none', true) }}
Helper daemons:
  need an update: {{ status_check_daemon_outdated | join(', ') | default('none', true) }}
Scheduled oneshot jobs:
  failing: {{ status_check_systemd_jobs_failed | join(', ') | default('none', true) }}
  not run yet: {{ status_check_systemd_jobs_never_run | join(', ') | default('none', true) }}
Managed scripts and unit files:
  need an update: {{ status_check_managed_artifacts_outdated | join(', ') | default('none', true) }}
Service packages:
  missing: {{ status_check_package_failed | join(', ') | default('none', true) }}
Docker containers:
  failing: {{ status_check_docker_failed_unique | join(', ') | default('none', true) }}
`,
	"Status check | print logs for failed services": `=== systemd logs of {{ item.item }} (last {{ status_check_journal_lines | default(40) }} lines) ===
{{ item.stdout | default('no logs') }}
`,
	"Status check | print docker logs for failed containers": `=== docker compose logs of {{ item.item }} (last {{ status_check_docker_log_lines | default(80) }} lines) ===
{{ item.stdout | default('no logs, or docker compose did not run') }}
`,
	"Status check | fail if there are problems (optional)": `Problems found with managed components:
  systemd: {{ status_check_systemd_failed_unique | join(', ') | default('none', true) }}
  oneshot: {{ status_check_systemd_jobs_failed | join(', ') | default('none', true) }}
  artifacts: {{ status_check_managed_artifacts_outdated | join(', ') | default('none', true) }}
  packages: {{ status_check_package_failed | join(', ') | default('none', true) }}
  docker: {{ status_check_docker_failed_unique | join(', ') | default('none', true) }}
`,
}
