# HAProxy server-state restoration

The state file preserves operator controls across reloads and restarts. It is
not a backup of configuration: `show servers state` also contains transport
overrides and DNS/health caches that can conflict with a new configuration.

`installer/haproxy_server_state.py` is shared by periodic dumps, panel reload,
cold start, package migration and rollback. The host installs the same source
under `/usr/local/libexec/easy-ha-proxy/`.
The update checker fingerprints this installed helper as a host-service
component; a helper-only source change runs the `ha-cfg` deployment stage.

| Fields | Restoration rule |
| --- | --- |
| `be_id`, `be_name`, `srv_id`, `srv_name`, `bk_f_forced_id`, `srv_f_forced_id` | Keep identity; reconcile settings by backend and server name. |
| `srv_admin_state` | Keep maintenance/drain. Remove the runtime FQDN override bit. HAProxy handles configured `disabled` changes and inherited states. |
| `srv_uweight`, `srv_iweight` | Keep both: HAProxy preserves runtime weight if configured weight is unchanged, and otherwise honors the new configured weight. |
| `srv_addr`, `srv_fqdn` | Fixed IP comes from config. Keep DNS cache only for the same hostname; resolve a renamed hostname or IP-to-DNS transition afresh. |
| `srv_port` | Explicit configured port wins; keep a discovered port only for the same SRV record. |
| `srvrecord` | Preserve discovery for the same record; clear a previous record/target after a configuration change. |
| `srv_op_state`, `srv_time_since_last_change`, `srv_check_status`, `srv_check_result`, `srv_check_health` | Keep health history while checks exist. After removing all checks, clear a health failure that could otherwise pin the server DOWN forever. Maintenance/drain still applies. |
| `srv_check_state`, `srv_agent_state` | Keep explicit administrative check disable while the check exists. HAProxy initializes new checks from config. |
| `srv_use_ssl`, `srv_check_port`, `srv_check_addr`, `srv_agent_addr`, `srv_agent_port` | Omit this optional suffix: TLS and check transport come from config. |

SNI, ALPN, certificate verification, HTTP Host, HTTP health URI/expected status,
backup role and maxconn are not configuration overrides stored in this protocol.
The real-worker audit also exercises their application after loading state.
Balancing and timeouts likewise are outside this protocol; this audit does not
claim to qualify every HAProxy option.

## Failure and startup paths

The dumper writes atomically and preserves existing permissions and ownership.
On an unavailable/malformed runtime reply it
reconciles the last valid snapshot with current config. Unknown formats and
incomplete rows never replace a valid snapshot. A systemd `ExecStartPre` guard
also normalizes before cold start; it is removed when state loading is disabled.
Migration and rollback normalize even legacy raw snapshots before restoration.
The saved recovery command includes its own normalizer copy; both files have
integrity checks, so recovery does not depend on the current source checkout.

## Regression checks

- `.tests/test_haproxy_server_state.py`: field policies and format validation.
- `.tests/test_server_state.py`: shell wrapper, fallback and Ansible ordering.
- `.tests/test_haproxy_package_migration.py`: migration snapshots and startup guard qualification.
- `.tests/integration/server_state_settings_smoke.py`: 24 transitions against isolated
  HAProxy processes and temporary HTTP/TLS backends, including SNI, ALPN,
  certificate verification, DNS, health checks, roles and weights.
- CI runs the real-worker audit on the distribution baseline; the native package
  workflow repeats it on HAProxy 3.4 for amd64/arm64. The disposable systemd
  migration fixture also installs the startup guard.

Protocol: [HAProxy management guide](https://docs.haproxy.org/3.4/management.html#show%20servers%20state).
