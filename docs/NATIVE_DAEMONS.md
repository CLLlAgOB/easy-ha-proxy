# Native Rust and Go Runtime

`easy-ha-proxy` ships a precompiled native runtime with a Python fallback for both `linux/amd64` and `linux/arm64` (including NanoPi ARM64 gateways):

- **`guardd-core` (Rust, ~2.1 MB)** + **`libguardd_core.so`**: zero-regex HAProxy access-log hot path (`~730k lines/s`, `~4.1 MB` RSS), SLRU IP memory, `/24` subnet correlation, SQLite persistence (`security.db`, `requests.db`), enforcer, and AF_UNIX HTTP API.
- **`easy-ha-proxy-agent` (Go, `CGO_ENABLED=0`, ~7.5–7.9 MB)**: single static zero-dependency multi-call binary hosting all 10 host daemons (`healthd`, `metricsd`, `alertd`, `controld`, `certd`, `backupd`, `updated`, `authelia-bansd`, `authelia-usersd`, `authelia-configd`) and 6 oneshot/timer utilities (`unit-failed`, `backup-run`, `server-state`, `udp-forward`, `cert-deliver`, `update-geoip`).
- **`easy-ha-proxy-panel` (Go, `CGO_ENABLED=0`, ~7.2 MB, `FROM scratch` container)**: optional native Go web administration panel replacing Python/Flask + Gunicorn with a ~12 MB scratch container and a built-in ~2 ms `healthcheck` subcommand (`haproxy_admin_use_go_panel: true` in `vars.yml`).

## Architecture & Release Bundles

CI builds and verifies dual-architecture tarballs in the `Native release bundles (amd64 + arm64)` workflow job:

- `easy-ha-proxy-native-linux-amd64.tar.gz`
- `easy-ha-proxy-native-linux-arm64.tar.gz`
- `SHA256SUMS`

Each archive contains:

```text
sbin/easy-ha-proxy-agent
sbin/guardd-core
lib/libguardd_core.so
```

## Default Runtime and Image Channels

Both `native_daemons_enabled` and `haproxy_admin_use_go_panel` default to `true`. The installer sets `haproxy_admin_image` from the selected image channel.

- The `alpha` channel pulls `go-alpha` for the panel and `native-alpha` for the host binaries. The stable channel pulls `go-latest` and `native-latest`.
- The native OCI image supports `linux/amd64` and `linux/arm64`. The installer verifies `SHA256SUMS` before copying binaries into `/usr/local/sbin/`.
- Operators can still override delivery with `native_local_bundle_dir` or an HTTPS `native_release_base_url` + `native_release_checksums`.

## Instant Rollback to Python

Set `native_daemons_enabled: false` and/or `haproxy_admin_use_go_panel: false` (or flip any individual `native_<daemon>_enabled: false`) in `vars.yml` and re-run Ansible. The original Python scripts remain installed in `/usr/local/sbin/`, so systemd units and the Docker container switch back immediately.
