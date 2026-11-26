# Native Rust and Go runtime

The host daemons, the host tools and the web panel are compiled binaries for
`linux/amd64` and `linux/arm64` (including NanoPi ARM64 gateways). There is no
other implementation: the former Python daemons and the Flask panel were
removed, and updates go forward only.

- **`guardd-core`** (Rust): the adaptive protection engine -- the HAProxy
  access-log hot path, per-address memory, `/24` correlation, SQLite
  persistence (`security.db`, `requests.db`), the enforcer and the AF_UNIX
  HTTP API.
- **`easy-ha-proxy-agent`** (Go, `CGO_ENABLED=0`, static): one multi-call
  binary for the host daemons (`healthd`, `metricsd`, `alertd`, `controld`,
  `certd`, `backupd`, `updated`, `authelia-bansd`, `authelia-usersd`,
  `authelia-configd`) and the tools (`unit-failed`, `backup-run`,
  `server-state`, `udp-forward`, `cert-deliver`, `update-geoip`,
  `apt-metadata`, `probe-host`), the installer (`apply`) and the update
  checker the update broker signs (`update-plan`, with `update-scope` for
  "only what changed").
- **`easy-ha-proxy-panel`** (Go, `CGO_ENABLED=0`): the web panel in a
  `FROM scratch` container with a built-in `healthcheck` subcommand. Its
  templates, static files and translations live in `go/panel/web`.

The installer's command line (`installer/`) and the host tools the backup
and OS-security brokers run (`full_backup.py`, `os_security.py`,
`ssh_protection.py`, ...) remain Python, on the platform interpreter.

## Release bundles and images

CI publishes, from each tested commit on `alpha` or `main`:

- the panel image `clllagob/haproxy-admin-ui:go-alpha` (or `go-latest`);
- the native OCI image `clllagob/haproxy-admin-ui:native-alpha` (or
  `native-latest`), also tagged `native-<channel>-<12 hex of the commit>`,
  holding `sbin/easy-ha-proxy-agent`, `sbin/guardd-core` and `SHA256SUMS`;
- the tarballs `easy-ha-proxy-native-linux-{amd64,arm64}.tar.gz` with
  `SHA256SUMS`, for air-gapped installs.

## Installation

The `native` stage of the playbook installs the binaries before the daemons
and the GeoIP updater need them:

- By default it takes the image CI built from the checked-out commit
  (`native_release_pin_revision: true`), checks that its revision label names
  that commit, copies the files out by digest and verifies `SHA256SUMS`.
- `native_local_bundle_dir` (a local tarball) or an HTTPS
  `native_release_base_url` with `native_release_checksums` override that.
- `native_release_verify_signature: true` also verifies the image's Cosign
  signature before anything is extracted.

A replaced binary restarts the daemons that run it; the update broker is
restarted once the update job that runs the playbook has finished.
