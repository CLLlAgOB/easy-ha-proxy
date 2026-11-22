# Native Rust + Go Host Daemons (Opt-In)

`easy-ha-proxy` ships an optional precompiled native runtime alongside the default Python daemons for both `linux/amd64` and `linux/arm64` (including NanoPi ARM64 gateways):

- **`guardd-core` (Rust, ~2.1 MB)** + **`libguardd_core.so`**: zero-regex HAProxy access-log hot path (`~730k lines/s`, `~4.1 MB` RSS), SLRU IP memory, `/24` subnet correlation, SQLite persistence (`security.db`, `requests.db`), enforcer, and AF_UNIX HTTP API.
- **`easy-ha-proxy-agent` (Go, `CGO_ENABLED=0`, ~6.7–7.1 MB)**: single static zero-dependency multi-call binary hosting all 7 orchestration/control daemons (`healthd`, `metricsd`, `alertd`, `controld`, `certd`, `backupd`, `updated`).

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

## Enabling Native Daemons (Opt-In)

All native switches default to `false` in `ansible/roles/haproxy-admin/defaults/main.yml`, so existing gateways continue running Python daemons unchanged until you opt in.

### Option A: Install from a verified HTTPS release mirror

Add to your `vars.yml`:

```yaml
native_daemons_enabled: true
native_release_base_url: "https://example.invalid/easy-ha-proxy/native"
native_release_checksums:
  amd64: "<64-hex sha256 of easy-ha-proxy-native-linux-amd64.tar.gz>"
  arm64: "<64-hex sha256 of easy-ha-proxy-native-linux-arm64.tar.gz>"
```

### Option B: Install from a pre-fetched local bundle directory

```yaml
native_daemons_enabled: true
native_local_bundle_dir: "/opt/easy-ha-proxy/native-bundles"
```

### Option C: Gradual per-daemon rollout (or Rust FFI acceleration only)

Keep `native_daemons_enabled: false` and enable individual services selectively:

```yaml
native_guardd_ffi_enabled: true   # accelerate Python guardd via libguardd_core.so
native_healthd_enabled: true
native_metricsd_enabled: true
native_alertd_enabled: true
```

Apply with:

```bash
ansible-playbook -i inventory ansible/easy-ha-proxy.yml --tags ha-adm-daemons
```

## Instant Rollback

Set `native_daemons_enabled: false` (or flip any individual `native_<daemon>_enabled: false`) in `vars.yml` and re-run `--tags ha-adm-daemons`. The original Python scripts remain installed in `/usr/local/sbin/`, so systemd units switch back immediately.
