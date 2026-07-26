# Third-party notices

easy-ha-proxy contains the following third-party or third-party-derived source.
Original notices are retained where present, and modified files carry explicit
provenance and modification notices.

| File or group | Origin/modification | License |
| --- | --- | --- |
| `ansible/roles/authelia/files/lua/auth-request.lua` | Vendored with its original notice | MIT |
| `ansible/roles/authelia/files/lua/json.lua` | Vendored with its original notice | MIT |
| `ansible/roles/authelia/files/lua/http.lua` | Vendored with its original notice | Apache-2.0 |
| `ansible/roles/authelia/templates/Event.{html,txt}.{en,ru}.j2` | Adapted from official Authelia notification templates; English/Russian variants and Ansible/Jinja wrapping | Apache-2.0 |
| `ansible/roles/authelia/templates/IdentityVerificationJWT.{html,txt}.{en,ru}.j2` | Adapted from official Authelia notification templates; English/Russian variants and Ansible/Jinja wrapping | Apache-2.0 |
| `ansible/roles/authelia/templates/IdentityVerificationOTC.{html,txt}.{en,ru}.j2` | Adapted from official Authelia notification templates; English/Russian variants and Ansible/Jinja wrapping | Apache-2.0 |
| `docker/app/haproxy_admin/static/vendor/flag-icons/flags/4x3/*.svg` | Vendored from `lipis/flag-icons` v7.5.0 | MIT |
| `/etc/haproxy/geoip/releases/*/dbip-country-lite.mmdb` and derived `*.geo`/`*.cidr` files on managed servers | DB-IP Country Lite data downloaded at installation/update time; country CIDRs are derived locally from the same release | CC BY 4.0 |

The complete MIT notices are included in the corresponding source-file headers.
The Authelia template provenance is documented by the
[official notification-template reference](https://www.authelia.com/reference/guides/notification-templates/)
and in each modified file. A copy of Apache License 2.0 is provided in
[`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt).
The vendored flag license is provided in
[`LICENSES/flag-icons-MIT.txt`](LICENSES/flag-icons-MIT.txt).

DB-IP Country Lite is not committed to this repository or embedded in the
container image. The managed server downloads it from DB-IP and the web UI
keeps the required `IP Geolocation by DB-IP` attribution link on every page
that can display country results. See the [DB-IP Lite license and attribution
terms](https://db-ip.com/db/lite.php) and the
[Creative Commons Attribution 4.0 license](https://creativecommons.org/licenses/by/4.0/).

Unless a file states otherwise, the original easy-ha-proxy code and
documentation are licensed under GPL-3.0-or-later; see [`LICENSE`](LICENSE).

Dependencies and container images fetched at build or installation time are not
vendored by this repository and remain subject to their respective license
terms.

The `maxminddb` Python reader is fetched as a dependency and is licensed under
Apache-2.0. It reads the DB-IP MMDB format locally; it does not contact MaxMind
or any geolocation API at runtime.

## Runtime dependency note

The current Authelia Compose template references `redis:7.4.9-alpine`. Redis's
[official license table](https://redis.io/legal/licenses/) lists Redis Community
Edition 7.4 under the RSALv2 or SSPLv1 terms. The image is fetched separately at
deployment time and is not relicensed by easy-ha-proxy. Review the upstream
terms for the intended use and re-check them when changing the image version.
