// JS for страницы редактирования site HAProxy
// - показ/скрытие блока удаления
// - динамический list backend-servers (main/backup)
// - сохранение site through /haproxy/sites/save (JSON API)
// - модалка for выпуска сертификата Let's Encrypt
// - переключатель режима сертификата (LE / manual)
// - загрузка своего сертификата through /haproxy/sites/<site>/upload-cert
// - "красивый" выбор файла сертификата (file-picker)
// - переключатель режима site: HTTP (TLS termination) vs TCP passthrough (SNI)
//   and скрытие/отключение HTTP-only настроек
// - переключение L4/L7 health-check and принудительный L4 for tcp_passthrough

(function () {
  try {
    console.log("[haproxy_site_edit] script loaded");

    // -------- Блок удаления site --------
    var btnShow = document.getElementById("btn-show-delete");
    var box = document.getElementById("delete-confirm");
    var btnCancel = document.getElementById("btn-delete-cancel");

    if (btnShow && box) {
      btnShow.addEventListener("click", function () {
        box.style.display = "block";
        box.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    }

    if (btnCancel && box) {
      btnCancel.addEventListener("click", function () {
        box.style.display = "none";
      });
    }

    // ------------------------------------------------------------------
    // Backend servers (multi-backend: main/backup)
    // ------------------------------------------------------------------
    var backendBody = document.getElementById("backend-servers-body");
    var btnAddBackend = document.getElementById("btn-add-backend");

    // ------------------------------------------------------------------
    // err_exclude (per-site)
    // ------------------------------------------------------------------
    var errExcludeBody = document.getElementById("err-exclude-body");
    var btnAddErrRule = document.getElementById("btn-add-err-rule");

    // Значения by default for плейсхолдеров host/port from верхних полей
    var backendIpInput = document.getElementById("field-backend-ip");
    var backendPortInput = document.getElementById("field-backend-port");

    var defaultBackendHostPlaceholder =
      (backendIpInput && (backendIpInput.value || backendIpInput.placeholder)) ||
      "";
    var defaultBackendPortPlaceholder =
      (backendPortInput &&
        (backendPortInput.value || backendPortInput.placeholder)) ||
      "";

    function createBackendRow(opts) {
      if (!backendBody) return null;
      opts = opts || {};
      var index = backendBody.querySelectorAll("tr.backend-row").length + 1;

      var tr = document.createElement("tr");
      tr.className = "backend-row";

      function makeCell() {
        return document.createElement("td");
      }

      // name
      var tdName = makeCell();
      var inpName = document.createElement("input");
      inpName.type = "text";
      inpName.className = "form-input backend-name";
      inpName.placeholder = "srv" + index;
      if (opts.name) {
        inpName.value = opts.name;
      }
      tdName.appendChild(inpName);
      tr.appendChild(tdName);

      // host/IP
      var tdHost = makeCell();
      var inpHost = document.createElement("input");
      inpHost.type = "text";
      inpHost.className = "form-input backend-host";
      inpHost.placeholder = defaultBackendHostPlaceholder;
      if (opts.host) {
        inpHost.value = opts.host;
      }
      tdHost.appendChild(inpHost);
      tr.appendChild(tdHost);

      // port
      var tdPort = makeCell();
      var inpPort = document.createElement("input");
      inpPort.type = "number";
      inpPort.min = "1";
      inpPort.max = "65535";
      inpPort.className = "form-input backend-port";
      if (opts.port) {
        inpPort.value = String(opts.port);
      } else if (defaultBackendPortPlaceholder) {
        inpPort.placeholder = defaultBackendPortPlaceholder;
      }
      tdPort.appendChild(inpPort);
      tr.appendChild(tdPort);

      // role main/backup
      var tdRole = makeCell();
      var selRole = document.createElement("select");
      selRole.className = "form-input backend-role";
      var optMain = document.createElement("option");
      optMain.value = "main";
      optMain.textContent = "Primary";
      var optBackup = document.createElement("option");
      optBackup.value = "backup";
      optBackup.textContent = "Backup";
      selRole.appendChild(optMain);
      selRole.appendChild(optBackup);
      selRole.value = opts.role || "main";
      tdRole.appendChild(selRole);
      tr.appendChild(tdRole);

      // weight
      var tdWeight = makeCell();
      var inpWeight = document.createElement("input");
      inpWeight.type = "number";
      inpWeight.min = "1";
      inpWeight.max = "65535";
      inpWeight.className = "form-input backend-weight";
      if (opts.weight != null) {
        inpWeight.value = String(opts.weight);
      } else {
        inpWeight.placeholder = "100";
      }
      tdWeight.appendChild(inpWeight);
      tr.appendChild(tdWeight);

      // кнопка удаления
      var tdActions = makeCell();
      tdActions.style.textAlign = "center";
      var btnRemove = document.createElement("button");
      btnRemove.type = "button";
      btnRemove.className = "btn btn-small btn-backend-remove";
      btnRemove.textContent = "✕";
      btnRemove.title = "Delete backend";
      tdActions.appendChild(btnRemove);
      tr.appendChild(tdActions);

      return tr;
    }

    function createErrRuleRow(opts) {
      opts = opts || {};
      if (!errExcludeBody) return null;

      var tr = document.createElement("tr");
      tr.className = "err-exclude-row";

      function makeCell() {
        return document.createElement("td");
      }

      // Path type
      var tdType = makeCell();
      var selType = document.createElement("select");
      selType.className = "form-input err-path-type";

      var optPath = document.createElement("option");
      optPath.value = "path";
      optPath.textContent = "path (exact match)";
      selType.appendChild(optPath);

      var optPathBeg = document.createElement("option");
      optPathBeg.value = "path_beg";
      optPathBeg.textContent = "path_beg (prefix)";
      selType.appendChild(optPathBeg);

      var optPathReg = document.createElement("option");
      optPathReg.value = "path_reg";
      optPathReg.textContent = "path_reg (regular expression)";
      selType.appendChild(optPathReg);

      selType.value = opts.path_type || "path_beg";
      tdType.appendChild(selType);
      tr.appendChild(tdType);

      // Value paths
      var tdValue = makeCell();
      var inpValue = document.createElement("input");
      inpValue.type = "text";
      inpValue.className = "form-input err-path-value";
      inpValue.placeholder = "/metrics or ^/static/";
      if (opts.path_value) {
        inpValue.value = opts.path_value;
      }
      tdValue.appendChild(inpValue);
      tr.appendChild(tdValue);

      // Methods
      var tdMethods = makeCell();
      var inpMethods = document.createElement("input");
      inpMethods.type = "text";
      inpMethods.className = "form-input err-methods";
      inpMethods.placeholder = "GET,POST";
      if (opts.methods_str) {
        inpMethods.value = opts.methods_str;
      }
      tdMethods.appendChild(inpMethods);
      tr.appendChild(tdMethods);

      // Кнопка удаления
      var tdActions = makeCell();
      tdActions.style.textAlign = "center";
      var btnRemove = document.createElement("button");
      btnRemove.type = "button";
      btnRemove.className = "btn btn-small btn-err-exclude-remove";
      btnRemove.textContent = "✕";
      btnRemove.title = "Delete rule";
      tdActions.appendChild(btnRemove);
      tr.appendChild(tdActions);

      return tr;
    }

    // ------------------------------------------------------------------
    // Вспомогательные функции for сохранения
    // ------------------------------------------------------------------
    var editForm = document.getElementById("site-edit-form");
    var saveStatus = document.getElementById("site-save-status");

    function setSaveStatus(text, isError) {
      if (!saveStatus) return;
      saveStatus.textContent = text || "";
      saveStatus.style.color = isError ? "#c0392b" : "";
    }

    function collectServers() {
      var body = backendBody;
      if (!body) return [];
      var rows = body.querySelectorAll("tr.backend-row");
      var servers = [];
      rows.forEach(function (row) {
        var nameInput = row.querySelector(".backend-name");
        var hostInput = row.querySelector(".backend-host");
        var portInput = row.querySelector(".backend-port");
        var roleSelect = row.querySelector(".backend-role");
        var weightInput = row.querySelector(".backend-weight");

        var host = hostInput && hostInput.value.trim();
        var portStr = portInput && portInput.value.trim();
        if (!host || !portStr) return; // пустые строки игнорируем

        var port = parseInt(portStr, 10);
        if (!port || port <= 0 || port > 65535) return;

        var srv = {
          host: host,
          port: port
        };

        var nameVal = nameInput && nameInput.value.trim();
        if (nameVal) srv.name = nameVal;

        if (roleSelect && roleSelect.value === "backup") {
          srv.backup = true;
        }

        if (weightInput) {
          var wStr = weightInput.value.trim();
          if (wStr) {
            var w = parseInt(wStr, 10);
            if (!Number.isNaN(w)) {
              srv.weight = w;
            }
          }
        }

        servers.push(srv);
      });
      return servers;
    }

    function tristateSelectValue(id) {
      var el = document.getElementById(id);
      if (!el) return undefined;
      var v = el.value;
      if (v === "") return undefined; // "by default" → not пишем key
      if (v === "true") return true;
      if (v === "false") return false;
      return undefined;
    }

    function effectiveSelectBool(el, fallbackStr) {
      // el.value: "", "true", "false"
      // if "", берём el.dataset.effDefault (if есть), иначе fallbackStr
      if (!el) return fallbackStr === "true";
      var v = el.value;
      if (v === "true") return true;
      if (v === "false") return false;
      var d = (el.dataset && el.dataset.effDefault) ? el.dataset.effDefault : fallbackStr;
      return d === "true";
    }

    function numField(id) {
      var el = document.getElementById(id);
      if (!el) return undefined;
      var s = el.value.trim();
      if (!s) return undefined;
      var n = parseInt(s, 10);
      if (Number.isNaN(n)) return NaN;
      return n;
    }

    function errIgnoreSelectValue(id) {
      var el = document.getElementById(id);
      if (!el) return undefined;
      var v = el.value;
      if (v === "") return undefined; // "by default" → not пишем key
      if (v === "rules") return true;      // включить err_exclude
      if (v === "ignore") return "ignore"; // полностью игнорировать errors
      return undefined;
    }

    function collectErrExclude() {
      if (!errExcludeBody) return [];
      var rows = errExcludeBody.querySelectorAll("tr.err-exclude-row");
      var rules = [];

      rows.forEach(function (row) {
        var typeSel = row.querySelector(".err-path-type");
        var valInput = row.querySelector(".err-path-value");
        var methInput = row.querySelector(".err-methods");

        if (!typeSel || !valInput) return;

        var pathType = (typeSel.value || "").trim();
        var pathVal = (valInput.value || "").trim();

        if (!pathType || !pathVal) return;

        var rule = {};
        if (pathType === "path") {
          rule.path = pathVal;
        } else if (pathType === "path_beg") {
          rule.path_beg = pathVal;
        } else if (pathType === "path_reg") {
          rule.path_reg = pathVal;
        } else {
          // неизвестный type — игнорируем
          return;
        }

        if (methInput) {
          var mStr = methInput.value.trim();
          if (mStr) {
            var parts = mStr
              .split(/[,\s]+/)
              .map(function (s) { return s.trim().toUpperCase(); })
              .filter(function (s) { return s.length > 0; });
            if (parts.length) {
              rule.methods = parts;
            }
          }
        }

        rules.push(rule);
      });

      return rules;
    }

    function buildSitePayloadFromForm(form) {
      var site = {};

      function text(id) {
        var el = document.getElementById(id);
        return el ? el.value.trim() : "";
      }

      // Обязательные fields
      site.name = text("field-name");
      site.domain = text("field-domain");

      // Site mode: tcp_passthrough (tri-state)
      var tcpPassVal = tristateSelectValue("tcp_passthrough");
      if (tcpPassVal !== undefined) {
        site.tcp_passthrough = tcpPassVal;
      }

      // Backend (single) — опциональный
      var bip = text("field-backend-ip");
      if (bip) {
        site.backend_ip = bip;
      }

      var backendPort = numField("field-backend-port");
      if (backendPort !== undefined) {
        if (Number.isNaN(backendPort)) {
          throw new Error("Invalid backend_port value");
        }
        site.backend_port = backendPort;
      }

      var bh = text("field-backend-host");
      if (bh) site.backend_host = bh;

      // Alt names (SAN)
      var altEl = document.getElementById("field-alt-names");
      if (altEl) {
        var lines = altEl.value
          .split("\n")
          .map(function (s) { return s.trim(); })
          .filter(function (s) { return s.length > 0; });
        if (lines.length) {
          site.alt_names = lines;
        }
      }

      // Тристейт-флаги (HTTP-fields + tcp_check)
      [
        "redirect_to_https",
        "authelia_enabled",
        "zero_trust",
        "backend_ssl",
        "backend_ssl_verify",
        "maintenance",
        "rate_ban",
        "compress",
        "geo"
      ].forEach(function (key) {
        var v = tristateSelectValue(key);
        if (v !== undefined) {
          site[key] = v;
        }
      });

      // Access gate: always rendered, so Default explicitly removes the flag.
      if (document.getElementById("access_gate")) {
        var accessGate = tristateSelectValue("access_gate");
        if (accessGate !== undefined) {
          site.access_gate = accessGate;
        } else {
          delete site.access_gate;
        }
        // The gate only works Authelia-protected and reachable, so persist
        // those two invariants regardless of the (locked) control state.
        if (accessGate === true) {
          site.authelia_enabled = true;
          site.zero_trust = false;
        }
      }

      // Availability alerts: the fields are always rendered, so an empty or
      // Default value explicitly removes the stored override.
      if (document.getElementById("alert_enabled")) {
        var alertEnabled = tristateSelectValue("alert_enabled");
        if (alertEnabled !== undefined) {
          site.alert_enabled = alertEnabled;
        } else {
          delete site.alert_enabled;
        }
        ["alert_mode", "alert_after", "alert_email"].forEach(function (key) {
          var el = document.getElementById(key);
          if (!el) return;
          var value = (el.value || "").trim();
          if (value) {
            site[key] = value;
          } else {
            delete site[key];
          }
        });
      }

      var geoCountriesText = text("geo_countries");
      if (geoCountriesText) {
        var geoCountries = Array.from(new Set(
          geoCountriesText
            .split(/[,\s]+/)
            .map(function (value) { return value.trim().toUpperCase(); })
            .filter(function (value) { return value.length > 0; })
        )).sort();
        if (geoCountries.length) {
          site.geo_countries = geoCountries;
        }
      }


// tcp_check:
// - in HTTP mode (tcp_passthrough=false): tri-state bool (L4 TCP connect vs L7 HTTP-check)
// - in TCP passthrough (tcp_passthrough=true): line "tcp"|"ssl" (type check backend)
var selTcpPassForCheck = document.getElementById("tcp_passthrough");
var effTcpPassForCheck = effectiveSelectBool(selTcpPassForCheck, "false");

if (effTcpPassForCheck === true) {
  var tcpModeEl = document.getElementById("tcp_passthrough_check");
  if (tcpModeEl) {
    var tv = (tcpModeEl.value || "").trim();
    if (tv) {
      site.tcp_check = tv; // "tcp" or "ssl"
    }
  }
} else {
  var tvb = tristateSelectValue("tcp_check");
  if (tvb !== undefined) {
    site.tcp_check = tvb;
  }
}

      // max_req_rate
      var mrr = numField("max_req_rate");
      if (mrr !== undefined) {
        if (Number.isNaN(mrr)) {
          throw new Error("Invalid max_req_rate value");
        }
        site.max_req_rate = mrr;
      }

      // Errors / error-based bans (per-site)
      var errLimit = numField("err_limit");
      if (errLimit !== undefined) {
        if (Number.isNaN(errLimit)) {
          throw new Error("Invalid err_limit value");
        }
        site.err_limit = errLimit;
      }

      var errWindowEl = document.getElementById("err_window");
      if (errWindowEl) {
        var ew = errWindowEl.value.trim();
        if (ew) {
          site.err_window = ew;
        }
      }

      var errSizeEl = document.getElementById("err_size");
      if (errSizeEl) {
        var es = errSizeEl.value.trim();
        if (es) {
          site.err_size = es;
        }
      }

      var errIgnore = errIgnoreSelectValue("err_ignore_rules");
      if (errIgnore !== undefined) {
        site.err_ignore_rules = errIgnore;
      }

      // Health check / HSTS / WAF
      var hu = text("health_uri");
      if (hu) site.health_uri = hu;

      var hs = numField("health_status");
      if (hs !== undefined) {
        if (Number.isNaN(hs)) {
          throw new Error("Invalid health_status value");
        }
        site.health_status = hs;
      }

      var hstsEl = document.getElementById("hsts");
      if (hstsEl) {
        var hv = hstsEl.value.trim();
        if (hv) {
          var normalizedHsts = hv.toLowerCase();
          if (normalizedHsts === "true" || normalizedHsts === "false") {
            site.hsts = normalizedHsts === "true";
          } else if (/^[0-9]+$/.test(normalizedHsts)) {
            site.hsts = Number.parseInt(normalizedHsts, 10);
          } else if (/^[0-9]+d$/.test(normalizedHsts)) {
            site.hsts = normalizedHsts;
          } else {
            throw new Error("Invalid HSTS max-age value");
          }
        }
      }

      var wafEl = document.getElementById("waf");
      if (wafEl) {
        var wv = wafEl.value.trim();
        if (wv) site.waf = wv;
      }

      // Load balancing / sticky / sessions
      var balanceEl = document.getElementById("balance");
      if (balanceEl) {
        var bv = balanceEl.value.trim();
        if (bv) {
          site.balance = bv;
        }
      }

      var stickyEl = document.getElementById("sticky");
      if (stickyEl) {
        var sv = stickyEl.value.trim();
        if (sv) {
          site.sticky = sv;
        }
      }

      var cookieNameEl = document.getElementById("cookie_name");
      if (cookieNameEl) {
        var cn = cookieNameEl.value.trim();
        if (cn) {
          site.cookie_name = cn;
        }
      }

      var cookieAttrsEl = document.getElementById("cookie_attrs");
      if (cookieAttrsEl) {
        var ca = cookieAttrsEl.value.trim();
        if (ca) {
          site.cookie_attrs = ca;
        }
      }

      var httpReuseEl = document.getElementById("http_reuse");
      if (httpReuseEl) {
        var hr = httpReuseEl.value.trim();
        if (hr) {
          site.http_reuse = hr;
        }
      }

      var sessTimeoutEl = document.getElementById("session_timeout");
      if (sessTimeoutEl) {
        var st = sessTimeoutEl.value.trim();
        if (st) {
          site.session_timeout = st;
        }
      }

      var kaTimeoutEl = document.getElementById("http_keepalive_timeout");
      if (kaTimeoutEl) {
        var kt = kaTimeoutEl.value.trim();
        if (kt) {
          site.http_keepalive_timeout = kt;
        }
      }

      var pls = tristateSelectValue("prefer_last_server");
      if (pls !== undefined) {
        site.prefer_last_server = pls;
      }

      var spliceVal = tristateSelectValue("enable_splice_backend");
      if (spliceVal !== undefined) {
        site.enable_splice_backend = spliceVal;
      }

      // Only these addresses may reach the site. Sent as a list; an empty
      // textarea removes the key and the site is public again.
      var allowEl = document.getElementById("allow_ips");
      if (allowEl) {
        var allowLines = allowEl.value
          .split(/[\s,;]+/)
          .map(function (s) { return s.trim(); })
          .filter(function (s) { return s.length > 0; });
        if (allowLines.length) {
          site.allow_ips = allowLines;
        }
      }

      // Client certificates. Independent of the certificate source above:
      // which authority signs this site's server certificate says nothing
      // about which authority may vouch for a visitor.
      var mtlsModeEl = document.getElementById("mtls_mode");
      var mtlsCaEl = document.getElementById("mtls_ca_id");
      if (mtlsModeEl && (mtlsModeEl.value === "optional" || mtlsModeEl.value === "required")) {
        site.mtls_mode = mtlsModeEl.value;
        site.mtls_ca_id = mtlsCaEl ? mtlsCaEl.value : "";
      }

      // Certificate source. Keep le_managed for backward compatibility.
      var certModeRadio = document.querySelector('input[name="cert_mode"]:checked');
      if (certModeRadio) {
        site.certificate_source = certModeRadio.value;
        site.le_managed = certModeRadio.value === "letsencrypt";
        if (certModeRadio.value === "external") {
          var externalCaSelect = document.getElementById("external_ca_id");
          if (externalCaSelect && externalCaSelect.value) {
            site.external_ca_id = externalCaSelect.value;
          }
        }
      }

      // ACME challenge. A saved DNS profile is what selects DNS-01, so there
      // is no separate stored flag: no profile means HTTP-01.
      var dnsChallengeEl = document.getElementById("acme_challenge_dns");
      var dnsProfileEl = document.getElementById("dns_profile");
      if (
        certModeRadio &&
        certModeRadio.value === "letsencrypt" &&
        dnsChallengeEl &&
        dnsChallengeEl.checked &&
        dnsProfileEl &&
        dnsProfileEl.value
      ) {
        site.dns_profile = dnsProfileEl.value;

        // Certificate-only names, where a wildcard is allowed.
        var certAltEl = document.getElementById("field-cert-alt-names");
        if (certAltEl) {
          var certAltLines = certAltEl.value
            .split("\n")
            .map(function (s) { return s.trim(); })
            .filter(function (s) { return s.length > 0; });
          if (certAltLines.length) {
            site.cert_alt_names = certAltLines;
          }
        }
      }

      // Key types (for LE-режима)
      var ktArr = [];
      var ecdsaEl = document.getElementById("key_type_ecdsa");
      if (ecdsaEl && ecdsaEl.checked) ktArr.push("ecdsa");
      var rsaEl = document.getElementById("key_type_rsa");
      if (rsaEl && rsaEl.checked) ktArr.push("rsa");
      if (ktArr.length) {
        site.key_types = ktArr;
      }

      // servers from table
      var servers = collectServers();
      if (servers && servers.length) {
        site.servers = servers;
      }

      // err_exclude (per-site)
      var errRules = collectErrExclude();
      if (errRules && errRules.length) {
        site.err_exclude = errRules;
      }

      // --- TCP passthrough: вычищаем HTTP-only настройки ---
      var selTcpPass = document.getElementById("tcp_passthrough");
      var effTcpPass = effectiveSelectBool(selTcpPass, "false");
      if (effTcpPass === true) {
// Чистим HTTP-only fields, чтобы not путаться in YAML/генерации
// (alt_names and balance оставляем: они используются and in tcp_passthrough)
delete site.backend_host;

delete site.le_managed;
delete site.key_types;
delete site.certificate_source;
delete site.external_ca_id;
delete site.dns_profile;
delete site.cert_alt_names;

delete site.redirect_to_https;
delete site.authelia_enabled;
delete site.zero_trust;
// The client certificate is checked in the HTTP frontend, which a
// passthrough site never reaches.
delete site.mtls_mode;
delete site.mtls_ca_id;
// A passthrough site is routed on SNI before any HTTP rule runs.
delete site.allow_ips;

delete site.backend_ssl;
delete site.backend_ssl_verify;

delete site.maintenance;
delete site.rate_ban;
delete site.compress;
delete site.max_req_rate;

delete site.err_limit;
delete site.err_window;
delete site.err_size;
delete site.err_ignore_rules;
delete site.err_exclude;

// L7 health-fields (for tcp_passthrough not используются)
delete site.health_uri;
delete site.health_status;

// HTTP-only extras
delete site.hsts;
delete site.waf;

// Sticky/cookie/HTTP timeouts — not актуальны for TCP passthrough
delete site.sticky;
delete site.cookie_name;
delete site.cookie_attrs;
delete site.http_reuse;
delete site.session_timeout;
delete site.http_keepalive_timeout;
delete site.prefer_last_server;
delete site.enable_splice_backend;

// Geo/ACL (in текущей реализации у тебя это HTTP-only)
delete site.geo;
delete site.geo_mode;
delete site.geo_countries;
      }

      var payload = {
        site: site,
        original_name: form.getAttribute("data-original-name") || site.name
      };
      return payload;
    }

    // ------------------------------------------------------------------
    // Обработка сабмита формы: валидация + POST /haproxy/sites/save
    // ------------------------------------------------------------------
    if (editForm) {
      editForm.addEventListener("submit", function (e) {
        e.preventDefault();

        var payload;
        try {
          payload = buildSitePayloadFromForm(editForm);
        } catch (err) {
          console.error("[haproxy_site_edit] buildSitePayload error", err);
          setSaveStatus(String(err), true);
          return;
        }

        if (!payload.site.name) {
          setSaveStatus("The 'name' field is required", true);
          return;
        }
        if (!payload.site.domain) {
          setSaveStatus("The 'domain' field is required", true);
          return;
        }

        // Логика: либо есть хотя бы one backend in таблице,
        // либо заполнена pair backend_ip + backend_port.
        var hasServers =
          Array.isArray(payload.site.servers) && payload.site.servers.length > 0;

        var backendIpSet = !!payload.site.backend_ip;
        var backendPortSet = typeof payload.site.backend_port === "number";

        var hasSingleBackend = backendIpSet && backendPortSet;

        // An access gate needs no backend: without one it serves the static
        // login page, with one it proxies like a normal site.
        var isGate = payload.site.access_gate === true;

        if (!hasServers && !hasSingleBackend && !isGate) {
          if (backendIpSet && !backendPortSet) {
            setSaveStatus(
              "backend_ip is set, but backend_port is missing. " +
              "Set the port or clear backend_ip and use the backend server table.",
              true
            );
            return;
          }
          if (!backendIpSet && backendPortSet) {
            setSaveStatus(
              "backend_port is set without backend_ip. " +
              "Set the IP/host or clear the port and use the backend server table.",
              true
            );
            return;
          }

          setSaveStatus(
            "Define at least one backend server in the table or set backend_ip and backend_port.",
            true
          );
          return;
        }

        setSaveStatus("Saving...", false);

        fetch("/haproxy/sites/save", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest"
          },
          body: JSON.stringify(payload)
        })
          .then(function (resp) {
            if (!resp.ok) {
              throw new Error("HTTP " + resp.status);
            }
            return resp.json();
          })
          .then(function (data) {
            if (!data || !data.ok) {
              var msg =
                (data && (data.error || data.message)) || "Save error";
              setSaveStatus(msg, true);
              return;
            }
            setSaveStatus(data.message || "Saved", false);
            document.dispatchEvent(
              new CustomEvent("easy-ha-proxy:config-state-changed")
            );
          })
          .catch(function (err) {
            console.error("[haproxy_site_edit] save error", err);
            setSaveStatus("Request error: " + err, true);
          });
      });
    } else {
      console.warn("[haproxy_site_edit] edit form not found");
    }

    // Делегирование клика by кнопке "✕" for удаления строки backend
    if (backendBody) {
      backendBody.addEventListener("click", function (e) {
        var target = e.target;
        if (!target) return;
        if (target.classList.contains("btn-backend-remove")) {
          var row = target.closest("tr");
          if (row && backendBody.contains(row)) {
            backendBody.removeChild(row);
          }
        }
      });
    }

    // Кнопка "+ Add backend server"
    if (btnAddBackend && backendBody) {
      btnAddBackend.addEventListener("click", function () {
        var tr = createBackendRow({});
        if (tr) {
          backendBody.appendChild(tr);
        }
      });
    }

    // Делегирование клика by кнопке "✕" for удаления rules err_exclude
    if (errExcludeBody) {
      errExcludeBody.addEventListener("click", function (e) {
        var target = e.target;
        if (!target) return;
        if (target.classList.contains("btn-err-exclude-remove")) {
          var row = target.closest("tr");
          if (row && errExcludeBody.contains(row)) {
            errExcludeBody.removeChild(row);
          }
        }
      });
    }

    // Кнопка "+ Add rule err_exclude"
    if (btnAddErrRule && errExcludeBody) {
      btnAddErrRule.addEventListener("click", function () {
        var tr = createErrRuleRow({});
        if (tr) {
          errExcludeBody.appendChild(tr);
        }
      });
    }

    // ------------------------------------------------------------------
    // Certificate source selector.
    // ------------------------------------------------------------------
    var certModeLe = document.getElementById("cert_mode_le");
    var certModeExternal = document.getElementById("cert_mode_external");
    var certModeInternal = document.getElementById("cert_mode_internal");
    var certBlockLe = document.getElementById("cert-block-le");
    var certBlockExternal = document.getElementById("cert-block-external");
    var certBlockInternal = document.getElementById("cert-block-internal");

    function updateCertModeUI() {
      var mode = "letsencrypt";
      if (certModeExternal && certModeExternal.checked) mode = "external";
      if (certModeInternal && certModeInternal.checked) mode = "internal";
      if (certBlockLe) {
        certBlockLe.style.display = mode === "letsencrypt" ? "" : "none";
      }
      if (certBlockExternal) {
        certBlockExternal.style.display = mode === "external" ? "" : "none";
      }
      if (certBlockInternal) {
        certBlockInternal.style.display = mode === "internal" ? "" : "none";
      }
    }

    if (certModeLe) certModeLe.addEventListener("change", updateCertModeUI);
    if (certModeExternal) certModeExternal.addEventListener("change", updateCertModeUI);
    if (certModeInternal) certModeInternal.addEventListener("change", updateCertModeUI);
    updateCertModeUI();

    // ------------------------------------------------------------------
    // HTTP-01 / DNS-01 selector.
    // ------------------------------------------------------------------
    var challengeHttp = document.getElementById("acme_challenge_http");
    var challengeDns = document.getElementById("acme_challenge_dns");
    var blockDns = document.getElementById("block-dns-01");

    function updateChallengeUI() {
      if (!blockDns) return;
      var useDns = !!(challengeDns && challengeDns.checked);
      blockDns.style.display = useDns ? "" : "none";
    }

    if (challengeHttp) challengeHttp.addEventListener("change", updateChallengeUI);
    if (challengeDns) challengeDns.addEventListener("change", updateChallengeUI);
    updateChallengeUI();

    // ------------------------------------------------------------------
    // Модальное окно логов выпуска сертификата
    // ------------------------------------------------------------------
    var modal = document.getElementById("issue-cert-modal");
    var modalLog = document.getElementById("issue-cert-log");
    var modalClose = document.getElementById("issue-cert-modal-close");

    // Точка статуса in заголовке модалки
    var issueDot = document.getElementById("issue-cert-status-dot");
    var issueDotTimer = null;

    function setDot(color, blinking) {
      if (!issueDot) return;

      if (issueDotTimer) {
        clearInterval(issueDotTimer);
        issueDotTimer = null;
      }

      issueDot.style.backgroundColor = color;
      issueDot.style.opacity = "1";

      if (blinking) {
        var visible = true;
        issueDotTimer = setInterval(function () {
          visible = !visible;
          issueDot.style.opacity = visible ? "1" : "0.2";
        }, 500);
      }
    }

    function openModal(title) {
      if (!modal) return;
      modal.style.display = "flex";
      if (modalLog) {
        modalLog.textContent = title ? title + "\n\n" : "";
        modalLog.scrollTop = modalLog.scrollHeight;
      }
    }

    function closeModal() {
      if (!modal) return;
      modal.style.display = "none";
      // Keep the indicator color as the final operation result.
    }

    function appendLog(line) {
      if (!modalLog) return;
      if (modalLog.textContent) {
        modalLog.textContent += "\n" + line;
      } else {
        modalLog.textContent = line;
      }
      modalLog.scrollTop = modalLog.scrollHeight;
    }

    if (modalClose) {
      modalClose.addEventListener("click", function () {
        closeModal();
      });
    }

    // ------------------------------------------------------------------
    // Issue or renew a certificate.
    // ------------------------------------------------------------------
    var btnIssue = document.getElementById("btn-issue-cert");
    var statusEl = document.getElementById("issue-cert-status");
    var btnIssueInternal = document.getElementById("btn-issue-internal-cert");
    var internalStatusEl = document.getElementById("issue-internal-cert-status");
    var siteNameInput = document.getElementById("site_name");

    function setStatus(msg) {
      var selected = document.querySelector('input[name="cert_mode"]:checked');
      var target = selected && selected.value === "internal" ? internalStatusEl : statusEl;
      if (!target) return;
      target.textContent = msg || "";
    }

    function issueCertificate(requestedSource) {
        var siteName = siteNameInput.value;
        if (!siteName) {
          setStatus("Could not determine the site name (site_name is empty)");
          return;
        }

        setStatus("Certificate issuance request sent...");
        openModal("Certificate issuance request for site: " + siteName);

        // A blinking yellow indicator marks an active request.
        setDot("#d4aa00", true);

        fetch("/haproxy/sites/" + encodeURIComponent(siteName) + "/issue-cert", {
          method: "POST",
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            dry_run: false,
            source: requestedSource
          })
        })
          .then(function (resp) {
            if (!resp.ok) {
              setStatus("Error HTTP: " + resp.status + " " + resp.statusText);
              setDot("#aa0000", false);
              return resp.text().then(function (t) {
                appendLog("HTTP " + resp.status + " " + resp.statusText);
                appendLog("");
                appendLog(t);
              });
            }

            return resp.text().then(function (raw) {
              var data;
              try {
                data = JSON.parse(raw);
              } catch (e) {
                appendLog("Raw service response (not JSON):");
                appendLog(raw);
                setStatus(
                  "Certificate service response is not JSON (" +
                  resp.status +
                  "): " +
                  raw.slice(0, 200)
                );
                console.error("Issue-cert raw response:", raw);
                setDot("#aa0000", false);
                return;
              }

              appendLog("");
              appendLog("=== Request result ===");
              appendLog("Domain: " + (data.domain || "—"));

              if (data.alt_names && data.alt_names.length) {
                appendLog("Alternative names: " + data.alt_names.join(", "));
              }

              if (data.key_types && data.key_types.length) {
                appendLog("Key types: " + data.key_types.join(", "));
              }

              if (data.source) {
                appendLog("Certificate source: " + data.source);
              }

              appendLog(
                "Mode: " +
                (data.dry_run
                  ? "dry-run (test mode, certificates are not written)"
                  : "production")
              );

              if (data.ok) {
                appendLog("Status: SUCCESS (certificate issued / renewed)");
                setStatus(
                  "Certificate issued/renewed. " +
                  'Open the "Sites" page to verify its status.'
                );
                // A steady green indicator marks success.
                setDot("#00aa00", false);
              } else {
                appendLog("Status: ERROR");
                appendLog(
                  "Message: " +
                  (data.message || data.error || "no details")
                );
                setStatus(
                  "Certificate issuance failed: " +
                  (data.message || data.error || "no details")
                );
                // A steady red indicator marks failure.
                setDot("#aa0000", false);
              }
            });
          })
          .catch(function (e) {
            appendLog("");
            appendLog("Request/network error: " + e);
            setStatus("Certificate service request failed: " + e);
            setDot("#aa0000", false);
          });
    }

    if (btnIssue && siteNameInput) {
      btnIssue.addEventListener("click", function () {
        issueCertificate("letsencrypt");
      });
    } else {
      console.warn("[haproxy_site_edit] btnIssue or site_name not found");
    }

    if (btnIssueInternal && siteNameInput) {
      btnIssueInternal.addEventListener("click", function () {
        issueCertificate("internal");
      });
    }

    // ------------------------------------------------------------------
    // Upload a custom certificate (manual mode).
    // ------------------------------------------------------------------
    var uploadBtn = document.getElementById("btn-upload-cert");
    var uploadStatus = document.getElementById("upload-cert-status");
    var certFileInput = document.getElementById("cert_file");

    // Custom file picker for the certificate.
    var certChooseBtn = document.getElementById("cert-file-choose");
    var certFileNameSpan = document.getElementById("cert-file-name");

    if (certChooseBtn && certFileInput && certFileNameSpan) {
      certChooseBtn.addEventListener("click", function () {
        certFileInput.click();
      });

      certFileInput.addEventListener("change", function () {
        if (!certFileInput.files || certFileInput.files.length === 0) {
          certFileNameSpan.textContent = "No file selected";
        } else {
          certFileNameSpan.textContent =
            certFileInput.files[0].name || "File selected";
        }
      });
    }

    function setUploadStatus(msg, isError) {
      if (!uploadStatus) return;
      uploadStatus.textContent = msg || "";
      uploadStatus.style.color = isError ? "#c0392b" : "";
    }

    if (uploadBtn && certFileInput && siteNameInput) {
      uploadBtn.addEventListener("click", function () {
        var siteName = siteNameInput.value;
        if (!siteName) {
          setUploadStatus("Could not determine the site name (site_name is empty)", true);
          return;
        }

        var file =
          certFileInput.files && certFileInput.files.length
            ? certFileInput.files[0]
            : null;
        if (!file) {
          setUploadStatus("Choose a certificate file (PEM)", true);
          return;
        }

        // Простая проверка расширения (можно ужесточить позже)
        var fname = file.name.toLowerCase();
        if (!(fname.endsWith(".pem") || fname.endsWith(".crt") || fname.endsWith(".cer"))) {
          setUploadStatus("Unexpected file extension. Expected .pem, .crt, or .cer.", true);
          return;
        }

        var formData = new FormData();
        formData.append("cert_file", file);

        setUploadStatus("Uploading certificate...", false);

        fetch("/haproxy/sites/" + encodeURIComponent(siteName) + "/upload-cert", {
          method: "POST",
          body: formData
        })
          .then(function (resp) {
            var ct = resp.headers.get("Content-Type") || "";
            if (ct.indexOf("application/json") !== -1) {
              return resp.json().then(function (data) {
                return { ok: resp.ok, data: data };
              });
            }
            return resp.text().then(function (text) {
              return { ok: resp.ok, data: { ok: resp.ok, message: text } };
            });
          })
          .then(function (res) {
            var ok = res.ok;
            var data = res.data || {};
            if (!ok || !data.ok) {
              setUploadStatus(data.message || data.error || "Certificate upload failed", true);
              return;
            }
            setUploadStatus(data.message || "Certificate uploaded successfully", false);
          })
          .catch(function (err) {
            console.error("[haproxy_site_edit] upload-cert error", err);
            setUploadStatus("Request error: " + err, true);
          });
      });
    } else {
      console.warn("[haproxy_site_edit] upload controls not found");
    }

    // ------------------------------------------------------------------
    // Переключение видимости health_uri/health_status (L4 vs L7)
    // + принудительный L4 for tcp_passthrough
    // ------------------------------------------------------------------
    function applyHealthVisibility() {
  var selTcpPass = document.getElementById("tcp_passthrough");
  var isTcpMode = effectiveSelectBool(selTcpPass, "false");

  var rowHttpTcpCheck = document.getElementById("row-http-tcp-check");
  var rowTcpPassCheck = document.getElementById("row-tcp-passthrough-check");

  var selHttp = document.getElementById("tcp_check");
  var selTcp = document.getElementById("tcp_passthrough_check");

  var rowUri = document.getElementById("row-health-uri");
  var rowStatus = document.getElementById("row-health-status");

  var inputUri = document.getElementById("health_uri");
  var inputStatus = document.getElementById("health_status");

  // TCP passthrough: показываем выбор типа TCP/SSL-check, and HTTP L4/L7 — скрываем
  if (isTcpMode) {
    if (rowHttpTcpCheck) rowHttpTcpCheck.style.display = "none";
    if (selHttp) selHttp.disabled = true;

    if (rowTcpPassCheck) rowTcpPassCheck.style.display = "";
    if (selTcp) selTcp.disabled = false;

    if (rowUri) rowUri.style.display = "none";
    if (rowStatus) rowStatus.style.display = "none";

    if (inputUri) inputUri.disabled = true;
    if (inputStatus) inputStatus.disabled = true;
    return;
  }

  // HTTP mode: показываем L4/L7 selector and управляем health_uri/health_status
  if (rowHttpTcpCheck) rowHttpTcpCheck.style.display = "";
  if (selHttp) selHttp.disabled = false;

  if (rowTcpPassCheck) rowTcpPassCheck.style.display = "none";
  if (selTcp) selTcp.disabled = true;

  if (!selHttp) return;

  // Value реально выбранное пользователем, либо "эффективный default"
  var effective = (selHttp.value && selHttp.value.length) ? selHttp.value : (selHttp.dataset.effDefault || "false");
  var isL4 = (effective === "true");

  if (rowUri) rowUri.style.display = isL4 ? "none" : "";
  if (rowStatus) rowStatus.style.display = isL4 ? "none" : "";

  if (inputUri) inputUri.disabled = isL4;
  if (inputStatus) inputStatus.disabled = isL4;
}

    // ------------------------------------------------------------------
    // Переключение видимости/доступности HTTP-only блоков when tcp_passthrough
    // ------------------------------------------------------------------
    function setBlockVisible(block, visible) {
      if (!block) return;
      block.style.display = visible ? "" : "none";
    }

    function setInputsDisabled(container, disabled) {
      if (!container) return;
      var els = container.querySelectorAll("input, select, textarea, button");
      els.forEach(function (el) {
        // Кнопки "Close" in модалке and прочее not трогаем — это not внутри контейнеров
        el.disabled = !!disabled;
      });
    }

    function applyTcpModeVisibility() {
  var selTcpPass = document.getElementById("tcp_passthrough");
  var isTcpMode = effectiveSelectBool(selTcpPass, "false");

  // Блоки (часть — HTTP-only)
  var blockBackendHost = document.getElementById("block-backend-host");

  var blockHttpLeft = document.getElementById("block-http-left");
  var blockCertAll = document.getElementById("block-cert-all");
  var blockHttpSticky = document.getElementById("block-http-sticky");

  var blockHttpRight = document.getElementById("block-http-right");

  var rowHsts = document.getElementById("row-hsts");
  var rowWaf = document.getElementById("row-waf");

  // In TCP passthrough:
  // - скрываем backend_host (Host header not применим)
  // - оставляем alt_names and balance, but скрываем cert + sticky/cookie/HTTP-only таймауты
  // - скрываем HTTP-only правую колонку
  // - скрываем hsts/waf
  if (isTcpMode) {
    setBlockVisible(blockBackendHost, false);
    setInputsDisabled(blockBackendHost, true);

    setBlockVisible(blockHttpLeft, true);
    setInputsDisabled(blockHttpLeft, false);

    setBlockVisible(blockCertAll, false);
    setInputsDisabled(blockCertAll, true);

    setBlockVisible(blockHttpSticky, false);
    setInputsDisabled(blockHttpSticky, true);

    setBlockVisible(blockHttpRight, false);
    setInputsDisabled(blockHttpRight, true);

    setBlockVisible(rowHsts, false);
    setInputsDisabled(rowHsts, true);

    setBlockVisible(rowWaf, false);
    setInputsDisabled(rowWaf, true);
  } else {
    setBlockVisible(blockBackendHost, true);
    setInputsDisabled(blockBackendHost, false);

    setBlockVisible(blockHttpLeft, true);
    setInputsDisabled(blockHttpLeft, false);

    setBlockVisible(blockCertAll, true);
    setInputsDisabled(blockCertAll, false);

    setBlockVisible(blockHttpSticky, true);
    setInputsDisabled(blockHttpSticky, false);

    setBlockVisible(blockHttpRight, true);
    setInputsDisabled(blockHttpRight, false);

    setBlockVisible(rowHsts, true);
    setInputsDisabled(rowHsts, false);

    setBlockVisible(rowWaf, true);
    setInputsDisabled(rowWaf, false);
  }

  // Health-check зависит and от tcp_passthrough тоже
  applyHealthVisibility();
}

    // Access gate: the authorization page cannot work without Authelia and must
    // stay reachable, so authelia_enabled is forced on and zero_trust off, with
    // both controls locked while the gate is enabled.
    function applyAccessGateLock() {
      var gateSel = document.getElementById("access_gate");
      if (!gateSel) return;
      var enabled = effectiveSelectBool(gateSel, "false");
      var aut = document.getElementById("authelia_enabled");
      var zt = document.getElementById("zero_trust");
      if (aut) {
        if (enabled) {
          aut.dataset.gatePrev = aut.value;
          aut.value = "true";
          aut.disabled = true;
          aut.title = "Locked on: an access gate requires Authelia.";
        } else if (aut.disabled && aut.dataset.gatePrev !== undefined) {
          aut.value = aut.dataset.gatePrev;
          aut.disabled = false;
          aut.title = "";
          delete aut.dataset.gatePrev;
        }
      }
      if (zt) {
        if (enabled) {
          zt.dataset.gatePrev = zt.value;
          zt.value = "false";
          zt.disabled = true;
          zt.title = "Locked off: the gate must stay reachable to authorize IPs.";
        } else if (zt.disabled && zt.dataset.gatePrev !== undefined) {
          zt.value = zt.dataset.gatePrev;
          zt.disabled = false;
          zt.title = "";
          delete zt.dataset.gatePrev;
        }
      }
    }

    // Инициализация: иногда DOMContentLoaded уже прошёл (if скрипт внизу)
    (function initNow() {
      applyTcpModeVisibility();
      applyAccessGateLock();

      var selAccessGate = document.getElementById("access_gate");
      if (selAccessGate) {
        selAccessGate.addEventListener("change", applyAccessGateLock);
      }

      var selTcpPass = document.getElementById("tcp_passthrough");
      if (selTcpPass) {
        selTcpPass.addEventListener("change", applyTcpModeVisibility);
      }

      var selTcpCheck = document.getElementById("tcp_check");
      if (selTcpCheck) {
        selTcpCheck.addEventListener("change", applyHealthVisibility);
      }

  var selTcpPassCheck = document.getElementById("tcp_passthrough_check");
  if (selTcpPassCheck) {
    selTcpPassCheck.addEventListener("change", applyHealthVisibility);
  }
})();

  } catch (e) {
    console.error("[haproxy_site_edit] fatal JS error:", e);
  }
})();
