// static/js/haproxy_sites.js

document.addEventListener("DOMContentLoaded", function () {
  const siteForm = document.getElementById("site-form");
  const sitesTable = document.querySelector("table.table");

  if (siteForm) {
    initSiteEditPage(siteForm);
  }

  if (sitesTable) {
    initSitesListPage(sitesTable);
  }
});

function initSitesListPage(table) {
  table.addEventListener("click", function (e) {
    const btn = e.target.closest(".js-delete-site");
    if (!btn) return;

    const name = btn.dataset.name;
    if (!name) return;

    if (!confirm(`Are you sure you want to delete site "${name}"?`)) return;

    fetch(`/haproxy/sites/${encodeURIComponent(name)}/delete`, {
      method: "POST",
      headers: {
        "X-Requested-With": "XMLHttpRequest",
      },
    })
      .then((r) => r.json())
      .then((data) => {
        if (data.ok) {
          document.dispatchEvent(
            new CustomEvent("easy-ha-proxy:config-state-changed")
          );
          // Удаляем line from table
          const row = table.querySelector(`tr[data-site-name="${CSS.escape(name)}"]`);
          if (row && row.parentNode) {
            row.parentNode.removeChild(row);
          }
          alert(data.message || "Site deleted");
        } else {
          alert(data.error || data.message || "Failed to delete site");
        }
      })
      .catch((err) => {
        console.error(err);
        alert("Site deletion request failed");
      });
  });
}

function initSiteEditPage(form) {
  const btnSave = document.getElementById("btn-save-site");
  const statusEl = document.getElementById("site-save-status");
  const btnToggleAdv = document.getElementById("btn-toggle-advanced");
  const advSection = document.getElementById("advanced-section");

  if (btnToggleAdv && advSection) {
    btnToggleAdv.addEventListener("click", () => {
      const visible = advSection.style.display !== "none";
      advSection.style.display = visible ? "none" : "block";
      btnToggleAdv.textContent = visible
        ? "Show advanced parameters"
        : "Hide advanced parameters";
    });
  }

  if (btnSave) {
    btnSave.addEventListener("click", () => {
      if (statusEl) {
        statusEl.textContent = "Saving...";
        statusEl.classList.remove("error", "ok");
      }

      const payload = buildSitePayload(form);

      fetch("/haproxy/sites/save", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Requested-With": "XMLHttpRequest",
        },
        body: JSON.stringify(payload),
      })
        .then((r) => r.json())
        .then((data) => {
          if (data.ok) {
            document.dispatchEvent(
              new CustomEvent("easy-ha-proxy:config-state-changed")
            );
            if (statusEl) {
              statusEl.textContent = data.message || "Saved";
              statusEl.classList.add("ok");
            }
            // После успешного сохранения — назад to списку
            setTimeout(() => {
              window.location.href = "/haproxy/sites";
            }, 600);
          } else {
            if (statusEl) {
              statusEl.textContent = data.error || data.message || "Save error";
              statusEl.classList.add("error");
            }
          }
        })
        .catch((err) => {
          console.error(err);
          if (statusEl) {
            statusEl.textContent = "Server request failed";
            statusEl.classList.add("error");
          }
        });
    });
  }
}

function buildSitePayload(form) {
  function val(id) {
    const el = document.getElementById(id);
    return el ? el.value.trim() : "";
  }

  function num(id) {
    const s = val(id);
    if (!s) return null;
    const n = parseInt(s, 10);
    return Number.isNaN(n) ? null : n;
  }

  function checked(id) {
    const el = document.getElementById(id);
    return el ? !!el.checked : false;
  }

  const site = {};

  site.name = val("field-name");
  site.domain = val("field-domain");
  site.backend_ip = val("field-backend-ip");
  const bp = num("field-backend-port");
  if (bp !== null) site.backend_port = bp;

  // alt_names: by строкам
  const altEl = document.getElementById("field-alt-names");
  if (altEl) {
    const lines = altEl.value
      .split("\n")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    if (lines.length > 0) {
      site.alt_names = lines;
    }
  }

  // Основные флаги
  site.redirect_to_https = checked("field-redirect-to-https");
  site.authelia_enabled = checked("field-authelia-enabled");
  site.zero_trust = checked("field-zero-trust");
  site.maintenance = checked("field-maintenance");
  site.tcp_passthrough = checked("field-tcp-passthrough");

  // Backend / health
  site.backend_ssl = checked("field-backend-ssl");
  site.backend_ssl_verify = checked("field-backend-ssl-verify");
  site.tcp_check = checked("field-tcp-check");

  const backendHost = val("field-backend-host");
  if (backendHost) site.backend_host = backendHost;

  const healthUri = val("field-health-uri");
  if (healthUri) site.health_uri = healthUri;

  const hs = num("field-health-status");
  if (hs !== null) site.health_status = hs;

  const backendSslCa = val("field-backend-ssl-ca");
  if (backendSslCa) site.backend_ssl_ca = backendSslCa;

  const backendAlpn = val("field-backend-alpn");
  if (backendAlpn) site.backend_alpn = backendAlpn;

  const verifyHost = val("field-verify-host");
  if (verifyHost) site.verify_host = verifyHost;

  // Sessions
  const httpReuse = val("field-http-reuse");
  if (httpReuse) site.http_reuse = httpReuse;

  const sessionTimeout = val("field-session-timeout");
  if (sessionTimeout) site.session_timeout = sessionTimeout;

  const httpKa = val("field-http-keepalive-timeout");
  if (httpKa) site.http_keepalive_timeout = httpKa;

  site.prefer_last_server = checked("field-prefer-last-server");

  // Баланс / sticky
  const balance = val("field-balance");
  if (balance) site.balance = balance;

  const sticky = val("field-sticky");
  if (sticky) site.sticky = sticky;

  const cookieName = val("field-cookie-name");
  if (cookieName) site.cookie_name = cookieName;

  const cookieAttrs = val("field-cookie-attrs");
  if (cookieAttrs) site.cookie_attrs = cookieAttrs;

  // Ограничения
  const mrr = num("field-max-req-rate");
  if (mrr !== null) site.max_req_rate = mrr;

  site.rate_ban = checked("field-rate-ban");

  // HSTS / WAF / compress
  const hsts = val("field-hsts");
  if (hsts) site.hsts = hsts;


  site.compress = checked("field-compress");

  const payload = {
    site: site,
    original_name: form.dataset.originalName || site.name,
  };

  return payload;
}
