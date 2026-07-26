/* Local GeoIP database status, updates and global country selection. */
(function () {
  "use strict";

  const t = window.t || ((value) => String(value));
  const numberFormat = new Intl.NumberFormat(document.documentElement.lang || undefined);
  const dateFormat = new Intl.DateTimeFormat(document.documentElement.lang || undefined, {
    dateStyle: "medium",
    timeStyle: "medium"
  });
  const UPDATE_POLL_INTERVAL_MS = 1200;
  const UPDATE_POLL_TIMEOUT_MS = 6 * 60 * 1000;

  const elements = {};
  let selectedCountries = [];
  let countryNetworkCounts = {};
  let selectionRevision = "";
  let selectionDirty = false;
  let requestRunning = false;
  let updateIsRunning = false;

  function byId(id) {
    return document.getElementById(id);
  }

  function setText(id, value) {
    const element = elements[id] || byId(id);
    if (element) element.textContent = value == null || value === "" ? "—" : String(value);
  }

  function setMessage(element, message, ok) {
    if (!element) return;
    element.textContent = message || "";
    element.classList.toggle("success", Boolean(message) && ok === true);
    element.classList.toggle("error", Boolean(message) && ok === false);
  }

  function formatNumber(value) {
    const numeric = Number(value);
    return Number.isFinite(numeric) ? numberFormat.format(numeric) : "—";
  }

  function formatBytes(value) {
    let numeric = Number(value);
    if (!Number.isFinite(numeric) || numeric < 0) return "—";
    const units = ["B", "KiB", "MiB", "GiB"];
    let index = 0;
    while (numeric >= 1024 && index < units.length - 1) {
      numeric /= 1024;
      index += 1;
    }
    return `${numeric.toLocaleString(document.documentElement.lang || undefined, {
      maximumFractionDigits: index === 0 ? 0 : 1
    })} ${units[index]}`;
  }

  function formatDate(value) {
    if (!value) return "—";
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? String(value) : dateFormat.format(parsed);
  }

  async function requestJson(url, options) {
    const response = await fetch(url, options || {});
    let payload;
    try {
      payload = await response.json();
    } catch (_error) {
      throw new Error(`${t("Unexpected server response")} (${response.status})`);
    }
    if (!response.ok || payload.ok === false) {
      const problem = new Error(payload.error || payload.message || `${t("Request failed")} (${response.status})`);
      problem.status = response.status;
      problem.payload = payload;
      throw problem;
    }
    return payload;
  }

  function delay(milliseconds) {
    return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
  }

  function statusLabel(activeState, subState, result) {
    return [activeState, subState, result]
      .map((value) => String(value || "").trim())
      .filter((value, index, values) => value && values.indexOf(value) === index)
      .join(" / ") || "—";
  }

  function renderCountries() {
    const container = elements["geoip-selected-countries"];
    if (!container) return;
    if (!selectedCountries.length) {
      container.innerHTML = `<span class="muted">${window.escapeHtml(t("No countries selected"))}</span>`;
      return;
    }
    container.innerHTML = selectedCountries.map((code) => {
      const countValue = countryNetworkCounts[code];
      const count = countValue && typeof countValue === "object"
        ? Number(countValue.ipv4 || 0) + Number(countValue.ipv6 || 0)
        : Number(countValue);
      const countMarkup = Number.isFinite(count)
        ? `<small title="${window.escapeHtml(t("Networks for this country"))}">${window.escapeHtml(formatNumber(count))}</small>`
        : "";
      return `
      <span class="geoip-country-chip">
        ${window.countryFlagMarkup(code)}
        <span class="mono notranslate" translate="no" data-i18n-skip>${window.escapeHtml(code)}</span>
        ${countMarkup}
        <button type="button" data-remove-country="${window.escapeHtml(code)}"
                aria-label="${window.escapeHtml(t("Remove country {code}", {code}))}">×</button>
      </span>
    `;
    }).join("");
  }

  function renderStatus(payload, options) {
    const settings = options || {};
    const database = payload.database || {};
    const selection = payload.selection || {};
    const runtimeConfig = payload.runtime_config || {};
    const service = payload.service || {};
    const timer = payload.timer || {};

    updateIsRunning = Boolean(payload.update_running);

    if (/^[0-9a-f]{64}$/i.test(String(selection.revision || ""))) {
      selectionRevision = String(selection.revision).toLowerCase();
    }

    countryNetworkCounts = database.country_networks && typeof database.country_networks === "object"
      ? database.country_networks
      : {};

    const dbStatus = elements["geoip-db-status"];
    if (dbStatus) {
      dbStatus.textContent = database.available
        ? (database.integrity_ok === false ? t("Database integrity error") : t("Database available"))
        : t("Database unavailable");
      dbStatus.className = database.available && database.integrity_ok !== false
        ? "geoip-value-success"
        : "geoip-value-error";
    }

    setText("geoip-db-records", formatNumber(database.records));
    setText("geoip-allowed-networks", formatNumber(database.allowed_networks));
    setText("geoip-db-size", formatBytes(database.size_bytes));
    setText("geoip-source-period", database.source_period || "—");
    setText("geoip-activated-at", formatDate(database.activated_at));
    setText("geoip-provider", database.provider || "—");
    setText("geoip-release", database.release || "—");
    setText("geoip-build-at", formatDate(database.build_at));
    setText("geoip-integrity", database.integrity_ok === true
      ? t("Integrity check passed")
      : (database.integrity_ok === false ? t("Integrity check failed") : "—"));

    const filterState = elements["geoip-filter-state"];
    if (filterState) {
      filterState.textContent = selection.access_filter_enabled
        ? t("Filtering enabled")
        : t("Filtering disabled");
      filterState.className = `config-status-pill ${selection.access_filter_enabled
        ? "config-status-pill--success"
        : "config-status-pill--neutral"}`;
    }
    setText(
      "geoip-filter-mode",
      t("Mode: {mode}", {mode: runtimeConfig.geoip_mode || "—"})
    );

    const syncWarning = elements["geoip-sync-warning"];
    if (syncWarning) syncWarning.hidden = payload.runtime_config_in_sync !== false;

    if (!selectionDirty || settings.replaceSelection) {
      selectedCountries = Array.from(new Set((selection.countries || [])
        .map((value) => String(value).trim().toUpperCase())
        .filter((value) => /^[A-Z]{2}$/.test(value)))).sort();
      selectionDirty = false;
      renderCountries();
    }

    setText("geoip-timer-status", statusLabel(
      timer.enabled === false ? t("disabled") : timer.active_state,
      timer.sub_state,
      ""
    ));
    setText("geoip-next-run", formatDate(timer.next_run_at));
    setText("geoip-last-trigger", formatDate(timer.last_trigger_at));
    const serviceCompleted = service.result === "success"
      && service.active_state === "inactive"
      && service.sub_state === "dead";
    setText(
      "geoip-service-result",
      serviceCompleted ? "completed / success" : statusLabel(service.active_state, service.sub_state, service.result)
    );
    setText("geoip-last-run", formatDate(service.last_run_at));

    const journal = elements["geoip-journal"];
    if (journal) {
      const lines = Array.isArray(payload.journal_tail) ? payload.journal_tail : [];
      journal.textContent = lines.length ? lines.join("\n") : t("No updater events yet");
    }
  }

  function setBusy(busy) {
    requestRunning = busy;
    ["geoip-refresh", "geoip-update", "geoip-save-countries", "geoip-add-countries", "geoip-force-update"]
      .forEach((id) => {
        const element = elements[id];
        if (element) element.disabled = busy;
      });
    if (elements["geoip-update"]) elements["geoip-update"].classList.toggle("loading", busy);
    if (!busy && elements["geoip-save-countries"]) {
      elements["geoip-save-countries"].disabled = updateIsRunning
        || !/^[0-9a-f]{64}$/.test(selectionRevision);
    }
    if (!busy && elements["geoip-update"]) {
      elements["geoip-update"].disabled = updateIsRunning;
    }
  }

  async function loadStatus(showMessage) {
    if (requestRunning) return;
    let refreshAgain = false;
    const wasUpdating = updateIsRunning;
    setBusy(true);
    if (showMessage) setMessage(elements["geoip-page-status"], t("Loading GeoIP status…"));
    try {
      const payload = await requestJson("/haproxy/geoip/status");
      renderStatus(payload);
      refreshAgain = Boolean(payload.update_running);
      if (refreshAgain) {
        setMessage(elements["geoip-page-status"], t("GeoIP update is running…"));
      } else if (wasUpdating) {
        const succeeded = String(payload.service?.result || "").toLowerCase() === "success"
          && String(payload.service?.exit_status ?? "0") === "0";
        setMessage(
          elements["geoip-page-status"],
          succeeded ? t("GeoIP database update completed.") : t("GeoIP database update failed"),
          succeeded
        );
      } else if (showMessage) {
        setMessage(elements["geoip-page-status"], t("GeoIP status refreshed."), true);
      }
    } catch (error) {
      if (error.payload) renderStatus(error.payload);
      setMessage(elements["geoip-page-status"], `${t("Failed to load GeoIP status")}: ${error.message}`, false);
    } finally {
      setBusy(false);
      if (refreshAgain) window.setTimeout(() => loadStatus(false), UPDATE_POLL_INTERVAL_MS);
    }
  }

  function addCountries(rawValue) {
    const rawCodes = String(rawValue || "").split(/[\s,;]+/).filter(Boolean);
    const invalid = rawCodes.filter((code) => !/^[A-Za-z]{2}$/.test(code));
    if (invalid.length) {
      setMessage(
        elements["geoip-countries-status"],
        `${t("Invalid ISO country codes")}: ${invalid.join(", ")}`,
        false
      );
      return false;
    }
    const next = new Set(selectedCountries);
    rawCodes.forEach((code) => next.add(code.toUpperCase()));
    selectedCountries = Array.from(next).sort();
    selectionDirty = true;
    renderCountries();
    setMessage(elements["geoip-countries-status"], "");
    return true;
  }

  async function updateDatabase() {
    if (requestRunning) return;
    setBusy(true);
    setMessage(elements["geoip-page-status"], t("Updating the GeoIP database…"));
    try {
      const payload = await requestJson("/haproxy/geoip/update", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({force: Boolean(elements["geoip-force-update"]?.checked)})
      });
      if (payload.status) renderStatus(payload.status);
      setMessage(elements["geoip-page-status"], t("GeoIP update is running…"));

      const startedAt = Date.now();
      const initialLastRun = String(payload.status?.service?.last_run_at || "");
      let sawRunning = Boolean(payload.status?.update_running);
      let status = payload.status || {};
      let consecutiveErrors = 0;
      while (Date.now() - startedAt < UPDATE_POLL_TIMEOUT_MS) {
        await delay(UPDATE_POLL_INTERVAL_MS);
        try {
          status = await requestJson("/haproxy/geoip/status");
          consecutiveErrors = 0;
        } catch (pollError) {
          consecutiveErrors += 1;
          if (consecutiveErrors >= 3) throw pollError;
          continue;
        }
        renderStatus(status);
        if (status.update_running) {
          sawRunning = true;
          continue;
        }
        const lastRunChanged = String(status.service?.last_run_at || "") !== initialLastRun;
        if (sawRunning || lastRunChanged || Date.now() - startedAt >= 5000) break;
      }

      if (status.update_running) {
        throw new Error(t("Timed out while waiting for the GeoIP update to finish."));
      }
      const serviceResult = String(status.service?.result || "").toLowerCase();
      const exitStatus = String(status.service?.exit_status ?? "");
      if (serviceResult !== "success" || (exitStatus && exitStatus !== "0")) {
        throw new Error(
          t("The GeoIP updater finished with {result}.", {
            result: serviceResult || t("an unknown result")
          })
        );
      }
      if (elements["geoip-force-update"]) elements["geoip-force-update"].checked = false;
      setMessage(elements["geoip-page-status"], t("GeoIP database update completed."), true);
    } catch (error) {
      if (error.payload?.status) renderStatus(error.payload.status);
      setMessage(elements["geoip-page-status"], `${t("GeoIP database update failed")}: ${error.message}`, false);
    } finally {
      setBusy(false);
    }
  }

  async function saveCountries(event) {
    event.preventDefault();
    if (requestRunning) return;
    const filterEnabled = elements["geoip-filter-state"]?.classList.contains("config-status-pill--success");
    if (filterEnabled && !selectedCountries.length) {
      setMessage(
        elements["geoip-countries-status"],
        t("Select at least one country while GeoIP filtering is enabled."),
        false
      );
      return;
    }
    setBusy(true);
    setMessage(elements["geoip-countries-status"], t("Saving country selection and rebuilding the ACL…"));
    try {
      const payload = await requestJson("/haproxy/geoip/countries", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({countries: selectedCountries, revision: selectionRevision})
      });
      if (payload.status) renderStatus(payload.status, {replaceSelection: true});
      setMessage(
        elements["geoip-countries-status"],
        payload.message || t("Country selection saved and the GeoIP ACL was rebuilt."),
        true
      );
    } catch (error) {
      if (error.status === 409 && error.payload?.status) {
        renderStatus(error.payload.status);
      }
      setMessage(elements["geoip-countries-status"], `${t("Failed to save country selection")}: ${error.message}`, false);
    } finally {
      setBusy(false);
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    [
      "geoip-page-status", "geoip-sync-warning", "geoip-db-status", "geoip-db-records", "geoip-allowed-networks",
      "geoip-db-size", "geoip-source-period", "geoip-activated-at", "geoip-provider",
      "geoip-release", "geoip-build-at", "geoip-integrity", "geoip-filter-state", "geoip-filter-mode",
      "geoip-selected-countries", "geoip-countries-status", "geoip-timer-status",
      "geoip-next-run", "geoip-last-trigger", "geoip-service-result", "geoip-last-run",
      "geoip-journal", "geoip-refresh", "geoip-update", "geoip-force-update",
      "geoip-country-input", "geoip-add-countries", "geoip-save-countries"
    ].forEach((id) => { elements[id] = byId(id); });

    elements["geoip-refresh"]?.addEventListener("click", () => loadStatus(true));
    elements["geoip-update"]?.addEventListener("click", updateDatabase);
    elements["geoip-add-countries"]?.addEventListener("click", () => {
      if (addCountries(elements["geoip-country-input"]?.value)) {
        elements["geoip-country-input"].value = "";
        elements["geoip-country-input"].focus();
      }
    });
    elements["geoip-country-input"]?.addEventListener("keydown", (event) => {
      if (event.key !== "Enter") return;
      event.preventDefault();
      elements["geoip-add-countries"]?.click();
    });
    elements["geoip-selected-countries"]?.addEventListener("click", (event) => {
      const button = event.target.closest("[data-remove-country]");
      if (!button) return;
      selectedCountries = selectedCountries.filter((code) => code !== button.dataset.removeCountry);
      selectionDirty = true;
      renderCountries();
    });
    byId("geoip-countries-form")?.addEventListener("submit", saveCountries);

    loadStatus(false);
  });
})();
