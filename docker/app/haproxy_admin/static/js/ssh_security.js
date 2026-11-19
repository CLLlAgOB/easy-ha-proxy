(function () {
  "use strict";
  const app = document.getElementById("ssh-protection-app");
  if (!app) return;
  const t = window.t;
  const el = (id) => document.getElementById("ssh-" + id);
  const states = {
    not_installed: "Fail2ban is not installed.",
    active: "Fail2ban is monitoring SSH.",
    jail_disabled: "Fail2ban is running. Its standard SSH rule is disabled.",
    service_stopped: "Fail2ban is installed. Its service is stopped.",
    service_failed: "The Fail2ban service failed. Check its configuration and system journal.",
    unavailable: "The Fail2ban service status could not be verified."
  };
  const thresholds = ["maxretry", "findtime", "bantime"];
  const sshLabels = {yes: "Enabled", no: "Disabled", "prohibit-password": "Without a password",
    "without-password": "Without a password", "forced-commands-only": "Forced commands only"};
  const connectionFields = {
    pubkeyauthentication: "Public key authentication", passwordauthentication: "Password authentication",
    kbdinteractiveauthentication: "Keyboard-interactive authentication", authenticationmethods: "Required authentication methods",
    permitrootlogin: "Root login", allowusers: "Allowed SSH users", allowgroups: "Allowed SSH groups",
    denyusers: "Denied SSH users", denygroups: "Denied SSH groups", persourcepenalties: "OpenSSH connection penalties"
  };
  let snapshot, timer, jobId, jobLog, polling, mutating = false, readFailed = false, dirty = false, operation;
  let renderedBlocks;

  async function api(name, body) {
    const query = name === "status" && jobId ? "?job_id=" + encodeURIComponent(jobId) : "";
    const response = await fetch(app.dataset[name + "Url"] + query, {
      method: body === undefined ? "GET" : "POST", credentials: "same-origin",
      headers: {Accept: "application/json", "Content-Type": "application/json",
        "X-CSRFToken": document.querySelector('meta[name="csrf-token"]')?.content || ""},
      ...(body === undefined ? {} : {body: JSON.stringify(body)})
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || data.ok !== true) {
      if (response.status === 404 && name === "status") jobId = "";
      if (data.error === "unknown update broker action") throw new Error("Update the host services to use SSH protection.");
      throw new Error(data.error || "Could not read SSH protection from the server.");
    }
    return data;
  }

  function report(message, error = false) {
    el("message").textContent = t(message);
    el("message").classList.toggle("text-danger", error);
  }

  function running() {
    return ["queued", "running"].includes(snapshot?.job?.status);
  }

  function cell(text) {
    const element = document.createElement("td");
    element.textContent = text;
    element.dataset.i18nSkip = "";
    return element;
  }

  function renderBlocks(active, busy) {
    const bans = snapshot.banned || [];
    const count = snapshot.currently_banned;
    const query = el("filter").value.trim().toLowerCase();
    const times = snapshot.ban_times || {};
    const visible = bans.filter((ip) => ip.toLowerCase().includes(query)).sort((a, b) => {
      const first = times[a]?.expires || "~";
      const second = times[b]?.expires || "~";
      return first < second ? -1 : first > second ? 1 : 0;
    });
    el("blocks").hidden = !active;
    el("filter-label").hidden = bans.length === 0;
    el("blocks-table").hidden = visible.length === 0;
    el("blocks-note").textContent = !count ? t("No IP addresses are currently blocked.")
      : query && !visible.length ? t("No matching IP in the displayed blocks.")
        : query || count > visible.length ? t("Showing {shown} of {total} blocked IP addresses.", {shown: visible.length, total: count}) : "";
    const currentBlocks = JSON.stringify([visible, times, busy]);
    if (currentBlocks === renderedBlocks) return;
    renderedBlocks = currentBlocks;
    el("banned").replaceChildren(...visible.map((ip) => {
      const row = document.createElement("tr");
      const actions = document.createElement("td");
      const button = document.createElement("button");
      button.type = "button";
      button.className = "btn btn-secondary";
      button.textContent = t("Unblock");
      button.dataset.i18nSkip = "";
      button.disabled = busy;
      button.setAttribute("aria-label", t("Unblock {ip}", {ip}));
      button.addEventListener("click", () => {
        if (window.confirm(t("Remove the SSH block for {ip}?", {ip}))) mutate("unban", {ip});
      });
      actions.append(button);
      const timing = times[ip];
      row.append(cell(ip), cell(timing?.started || "—"),
        cell(timing?.permanent ? t("Permanent") : timing?.expires || "—"), actions);
      return row;
    }));
  }

  function renderFirewall(active, firewall) {
    const states = {
      idle: "There are no active SSH blocks to verify in the firewall.",
      verified: "Active SSH blocks are present in the firewall.",
      missing: "The firewall is missing rules for one or more active SSH blocks.",
      ports_changed: "The SSH listening ports have changed since the Fail2ban rule was configured.",
      unknown: "The firewall rules for SSH could not be read.",
      order_unknown: "Earlier firewall rules may take precedence over SSH blocks.",
      partial: "The firewall check covered the displayed addresses.",
      external: "Firewall verification is available for the panel-managed SSH rule."
    };
    const state = firewall?.state;
    el("firewall").hidden = !active || !states[state];
    el("firewall").textContent = states[state] ? t(states[state]) : "";
    el("firewall").classList.toggle("text-warning", ["missing", "ports_changed", "unknown", "order_unknown", "partial"].includes(state));
  }

  function renderTrustedWarning() {
    const ranges = el("trusted").value.trim().split(/\s+/).flatMap((value) => {
      const match = value.match(/^([^/]+)\/(\d{1,3})$/);
      if (!match) return [];
      const bits = match[1].includes(":") ? 128 : 32;
      const prefix = Number(match[2]);
      if (prefix >= (bits === 128 ? 64 : 24)) return [];
      const count = (1n << BigInt(bits - prefix)).toLocaleString(document.documentElement.lang || undefined);
      return [match[0] + " (" + count + ")"];
    });
    el("trusted-warning").hidden = ranges.length === 0;
    el("trusted-warning").textContent = ranges.length
      ? t("Broad trusted ranges exempt many addresses from SSH blocks. Check {ranges}.", {ranges: ranges.join(", ")}) : "";
  }

  function duration(seconds) {
    if (seconds < 0) return t("Unlimited");
    const unit = seconds % 3600 === 0 && seconds > 0 ? "hour" : seconds % 60 === 0 ? "minute" : "second";
    const scale = {hour: 3600, minute: 60, second: 1}[unit];
    return new Intl.NumberFormat(document.documentElement.lang || undefined, {style: "unit", unit, unitDisplay: "short"})
      .format(seconds / scale);
  }

  async function loadHistory() {
    el("history-note").textContent = t("Reading unblock history…");
    try {
      const result = await api("unblockHistory");
      el("history-table").hidden = !result.events.length;
      el("history-note").textContent = result.available
        ? (result.events.length ? "" : t("No manual SSH unblocks have been recorded."))
        : t("The SSH unblock history could not be read.");
      el("history-events").replaceChildren(...result.events.map((event) => {
        const row = document.createElement("tr");
        row.append(cell(window.EasyHaProxyTime.dateTime(event.ts * 1000)),
          cell(event.summary.replace(/^ip:\s+/, "")), cell(event.actor));
        return row;
      }));
    } catch (error) {
      el("history-table").hidden = true;
      el("history-note").textContent = t(error.message);
    }
  }

  function render() {
    const {monitoring, state, managed, external_config: external, error, job, openssh, policy,
      effective_policy: effective, listeners, firewall} = snapshot;
    const active = monitoring && state === "active";
    const busy = mutating || readFailed || running();
    const configurable = monitoring && !external && !error &&
      (state === "not_installed" || state === "jail_disabled" || state === "service_stopped" ||
        (managed && ["active", "service_failed"].includes(state)));
    operation = state === "not_installed" ? "install" : "enable";
    el("monitoring").hidden = false;
    el("monitoring").disabled = busy;
    el("monitoring").textContent = t(monitoring ? "Pause monitoring in the panel" : "Resume monitoring in the panel");
    el("state").textContent = t(monitoring ? (states[state] || states.unavailable)
      : "Panel monitoring and SSH alerts are paused. Fail2ban continues to run on the server.");
    const owner = monitoring && (external || (active && !managed) ? "The SSH rule is managed on the server."
      : managed ? "The panel manages the Fail2ban SSH rule." : "");
    el("owner").hidden = !owner;
    el("owner").textContent = owner ? t(owner) : "";
    el("error").hidden = !error;
    el("error").textContent = error ? t(error) : "";
    if (configurable && el("configuration").hidden && !active) el("configuration").open = true;
    el("configuration").hidden = !configurable;
    el("trusted").disabled = busy;
    if (!dirty) {
      el("trusted").value = (snapshot.trusted || []).join("\n");
      renderTrustedWarning();
      if (policy) {
        for (const key of thresholds) el(key).value = policy[key] / (key === "maxretry" ? 1 : 60);
      }
    }
    el("thresholds").hidden = !policy;
    for (const key of thresholds) el(key).disabled = busy || !policy;
    const effectiveKnown = thresholds.every((key) => Number.isInteger(effective?.[key]));
    el("policy-summary").hidden = !active || !effectiveKnown;
    el("policy-summary").textContent = effectiveKnown ? t(effective.bantime < 0
      ? "{attempts} failed attempts in {window} · permanent block"
      : "{attempts} failed attempts in {window} · block for {duration}", {
        attempts: effective.maxretry, window: duration(effective.findtime), duration: duration(effective.bantime)}) : "";
    el("effective-trusted").hidden = !active || !Array.isArray(effective?.trusted);
    el("effective-trusted-value").textContent = effective?.trusted?.length
      ? effective.trusted.join(", ") : t("No trusted addresses were reported.");
    el("configure").hidden = !configurable;
    el("configure").disabled = busy;
    el("configure").textContent = t(operation === "install" ? "Install Fail2ban and enable SSH blocking"
      : active ? (policy ? "Save SSH blocking policy" : "Save trusted addresses") : "Enable SSH blocking");
    el("disable").hidden = !configurable || !managed || !snapshot.managed_enabled;
    el("disable").disabled = busy;
    el("counters").hidden = !active;
    for (const key of ["currently_failed", "total_failed", "currently_banned", "total_banned"]) {
      el(key.replace("_", "-")).textContent = snapshot[key] ?? "—";
    }
    renderFirewall(active, firewall);
    renderBlocks(active, busy);
    el("history").hidden = !monitoring;
    el("openssh").hidden = !monitoring || !Object.keys(openssh || {}).length;
    el("listeners").textContent = listeners?.length ? listeners.join(", ") : t("Unavailable");
    el("connection-details").hidden = !listeners;
    for (const key of ["passwordauthentication", "kbdinteractiveauthentication", "permitrootlogin", "persourcepenalties"]) {
      const value = openssh?.[key];
      el(key).textContent = value ? t(sshLabels[value] || value) : t("Unavailable");
    }
    el("job-details").hidden = !job;
    el("job").textContent = job ? t(job.status) + (job.error || job.result?.message ? " · " + t(job.error || job.result.message) : "") : "";
    const log = job?.output?.log || (jobLog?.id === job?.id ? jobLog?.text : "");
    el("job-log").hidden = !log;
    el("job-log").textContent = log || "";
  }

  async function poll() {
    if (polling || mutating) return;
    polling = api("status");
    try {
      snapshot = await polling;
      if (readFailed) report("");
      readFailed = false;
      if (jobId && snapshot.job?.id === jobId && !running()) {
        jobLog = {id: jobId, text: snapshot.job.output?.log};
        jobId = "";
      }
    } catch (error) {
      readFailed = true;
      if (!snapshot) el("state").textContent = t(states.unavailable);
      report(error.message, true);
    } finally {
      polling = null;
      if (snapshot) render();
      clearTimeout(timer);
      timer = setTimeout(poll, running() ? 1500 : snapshot?.monitoring === false ? 30000 : 10000);
    }
  }

  async function mutate(name, body) {
    if (mutating || readFailed || running()) return;
    mutating = true;
    clearTimeout(timer);
    render();
    report("");
    try {
      await polling;
      if (running()) return;
      const result = await api(name, body);
      if (result.job_id) {
        jobId = result.job_id;
        snapshot.job = result.job;
        dirty = false;
        el("job-details").open = true;
      }
      if (result.message) report(result.message);
      if (name === "unban" && el("history").open) loadHistory();
    } catch (error) {
      report(error.message, true);
    } finally {
      mutating = false;
      await poll();
    }
  }

  el("monitoring").addEventListener("click", () => mutate("monitoring", {enabled: !snapshot.monitoring}));
  el("refresh").addEventListener("click", poll);
  el("filter").addEventListener("input", () => renderBlocks(snapshot.state === "active", mutating || readFailed || running()));
  el("history").addEventListener("toggle", () => { if (el("history").open) loadHistory(); });
  el("trusted").addEventListener("input", () => { dirty = true; renderTrustedWarning(); });
  for (const key of thresholds) el(key).addEventListener("input", () => { dirty = true; });
  el("configuration-form").addEventListener("submit", (event) => {
    event.preventDefault();
    if (el("configure").disabled) return;
    const trusted = el("trusted").value.trim().split(/\s+/).filter(Boolean);
    const prompt = operation === "install" ? "Install Fail2ban and enable SSH blocking on this server?"
      : snapshot.state === "active" ? "Save the SSH blocking policy?" : "Enable Fail2ban SSH blocking on this server?";
    const body = {operation, trusted};
    if (snapshot.policy) {
      body.policy = Object.fromEntries(thresholds.map((key) => [key, Number(el(key).value) * (key === "maxretry" ? 1 : 60)]));
    }
    const warning = el("trusted-warning").hidden ? "" : "\n\n" + el("trusted-warning").textContent;
    if (window.confirm(t(prompt) + warning)) mutate("protection", body);
  });
  el("disable").addEventListener("click", () => {
    if (window.confirm(t("Disable the panel-managed Fail2ban SSH rule?"))) mutate("protection", {operation: "disable", trusted: []});
  });
  el("job-details").addEventListener("toggle", () => {
    if (el("job-details").open && snapshot?.job && jobLog?.id !== snapshot.job.id && !jobId) {
      jobId = snapshot.job.id;
      poll();
    }
  });
  el("connection-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = el("connection-check");
    const output = el("connection-result");
    button.disabled = true;
    output.hidden = true;
    el("connection-message").textContent = t("Checking OpenSSH configuration…");
    try {
      const params = Object.fromEntries(new FormData(event.currentTarget));
      const result = await api("connection", params);
      output.replaceChildren(...Object.entries(connectionFields).filter(([key]) => result.openssh[key]).map(([key, label]) => {
        const item = document.createElement("div");
        const name = document.createElement("dt");
        const value = document.createElement("dd");
        name.textContent = t(label);
        value.textContent = t(sshLabels[result.openssh[key]] || result.openssh[key]);
        item.append(name, value);
        return item;
      }));
      el("connection-message").textContent = "";
      output.hidden = false;
    } catch (error) {
      el("connection-message").textContent = t(error.message);
    } finally {
      button.disabled = false;
    }
  });
  poll();
})();
