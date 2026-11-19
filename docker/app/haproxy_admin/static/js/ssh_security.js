(function () {
  "use strict";
  const app = document.getElementById("ssh-protection-app");
  if (!app) return;
  const t = window.t;
  const el = (id) => document.getElementById("ssh-" + id);
  const states = {
    not_installed: "Fail2ban is not installed.",
    active: "Fail2ban is monitoring SSH and can block IP addresses.",
    jail_disabled: "Fail2ban is running. Its standard SSH rule is disabled.",
    service_stopped: "Fail2ban is installed. Its service is stopped.",
    service_failed: "The Fail2ban service failed. Check its configuration and system journal.",
    unavailable: "The Fail2ban service status could not be verified."
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

  function renderBlocks(active, busy) {
    const bans = snapshot.banned || [];
    const count = snapshot.currently_banned;
    el("blocks").hidden = !active;
    el("blocks-table").hidden = bans.length === 0;
    el("blocks-note").textContent = !count ? t("No IP addresses are currently blocked.")
      : count > bans.length ? t("Showing {shown} of {total} blocked IP addresses.", {shown: bans.length, total: count}) : "";
    const currentBlocks = JSON.stringify([bans, busy]);
    if (currentBlocks === renderedBlocks) return;
    renderedBlocks = currentBlocks;
    el("banned").replaceChildren(...bans.map((ip) => {
      const row = document.createElement("tr");
      const address = document.createElement("td");
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
      address.textContent = ip;
      actions.append(button);
      row.append(address, actions);
      return row;
    }));
  }

  function render() {
    const {monitoring, state, managed, external_config: external, error, job, openssh} = snapshot;
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
      : "Monitoring in the panel is paused. Fail2ban continues to use its server configuration.");
    const owner = monitoring && (external || (active && !managed) ? "The SSH rule is managed on the server."
      : managed ? "The panel manages the Fail2ban SSH rule." : "");
    el("owner").hidden = !owner;
    el("owner").textContent = owner ? t(owner) : "";
    el("error").hidden = !error;
    el("error").textContent = error ? t(error) : "";
    el("configuration").hidden = !configurable;
    el("trusted").disabled = busy;
    if (!dirty) el("trusted").value = (snapshot.trusted || []).join("\n");
    el("configure").hidden = !configurable;
    el("configure").disabled = busy;
    el("configure").textContent = t(operation === "install" ? "Install Fail2ban and enable SSH blocking"
      : active ? "Save trusted addresses" : "Enable SSH blocking");
    el("disable").hidden = !configurable || !managed || !snapshot.managed_enabled;
    el("disable").disabled = busy;
    el("counters").hidden = !active;
    for (const key of ["currently_failed", "total_failed", "currently_banned", "total_banned"]) {
      el(key.replace("_", "-")).textContent = snapshot[key] ?? "—";
    }
    renderBlocks(active, busy);
    el("openssh").hidden = !monitoring || !Object.keys(openssh || {}).length;
    const sshLabels = {yes: "Enabled", no: "Disabled", "prohibit-password": "Without a password",
      "without-password": "Without a password", "forced-commands-only": "Forced commands only"};
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
    } catch (error) {
      report(error.message, true);
    } finally {
      mutating = false;
      await poll();
    }
  }

  el("monitoring").addEventListener("click", () => mutate("monitoring", {enabled: !snapshot.monitoring}));
  el("trusted").addEventListener("input", () => { dirty = true; });
  el("configuration-form").addEventListener("submit", (event) => {
    event.preventDefault();
    if (el("configure").disabled) return;
    const trusted = el("trusted").value.trim().split(/\s+/).filter(Boolean);
    const prompt = operation === "install" ? "Install Fail2ban and enable SSH blocking on this server?"
      : snapshot.state === "active" ? "Save the trusted addresses for SSH blocking?" : "Enable Fail2ban SSH blocking on this server?";
    if (window.confirm(t(prompt))) mutate("protection", {operation, trusted});
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
  poll();
})();
