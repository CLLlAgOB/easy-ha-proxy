/* Applied bans and the evidence for one particular strike. Read-only. */
(function () {
  "use strict";
  const core = window.EasyHaProxyAdaptive;
  const t = window.t || ((text) => text);
  const byId = (id) => document.getElementById(id);
  const clock = window.EasyHaProxyTime.formatter({dateStyle: "short", timeStyle: "medium"});
  const when = (value) => Number(value) > 0 ? clock.format(new Date(Number(value) * 1000)) : "—";
  let detailSequence = 0;
  let requestSequence = 0;
  let selected = null;
  let nextRequest = 0;
  let requestCount = 0;
  function text(id, value) { byId(id).textContent = value; }
  function cell(row, value, className = "") {
    const td = document.createElement("td");
    td.textContent = value == null || value === "" ? "—" : String(value);
    td.className = className; row.appendChild(td); return td;
  }
  async function get(path, params) {
    const response = await fetch(`${path}?${new URLSearchParams(params)}`, {
      credentials: "same-origin", headers: {Accept: "application/json"}
    });
    const payload = await response.json();
    if (!response.ok || payload.ok === false) throw new Error(payload.error || `HTTP ${response.status}`);
    return payload;
  }
  async function openBan(ban) {
    const ticket = ++detailSequence;
    ++requestSequence;
    selected = null;

    text("ab-detail-title", `${ban.ip} · ${when(ban.ts)}`);

    text("ab-detail-note", t("Loading ban details…"));
    text("ab-evidence-note", "");
    text("ab-requests-note", "");
    byId("ab-evidence").replaceChildren();
    byId("ab-requests").replaceChildren();
    byId("ab-more").hidden = true;
    byId("ab-explorer").hidden = true;
    byId("ab-ip-page").href = `/ip/${encodeURIComponent(ban.ip)}`;
    try {
      const payload = await get("/api/security/adaptive/ban", ban.id ? {id: ban.id} : {ip: ban.ip, at: ban.ts});
      if (ticket !== detailSequence) return;
      selected = payload.ban;
      text("ab-detail-title", `${selected.ip} · ${when(selected.ts)}`);
      byId("ab-ip-page").href = `/ip/${encodeURIComponent(selected.ip)}`;
      text("ab-detail-note", `${t("Ban score")}: ${selected.score} · ${t("Ban step")}: ${selected.strike > 0 ? selected.strike : "—"} · ${t("Scheduled end")}: ${when(selected.until)}`);
      const evidence = (selected.reason.evidence || []).slice().sort((a, b) => a.ts - b.ts);
      evidence.forEach((item) => {
        const row = document.createElement("tr");
        cell(row, when(item.ts));
        cell(row, `${core.banReason(item.event_type, t)}${item.category ? ` / ${core.banReason(item.category, t)}` : ""}`);
        cell(row, item.site);
        cell(row, item.detail, "ab-wrap");
        cell(row, `+${item.points}`);
        byId("ab-evidence").appendChild(row);
      });
      text("ab-evidence-note", evidence.length ?
        `${t("Saved findings")}: ${evidence.length} / ${selected.reason.evidence_total || evidence.length}` :
        t("This older ban has no saved findings. The current score cannot explain a past decision."));
    } catch (error) {
      if (ticket !== detailSequence) return;
      // Older records can be pruned independently of the requests. Still
      // offer the real request log for the exact IP and time the row carried.
      selected = ban;
      text("ab-detail-note", `${t("Could not load ban findings")}: ${t(error.message)}`);
    }
    if (ticket === detailSequence) loadRequests(false);
  }
  async function loadRequests(append) {
    if (!selected) return;
    if (!Number.isFinite(Number(selected.ts)) || Number(selected.ts) <= 0) {
      text("ab-requests-note", t("The ban time is unknown. Use address details to inspect the available history."));
      return;
    }
    const ticket = ++requestSequence;
    const params = core.banRequestParams(selected, byId("ab-hours").value);
    if (!append) {
      nextRequest = 0;
      requestCount = 0;
      byId("ab-requests").replaceChildren();
    } else params.before = nextRequest;
    byId("ab-explorer").href = `/security/requests?${new URLSearchParams(params)}`;
    byId("ab-explorer").hidden = false;
    byId("ab-more").disabled = true;
    text("ab-requests-note", t("Loading requests…"));
    try {
      const payload = await get("/api/security/requests", params);
      if (ticket !== requestSequence) return;
      (payload.requests || []).forEach((item) => {
        const row = document.createElement("tr");
        cell(row, when(item.ts)); cell(row, item.method); cell(row, item.host || item.backend);
        cell(row, item.path, "ab-wrap"); cell(row, item.status); cell(row, item.user_agent, "ab-wrap");
        byId("ab-requests").appendChild(row);
        ++requestCount;
      });
      nextRequest = Number(payload.next || 0);
      let note = requestCount ? `${t("Requests shown")}: ${requestCount}` :
        t("No retained requests in this interval. Recording may have been disabled or older requests may have expired.");
      if (payload.source === "memory") note += ` ${t("Only the recent in-memory buffer is available.")} ${t("Available since")}: ${when(payload.reaches_back_to)}`;
      if (payload.timed_out) note += ` ${t("Search is incomplete. Load older requests to continue.")}`;
      text("ab-requests-note", note);
      byId("ab-more").hidden = !nextRequest;
    } catch (error) {
      if (ticket !== requestSequence) return;
      text("ab-requests-note", `${t("Request log is unavailable")}: ${t(error.message)}`);
      byId("ab-more").hidden = !nextRequest;
    } finally {
      if (ticket === requestSequence) byId("ab-more").disabled = false;
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    const params = new URLSearchParams(window.location.search);
    byId("ab-back").href = core.banReturnUrl(params.get("return"));
    byId("ab-hours").addEventListener("change", () => loadRequests(false));
    byId("ab-more").addEventListener("click", () => loadRequests(true));
    openBan(JSON.parse(byId("ab-detail").dataset.ban));
  });
})();
