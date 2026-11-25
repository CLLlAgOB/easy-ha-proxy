/* Adaptive protection: the decisions behind the page, without the page.
 *
 * What the weight simulator asks for, how the ban ladder is shown, edited
 * and checked, what switching the mode will do, where each score band
 * starts and ends, and how an address's findings are explained. Nothing
 * here touches the DOM or the network, so the same file is loaded by the
 * page and by the tests in .tests/js/. Words are passed in as label(key):
 * the page passes its translator, the tests their own.
 */
(function (root, factory) {
  "use strict";
  const api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    root.EasyHaProxyAdaptive = api;
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const identity = (value) => String(value);

  const STATES = ["HOSTILE", "HIGH_RISK", "SUSPICIOUS", "WATCH", "NORMAL"];

  // The abbreviations the rest of the application already uses, rather than
  // single letters of my own. A one-letter catalogue key would be a trap:
  // the DOM translator substitutes catalogue words inside strings it did
  // not match whole, so "d" would sit waiting for the first page that
  // prints a lone "d" in some other sense. Abbreviations also sidestep
  // Russian numeral agreement, which is why these are not "7 days".
  const UNITS = [
    {key: "min", seconds: 60},
    {key: "hr", seconds: 3600},
    {key: "days", seconds: 86400}
  ];
  const MAX_LADDER_STEPS = 6;
  const NEW_LADDER_STEP = 3600;

  /* ---------- simulator ---------- */

  // The query for the weight simulator: only the fields filled in. Decay is
  // typed in hours, because that is how an operator thinks about how long a
  // finding should still count, and sent in seconds.
  function simulatorParams(fields) {
    const params = {};
    Object.entries(fields.weights || {}).forEach(([name, raw]) => {
      const value = String(raw == null ? "" : raw).trim();
      if (value !== "") params[`w.${name}`] = value;
    });
    const cap = String(fields.cap == null ? "" : fields.cap).trim();
    if (cap !== "") params.cap = cap;
    const decay = String(fields.decayHours == null ? "" : fields.decayHours).trim();
    if (decay !== "") {
      const hours = Number(decay);
      if (Number.isFinite(hours)) params.decay = String(Math.round(hours * 3600));
    }
    return params;
  }

  /* ---------- ban ladder ---------- */

  // A length in the largest unit that divides it exactly, so a stored
  // 604800 comes back as 7 days rather than 10080 minutes -- and 36 hours
  // stays 36 hours instead of becoming "2 days".
  function splitDuration(seconds) {
    const total = Number(seconds) || 0;
    for (const unit of UNITS.slice().reverse()) {
      if (total >= unit.seconds && total % unit.seconds === 0) {
        return {value: total / unit.seconds, unit: unit.key};
      }
    }
    return {value: Math.max(1, Math.round(total / 60)), unit: "min"};
  }

  // How a step reads on the page: the same value and unit the editor shows.
  function ladderText(seconds, label) {
    const parts = splitDuration(seconds);
    return `${parts.value} ${(label || identity)(parts.unit)}`;
  }

  // What a row of the editor stands for: never less than one of its unit.
  function stepSeconds(value, unitKey) {
    const unit = UNITS.find((entry) => entry.key === unitKey) || UNITS[0];
    return Math.max(1, Number(value) || 1) * unit.seconds;
  }

  // The first step shorter than the one before it, or -1. Checked here so an
  // obvious mistake is named before it becomes a request; the daemon checks
  // again and its answer is the one that holds.
  function ladderProblem(steps) {
    for (let index = 1; index < steps.length; index += 1) {
      if (steps[index] < steps[index - 1]) return index;
    }
    return -1;
  }

  function canAddStep(steps) {
    return steps.length < MAX_LADDER_STEPS;
  }

  function canRemoveStep(steps) {
    return steps.length > 1;
  }

  // A new step starts at the last one, which is the only value that cannot
  // break the "never shorter than the step before" rule.
  function nextStep(steps) {
    return steps.length ? steps[steps.length - 1] : NEW_LADDER_STEP;
  }

  /* ---------- mode ---------- */

  // What the confirmation says before the mode changes: how many addresses
  // enforcement would ban at once, and how many of them signed in later;
  // that leaving enforcement lifts every ban it placed; or just asks.
  function modeConfirmation(mode, currentMode, summary) {
    if (mode === "enforce") {
      return {
        kind: "enforce",
        wouldBan: Number((summary || {}).would_ban) || 0,
        suspects: Number((summary || {}).likely_false_positive) || 0
      };
    }
    if (currentMode === "enforce") return {kind: "lift"};
    return {kind: "change"};
  }

  /* ---------- scores ---------- */

  // The bands from the highest down, each with where it ends: the page said
  // it would "ban what crosses the threshold" and never said what the
  // threshold was, so a score of 43 carried no meaning.
  function bandRanges(bands) {
    const ordered = (bands || []).slice().sort((a, b) => b.from - a.from);
    return ordered.map((band, index) => ({
      state: band.state,
      bans: Boolean(band.bans),
      from: band.from,
      upTo: index === 0 ? null : ordered[index - 1].from - 1
    }));
  }

  // The states present in a summary, worst first, with their counts.
  function statesPresent(byState) {
    return STATES
      .filter((state) => (byState || {})[state])
      .map((state) => [state, byState[state]]);
  }

  // How long a ban has left, in the two largest units. Each is rounded with
  // the whole, so 2 days 23.6 hours reads "3 days 0 hr" -- not "2 days 24
  // hr", as rounding the remainder on its own did.
  function formatLeft(seconds, label) {
    const say = label || identity;
    const total = Math.max(0, Number(seconds) || 0);
    const minutes = Math.max(1, Math.round(total / 60));
    if (minutes < 60) return `${minutes}${say("min")}`;
    if (minutes < 1440) return `${Math.floor(minutes / 60)}${say("hr")} ${minutes % 60}${say("min")}`;
    const hours = Math.round(total / 3600);
    return `${Math.floor(hours / 24)}${say("days")} ${hours % 24}${say("hr")}`;
  }

  /* ---------- an address's findings ---------- */

  function newestFirst(contributions) {
    return (contributions || []).slice().sort((a, b) => Number(b.ts) - Number(a.ts));
  }

  // What was measured, against what, and which setting moves it. Without
  // this the page can say a limit was hit but not which one or by how much,
  // which is exactly what an operator needs to decide whether the limit is
  // wrong.
  function findingContext(item, label) {
    const say = label || identity;
    const bits = [];
    if (item.site_domain || item.site_name) bits.push(item.site_domain || item.site_name);
    if (item.observed != null && item.limit != null) {
      bits.push(
        `${item.observed}${item.unit ? " " + say(item.unit) : ""} / ${say("limit")} ` +
        `${item.limit}${item.window ? " / " + item.window : ""}`
      );
      if (item.over_by > 0) bits.push(`+${item.over_by} ${say("over")}`);
    } else if (item.detail) {
      bits.push(item.detail);
    }
    if (item.setting) {
      bits.push(`${say("raise")} ${item.setting}` + (item.suggested ? ` → ${item.suggested}` : ""));
    }
    return bits;
  }

  // What a finding added to the score, or why it added nothing.
  function findingPoints(item, label) {
    return Number(item.points) > 0 ? `+${item.points}` : `0 · ${(label || identity)(item.reason)}`;
  }

  function banRows(rows, filters, label = identity) {
    const query = String(filters.q || "").trim().toLowerCase();
    const key = ["ip", "ts", "until", "score", "strike"].includes(filters.sort) ? filters.sort : "ts";
    const direction = filters.direction === "asc" ? 1 : -1;
    return (rows || []).map((row) => ({...row, ts: row.ts ?? row.banned_at, strike: row.strike ?? row.strikes}))
      .filter((row) => Number(row.ts) >= Number(filters.since || 0) &&
        (!query || `${row.ip} ${(row.categories || []).join(" ")} ${(row.categories || []).map((value) => banReason(value, label)).join(" ")}`.toLowerCase().includes(query)))
      .sort((a, b) => direction * (key === "ip" ? String(a.ip).localeCompare(String(b.ip)) :
        (Number(a[key] || 0) - Number(b[key] || 0))) || String(a.ip).localeCompare(String(b.ip)));
  }

  function banRequestParams(ban, hours) {
    const span = [1, 6, 24, 168].includes(Number(hours)) ? Number(hours) : 1;
    return {client: ban.ip, since: Math.max(0, Number(ban.ts) - span * 3600),
      until: Number(ban.ts), hide_admin: "0", limit: 100};
  }

  const BAN_REASONS = {
    secrets: "Secret file probes", vcs: "Repository probes", wordpress: "WordPress probes",
    config: "Configuration probes", "rce-probe": "Command execution probes", "server-info": "Server information probes",
    "known-exploit": "Known exploit probes", subnet: "Coordinated /24 subnet campaign",
    "proto-ua-mismatch": "Browser User-Agent over HTTP/1.0", "unusual-method-probe": "Unusual HTTP method probe",
    SCANNER_PATH: "Scanner signature", SCANNER_PATH_DECISIVE: "Decisive scanner signature",
    QUERY_INJECTION: "Query injection", SUBNET_CAMPAIGN: "Coordinated /24 subnet campaign",
    SCANNER_MULTI_CATEGORY: "Several scanner categories", LOW_AND_SLOW_SCANNER: "Persistent slow scanning",
    NOT_FOUND_ENUMERATION: "Missing path enumeration", WIDE_ENUMERATION: "Wide path enumeration",
    MASS_ENUMERATION: "Mass path enumeration", RECURRING_SCANNER: "Repeated scanning",
    INVALID_HOST_ACTIVITY: "Unknown host probes", NOSNI_PROBING: "Requests without a server name",
    RATE_EXCEEDED: "Request rate exceeded", ERROR_RATE_EXCEEDED: "Error rate exceeded",
    LEGACY_HAPROXY_BAN: "HAProxy rule", HARD_FLOOR_EPISODE: "Hard protection threshold"
  };
  function banReason(value, label = identity) { return label(BAN_REASONS[value] || value || "Unknown reason"); }
  function banSearchTerms(query, label = identity) {
    const text = String(query || "").trim().toLowerCase();
    return text ? Object.keys(BAN_REASONS).filter((key) => banReason(key, label).toLowerCase().includes(text)) : [];
  }

  function reputationRows(rows, showNormal = false) {
    return (rows || []).filter((row) => showNormal || STATES.slice(0, -1).includes(row.state) || row.likely_false_positive)
      .slice().sort((a, b) => Number(Boolean(b.likely_false_positive)) - Number(Boolean(a.likely_false_positive)) ||
        Number(b.score || 0) - Number(a.score || 0) || Number(b.last_seen || 0) - Number(a.last_seen || 0));
  }
  function reputationPage(rows, showNormal, page) {
    const found = reputationRows(rows, showNormal);
    const current = Math.min(Math.max(0, Number(page) || 0), Math.max(0, Math.ceil(found.length / 10) - 1));
    return {rows: found.slice(current * 10, current * 10 + 10), total: found.length, page: current};
  }

  function banListState(search) {
    const params = new URLSearchParams(search);
    const integer = (key, max) => Math.min(max, Math.max(0, Math.floor(Number(params.get(key)) || 0)));
    return {mode: params.get("mode") === "history" ? "history" : "active", q: (params.get("q") || "").slice(0, 100),
      period: [86400, 604800, 2592000].includes(Number(params.get("period"))) ? Number(params.get("period")) : 0,
      since: integer("since", 2000000000),
      sort: ["ip", "ts", "until", "score", "strike"].includes(params.get("sort")) ? params.get("sort") : "ts",
      direction: params.get("direction") === "asc" ? "asc" : "desc",
      page: integer("page", 40000), snapshot: integer("snapshot", Number.MAX_SAFE_INTEGER)};
  }
  function banListUrl(state) {
    return `/security/adaptive/bans?${new URLSearchParams(banListState(new URLSearchParams(state)))}`;
  }
  function banReturnUrl(value) {
    try {
      const url = new URL(value || "/security/adaptive/bans", "https://local.invalid");
      if (url.origin !== "https://local.invalid" || url.pathname !== "/security/adaptive/bans") return "/security/adaptive/bans";
      return banListUrl(banListState(url.search));
    } catch { return "/security/adaptive/bans"; }
  }
  function banDetailUrl(ban, returnTo) {
    const params = new URLSearchParams({ip: ban.ip || "", at: ban.ts || 0, return: banReturnUrl(returnTo)});
    if (ban.id) params.set("id", ban.id);
    return `/security/adaptive/ban?${params}`;
  }

  return {
    banRows,
    banRequestParams,
    banReason,
    banSearchTerms,
    BAN_REASONS,
    reputationRows,
    reputationPage,
    banListState,
    banListUrl,
    banReturnUrl,
    banDetailUrl,
    STATES,
    UNITS,
    MAX_LADDER_STEPS,
    simulatorParams,
    splitDuration,
    ladderText,
    stepSeconds,
    ladderProblem,
    canAddStep,
    canRemoveStep,
    nextStep,
    modeConfirmation,
    bandRanges,
    statesPresent,
    formatLeft,
    newestFirst,
    findingContext,
    findingPoints
  };
});
