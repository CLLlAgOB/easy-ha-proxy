/* Live activity: the decisions behind the page, without the page.
 *
 * What a saved choice restores to, what the filters ask the server for, how
 * the tables sort, which badges and which ban action a row gets, how the
 * timeline is stacked and what the note under the cards says. Nothing here
 * touches the DOM, storage or the network, so the same file is loaded by the
 * page and by the tests in .tests/js/. Words are passed in as label(key):
 * the page passes its translator, the tests their own.
 */
(function (root, factory) {
  "use strict";
  const api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    root.EasyHaProxyLive = api;
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const identity = (value) => String(value);

  const WINDOW_PRESETS = [30, 60, 300, 900];
  const WINDOW_MIN = 5;
  const WINDOW_MAX = 3600;
  const REFRESH_CHOICES = [2, 5, 10, 30];
  const TABS = ["addresses", "sites", "events", "banned"];
  // The columns each table can be sorted by, as the page's headers name them.
  const SORT_KEYS = {
    addresses: ["requests", "rate", "errors", "server_errors", "blocked", "bytes", "last"],
    sites: ["requests", "errors", "server_errors", "blocked", "addresses", "p50_ms", "p95_ms"]
  };
  // Under a flood the page falls behind the log rather than compete with
  // HAProxy for it; past this it says so.
  const BEHIND_SECONDS = 15;

  function defaults() {
    return {
      window: 60,
      refresh: 5,
      tab: "addresses",
      // The admin panel's own requests, hidden until asked for.
      admin: false,
      sort: {
        addresses: {key: "requests", dir: -1},
        sites: {key: "requests", dir: -1}
      }
    };
  }

  /* ---------- choices ---------- */

  // What the browser remembered, kept only where it is something the page
  // itself could have chosen; anything else, including a damaged entry, is
  // the default. A sort order that no longer names a column used to be
  // taken as it was, and the table then sorted by address alone.
  function restoreSettings(saved) {
    const result = defaults();
    if (!saved || typeof saved !== "object") return result;
    const window = Number(saved.window);
    if (Number.isFinite(window) && window >= WINDOW_MIN && window <= WINDOW_MAX) {
      result.window = Math.round(window);
    }
    if (REFRESH_CHOICES.includes(Number(saved.refresh))) result.refresh = Number(saved.refresh);
    if (TABS.includes(saved.tab)) result.tab = saved.tab;
    if (typeof saved.admin === "boolean") result.admin = saved.admin;
    const sort = saved.sort && typeof saved.sort === "object" ? saved.sort : {};
    Object.keys(SORT_KEYS).forEach((table) => {
      const entry = sort[table];
      if (
        entry && typeof entry === "object" &&
        SORT_KEYS[table].includes(entry.key) &&
        (entry.dir === 1 || entry.dir === -1)
      ) {
        result.sort[table] = {key: entry.key, dir: entry.dir};
      }
    });
    return result;
  }

  // A typed window, or null when it is not one the page accepts.
  function customWindow(value) {
    const seconds = Number(value);
    if (!Number.isFinite(seconds) || seconds < WINDOW_MIN || seconds > WINDOW_MAX) return null;
    return Math.round(seconds);
  }

  function isPresetWindow(seconds) {
    return WINDOW_PRESETS.includes(Number(seconds));
  }

  // The filters as the server takes them: only what is set, text trimmed.
  function requestParams(values) {
    const params = {window: values.window};
    const ip = String(values.ip || "").trim();
    if (ip) params.ip = ip;
    if (values.host) params.host = values.host;
    if (values.country) params.country = values.country;
    if (values.status) params.status = values.status;
    const query = String(values.q || "").trim();
    if (query) params.q = query;
    if (values.blocked) params.blocked = "1";
    if (values.banned) params.banned = "1";
    if (!values.admin) params.hide_admin = "1";
    return params;
  }

  // Which bar of the timeline a position falls on, as a share of its width.
  function timelineIndex(share, count) {
    if (!count) return -1;
    return Math.min(count - 1, Math.max(0, Math.floor(share * count)));
  }

  // The seconds one bar covers: the window ends now, and the last bar may be
  // cut short by it.
  function timelineSpan(index, data) {
    const now = Number(data.now) || 0;
    const window = Number(data.window) || 0;
    const bucket = Math.max(1, Number(data.bucket_seconds) || 1);
    const from = now - window + index * bucket;
    return {from: from, to: Math.min(now, from + bucket)};
  }

  // A select's choices: the values in the data, plus the current choice if
  // it has left it -- or the filter would silently drop the moment its last
  // request leaves the window.
  function selectValues(values, current) {
    const list = values.slice();
    if (current && !list.includes(current)) list.push(current);
    return list;
  }

  /* ---------- sorting ---------- */

  // Locally, on the last answer: sorting never asks the server again. Ties
  // go by address or site name, so equal rows do not trade places.
  function sortRows(rows, sort) {
    const {key, dir} = sort;
    return rows.slice().sort((a, b) => {
      const left = Number(a[key] || 0);
      const right = Number(b[key] || 0);
      return (left - right) * dir || String(a.ip || a.host).localeCompare(String(b.ip || b.host));
    });
  }

  // The same column again reverses it; another column starts biggest first.
  function sortAfterClick(current, key) {
    return current.key === key ? {key: key, dir: -current.dir} : {key: key, dir: -1};
  }

  /* ---------- rows ---------- */

  function statusTone(status) {
    const code = Number(status) || 0;
    if (code >= 500) return "la-s5";
    if (code >= 400) return "la-s4";
    if (code >= 300) return "la-s3";
    return "la-s2";
  }

  // Every request in the window was refused: the row is marked as such.
  function fullyRefused(row) {
    return Boolean(row.blocked) && row.blocked === row.requests;
  }

  // Which badges a row carries, in the order shown. Refusals belong to the
  // window, not to the present: an address refused by zero trust and signed
  // in a minute later shows both, and the two must not read as a
  // contradiction.
  function badgeKinds(row) {
    const kinds = [];
    if (row.ban) kinds.push("banned");
    if (row.connection_limited) kinds.push("limited");
    if (row.allow_listed) kinds.push("allow-listed");
    if (row.authorized) kinds.push("signed-in");
    if (row.reason && row.blocked) kinds.push("refused");
    return kinds;
  }

  // The one ban control that works for the address. A plain ban on an
  // allow-listed address does nothing, so an address listed by itself is
  // offered "drop & ban"; one covered only by a wider range gets no
  // one-click ban, because dropping the range would un-protect the rest.
  function banAction(banned, allowEntry) {
    if (banned) return "unban";
    if (allowEntry === "host") return "drop-and-ban";
    if (allowEntry === "range") return "in-allowed-range";
    return "ban";
  }

  // How an address is allow-listed: the server says so, and an older one
  // only says that it is.
  function allowEntryOf(row) {
    return row.allow_entry || (row.allow_listed ? "host" : null);
  }

  /* ---------- summary ---------- */

  function cardTone(value, warnAt) {
    if (value >= warnAt) return "bad";
    if (value > 0) return "warn";
    return "";
  }

  // What the note under the cards says: that the page is behind the log,
  // that the window is only partly in memory, or just what is shown.
  function summaryNote(data) {
    const behind = Number(data.lag_bytes || 0) > 0 && Number(data.lag_seconds || 0) > BEHIND_SECONDS;
    if (behind) return {kind: "behind", seconds: Number(data.lag_seconds)};
    if (data.truncated) return {kind: "partial", seconds: Number(data.covered_seconds) || 0};
    return {kind: "window", seconds: Number(data.window) || 0, bucket: Number(data.bucket_seconds) || 0};
  }

  // Refusal reasons, most frequent first.
  function refusalCounts(refusals) {
    return Object.entries(refusals || {}).sort((a, b) => b[1] - a[1]);
  }

  // The requests chart: one stacked bar per bucket -- answered, errors,
  // refused, bottom up -- scaled to the busiest bucket.
  function timelineRects(bars, width, height) {
    const peak = Math.max(1, ...bars.map((bar) => bar.ok + bar.errors + bar.blocked));
    const step = width / Math.max(1, bars.length);
    const rects = [];
    bars.forEach((bar, index) => {
      let y = height;
      ["ok", "errors", "blocked"].forEach((part) => {
        const h = (bar[part] / peak) * (height - 4);
        if (h <= 0) return;
        y -= h;
        rects.push({part: part, x: index * step + 1, y: y, width: Math.max(1, step - 2), height: h});
      });
    });
    return rects;
  }

  /* ---------- formats ---------- */

  // Rounded to the unit before the unit is chosen, so 59.5 minutes reads
  // "1 hr" rather than "60 min".
  function duration(seconds, label) {
    const say = label || identity;
    const value = Math.max(0, Math.round(Number(seconds) || 0));
    if (value < 60) return `${value} ${say("sec")}`;
    const minutes = Math.round(value / 60);
    if (minutes < 60) return `${minutes} ${say("min")}`;
    const hours = Math.round(value / 3600);
    if (hours < 24) return `${hours} ${say("hr")}`;
    return `${Math.round(value / 86400)} ${say("days")}`;
  }

  function bytes(value) {
    let size = Number(value || 0);
    const units = ["B", "KiB", "MiB", "GiB"];
    let index = 0;
    while (size >= 1024 && index < units.length - 1) {
      size /= 1024;
      index += 1;
    }
    return `${size.toFixed(index ? 1 : 0)} ${units[index]}`;
  }

  return {
    WINDOW_PRESETS,
    REFRESH_CHOICES,
    TABS,
    SORT_KEYS,
    BEHIND_SECONDS,
    defaults,
    restoreSettings,
    customWindow,
    isPresetWindow,
    requestParams,
    selectValues,
    sortRows,
    sortAfterClick,
    statusTone,
    fullyRefused,
    badgeKinds,
    banAction,
    allowEntryOf,
    cardTone,
    summaryNote,
    refusalCounts,
    timelineRects,
    timelineIndex,
    timelineSpan,
    duration,
    bytes
  };
});
