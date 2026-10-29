/* Request log: the decisions behind the page, without the page.
 *
 * What the address says about the search on screen, what a link from
 * elsewhere may set, and what the server is asked. Nothing here touches the
 * DOM, storage or the network, so the same file is loaded by the page and by
 * the tests in .tests/js/.
 */
(function (root, factory) {
  "use strict";
  const api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    root.EasyHaProxyRequestLog = api;
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  // The period choices, in seconds; 0 is everything kept.
  const RANGES = [3600, 21600, 86400, 259200, 0];
  const DEFAULT_RANGE = 86400;
  const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "PROPFIND"];
  // Filters typed as text, by the name the address and the server use.
  const TEXT_FILTERS = ["status", "client", "host", "backend", "path", "request_id", "agent"];
  const MAX_TEXT = 200;
  const MAX_SLOWER_MS = 86400000;

  function clean(value, max) {
    return String(value === null || value === undefined ? "" : value).trim().slice(0, max || MAX_TEXT);
  }

  function slowerOf(value) {
    const number = Number(value);
    return Number.isInteger(number) && number > 0 && number <= MAX_SLOWER_MS ? number : 0;
  }

  function chosenPeriod(view) {
    const since = Number(view.since);
    const until = Number(view.until);
    return Number.isInteger(since) && Number.isInteger(until) && since > 0 && until - since >= 60
      ? { since, until }
      : null;
  }

  // The view as the address writes it: only what differs from a fresh page,
  // so a plain visit keeps a plain address.
  function viewQuery(view) {
    const query = {};
    const period = chosenPeriod(view);
    if (period) {
      query.since = String(period.since);
      query.until = String(period.until);
    } else if (view.range !== undefined && RANGES.includes(Number(view.range)) &&
               Number(view.range) !== DEFAULT_RANGE) {
      query.range = String(Number(view.range));
    }
    TEXT_FILTERS.forEach((name) => {
      const value = clean(view[name]);
      if (value) query[name] = value;
    });
    const method = clean(view.method, 10).toUpperCase();
    if (/^[A-Z]{3,10}$/.test(method)) query.method = method;
    if (view.refused) query.refused = "1";
    const slower = slowerOf(view.slower);
    if (slower) query.slower = String(slower);
    if (view.admin) query.admin = "1";
    return query;
  }

  // The address read back, checked: a link may come from anywhere.
  function viewFromQuery(search) {
    const params = new URLSearchParams(search || "");
    const view = {};
    const period = chosenPeriod({ since: params.get("since"), until: params.get("until") });
    if (period) {
      view.since = period.since;
      view.until = period.until;
    }
    const range = params.get("range");
    if (range !== null && range !== "" && RANGES.includes(Number(range))) view.range = Number(range);
    TEXT_FILTERS.forEach((name) => {
      const value = clean(params.get(name));
      if (value) view[name] = value;
    });
    const method = clean(params.get("method"), 10).toUpperCase();
    if (/^[A-Z]{3,10}$/.test(method)) view.method = method;
    if (params.get("refused") === "1") view.refused = true;
    const slower = slowerOf(params.get("slower"));
    if (slower) view.slower = slower;
    if (params.get("admin") === "1") view.admin = true;
    return view;
  }

  // What the server is asked: the period as times from now, and the
  // panel's own requests left out unless asked for.
  function searchParams(view, now) {
    const params = {};
    const period = chosenPeriod(view);
    if (period) {
      params.since = String(period.since);
      params.until = String(period.until);
    } else {
      const range = view.range === undefined || !RANGES.includes(Number(view.range))
        ? DEFAULT_RANGE
        : Number(view.range);
      if (range > 0) params.since = String(Math.floor(Number(now)) - range);
    }
    TEXT_FILTERS.forEach((name) => {
      const value = clean(view[name]);
      if (value) params[name] = value;
    });
    const method = clean(view.method, 10).toUpperCase();
    if (/^[A-Z]{3,10}$/.test(method)) params.method = method;
    if (view.refused) params.refused = "1";
    const slower = slowerOf(view.slower);
    if (slower) params.slower = String(slower);
    if (!view.admin) params.hide_admin = "1";
    return params;
  }

  // Two views ask for the same thing: the address need not change.
  function sameQuery(left, right) {
    const a = viewQuery(left);
    const b = viewQuery(right);
    const keys = Object.keys(a);
    return keys.length === Object.keys(b).length && keys.every((key) => a[key] === b[key]);
  }

  /* ---------- the overview ---------- */

  // The parts of a bar, bottom up, as the summary counts them.
  const KINDS = ["ok", "client_errors", "server_errors", "refused"];

  // Stacked bars for the summary's histogram, the tallest bar at the top.
  function histogramRects(buckets, width, height) {
    const bars = Array.isArray(buckets) ? buckets : [];
    const peak = Math.max(1, ...bars.map((bar) => bar.reduce((sum, value) => sum + (Number(value) || 0), 0)));
    const step = width / Math.max(1, bars.length);
    const rects = [];
    bars.forEach((bar, index) => {
      let y = height;
      KINDS.forEach((kind, part) => {
        const h = ((Number(bar[part]) || 0) / peak) * (height - 4);
        if (h <= 0) return;
        y -= h;
        rects.push({kind, index, x: index * step + 1, y, width: Math.max(1, step - 2), height: h});
      });
    });
    return rects;
  }

  // The bar under a point of the histogram, -1 off it.
  function barAt(fraction, count) {
    if (!(count > 0) || !(fraction >= 0) || fraction > 1) return -1;
    return Math.min(count - 1, Math.floor(fraction * count));
  }

  // The period of bars from one to another, in either order; never past now.
  function barsSpan(from, to, summary, now) {
    const first = Math.min(from, to);
    const last = Math.max(from, to);
    const start = Number(summary.start) + first * Number(summary.bucket_seconds);
    let end = Number(summary.start) + (last + 1) * Number(summary.bucket_seconds);
    if (now !== undefined && end > now) end = Math.floor(now);
    return {since: start, until: Math.max(end, start + 60)};
  }

  // How far back the record reaches, and whether the size cap rather than
  // the retention decides it: then the oldest request is younger than the
  // days kept, and the store is at its cap.
  function historyReach(status, now) {
    const oldest = Number(status && status.oldest_ts) || 0;
    if (!oldest) return null;
    const days = Number(status.retention_days) || 0;
    const full = Number(status.database_bytes) >= 0.9 * (Number(status.max_bytes) || Infinity);
    const short = days > 0 && oldest > Number(now) - days * 86400 + 3600;
    return {oldest, cappedBySize: full && short};
  }

  return {
    RANGES,
    DEFAULT_RANGE,
    METHODS,
    TEXT_FILTERS,
    KINDS,
    viewQuery,
    viewFromQuery,
    searchParams,
    sameQuery,
    histogramRects,
    barAt,
    barsSpan,
    historyReach
  };
});
