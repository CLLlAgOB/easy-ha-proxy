/* Historical monitoring: the arithmetic behind the page, without the page.
 *
 * Which lines a chart has and which are shown, where its scale tops out,
 * what each legend reading stands for, how an availability bar is cut into
 * pieces, and how a drag across a chart becomes a period. Nothing here
 * touches the DOM, storage or the network, so the same file is loaded by
 * the page and by the tests in .tests/js/. Numbers are formatted by a
 * function passed in, so the page keeps its locale and the tests their own.
 */
(function (root, factory) {
  "use strict";
  const api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    root.EasyHaProxyMonitoring = api;
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const plainNumber = (value) => String(Math.round(value * 100) / 100);

  // One line per part of the gateway, coloured by its place in the sorted
  // list of names rather than by its rank: the rank changes with every
  // refresh, and a line that changed colour each time would be unreadable.
  const COMPONENT_COLORS = [
    "#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd", "#8c564b",
    "#e377c2", "#7f7f7f", "#bcbd22", "#17becf", "#aec7e8", "#ffbb78",
    "#98df8a", "#ff9896", "#c5b0d5", "#c49c94", "#f7b6d2", "#dbdb8d",
    "#9edae5", "#393b79"
  ];

  const RANGE_SECONDS = {
    "1h": 3600,
    "6h": 21600,
    "24h": 86400,
    "7d": 604800,
    "30d": 2592000,
    "90d": 7776000,
    "1y": 31536000
  };

  // An outage narrower than this share of the period is drawn wider than it
  // was (see the min-width in the page's CSS), and outages closer together
  // than the gap leave no room for the up time between them.
  const FLAP_SHORT_SHARE = 0.006;
  const FLAP_GAP_SHARE = 0.02;
  const FLAP_STRIPE_PX = 10;

  // A drag narrower than this still shows five minutes, centred on it.
  const MIN_ZOOM_SECONDS = 300;

  function rangeSeconds(key) {
    return RANGE_SECONDS[key] || 86400;
  }

  /* ---------- lines ---------- */

  // The chart's own lines, and on the processor and memory charts one more
  // per part of the gateway the collector reported.
  function seriesFor(chart, payload) {
    if (!chart.components) return chart.series;
    const parts = (payload && payload.components) || [];
    const ids = parts.map((part) => `${part.group}:${part.name}`).sort();
    return chart.series.concat(
      parts.map((part) => {
        const id = `${part.group}:${part.name}`;
        return {
          key: `component:${id}`,
          label: part.label || part.name,
          group: part.group,
          component: true,
          color: COMPONENT_COLORS[ids.indexOf(id) % COMPONENT_COLORS.length],
          percent: chart.name === "cpu",
          bytes: chart.name === "memory",
          summary: "mean",
          hidden: true,
          values: part.values || [],
          peak: part.peak
        };
      })
    );
  }

  // Only choices the operator made are kept; everything else follows the
  // line's own default, so a line added later starts the way it was meant to.
  function lineVisible(choices, chartName, spec) {
    const chosen = choices && choices[chartName];
    if (chosen && Object.prototype.hasOwnProperty.call(chosen, spec.key)) {
      return Boolean(chosen[spec.key]);
    }
    return !spec.hidden;
  }

  function lineChoicesAfter(choices, chartName, spec, visible) {
    const next = Object.assign({}, choices);
    const chosen = Object.assign({}, next[chartName]);
    if (visible === !spec.hidden) delete chosen[spec.key];
    else chosen[spec.key] = visible;
    next[chartName] = chosen;
    return next;
  }

  /* ---------- scale ---------- */

  function niceCeiling(value, binary) {
    if (!(value > 0)) return 1;
    if (binary && value >= 1024) {
      // Bytes round in their own units: 2 GiB at the top, not 4.66. Past
      // 1024 of a unit the next one says it: 1010 MiB tops out at 1 GiB,
      // not at 2000 MiB, which the axis would print as 1.95 GiB.
      let unit = 1;
      while (value / unit >= 1024) unit *= 1024;
      const top = niceCeiling(value / unit, false);
      if (top > 1024) return niceCeiling(value / (unit * 1024), false) * unit * 1024;
      return top * unit;
    }
    const magnitude = Math.pow(10, Math.floor(Math.log10(value)));
    const normalized = value / magnitude;
    let step;
    if (normalized <= 1) step = 1;
    else if (normalized <= 2) step = 2;
    else if (normalized <= 5) step = 5;
    else step = 10;
    return step * magnitude;
  }

  // What a chart draws: its shown lines, counters turned into rates, and the
  // top of the scale. Counters are stored per bucket; a rate is the only
  // comparable value once the server changes resolution between ranges.
  // Hidden lines are left out of the scale too, so hiding the big ones lets
  // the small ones fill it.
  // A missing value is a gap, not a zero: Number(null) is 0, which drew a
  // slot with no requests as an instant response.
  function reading(value) {
    if (value === null || value === undefined || value === "") return null;
    const number = Number(value);
    return Number.isFinite(number) ? number : null;
  }

  // The runs of values a line can be drawn through, as [first, last] index
  // pairs; a gap ends one run and the next value starts another.
  function segments(values) {
    const runs = [];
    let start = null;
    values.forEach((value, index) => {
      if (value === null) {
        if (start !== null) runs.push([start, index - 1]);
        start = null;
      } else if (start === null) {
        start = index;
      }
    });
    if (start !== null) runs.push([start, values.length - 1]);
    return runs;
  }

  function chartData(chart, payload, isVisible) {
    const step = Number(payload && payload.resolution_seconds) || 60;
    const shown = isVisible || ((spec) => !spec.hidden);
    const datasets = seriesFor(chart, payload)
      .filter((spec) => shown(spec))
      .map((spec) => {
        const raw = spec.values || (payload && payload.series && payload.series[spec.key]) || [];
        const values = raw.map((value) => {
          const number = reading(value);
          return number !== null && spec.rate ? number / step : number;
        });
        return {spec: spec, values: values};
      });
    let maximum = 0;
    datasets.forEach((dataset) => {
      dataset.values.forEach((value) => {
        if (Number.isFinite(value) && value > maximum) maximum = value;
      });
    });
    return {
      step: step,
      datasets: datasets,
      top: niceCeiling(maximum, Boolean(chart.series[0].bytes))
    };
  }

  /* ---------- refresh ---------- */

  // A refresh's few new minutes joined to the window already drawn. Slots
  // from `from` on come from the fresh answer -- the last one was still
  // filling when it was first read -- and slots older than `keepFrom` fall
  // off the left edge. A line one answer lacks reads as a gap there.
  function mergeSeries(previous, fresh, from, keepFrom) {
    const before = (previous && previous.series) || {};
    const after = (fresh && fresh.series) || {};
    const keys = Array.from(new Set(Object.keys(before).concat(Object.keys(after))));
    const points = [];
    const series = {};
    keys.forEach((key) => {
      series[key] = [];
    });
    const take = (source, index) => {
      keys.forEach((key) => {
        const value = (source[key] || [])[index];
        series[key].push(value === undefined ? null : value);
      });
    };
    ((previous && previous.points) || []).forEach((slot, index) => {
      if (slot >= keepFrom && slot < from) {
        points.push(slot);
        take(before, index);
      }
    });
    ((fresh && fresh.points) || []).forEach((slot, index) => {
      if (slot >= keepFrom) {
        points.push(slot);
        take(after, index);
      }
    });
    const merged = Object.assign({}, previous, {
      points: points,
      series: series,
      until: fresh && fresh.until !== undefined ? fresh.until : previous && previous.until
    });
    // The lines per component are never joined: a chart showing them is
    // fetched whole (see monitoring.js).
    delete merged.components;
    return merged;
  }

  // Which samples get a time under them: no more labels than fit, at most
  // five, first and last always -- full screen on a phone is narrow.
  function timeLabelIndexes(pointCount, plotWidth) {
    if (pointCount < 1) return [];
    const count = Math.min(5, pointCount, Math.max(2, Math.floor(plotWidth / 90)));
    const indexes = [];
    for (let index = 0; index < count; index += 1) {
      indexes.push(count === 1 ? 0 : Math.round((index / (count - 1)) * (pointCount - 1)));
    }
    return indexes;
  }

  /* ---------- legend ---------- */

  // What the number beside each line stands for. A "Peak" line is the
  // highest value in each bucket, so its reading is the highest over the
  // period shown -- with when it was -- and an "Average" line's is the mean
  // over the period. Showing the last bucket for both, as the legend used
  // to, put "Peak: 7" under a chart that climbs to 44.
  function legendReading(spec, raw) {
    let value = 0;
    let index = null;
    if (spec.summary === "max") {
      raw.forEach((item, position) => {
        const number = reading(item);
        if (number !== null && (index === null || number > value)) {
          value = number;
          index = position;
        }
      });
    } else if (spec.summary === "mean") {
      const numbers = raw.map(reading).filter((number) => number !== null);
      value = numbers.length ? numbers.reduce((sum, item) => sum + item, 0) / numbers.length : 0;
    } else {
      for (let position = raw.length - 1; position >= 0; position -= 1) {
        const number = reading(raw[position]);
        if (number !== null) {
          value = number;
          break;
        }
      }
    }
    return {value: value, index: index};
  }

  function formatBytes(value, formatNumber) {
    const numeric = Number(value);
    if (!Number.isFinite(numeric)) return "—";
    const format = formatNumber || plainNumber;
    const units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let size = Math.abs(numeric);
    let index = 0;
    while (size >= 1024 && index < units.length - 1) {
      size /= 1024;
      index += 1;
    }
    const sign = numeric < 0 ? "-" : "";
    return `${sign}${format(size)} ${units[index]}`;
  }

  /* ---------- availability ---------- */

  // Deliberately not translated: single-letter unit keys are exactly the kind
  // of fragment the DOM translator would match inside unrelated words, and
  // "2h 15m" reads the same in every language this UI ships.
  function formatDuration(seconds) {
    const total = Math.max(0, Math.round(Number(seconds) || 0));
    if (total === 0) return "0s";
    const days = Math.floor(total / 86400);
    const hours = Math.floor((total % 86400) / 3600);
    const minutes = Math.floor((total % 3600) / 60);
    const rest = total % 60;
    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${minutes}m`;
    if (minutes > 0) return `${minutes}m ${rest}s`;
    return `${rest}s`;
  }

  // Short outages each keep a few pixels so that one of them is not lost in
  // a day. Sixty-nine of them in a row, 24 minutes in all, then painted
  // nine hours of the bar red: a server 98% available looked 40% down. A
  // run of such outages becomes one piece, drawn to scale and striped in
  // proportion to the time it was really down.
  function timelinePieces(spans, window) {
    const isShort = (span) =>
      span.state !== "UP" && (Number(span.end) - Number(span.start)) / window < FLAP_SHORT_SHARE;
    const isGap = (span) =>
      span.state === "UP" && (Number(span.end) - Number(span.start)) / window < FLAP_GAP_SHARE;
    const pieces = [];
    let index = 0;
    while (index < spans.length) {
      const span = spans[index];
      if (!isShort(span)) {
        pieces.push({span});
        index += 1;
        continue;
      }
      let last = index;
      while (true) {
        let next = last + 1;
        if (next < spans.length && isGap(spans[next])) next += 1;
        if (next >= spans.length || !isShort(spans[next])) break;
        last = next;
      }
      const run = spans.slice(index, last + 1);
      const outages = run.filter((item) => item.state !== "UP");
      if (outages.length < 2) {
        pieces.push({span});
        index += 1;
        continue;
      }
      pieces.push({
        flapping: true,
        start: Number(run[0].start),
        end: Number(run[run.length - 1].end),
        outages: outages.length,
        down: outages.reduce((sum, item) => sum + Number(item.end) - Number(item.start), 0)
      });
      index = last + 1;
    }
    return pieces;
  }

  // How many pixels of each stripe on an unstable stretch are red: in
  // proportion to the time really down, never none and never all.
  function flapStripe(piece) {
    const length = Number(piece.end) - Number(piece.start);
    const stripe = length > 0 ? Math.round((piece.down / length) * FLAP_STRIPE_PX) : FLAP_STRIPE_PX;
    return Math.min(FLAP_STRIPE_PX - 1, Math.max(1, stripe));
  }

  // The unavailable total is a sum over the chosen window, so the same
  // outage reads differently in an hour and in a day. What the sum is made
  // of: how many outages, and how long the last one has lasted if it is
  // still going on (null when it is not).
  function outageFacts(entry, until) {
    const outages = (entry.spans || []).filter((span) => span.state !== "UP");
    const last = outages[outages.length - 1];
    const ongoing = Boolean(last) && entry.current_state !== "UP" && Number(last.end) >= until;
    return {
      count: outages.length,
      ongoingSeconds: ongoing ? Number(last.end) - Number(last.start) : null
    };
  }

  /* ---------- backends ---------- */

  // Busiest first by default; ties, and the "name" order, go by name.
  function sortedBackends(backends, order) {
    const items = backends.slice();
    if (order === "name") {
      items.sort((a, b) => String(a.label).localeCompare(String(b.label)));
    } else {
      const direction = order === "asc" ? 1 : -1;
      items.sort(
        (a, b) =>
          direction * (Number(a.bytes_total) - Number(b.bytes_total)) ||
          String(a.label).localeCompare(String(b.label))
      );
    }
    return items;
  }

  /* ---------- drag to zoom ---------- */

  // The x axis is spaced by sample, not by clock, so a position maps to a
  // time through the samples either side of it -- which is also what the
  // operator saw under the pointer.
  function timeAtX(geometry, x) {
    const points = geometry.points;
    if (points.length === 1) return Number(points[0]);
    const fraction = Math.min(Math.max((x - geometry.left) / geometry.plotWidth, 0), 1);
    const position = fraction * (points.length - 1);
    const lower = Math.floor(position);
    const upper = Math.min(lower + 1, points.length - 1);
    return Number(points[lower]) +
      (Number(points[upper]) - Number(points[lower])) * (position - lower);
  }

  /* ---------- the view in the address ---------- */

  // What the page shows, as query parameters: a link to it opens the same
  // view. Only what differs from the defaults is written.
  function viewQuery(view) {
    const query = {};
    if (view.window) {
      query.since = String(view.window.since);
      query.until = String(view.window.until);
    } else if (view.range && view.range !== view.defaultRange) {
      query.range = view.range;
    }
    if (view.site) query.site = view.site;
    return query;
  }

  // The view a link asks for, checked: an unknown range, a malformed or
  // backwards period and an empty site are dropped, never trusted.
  function viewFromQuery(search, ranges) {
    const params = new URLSearchParams(search || "");
    const view = {};
    const range = params.get("range");
    if (range && ranges.includes(range)) view.range = range;
    const since = Number(params.get("since"));
    const until = Number(params.get("until"));
    if (Number.isInteger(since) && Number.isInteger(until) && since > 0 && until - since >= 60) {
      view.window = {since: since, until: until};
    }
    const site = (params.get("site") || "").trim();
    if (site && site.length <= 200) view.site = site;
    return view;
  }

  // The sample under a pointer: the nearest one, the axis being spaced by
  // sample (see timeAtX).
  function indexAtX(geometry, x) {
    const count = geometry.points.length;
    if (count <= 1) return 0;
    const fraction = Math.min(Math.max((x - geometry.left) / geometry.plotWidth, 0), 1);
    return Math.round(fraction * (count - 1));
  }

  function xAtIndex(geometry, index) {
    const count = geometry.points.length;
    if (count <= 1) return geometry.left + geometry.plotWidth / 2;
    return geometry.left + (index / (count - 1)) * geometry.plotWidth;
  }

  /* ---------- events on the charts ---------- */

  // The sample a moment falls in: the last one at or before it. -1 outside
  // the drawn samples, so an event of another period is not pinned to an edge.
  function indexAtTime(points, step, ts) {
    const count = (points || []).length;
    const moment = Number(ts);
    if (!count || !Number.isFinite(moment)) return -1;
    const last = Number(points[count - 1]) + Math.max(1, Number(step) || 0);
    if (moment < Number(points[0]) || moment >= last) return -1;
    let low = 0;
    let high = count - 1;
    while (low < high) {
      const middle = Math.ceil((low + high) / 2);
      if (Number(points[middle]) <= moment) low = middle;
      else high = middle - 1;
    }
    return low;
  }

  // Events by the sample they fall in: ten changes in one minute are one
  // mark, not a smudge. A mark takes the colour of its gravest event.
  const EVENT_KINDS = ["change", "recovered", "alert"];

  function eventMarks(points, step, events) {
    const marks = new Map();
    (events || []).forEach((event) => {
      const kind = EVENT_KINDS.includes(event.kind) ? event.kind : "change";
      const index = indexAtTime(points, step, event.ts);
      if (index < 0) return;
      let mark = marks.get(index);
      if (!mark) {
        mark = {index: index, kind: kind, events: []};
        marks.set(index, mark);
      }
      mark.events.push(event);
      if (EVENT_KINDS.indexOf(kind) > EVENT_KINDS.indexOf(mark.kind)) mark.kind = kind;
    });
    return Array.from(marks.values()).sort((a, b) => a.index - b.index);
  }

  // How many samples a few pixels span: on a chart of a thousand samples
  // the pointer seldom lands on a mark's own pixel, on one of ten it should
  // not reach the neighbours.
  function eventReach(geometry, pixels) {
    const count = geometry.points.length;
    if (count <= 1) return 0;
    const perSample = geometry.plotWidth / (count - 1);
    return Math.floor(pixels / Math.max(perSample, 0.001));
  }

  // The events within reach of a sample, oldest first.
  function eventsNear(marks, index, reach) {
    const found = [];
    (marks || []).forEach((mark) => {
      if (Math.abs(mark.index - index) <= reach) found.push(...mark.events);
    });
    return found.sort((a, b) => Number(a.ts) - Number(b.ts));
  }

  /* ---------- requests per backend ---------- */

  // The orders the list is read in: the busiest, the failing, the slow.
  // Errors by count, not share -- two failed requests out of two is 100%
  // and still not the backend to look at first.
  const REQUEST_SORTS = ["requests", "errors5xx", "errors4xx", "slowest", "name"];

  function sortedBackendRequests(items, order) {
    const list = (items || []).slice();
    const byLabel = (a, b) => String(a.label).localeCompare(String(b.label));
    const timed = (value) => (value === null || value === undefined ? -1 : Number(value));
    const keys = {
      requests: (item) => [Number(item.requests) || 0],
      errors5xx: (item) => [Number(item.resp_5xx) || 0, Number(item.share_5xx) || 0],
      errors4xx: (item) => [Number(item.resp_4xx) || 0, Number(item.share_4xx) || 0],
      slowest: (item) => [timed(item.response_ms_avg)]
    };
    const key = keys[order];
    if (!key) return list.sort(byLabel);
    return list.sort((a, b) => {
      const left = key(a);
      const right = key(b);
      for (let index = 0; index < left.length; index += 1) {
        if (right[index] !== left[index]) return right[index] - left[index];
      }
      return byLabel(a, b);
    });
  }

  function zoomWindow(since, until) {
    if (until - since < MIN_ZOOM_SECONDS) {
      const middle = (since + until) / 2;
      since = middle - MIN_ZOOM_SECONDS / 2;
      until = middle + MIN_ZOOM_SECONDS / 2;
    }
    return {since: Math.floor(since), until: Math.ceil(until)};
  }

  return {
    COMPONENT_COLORS,
    FLAP_SHORT_SHARE,
    FLAP_GAP_SHARE,
    FLAP_STRIPE_PX,
    MIN_ZOOM_SECONDS,
    rangeSeconds,
    seriesFor,
    lineVisible,
    lineChoicesAfter,
    niceCeiling,
    reading,
    segments,
    mergeSeries,
    chartData,
    timeLabelIndexes,
    legendReading,
    formatBytes,
    formatDuration,
    timelinePieces,
    flapStripe,
    outageFacts,
    sortedBackends,
    timeAtX,
    viewQuery,
    viewFromQuery,
    indexAtX,
    xAtIndex,
    indexAtTime,
    eventMarks,
    eventReach,
    eventsNear,
    REQUEST_SORTS,
    sortedBackendRequests,
    zoomWindow
  };
});
