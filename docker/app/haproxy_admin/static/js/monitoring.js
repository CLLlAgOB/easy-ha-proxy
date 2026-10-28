/* Historical monitoring: overview cards, time-series charts, storage status.
 *
 * Charts are drawn as plain SVG on purpose. The page runs under a strict CSP
 * with script-src 'self', so a charting library would have to be vendored into
 * the image; a few hundred lines of line-plot code is cheaper to ship, audit
 * and keep working than a bundled dependency.
 *
 * The arithmetic -- scales, legend readings, availability pieces, zoom --
 * lives in monitoring_core.js, where the tests in .tests/js/ reach it.
 */
(function () {
  "use strict";

  const core = window.EasyHaProxyMonitoring;
  const t = window.t || ((value) => String(value));
  const numberFormat = new Intl.NumberFormat(document.documentElement.lang || undefined);
  const decimalFormat = new Intl.NumberFormat(document.documentElement.lang || undefined, {
    minimumFractionDigits: 0,
    maximumFractionDigits: 2
  });
  const timeFormat = new Intl.DateTimeFormat(document.documentElement.lang || undefined, {
    hour: "2-digit",
    minute: "2-digit"
  });
  const dateTimeFormat = new Intl.DateTimeFormat(document.documentElement.lang || undefined, {
    dateStyle: "short",
    timeStyle: "short"
  });
  const dateFormat = new Intl.DateTimeFormat(document.documentElement.lang || undefined, {
    month: "short",
    day: "numeric"
  });

  const SVG_NS = "http://www.w3.org/2000/svg";
  const REFRESH_INTERVAL_MS = 30000;

  const CHARTS = [
    {
      name: "requests",
      series: [{ key: "requests", label: "Requests", color: "#4a86c8", rate: true }]
    },
    {
      name: "traffic",
      series: [
        { key: "bytes_in", label: "Inbound", color: "#4a86c8", rate: true, bytes: true },
        { key: "bytes_out", label: "Outbound", color: "#2e9e5b", rate: true, bytes: true }
      ]
    },
    {
      name: "responses",
      series: [
        { key: "resp_2xx", label: "2xx", color: "#2e9e5b", rate: true },
        { key: "resp_3xx", label: "3xx", color: "#4a86c8", rate: true },
        { key: "resp_4xx", label: "4xx", color: "#c8a13a", rate: true },
        { key: "resp_5xx", label: "5xx", color: "#cc4b4b", rate: true }
      ]
    },
    {
      name: "latency",
      series: [
        { key: "response_ms_avg", label: "Average", color: "#4a86c8", summary: "mean" },
        { key: "response_ms_max", label: "Peak", color: "#c8a13a", summary: "max" }
      ]
    },
    {
      name: "connections",
      series: [
        { key: "conn_cur_avg", label: "Average", color: "#4a86c8", summary: "mean" },
        { key: "conn_cur_max", label: "Peak", color: "#c8a13a", summary: "max" }
      ]
    },
    {
      // Never a rate: these arrive as percentages and dividing them by the
      // bucket step would turn 40% into 0.7 of nothing.
      name: "cpu",
      components: true,
      series: [
        { key: "cpu_avg", label: "Average", color: "#4a86c8", percent: true, summary: "mean" },
        { key: "cpu_max", label: "Peak", color: "#c8a13a", percent: true, summary: "max" },
        { key: "haproxy_busy_avg", label: "HAProxy busy", color: "#8a63d2", percent: true, summary: "mean" },
        { key: "helpers", label: "Helper services", color: "#2e9e5b", percent: true, summary: "mean" },
        { key: "containers", label: "Containers", color: "#d0743c", percent: true, summary: "mean" },
        { key: "other", label: "Other processes", color: "#9e9e9e", percent: true, summary: "mean", hidden: true }
      ]
    },
    {
      // Used is what `free` calls used: everything the kernel could not hand
      // back at once. Total is drawn so the scale reads against the machine.
      name: "memory",
      components: true,
      series: [
        { key: "memory_avg", label: "Used", color: "#4a86c8", bytes: true, summary: "mean" },
        { key: "memory_max", label: "Peak", color: "#c8a13a", bytes: true, summary: "max" },
        { key: "memory_total", label: "Total", color: "#6b6b6b", bytes: true, summary: "last", dash: true },
        { key: "helpers", label: "Helper services", color: "#2e9e5b", bytes: true, summary: "mean" },
        { key: "containers", label: "Containers", color: "#d0743c", bytes: true, summary: "mean" },
        { key: "other", label: "Other processes", color: "#9e9e9e", bytes: true, summary: "mean", hidden: true }
      ]
    }
  ];

  // Which lines are shown, per chart. Only choices the operator made are
  // stored; everything else follows the line's own default.
  const VISIBILITY_KEY = "monitoring.lines";
  let lineChoices = {};
  try {
    const stored = JSON.parse(window.localStorage.getItem(VISIBILITY_KEY) || "{}");
    if (stored && typeof stored === "object") lineChoices = stored;
  } catch (error) {
    lineChoices = {};
  }

  function lineVisible(chart, spec) {
    return core.lineVisible(lineChoices, chart.name, spec);
  }

  function setLineVisible(chart, spec, visible) {
    lineChoices = core.lineChoicesAfter(lineChoices, chart.name, spec, visible);
    try {
      window.localStorage.setItem(VISIBILITY_KEY, JSON.stringify(lineChoices));
    } catch (error) {
      // Private mode: the choice lasts for this page only.
    }
  }

  let currentRange = "24h";
  let currentSite = "";
  let refreshTimer = null;
  let inFlight = false;

  function byId(id) {
    return document.getElementById(id);
  }

  function setText(id, value) {
    const element = byId(id);
    if (element) element.textContent = value == null || value === "" ? "—" : String(value);
  }

  function formatBytes(value) {
    return core.formatBytes(value, (size) => decimalFormat.format(size));
  }

  function formatCount(value) {
    const numeric = Number(value);
    return Number.isFinite(numeric) ? numberFormat.format(numeric) : "—";
  }

  function formatRate(value) {
    const numeric = Number(value);
    if (!Number.isFinite(numeric)) return "—";
    return decimalFormat.format(numeric);
  }

  function uiText(value) {
    return t(value);
  }

  /* ---------- chart drawing ---------- */

  function axisLabel(spec, value) {
    if (spec.percent) return `${decimalFormat.format(value)}%`;
    if (spec.bytes) return formatBytes(value);
    if (value >= 1000) return formatCount(Math.round(value));
    return decimalFormat.format(value);
  }

  function timeLabel(seconds, rangeSeconds) {
    const date = new Date(seconds * 1000);
    return rangeSeconds > 3 * 86400 ? dateFormat.format(date) : timeFormat.format(date);
  }

  function element(name, attributes) {
    const node = document.createElementNS(SVG_NS, name);
    Object.keys(attributes || {}).forEach((key) => {
      node.setAttribute(key, String(attributes[key]));
    });
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function drawEmpty(svg, message) {
    svg.__geometry = null;
    clear(svg);
    svg.setAttribute("viewBox", "0 0 600 190");
    const text = element("text", {
      x: 300,
      y: 95,
      "text-anchor": "middle",
      class: "mon-tick"
    });
    text.textContent = message;
    svg.appendChild(text);
  }

  function drawChart(svg, chart, payload, rangeSeconds) {
    const points = (payload && payload.points) || [];
    if (!points.length) {
      drawEmpty(svg, uiText("No data for this period"));
      return;
    }

    // Full screen draws at the size it is shown, so text stays text-sized;
    // the cards keep the fixed frame the page was laid out around.
    let width = 600;
    let height = 190;
    if (svg.closest(".mon-chart-expanded")) {
      const box = svg.getBoundingClientRect();
      width = Math.max(320, Math.round(box.width));
      height = Math.max(200, Math.round(box.height));
    }
    const padding = { top: 10, right: 8, bottom: 22, left: chart.series[0].bytes ? 70 : 54 };
    const plotWidth = width - padding.left - padding.right;
    const plotHeight = height - padding.top - padding.bottom;

    // Only the lines shown: hidden ones leave the scale as well.
    const view = core.chartData(chart, payload, (spec) => lineVisible(chart, spec));
    const step = view.step;
    const datasets = view.datasets;
    const top = view.top;

    clear(svg);
    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);

    const xFor = (index) =>
      padding.left + (points.length === 1 ? plotWidth / 2 : (index / (points.length - 1)) * plotWidth);
    const yFor = (value) => padding.top + plotHeight - (Math.max(0, value) / top) * plotHeight;
    // What a drag across the chart needs to turn a stretch of it into times.
    svg.__geometry = {
      points: points,
      step: step,
      width: width,
      left: padding.left,
      top: padding.top,
      plotWidth: plotWidth,
      plotHeight: plotHeight
    };

    for (let tick = 0; tick <= 2; tick += 1) {
      const value = (top / 2) * tick;
      const y = yFor(value);
      svg.appendChild(
        element("line", {
          class: "mon-gridline",
          x1: padding.left,
          x2: width - padding.right,
          y1: y,
          y2: y
        })
      );
      const label = element("text", {
        class: "mon-tick",
        x: padding.left - 6,
        y: y + 3,
        "text-anchor": "end"
      });
      label.textContent = axisLabel(chart.series[0], value);
      svg.appendChild(label);
    }

    svg.appendChild(
      element("line", {
        class: "mon-axis",
        x1: padding.left,
        x2: width - padding.right,
        y1: padding.top + plotHeight,
        y2: padding.top + plotHeight
      })
    );

    // No more time labels than fit: full screen on a phone is narrow.
    const labelled = core.timeLabelIndexes(points.length, plotWidth);
    labelled.forEach((pointIndex, index) => {
      const label = element("text", {
        class: "mon-tick",
        x: xFor(pointIndex),
        y: height - 6,
        "text-anchor": index === 0 ? "start" : index === labelled.length - 1 ? "end" : "middle"
      });
      label.textContent = timeLabel(points[pointIndex], rangeSeconds);
      svg.appendChild(label);
    });

    datasets.forEach((dataset) => {
      // A gap (no value, e.g. no requests to time) breaks the line and its
      // area rather than dropping them to zero.
      const runs = core.segments(dataset.values);
      const pieces = runs.map(([first, last]) => {
        const points = [];
        for (let index = first; index <= last; index += 1) {
          points.push(`${index === first ? "M" : "L"}${xFor(index).toFixed(1)},${yFor(dataset.values[index]).toFixed(1)}`);
        }
        return { first: first, last: last, d: points.join(" ") };
      });
      const path = pieces.map((piece) => piece.d).join(" ");
      if (!path) return;
      if (datasets.length <= 2 && !dataset.spec.dash) {
        const floor = (padding.top + plotHeight).toFixed(1);
        const area = pieces
          .map((piece) => `${piece.d} L${xFor(piece.last).toFixed(1)},${floor} L${xFor(piece.first).toFixed(1)},${floor} Z`)
          .join(" ");
        svg.appendChild(element("path", { class: "mon-area", d: area, fill: dataset.spec.color }));
      }
      const line = { class: "mon-line", d: path, stroke: dataset.spec.color };
      if (dataset.spec.dash) line["stroke-dasharray"] = "6 4";
      svg.appendChild(element("path", line));
    });
  }

  // What the number beside each line stands for (see legendReading in
  // monitoring_core.js): the highest over the period for a "Peak" line, the
  // mean for an "Average" one, the latest value for the rest.
  const LEGEND_HINTS = {
    max: "Highest over the shown period",
    mean: "Average over the shown period",
    last: "Latest value"
  };

  function legendValue(spec, value) {
    if (spec.percent) return `${decimalFormat.format(value)}%`;
    if (spec.bytes) return spec.rate ? `${formatBytes(value)}/s` : formatBytes(value);
    return formatRate(value);
  }

  // Whether the per-component list is unfolded, per chart. Folded by
  // default: on a card it is a long list, in full screen it always opens.
  const COMPONENTS_OPEN_KEY = "monitoring.components.open";
  let componentsOpen = {};
  try {
    const stored = JSON.parse(window.localStorage.getItem(COMPONENTS_OPEN_KEY) || "{}");
    if (stored && typeof stored === "object") componentsOpen = stored;
  } catch (error) {
    componentsOpen = {};
  }

  function renderLegend(chart, payload) {
    const legend = byId(`mon-legend-${chart.name}`);
    if (!legend) return;
    legend.textContent = "";
    const step = Number(payload && payload.resolution_seconds) || 60;
    const points = (payload && payload.points) || [];
    const spanSeconds = points.length > 1
      ? Number(points[points.length - 1]) - Number(points[0])
      : 0;
    const expanded = Boolean(legend.closest(".mon-chart-expanded"));
    let parts = null;
    core.seriesFor(chart, payload).forEach((spec) => {
      const raw = spec.values || (payload && payload.series && payload.series[spec.key]) || [];
      const reading = core.legendReading(spec, raw);
      const value = spec.rate ? reading.value / step : reading.value;
      const visible = lineVisible(chart, spec);
      // A button, so a line can be hidden to let the others fill the scale.
      const item = document.createElement("button");
      item.type = "button";
      item.className = "mon-line-toggle";
      item.setAttribute("aria-pressed", visible ? "true" : "false");
      let hint = uiText(LEGEND_HINTS[spec.summary || "last"]);
      if (spec.component) {
        hint += ` · ${uiText("Peak")}: ${legendValue(spec, Number(spec.peak) || 0)}`;
      }
      item.title = `${hint}. ${uiText("Click to show or hide the line")}`;
      const swatch = document.createElement("i");
      swatch.style.background = spec.color;
      item.appendChild(swatch);
      const label = document.createElement("span");
      if (spec.component) {
        // A unit or container name: machine data, never translated.
        label.setAttribute("data-i18n-skip", "");
        label.setAttribute("translate", "no");
        label.textContent = `${spec.label}: `;
      } else {
        label.textContent = `${uiText(spec.label)}: `;
      }
      item.appendChild(label);
      const shown = document.createElement("b");
      shown.setAttribute("data-i18n-skip", "");
      shown.setAttribute("translate", "no");
      shown.textContent = legendValue(spec, value);
      item.appendChild(shown);
      if (reading.index !== null && points[reading.index] !== undefined) {
        const when = document.createElement("small");
        when.setAttribute("data-i18n-skip", "");
        when.setAttribute("translate", "no");
        const at = new Date(Number(points[reading.index]) * 1000);
        when.textContent = ` · ${(spanSeconds >= 86400 ? dateTimeFormat : timeFormat).format(at)}`;
        item.appendChild(when);
      }
      item.addEventListener("click", () => {
        setLineVisible(chart, spec, !lineVisible(chart, spec));
        redrawChart(chart.name);
      });

      if (!spec.component) {
        legend.appendChild(item);
        return;
      }
      if (!parts) parts = componentsList(legend, chart, expanded);
      parts.appendChild(item);
    });
    // The lines per component are fetched only when the list is open: the
    // folded list still has to be there to be opened.
    if (chart.components && !parts) componentsList(legend, chart, expanded);
  }

  function componentsList(legend, chart, expanded) {
    const details = document.createElement("details");
    details.className = "mon-components";
    details.open = expanded || Boolean(componentsOpen[chart.name]);
    const summary = document.createElement("summary");
    summary.textContent = uiText("By component");
    details.appendChild(summary);
    const parts = document.createElement("div");
    parts.className = "mon-legend";
    details.appendChild(parts);
    details.addEventListener("toggle", () => {
      if (!legend.closest(".mon-chart-expanded")) {
        componentsOpen[chart.name] = details.open;
        remember(COMPONENTS_OPEN_KEY, JSON.stringify(componentsOpen));
      }
      if (details.open) loadComponents(chart.name);
    });
    legend.appendChild(details);
    return parts;
  }

  // Whether a chart's lines per component should be in its answer.
  function wantsComponents(name) {
    return Boolean(componentsOpen[name]) || expandedChart === name;
  }

  function hasComponents(name) {
    const last = lastCharts[name];
    return Boolean(last && last.payload && Array.isArray(last.payload.components));
  }

  // Fetch one chart again, with its lines per component, once the list is
  // opened or the chart goes full screen.
  async function loadComponents(name) {
    const chart = CHARTS.find((item) => item.name === name);
    if (!chart || !chart.components || hasComponents(name)) return;
    const params = Object.assign({ range: currentRange }, windowParams());
    if (currentSite) params.site = currentSite;
    try {
      const payload = await getJson(
        "/api/monitoring/series",
        Object.assign({ chart: name, components: "1" }, params)
      );
      const seconds = customWindow
        ? customWindow.until - customWindow.since
        : rangeSeconds(currentRange);
      lastCharts[name] = { payload: payload, seconds: seconds };
      redrawChart(name);
    } catch (error) {
      /* the chart keeps what it had; the next refresh tries again */
    }
  }

  /* ---------- availability timeline ---------- */

  // "2h 15m": never translated, see monitoring_core.js.
  const formatDuration = core.formatDuration;

  function spanPeriod(span, windowSeconds) {
    const format = windowSeconds >= 86400 ? dateTimeFormat : timeFormat;
    const start = format.format(new Date(Number(span.start) * 1000));
    const end = format.format(new Date(Number(span.end) * 1000));
    return `${start}–${end}`;
  }

  // The unavailable total is a sum over the chosen window, so the same
  // outage reads differently in an hour and in a day. Say what the sum is
  // made of: how many outages, and whether one is still going on.
  function outageSummary(entry, until) {
    const facts = core.outageFacts(entry, until);
    const line = document.createElement("small");
    const parts = [];
    if (facts.count) {
      parts.push(t("outages: {count}", {count: facts.count}));
    }
    line.textContent = parts.join(" · ");
    if (facts.ongoingSeconds !== null) {
      const label = document.createElement("span");
      label.textContent = `${parts.length ? " · " : ""}${t("ongoing for")} `;
      line.appendChild(label);
      const duration = document.createElement("span");
      duration.setAttribute("data-i18n-skip", "");
      duration.setAttribute("translate", "no");
      duration.textContent = formatDuration(facts.ongoingSeconds);
      line.appendChild(duration);
    }
    return line;
  }

  function spanClass(state) {
    if (state === "UP") return "mon-span-up";
    if (state === "DOWN") return "mon-span-down";
    return "mon-span-other";
  }

  function renderTimeline(payload) {
    const host = byId("mon-timeline");
    if (!host) return;
    host.textContent = "";

    const objects = (payload && payload.objects) || [];
    if (!objects.length) {
      const empty = document.createElement("div");
      empty.className = "mon-empty";
      empty.textContent = uiText("No state changes recorded for this period");
      host.appendChild(empty);
      setText("mon-timeline-note", "");
      return;
    }

    const since = Number(payload.since) || 0;
    const until = Number(payload.until) || since + 1;
    const window = Math.max(1, until - since);

    objects.forEach((entry) => {
      const row = document.createElement("div");
      row.className = "mon-timeline-row";

      const name = document.createElement("div");
      name.className = "mon-timeline-name";
      const title = document.createElement("span");
      title.setAttribute("data-i18n-skip", "");
      title.setAttribute("translate", "no");
      title.textContent = entry.server ? entry.server : entry.label || entry.proxy;
      name.appendChild(title);
      const subtitle = document.createElement("small");
      subtitle.setAttribute("data-i18n-skip", "");
      subtitle.setAttribute("translate", "no");
      subtitle.textContent = entry.server ? entry.label || entry.proxy : uiText("Backend");
      name.appendChild(subtitle);
      row.appendChild(name);

      const track = document.createElement("div");
      track.className = "mon-timeline-track";
      // A run of short outages is one piece, drawn to scale and striped in
      // proportion to the time it was down (see timelinePieces).
      core.timelinePieces(entry.spans || [], window).forEach((part) => {
        if (part.flapping) {
          const length = part.end - part.start;
          const piece = document.createElement("i");
          piece.className = "mon-span-flap";
          piece.style.flex = `0 0 ${(length / window) * 100}%`;
          piece.style.setProperty("--down", `${core.flapStripe(part)}px`);
          piece.title = [
            t("Unstable"),
            spanPeriod(part, window),
            t("outages: {count}", {count: part.outages}),
            `${uiText("Unavailable")} ${formatDuration(part.down)}`,
          ].join(" · ");
          track.appendChild(piece);
          return;
        }
        const span = part.span;
        const seconds = Number(span.end) - Number(span.start);
        const width = (seconds / window) * 100;
        if (!(width > 0)) return;
        const piece = document.createElement("i");
        piece.className = spanClass(span.state);
        // Up time gives way; anything else keeps the few pixels its CSS
        // min-width asks for. Drawn strictly to scale, a six-minute outage
        // in a day was two or three pixels wide -- the total counted it and
        // the bar all but hid it, so the day and the hour looked like they
        // disagreed.
        piece.style.flex = span.state === "UP" ? `1 1 ${width}%` : `0 0 ${width}%`;
        piece.title = `${span.state} · ${spanPeriod(span, window)} · ${formatDuration(seconds)}`;
        track.appendChild(piece);
      });
      row.appendChild(track);

      const meta = document.createElement("div");
      meta.className = "mon-timeline-meta";
      const availability = Number(entry.availability);
      const percent = Number.isFinite(availability)
        ? `${decimalFormat.format(availability * 100)}%`
        : "—";
      const state = document.createElement("b");
      state.setAttribute("data-i18n-skip", "");
      state.setAttribute("translate", "no");
      state.textContent = `${entry.current_state || "—"} · ${percent}`;
      meta.appendChild(state);
      if (entry.downtime_seconds) {
        const label = document.createElement("span");
        label.textContent = ` · ${uiText("Unavailable")} `;
        meta.appendChild(label);
        const duration = document.createElement("span");
        duration.setAttribute("data-i18n-skip", "");
        duration.setAttribute("translate", "no");
        duration.textContent = formatDuration(entry.downtime_seconds);
        meta.appendChild(duration);
        meta.appendChild(outageSummary(entry, until));
      }
      row.appendChild(meta);

      host.appendChild(row);
    });

    setText(
      "mon-timeline-note",
      payload.truncated ? uiText("Some transitions were omitted") : ""
    );
  }

  /* ---------- traffic per backend ---------- */

  // The same card answers "was it up" and "how much went through it". The
  // choice is kept in the browser: someone who came for traffic yesterday
  // comes for traffic today.
  const BACKEND_VIEWS = ["availability", "traffic"];
  const BACKEND_SORTS = ["desc", "asc", "name"];
  let backendsView = "availability";
  let backendsSort = "desc";
  let backendTrafficState = null;

  function remembered(key, allowed, fallback) {
    try {
      const value = window.localStorage.getItem(key);
      return allowed.includes(value) ? value : fallback;
    } catch (error) {
      return fallback;
    }
  }

  function remember(key, value) {
    try {
      window.localStorage.setItem(key, value);
    } catch (error) {
      // Private mode: the choice lasts for this page only.
    }
  }

  function renderBackendTraffic(payload) {
    const host = byId("mon-backend-traffic");
    if (!host) return;
    if (payload !== undefined) backendTrafficState = payload;
    host.textContent = "";

    const backends = (backendTrafficState && backendTrafficState.backends) || [];
    if (!backends.length) {
      const empty = document.createElement("div");
      empty.className = "mon-empty";
      empty.textContent = uiText("No data for this period");
      host.appendChild(empty);
      if (backendsView === "traffic") setText("mon-timeline-note", "");
      return;
    }

    // Bars are measured against the busiest backend, not against the total:
    // against the total, everything below the first row is a sliver.
    const busiest = Math.max(1, ...backends.map((entry) => Number(entry.bytes_total) || 0));

    core.sortedBackends(backends, backendsSort).forEach((entry) => {
      const row = document.createElement("div");
      row.className = "mon-timeline-row";

      const name = document.createElement("div");
      name.className = "mon-timeline-name";
      const title = document.createElement("span");
      title.setAttribute("data-i18n-skip", "");
      title.setAttribute("translate", "no");
      title.textContent = entry.label || entry.proxy;
      name.appendChild(title);
      const sessions = document.createElement("small");
      sessions.textContent = `${uiText("Sessions")}: ${formatCount(entry.sessions)}`;
      name.appendChild(sessions);
      row.appendChild(name);

      const track = document.createElement("div");
      track.className = "mon-timeline-track";
      [
        ["mon-traffic-in", "Inbound", entry.bytes_in],
        ["mon-traffic-out", "Outbound", entry.bytes_out],
      ].forEach(([className, label, bytes]) => {
        const width = ((Number(bytes) || 0) / busiest) * 100;
        if (!(width > 0)) return;
        const piece = document.createElement("i");
        piece.className = className;
        piece.style.flex = `0 0 ${width}%`;
        piece.title = `${uiText(label)} ${formatBytes(bytes)}`;
        track.appendChild(piece);
      });
      row.appendChild(track);

      const meta = document.createElement("div");
      meta.className = "mon-timeline-meta";
      const total = document.createElement("b");
      total.setAttribute("data-i18n-skip", "");
      total.setAttribute("translate", "no");
      total.textContent = `${formatBytes(entry.bytes_total)} · ${decimalFormat.format(Number(entry.share) || 0)}%`;
      meta.appendChild(total);
      const split = document.createElement("small");
      split.textContent =
        `${uiText("Inbound")} ${formatBytes(entry.bytes_in)} · ` +
        `${uiText("Outbound")} ${formatBytes(entry.bytes_out)}`;
      meta.appendChild(split);
      row.appendChild(meta);

      host.appendChild(row);
    });

    if (backendsView === "traffic") {
      setText(
        "mon-timeline-note",
        `${backends.length} · ${formatBytes(backendTrafficState.bytes_total)}`
      );
    }
  }

  async function loadBackendTraffic() {
    const payload = await getJson(
      "/api/monitoring/backends",
      Object.assign({ range: currentRange }, windowParams())
    ).catch(() => null);
    renderBackendTraffic(payload);
  }

  function showBackendsView() {
    const traffic = backendsView === "traffic";
    const timeline = byId("mon-timeline");
    const table = byId("mon-backend-traffic");
    const sortWrap = byId("mon-backends-sort-wrap");
    if (timeline) timeline.hidden = traffic;
    if (table) table.hidden = !traffic;
    if (sortWrap) sortWrap.hidden = !traffic;
    const title = byId("mon-backends-title");
    if (title) {
      title.textContent = uiText(traffic ? "Backend traffic" : "Backend availability");
    }
    const group = byId("mon-backends-view");
    if (group) {
      group.querySelectorAll("button").forEach((item) => {
        item.setAttribute("aria-pressed", item.dataset.view === backendsView ? "true" : "false");
      });
    }
  }

  function bindBackendsView() {
    backendsView = remembered("mon-backends-view", BACKEND_VIEWS, "availability");
    backendsSort = remembered("mon-backends-sort", BACKEND_SORTS, "desc");
    const sort = byId("mon-backends-sort");
    if (sort) {
      sort.value = backendsSort;
      sort.addEventListener("change", () => {
        if (!BACKEND_SORTS.includes(sort.value)) return;
        backendsSort = sort.value;
        remember("mon-backends-sort", backendsSort);
        renderBackendTraffic();
      });
    }
    const group = byId("mon-backends-view");
    if (group) {
      group.addEventListener("click", (event) => {
        const button = event.target.closest("button[data-view]");
        if (!button || !BACKEND_VIEWS.includes(button.dataset.view)) return;
        backendsView = button.dataset.view;
        remember("mon-backends-view", backendsView);
        showBackendsView();
        // The note beside the heading belongs to whichever list is shown.
        if (backendsView === "traffic") loadBackendTraffic();
        else loadAll();
      });
    }
    showBackendsView();
  }

  /* ---------- data loading ---------- */

  async function getJson(path, params) {
    const query = new URLSearchParams(params || {});
    const response = await fetch(`${path}?${query.toString()}`, {
      headers: { Accept: "application/json" },
      credentials: "same-origin"
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(payload.error || `HTTP ${response.status}`);
      error.unavailable = Boolean(payload.unavailable) || response.status === 503;
      throw error;
    }
    return payload;
  }

  function showUnavailable(visible) {
    const notice = byId("mon-unavailable");
    if (notice) notice.hidden = !visible;
  }

  function showPaused(visible) {
    const notice = byId("mon-paused");
    if (notice) notice.hidden = !visible;
  }

  const rangeSeconds = core.rangeSeconds;

  function renderSummary(data) {
    const totals = data.totals || {};
    const connections = data.connections || {};
    const health = data.health || {};

    setText("mon-rps", formatRate(data.requests_per_second));
    setText(
      "mon-requests-total",
      `${uiText("Total")}: ${formatCount(totals.requests)}`
    );

    setText("mon-conns", formatCount(connections.conn_cur_avg));
    setText(
      "mon-conns-peak",
      `${uiText("Peak")}: ${formatCount(connections.conn_cur_max)}`
    );

    const inBytes = Number(totals.bytes_in) || 0;
    const outBytes = Number(totals.bytes_out) || 0;
    setText("mon-traffic", formatBytes(inBytes + outBytes));
    setText(
      "mon-traffic-split",
      `${uiText("Inbound")} ${formatBytes(inBytes)} · ${uiText("Outbound")} ${formatBytes(outBytes)}`
    );

    const classes = byId("mon-classes");
    if (classes) {
      classes.textContent = "";
      [
        ["2xx", totals.resp_2xx, "mon-2xx"],
        ["3xx", totals.resp_3xx, "mon-3xx"],
        ["4xx", totals.resp_4xx, "mon-4xx"],
        ["5xx", totals.resp_5xx, "mon-5xx"]
      ].forEach(([label, value, className]) => {
        const item = document.createElement("span");
        item.className = className;
        item.textContent = `${label} ${formatCount(value)}`;
        classes.appendChild(item);
      });
    }

    const answered =
      (Number(totals.resp_2xx) || 0) +
      (Number(totals.resp_3xx) || 0) +
      (Number(totals.resp_4xx) || 0) +
      (Number(totals.resp_5xx) || 0);
    const failed = Number(totals.resp_5xx) || 0;
    setText(
      "mon-error-ratio",
      answered > 0
        ? `${uiText("Server errors")}: ${decimalFormat.format((failed / answered) * 100)}%`
        : ""
    );

    setText(
      "mon-health",
      `${formatCount(health.backends_up)} / ${formatCount(health.backends_total)}`
    );
    setText(
      "mon-health-servers",
      `${uiText("Servers up")}: ${formatCount(health.servers_up)} / ${formatCount(health.servers_total)}`
    );

    // Hidden rather than shown as 0% when there is nothing to show: a
    // database written before the collector learned to read the machine has
    // no rows at all for it, and a confident zero would be a lie.
    const load = data.load || {};
    const cpuCard = byId("mon-card-cpu");
    if (cpuCard) cpuCard.hidden = !load.observed;
    if (load.observed) {
      setText("mon-cpu", `${decimalFormat.format(load.cpu_avg)}%`);
      setText(
        "mon-cpu-detail",
        `${uiText("Peak")}: ${decimalFormat.format(load.cpu_max)}%`
        + ` · HAProxy: ${decimalFormat.format(load.haproxy_busy_avg)}%`
      );
    }
    // The same rule for memory, which a collector older than the memory
    // columns never recorded: no total means nothing was measured.
    const memoryObserved = Boolean(load.observed) && Number(load.memory_total) > 0;
    const memoryCard = byId("mon-card-memory");
    if (memoryCard) memoryCard.hidden = !memoryObserved;
    if (memoryObserved) {
      setText("mon-memory", formatBytes(load.memory_avg));
      setText(
        "mon-memory-detail",
        `${uiText("Peak")}: ${formatBytes(load.memory_max)}`
        + ` · ${uiText("Total")}: ${formatBytes(load.memory_total)}`
      );
    }

    const collector = data.collector || {};
    showPaused(Boolean(collector.writes_paused));
    setText("mon-updated", data.ts ? dateTimeFormat.format(new Date(data.ts * 1000)) : "");
  }

  function renderStorage(storage) {
    if (!storage) return;
    const limit = Number(storage.max_database_bytes) || 0;
    const total = Number(storage.total_bytes) || 0;
    const fraction = limit > 0 ? Math.min(1, total / limit) : 0;

    const bar = byId("mon-storage-bar");
    if (bar) {
      const fill = bar.querySelector("i");
      if (fill) fill.style.width = `${(fraction * 100).toFixed(1)}%`;
      bar.classList.toggle("warn", storage.state === "WARNING" || storage.state === "PRESSURE");
      bar.classList.toggle("crit", storage.state === "CRITICAL");
    }

    setText("mon-storage-state", storage.state || "");
    setText("mon-st-db", formatBytes(storage.database_bytes));
    setText("mon-st-wal", formatBytes(storage.wal_bytes));
    setText("mon-st-total", formatBytes(total));
    setText("mon-st-limit", limit > 0 ? formatBytes(limit) : uiText("Unlimited"));
    setText("mon-st-free", formatBytes((storage.filesystem || {}).free_bytes));
    setText("mon-st-reserve", formatBytes(storage.reserved_free_bytes));

    const growth = storage.growth || {};
    setText(
      "mon-st-growth",
      growth.last_7d_bytes == null ? "—" : formatBytes(growth.last_7d_bytes)
    );
    setText("mon-st-trend", growth.trend ? uiText(growth.trend) : "—");

    const retention = storage.effective_retention || {};
    setText(
      "mon-st-ret-minute",
      `${formatCount(retention.minute_days)} ${uiText("days")} · ${uiText("servers")} ${formatCount(retention.minute_server_hours)} ${uiText("hours")}`
    );
    setText("mon-st-ret-hour", `${formatCount(retention.hour_days)} ${uiText("days")}`);
  }

  async function loadSites() {
    const select = byId("mon-site");
    if (!select) return;
    try {
      const data = await getJson("/api/monitoring/sites", {});
      const previous = select.value;
      while (select.options.length > 1) select.remove(1);
      (data.sites || []).forEach((site) => {
        const option = document.createElement("option");
        option.value = site.proxy;
        option.textContent = site.label;
        select.appendChild(option);
      });
      if (previous) select.value = previous;
    } catch (error) {
      if (error.unavailable) showUnavailable(true);
    }
  }

  /* ---------- uplinks ---------- */

  // Worked out from the backends rather than configured: every server on the
  // same address is the same link. A gateway with a main connection and a
  // reserve comes out as two rows without anything having to be set up.

  let channelState = [];
  let hiddenState = [];
  // An explicit period, when a preset cannot say what happened on Tuesday.
  // Empty means "use the preset", which is the normal case.
  let customWindow = null;

  function windowParams() {
    return customWindow
      ? { since: customWindow.since, until: customWindow.until }
      : {};
  }

  // A collector older than this page ignores since/until and answers with
  // its preset instead. The charts then plot a day's points inside a
  // two-hour window, every one falls outside it, and the page says "no data
  // for this period" -- which is true of what it was given and completely
  // misleading about why. The daemon names the window it actually used, so
  // the disagreement is visible; say it rather than draw the empty result.
  function noteWindowSkew(payload) {
    if (!customWindow || !payload) return false;
    if (payload.range === "custom") return false;
    setWindowNote(
      uiText("The collector on this gateway is an older version and ignores a chosen period; it answered with its own preset. Update the daemons component.")
    );
    return true;
  }

  function csrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") || "" : "";
  }

  function channelLabel(channel) {
    return channel.label || channel.default_label || channel.host;
  }

  function renderChannels(payload) {
    const card = document.getElementById("mon-channels-card");
    const host = document.getElementById("mon-channels");
    if (!card || !host) return;

    const channels = (payload && payload.channels) || [];
    hiddenState = (payload && payload.hidden) || [];
    channelState = channels.concat(hiddenState);
    // One link is not a comparison, and zero is not worth a card -- unless
    // something is only hidden, in which case there has to be a way back.
    card.hidden = channels.length < 2 && hiddenState.length === 0;
    if (card.hidden) return;

    const note = document.getElementById("mon-channels-note");
    if (note) {
      note.textContent = `${channels.length} · ${formatBytes(payload.bytes_total)}`;
    }

    renderHiddenDrawer();

    host.textContent = "";
    channels.forEach((channel) => {
      const row = document.createElement("div");
      row.className = "mon-channel" + (channel.backup ? " reserve" : "");

      const name = document.createElement("div");
      name.className = "mon-channel-name";
      const label = document.createElement("span");
      label.setAttribute("data-i18n-skip", "");
      label.setAttribute("translate", "no");
      label.textContent = channelLabel(channel);
      name.appendChild(label);

      const kind = document.createElement("span");
      kind.className = "mon-sub";
      kind.textContent = channel.backup
        ? uiText("reserve")
        : uiText("in use");
      name.appendChild(kind);

      const rename = document.createElement("button");
      rename.type = "button";
      rename.className = "mon-channel-rename";
      rename.textContent = uiText("rename");
      rename.addEventListener("click", () => renameChannel(channel));
      name.appendChild(rename);

      // Not every backend host is an uplink -- a single application server
      // is just a server -- and a list that cannot be tidied is one nobody
      // reads.
      const hide = document.createElement("button");
      hide.type = "button";
      hide.className = "mon-channel-rename";
      hide.textContent = channel.hidden ? uiText("show") : uiText("hide");
      hide.addEventListener("click", () => setHidden(channel, !channel.hidden));
      name.appendChild(hide);
      row.appendChild(name);

      const where = document.createElement("div");
      where.className = "mon-channel-where";
      where.setAttribute("data-i18n-skip", "");
      where.setAttribute("translate", "no");
      where.textContent = channel.host;
      row.appendChild(where);

      const traffic = document.createElement("div");
      traffic.className = "mon-channel-traffic";
      const total = document.createElement("b");
      total.setAttribute("data-i18n-skip", "");
      total.setAttribute("translate", "no");
      total.textContent = formatBytes(channel.bytes_total);
      traffic.appendChild(total);
      const share = document.createElement("span");
      share.className = "mon-channel-share";
      // The backend count is the honest reason a link is busy, so it is
      // next to the number rather than left to be guessed.
      // "backends: 8" rather than "8 backends": Russian declines the noun
      // after 2-4 differently from after 5+, and the count moves.
      share.textContent =
        `${channel.share}% · ` + uiText("backends") + `: ${channel.backend_count}`;
      traffic.appendChild(share);
      row.appendChild(traffic);

      const bar = document.createElement("div");
      bar.className = "mon-channel-bar";
      const fill = document.createElement("i");
      fill.style.width = `${Math.max(0, Math.min(100, channel.share))}%`;
      bar.appendChild(fill);
      row.appendChild(bar);

      host.appendChild(row);
    });
  }

  function renderHiddenDrawer() {
    const wrap = document.getElementById("mon-channels-hidden-wrap");
    const box = document.getElementById("mon-channels-hidden");
    const toggle = document.getElementById("mon-channels-toggle");
    if (!wrap || !box || !toggle) return;

    wrap.hidden = hiddenState.length === 0;
    toggle.textContent = box.hidden
      ? `${uiText("Show hidden")} (${hiddenState.length})`
      : uiText("Hide the list");
    if (box.hidden) return;

    box.textContent = "";
    hiddenState.forEach((channel) => {
      const row = document.createElement("div");
      row.className = "mon-channel";
      row.style.opacity = ".6";

      const name = document.createElement("div");
      name.className = "mon-channel-name";
      const label = document.createElement("span");
      label.setAttribute("data-i18n-skip", "");
      label.setAttribute("translate", "no");
      label.textContent = channelLabel(channel);
      name.appendChild(label);
      const back = document.createElement("button");
      back.type = "button";
      back.className = "mon-channel-rename";
      back.textContent = uiText("show");
      back.addEventListener("click", () => setHidden(channel, false));
      name.appendChild(back);
      row.appendChild(name);

      const where = document.createElement("div");
      where.className = "mon-channel-where";
      where.setAttribute("data-i18n-skip", "");
      where.setAttribute("translate", "no");
      where.textContent = channel.host;
      row.appendChild(where);

      const traffic = document.createElement("div");
      traffic.className = "mon-channel-traffic";
      traffic.setAttribute("data-i18n-skip", "");
      traffic.setAttribute("translate", "no");
      traffic.textContent = formatBytes(channel.bytes_total);
      row.appendChild(traffic);

      box.appendChild(row);
    });
  }

  async function setHidden(channel, hidden) {
    const hosts = new Set(hiddenState.map((item) => item.host));
    if (hidden) {
      hosts.add(channel.host);
    } else {
      hosts.delete(channel.host);
    }
    await saveChannels(Array.from(hosts));
  }

  function sayChannels(message, isError) {
    const host = document.getElementById("mon-channels-result");
    if (!host) return;
    host.textContent = message || "";
    host.style.color = isError ? "#cc4b4b" : "";
  }

  async function renameChannel(channel) {
    const current = channel.label || "";
    const next = window.prompt(
      `${uiText("Name for this uplink")} (${channel.host})`,
      current
    );
    if (next === null) return;

    const trimmed = next.trim();
    await saveChannels(null, { host: channel.host, label: trimmed });
  }

  // Names and visibility go together in one request, because the daemon
  // stores them together and a partial write would drop the other half.
  async function saveChannels(hidden, rename) {
    const labels = {};
    channelState.forEach((item) => {
      if (item.label) labels[item.host] = item.label;
    });
    if (rename) {
      if (rename.label) {
        labels[rename.host] = rename.label;
      } else {
        // Cleared: back to whatever HAProxy calls the servers on it.
        delete labels[rename.host];
      }
    }
    const body = { labels };
    if (hidden !== null && hidden !== undefined) body.hidden = hidden;

    try {
      const response = await fetch("/api/monitoring/channels/labels", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken()
        },
        body: JSON.stringify(body)
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || data.ok === false) {
        sayChannels(data.error || uiText("Could not save the name"), true);
        return;
      }
      // Same skew, quieter symptom: an older collector accepts the request,
      // drops the hidden list and answers ok, so the button appears to do
      // nothing at all.
      if (body.hidden !== undefined && data.hidden === undefined) {
        sayChannels(
          uiText("The collector on this gateway is an older version and cannot hide channels yet. Update the daemons component."),
          true
        );
        return;
      }
      sayChannels("");
      await loadChannels();
    } catch (error) {
      sayChannels(String(error), true);
    }
  }

  async function loadChannels() {
    const payload = await getJson(
      "/api/monitoring/channels",
      Object.assign({ range: currentRange }, windowParams())
    ).catch(() => null);
    if (payload) renderChannels(payload);
  }

  // The last answer for each chart, so hiding a line or opening a chart in
  // full screen redraws at once instead of asking the server again.
  const lastCharts = {};

  function redrawChart(name) {
    const chart = CHARTS.find((item) => item.name === name);
    const svg = byId(`mon-plot-${name}`);
    if (!chart || !svg) return;
    const last = lastCharts[name];
    if (!last) {
      drawEmpty(svg, uiText("No data for this period"));
      return;
    }
    drawChart(svg, chart, last.payload, last.seconds);
    renderLegend(chart, last.payload);
  }

  /* ---------- full screen ---------- */

  // The card is moved into an overlay on <body> rather than restyled where
  // it stands: a transformed or filtered ancestor would turn position:fixed
  // into "fixed to that ancestor". A placeholder keeps its place in the grid.
  let expandedChart = null;
  let expandedPlaceholder = null;

  function expandButtonState(card, open) {
    const button = card.querySelector(".mon-expand");
    if (!button) return;
    const label = uiText(open ? "Exit full screen" : "Full screen");
    button.setAttribute("aria-pressed", open ? "true" : "false");
    button.title = label;
    button.setAttribute("aria-label", label);
  }

  function setExpanded(name) {
    const overlay = byId("mon-overlay");
    if (!overlay) return;
    if (expandedChart) {
      const card = document.querySelector(`.mon-chart[data-chart="${expandedChart}"]`);
      if (card && expandedPlaceholder && expandedPlaceholder.parentNode) {
        expandedPlaceholder.parentNode.replaceChild(card, expandedPlaceholder);
      }
      if (card) {
        card.classList.remove("mon-chart-expanded");
        expandButtonState(card, false);
      }
      const previous = expandedChart;
      expandedChart = null;
      expandedPlaceholder = null;
      redrawChart(previous);
    }
    const card = name ? document.querySelector(`.mon-chart[data-chart="${name}"]`) : null;
    if (card) {
      expandedPlaceholder = document.createElement("div");
      expandedPlaceholder.className = "mon-chart mon-chart-placeholder";
      expandedPlaceholder.style.height = `${card.offsetHeight}px`;
      card.parentNode.replaceChild(expandedPlaceholder, card);
      overlay.appendChild(card);
      card.classList.add("mon-chart-expanded");
      expandButtonState(card, true);
      expandedChart = name;
    }
    overlay.hidden = !expandedChart;
    document.body.classList.toggle("mon-overlay-open", Boolean(expandedChart));
    // In the address, so a reload -- or a link sent to a colleague -- opens
    // the same chart.
    try {
      const url = new URL(window.location.href);
      url.hash = expandedChart ? `chart=${expandedChart}` : "";
      window.history.replaceState(null, "", url.toString().replace(/#$/, ""));
    } catch (error) {
      /* the address stays as it was */
    }
    if (expandedChart) {
      redrawChart(expandedChart);
      loadComponents(expandedChart);
      const button = card.querySelector(".mon-expand");
      if (button) button.focus();
    }
  }

  function bindFullScreen() {
    document.querySelectorAll(".mon-chart[data-chart] .mon-expand").forEach((button) => {
      button.addEventListener("click", () => {
        const name = button.closest(".mon-chart").dataset.chart;
        setExpanded(expandedChart === name ? null : name);
      });
    });
    const overlay = byId("mon-overlay");
    if (overlay) {
      overlay.addEventListener("click", (event) => {
        if (event.target === overlay) setExpanded(null);
      });
    }
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && expandedChart && !zoomDragging) setExpanded(null);
    });
    let pending = false;
    window.addEventListener("resize", () => {
      if (!expandedChart || pending) return;
      pending = true;
      window.requestAnimationFrame(() => {
        pending = false;
        if (expandedChart) redrawChart(expandedChart);
      });
    });
    const wanted = /^#chart=([a-z_]+)$/.exec(window.location.hash || "");
    if (wanted && CHARTS.some((chart) => chart.name === wanted[1])) setExpanded(wanted[1]);
  }

  async function loadAll() {
    // A refresh redraws the charts, which would drop a selection in progress.
    if (inFlight || zoomDragging) return;
    inFlight = true;
    const params = Object.assign({ range: currentRange }, windowParams());
    if (currentSite) params.site = currentSite;

    try {
      const summary = await getJson("/api/monitoring/summary", params);
      showUnavailable(false);
      if (noteWindowSkew(summary)) {
        // Show what it did return rather than an empty frame, now that the
        // note says which period it belongs to.
        customWindow = null;
      }
      renderSummary(summary);
      renderStorage(summary.storage);

      const timeline = await getJson("/api/monitoring/states", params).catch(() => null);
      renderTimeline(timeline);
      // After the timeline: both write the note beside the heading, and the
      // list on show has the last word.
      if (backendsView === "traffic") await loadBackendTraffic();

      // Not scoped by site: a link carries every site pointed at it.
      await loadChannels();

      const seconds = customWindow
        ? customWindow.until - customWindow.since
        : rangeSeconds(currentRange);
      const results = await Promise.all(
        CHARTS.map((chart) => {
          const query = Object.assign({ chart: chart.name }, params);
          if (chart.components) query.components = wantsComponents(chart.name) ? "1" : "0";
          return getJson("/api/monitoring/series", query).catch(() => null);
        })
      );
      results.forEach((payload, index) => {
        const chart = CHARTS[index];
        lastCharts[chart.name] = payload ? { payload: payload, seconds: seconds } : null;
        redrawChart(chart.name);
        if (payload && index === 0) {
          // Always in minutes: "min" is already in the catalog, and one unit
          // keeps the reading comparable as the server changes resolution.
          const step = Number(payload.resolution_seconds) || 60;
          setText(
            "mon-resolution",
            `${uiText("Resolution")}: ${formatCount(step / 60)} ${uiText("min")}`
          );
        }
      });
    } catch (error) {
      showUnavailable(Boolean(error.unavailable));
      CHARTS.forEach((chart) => {
        lastCharts[chart.name] = null;
        redrawChart(chart.name);
      });
    } finally {
      inFlight = false;
    }
  }

  /* ---------- drag to zoom ---------- */

  // Drag across a chart to look at just that stretch: the selection becomes
  // the chosen period for every chart and the availability bars, exactly as
  // if it had been typed into "Period...". Each zoom remembers what was shown
  // before it, so "Zoom out" -- or a double-click on a chart -- steps back
  // one level at a time, and a preset or "Back to presets" starts afresh.
  const zoomHistory = [];
  let zoomDragging = false;

  function updateZoomOut() {
    const button = byId("mon-zoom-out");
    if (button) button.hidden = !zoomHistory.length;
  }

  function markCustomRange(active) {
    const ranges = byId("mon-ranges");
    if (!ranges) return;
    ranges.querySelectorAll("button").forEach((item) => {
      const pressed = active
        ? item.id === "mon-range-custom"
        : item.dataset.range === currentRange;
      item.setAttribute("aria-pressed", pressed ? "true" : "false");
    });
  }

  function showWindow(next) {
    customWindow = next;
    markCustomRange(Boolean(next));
    if (next) {
      const from = byId("mon-window-from");
      const to = byId("mon-window-to");
      if (from) from.value = toLocalInput(next.since);
      if (to) to.value = toLocalInput(next.until);
    }
    updateZoomOut();
    setWindowNote("");
    loadAll();
  }

  function zoomTo(since, until) {
    zoomHistory.push(customWindow ? Object.assign({}, customWindow) : null);
    showWindow(core.zoomWindow(since, until));
  }

  function zoomOut() {
    if (!zoomHistory.length) return;
    showWindow(zoomHistory.pop());
  }

  function bindZoom(svg) {
    let start = null;
    let band = null;
    const toX = (event, geometry) => {
      const box = svg.getBoundingClientRect();
      const x = ((event.clientX - box.left) / Math.max(box.width, 1)) * geometry.width;
      return Math.min(Math.max(x, geometry.left), geometry.left + geometry.plotWidth);
    };
    const stop = () => {
      if (band && band.parentNode) band.parentNode.removeChild(band);
      band = null;
      start = null;
      zoomDragging = false;
    };

    svg.addEventListener("pointerdown", (event) => {
      const geometry = svg.__geometry;
      if (!geometry || event.button !== 0) return;
      start = toX(event, geometry);
      zoomDragging = true;
      // Keeps the drag ours when the pointer leaves the chart; a selection
      // still works without it, so a refusal must not abort the drag.
      try {
        svg.setPointerCapture(event.pointerId);
      } catch (error) {
        /* not capturable: carry on uncaptured */
      }
      band = element("rect", {
        class: "mon-brush",
        x: start,
        y: geometry.top,
        width: 0,
        height: geometry.plotHeight
      });
      svg.appendChild(band);
      event.preventDefault();
    });
    svg.addEventListener("pointermove", (event) => {
      const geometry = svg.__geometry;
      if (start === null || !geometry || !band) return;
      const x = toX(event, geometry);
      band.setAttribute("x", Math.min(start, x));
      band.setAttribute("width", Math.abs(x - start));
    });
    svg.addEventListener("pointerup", (event) => {
      const geometry = svg.__geometry;
      if (start === null || !geometry) {
        stop();
        return;
      }
      const end = toX(event, geometry);
      const left = Math.min(start, end);
      const right = Math.max(start, end);
      stop();
      // A click or a twitch is not a selection.
      if (right - left < 6) return;
      // The axis is spaced by sample, not by clock (see timeAtX).
      zoomTo(core.timeAtX(geometry, left), core.timeAtX(geometry, right) + geometry.step);
    });
    svg.addEventListener("pointercancel", stop);
    svg.addEventListener("dblclick", zoomOut);
  }

  function scheduleRefresh() {
    if (refreshTimer) window.clearInterval(refreshTimer);
    refreshTimer = window.setInterval(() => {
      if (!document.hidden) loadAll();
    }, REFRESH_INTERVAL_MS);
  }

  function setWindowNote(text) {
    const note = byId("mon-window-note");
    if (note) note.textContent = text || "";
  }

  function localInputToEpoch(value) {
    // datetime-local has no zone; the browser's own is what the operator
    // means when they type a time.
    if (!value) return 0;
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) ? Math.floor(parsed / 1000) : 0;
  }

  function bindWindowControls() {
    const panel = byId("mon-window");
    const open = byId("mon-range-custom");
    if (open && panel) {
      open.addEventListener("click", () => {
        panel.hidden = !panel.hidden;
        if (panel.hidden) return;
        // Seed with the preset currently shown, so the fields start
        // somewhere sensible rather than empty.
        const until = Math.floor(Date.now() / 1000);
        const since = until - rangeSeconds(currentRange);
        const from = byId("mon-window-from");
        const to = byId("mon-window-to");
        if (from && !from.value) from.value = toLocalInput(since);
        if (to && !to.value) to.value = toLocalInput(until);
      });
    }

    const apply = byId("mon-window-apply");
    if (apply) {
      apply.addEventListener("click", () => {
        const since = localInputToEpoch((byId("mon-window-from") || {}).value);
        const until = localInputToEpoch((byId("mon-window-to") || {}).value);
        if (!since || !until || until <= since) {
          setWindowNote(uiText("Choose a start earlier than the end"));
          return;
        }
        customWindow = { since: since, until: until };
        zoomHistory.length = 0;
        updateZoomOut();
        const ranges = byId("mon-ranges");
        if (ranges) {
          ranges.querySelectorAll("button").forEach((item) => {
            item.setAttribute(
              "aria-pressed", item.id === "mon-range-custom" ? "true" : "false"
            );
          });
        }
        setWindowNote("");
        loadAll();
      });
    }

    const clear = byId("mon-window-clear");
    if (clear) {
      clear.addEventListener("click", () => {
        customWindow = null;
        zoomHistory.length = 0;
        updateZoomOut();
        setWindowNote("");
        if (panel) panel.hidden = true;
        const ranges = byId("mon-ranges");
        if (ranges) {
          ranges.querySelectorAll("button").forEach((item) => {
            item.setAttribute(
              "aria-pressed",
              item.dataset.range === currentRange ? "true" : "false"
            );
          });
        }
        loadAll();
      });
    }

    const toggle = byId("mon-channels-toggle");
    if (toggle) {
      toggle.addEventListener("click", () => {
        const box = byId("mon-channels-hidden");
        if (box) box.hidden = !box.hidden;
        renderHiddenDrawer();
      });
    }
  }

  function toLocalInput(epochSeconds) {
    const date = new Date(epochSeconds * 1000);
    const pad = (n) => String(n).padStart(2, "0");
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-` +
      `${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
  }

  function bindControls() {
    const ranges = byId("mon-ranges");
    if (ranges) {
      ranges.addEventListener("click", (event) => {
        const button = event.target.closest("button[data-range]");
        if (!button) return;
        currentRange = button.dataset.range;
        // Choosing a preset leaves the explicit period, or the page would
        // show one thing and highlight another.
        customWindow = null;
        zoomHistory.length = 0;
        updateZoomOut();
        setWindowNote("");
        ranges.querySelectorAll("button").forEach((item) => {
          item.setAttribute("aria-pressed", item === button ? "true" : "false");
        });
        loadAll();
      });
      const active = ranges.querySelector('button[aria-pressed="true"]');
      if (active && active.dataset.range) currentRange = active.dataset.range;
    }

    bindWindowControls();
    bindBackendsView();
    bindFullScreen();

    CHARTS.forEach((chart) => {
      const svg = byId(`mon-plot-${chart.name}`);
      if (svg) bindZoom(svg);
    });
    const zoomOutButton = byId("mon-zoom-out");
    if (zoomOutButton) zoomOutButton.addEventListener("click", zoomOut);

    const site = byId("mon-site");
    if (site) {
      site.addEventListener("change", () => {
        currentSite = site.value;
        loadAll();
      });
    }
  }

  document.addEventListener("DOMContentLoaded", async () => {
    bindControls();
    await loadSites();
    await loadAll();
    scheduleRefresh();
  });
})();
