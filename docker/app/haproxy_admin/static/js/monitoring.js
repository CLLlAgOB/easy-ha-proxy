/* Historical monitoring: overview cards, time-series charts, storage status.
 *
 * Charts are drawn as plain SVG on purpose. The page runs under a strict CSP
 * with script-src 'self', so a charting library would have to be vendored into
 * the image; a few hundred lines of line-plot code is cheaper to ship, audit
 * and keep working than a bundled dependency.
 */
(function () {
  "use strict";

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
        { key: "response_ms_avg", label: "Average", color: "#4a86c8" },
        { key: "response_ms_max", label: "Peak", color: "#c8a13a" }
      ]
    },
    {
      name: "connections",
      series: [
        { key: "conn_cur_avg", label: "Average", color: "#4a86c8" },
        { key: "conn_cur_max", label: "Peak", color: "#c8a13a" }
      ]
    }
  ];

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
    const numeric = Number(value);
    if (!Number.isFinite(numeric)) return "—";
    const units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let size = Math.abs(numeric);
    let index = 0;
    while (size >= 1024 && index < units.length - 1) {
      size /= 1024;
      index += 1;
    }
    const sign = numeric < 0 ? "-" : "";
    return `${sign}${decimalFormat.format(size)} ${units[index]}`;
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

  function niceCeiling(value) {
    if (!(value > 0)) return 1;
    const magnitude = Math.pow(10, Math.floor(Math.log10(value)));
    const normalized = value / magnitude;
    let step;
    if (normalized <= 1) step = 1;
    else if (normalized <= 2) step = 2;
    else if (normalized <= 5) step = 5;
    else step = 10;
    return step * magnitude;
  }

  function axisLabel(spec, value) {
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

    const width = 600;
    const height = 190;
    const padding = { top: 10, right: 8, bottom: 22, left: 54 };
    const plotWidth = width - padding.left - padding.right;
    const plotHeight = height - padding.top - padding.bottom;
    const step = Number(payload.resolution_seconds) || 60;

    // Counters are stored per bucket; a rate is the only comparable value once
    // the server changes resolution between ranges.
    const datasets = chart.series.map((spec) => {
      const raw = (payload.series && payload.series[spec.key]) || [];
      const values = raw.map((value) => (spec.rate ? Number(value) / step : Number(value)));
      return { spec: spec, values: values };
    });

    let maximum = 0;
    datasets.forEach((dataset) => {
      dataset.values.forEach((value) => {
        if (Number.isFinite(value) && value > maximum) maximum = value;
      });
    });
    const top = niceCeiling(maximum);

    clear(svg);
    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);

    const xFor = (index) =>
      padding.left + (points.length === 1 ? plotWidth / 2 : (index / (points.length - 1)) * plotWidth);
    const yFor = (value) => padding.top + plotHeight - (Math.max(0, value) / top) * plotHeight;

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

    const labelCount = Math.min(5, points.length);
    for (let index = 0; index < labelCount; index += 1) {
      const pointIndex =
        labelCount === 1 ? 0 : Math.round((index / (labelCount - 1)) * (points.length - 1));
      const label = element("text", {
        class: "mon-tick",
        x: xFor(pointIndex),
        y: height - 6,
        "text-anchor": index === 0 ? "start" : index === labelCount - 1 ? "end" : "middle"
      });
      label.textContent = timeLabel(points[pointIndex], rangeSeconds);
      svg.appendChild(label);
    }

    datasets.forEach((dataset) => {
      const path = dataset.values
        .map((value, index) => `${index === 0 ? "M" : "L"}${xFor(index).toFixed(1)},${yFor(value).toFixed(1)}`)
        .join(" ");
      if (!path) return;
      if (chart.series.length <= 2) {
        const area =
          `${path} L${xFor(dataset.values.length - 1).toFixed(1)},${(padding.top + plotHeight).toFixed(1)}` +
          ` L${xFor(0).toFixed(1)},${(padding.top + plotHeight).toFixed(1)} Z`;
        svg.appendChild(element("path", { class: "mon-area", d: area, fill: dataset.spec.color }));
      }
      svg.appendChild(
        element("path", { class: "mon-line", d: path, stroke: dataset.spec.color })
      );
    });
  }

  function renderLegend(chart, payload) {
    const legend = byId(`mon-legend-${chart.name}`);
    if (!legend) return;
    legend.textContent = "";
    const step = Number(payload && payload.resolution_seconds) || 60;
    chart.series.forEach((spec) => {
      const raw = (payload && payload.series && payload.series[spec.key]) || [];
      let last = 0;
      for (let index = raw.length - 1; index >= 0; index -= 1) {
        if (Number.isFinite(Number(raw[index]))) {
          last = Number(raw[index]);
          break;
        }
      }
      const value = spec.rate ? last / step : last;
      const item = document.createElement("span");
      const swatch = document.createElement("i");
      swatch.style.background = spec.color;
      item.appendChild(swatch);
      const label = document.createElement("span");
      label.textContent = `${uiText(spec.label)}: `;
      item.appendChild(label);
      const reading = document.createElement("b");
      reading.setAttribute("data-i18n-skip", "");
      reading.setAttribute("translate", "no");
      reading.textContent = spec.bytes ? `${formatBytes(value)}/s` : formatRate(value);
      item.appendChild(reading);
      legend.appendChild(item);
    });
  }

  /* ---------- availability timeline ---------- */

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
      (entry.spans || []).forEach((span) => {
        const width = ((Number(span.end) - Number(span.start)) / window) * 100;
        if (!(width > 0)) return;
        const piece = document.createElement("i");
        piece.className = spanClass(span.state);
        piece.style.width = `${width}%`;
        piece.title = `${span.state} · ${formatDuration(Number(span.end) - Number(span.start))}`;
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
      }
      row.appendChild(meta);

      host.appendChild(row);
    });

    setText(
      "mon-timeline-note",
      payload.truncated ? uiText("Some transitions were omitted") : ""
    );
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

  function rangeSeconds(key) {
    const table = { "1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800, "30d": 2592000, "90d": 7776000, "1y": 31536000 };
    return table[key] || 86400;
  }

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

  async function loadAll() {
    if (inFlight) return;
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

      // Not scoped by site: a link carries every site pointed at it.
      await loadChannels();

      const seconds = rangeSeconds(currentRange);
      const results = await Promise.all(
        CHARTS.map((chart) =>
          getJson("/api/monitoring/series", Object.assign({ chart: chart.name }, params)).catch(
            () => null
          )
        )
      );
      results.forEach((payload, index) => {
        const chart = CHARTS[index];
        const svg = byId(`mon-plot-${chart.name}`);
        if (!svg) return;
        if (!payload) {
          drawEmpty(svg, uiText("No data for this period"));
          return;
        }
        drawChart(svg, chart, payload, seconds);
        renderLegend(chart, payload);
        if (index === 0) {
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
        const svg = byId(`mon-plot-${chart.name}`);
        if (svg) drawEmpty(svg, uiText("No data for this period"));
      });
    } finally {
      inFlight = false;
    }
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
