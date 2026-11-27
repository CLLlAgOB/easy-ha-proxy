const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

test("monitoring draws a ready chart before slow series, tables, and events", async () => {
  // Exercise the page's request ordering with controlled responses.
  const source = fs.readFileSync(path.join(__dirname, "../../go/panel/web/static/js/monitoring.js"), "utf8");
  const start = source.indexOf("  async function loadAll(options) {");
  assert.notEqual(start, -1);
  const end = source.indexOf("\n  }", start) + "\n  }".length;
  const latency = deferred();
  const timeline = deferred();
  const events = deferred();
  const series = { points: [60], resolution_seconds: 60 };
  const draws = [];
  const noop = () => {};
  const page = {
    CHARTS: [{ name: "requests" }, { name: "latency" }],
    inFlight: false,
    zoomDragging: false,
    currentRange: "1y",
    currentSite: "",
    customWindow: null,
    chartsView: "",
    chartsFetchedAt: 0,
    showEvents: true,
    eventsState: null,
    lastCharts: {},
    rangeSeconds: () => 365 * 86400,
    windowParams: () => ({}),
    eventsParams: () => ({}),
    chartPlan: (chart) => ({ from: null, query: { chart: chart.name } }),
    chartOn: () => true,
    monitorOn: (name) => name === "availability",
    getJson(route, params) {
      switch (route) {
        case "/api/monitoring/summary": return Promise.resolve({});
        case "/api/monitoring/series": return params.chart === "requests" ? Promise.resolve(series) : latency.promise;
        case "/api/monitoring/states": return timeline.promise;
        case "/api/monitoring/attention": return Promise.resolve({});
        case "/api/monitoring/events": return events.promise;
        default: throw new Error(`Unexpected monitoring request ${route}`);
      }
    },
    redrawChart(name) { draws.push([name, page.eventsState]); },
    backendsView: "availability",
    clearReadings: noop,
    writeAddress: noop,
    updateLogLinks: noop,
    showUnavailable: noop,
    noteWindowSkew: noop,
    applyMonitors: noop,
    renderSummary: noop,
    renderStorage: noop,
    renderTimeline: noop,
    renderAttention: noop,
    renderEventsCount: noop,
    formatCount: String,
    uiText: String,
    setText: noop,
  };
  const loaded = vm.runInNewContext(source.slice(start, end) + "\nloadAll();", page);
  await new Promise(setImmediate);
  assert.deepEqual(draws, [["requests", null]]);

  const overlay = { events: [{ ts: 60 }] };
  events.resolve(overlay);
  await new Promise(setImmediate);
  assert.deepEqual(draws, [["requests", null], ["requests", overlay]]);

  latency.resolve(series);
  timeline.resolve({});
  await loaded;
  assert.deepEqual(draws.at(-1), ["latency", overlay]);
  assert.equal(page.inFlight, false);
});
