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

const source = fs.readFileSync(path.join(__dirname, "../../go/panel/web/static/js/monitoring.js"), "utf8");
const loaders = ["loadNearCharts", "loadOneChart", "loadAll"].map((name) => {
  const start = source.search(new RegExp(`^  (?:async )?function ${name}\\(`, "m"));
  assert.notEqual(start, -1, name);
  return source.slice(start, source.indexOf("\n  }", start) + "\n  }".length);
}).join("\n");
const settle = () => new Promise(setImmediate);
const series = { points: [60], resolution_seconds: 60 };

function monitoringPage(overrides) {
  const noop = () => {};
  const page = vm.createContext({
    AbortController,
    CHARTS: [{ name: "requests" }, { name: "latency" }],
    inFlight: false,
    zoomDragging: false,
    sharedReading: null,
    currentRange: "1h",
    currentSite: "",
    customWindow: null,
    chartSession: null,
    reloadPending: false,
    LONG_RANGE_REFRESH_SECONDS: 300,
    showEvents: false,
    eventsState: null,
    lastCharts: {},
    rangeSeconds: () => 3600,
    windowParams: () => ({}),
    eventsParams: () => ({}),
    chartPlan: (chart, session) => ({ from: null, query: { ...session.params, chart: chart.name } }),
    chartNearViewport: () => true,
    chartOn: () => true,
    monitorOn: () => false,
    getJson: () => Promise.resolve({}),
    redrawChart: noop,
    backendsView: "availability",
    byId: noop,
    clearReadings: noop,
    writeAddress: noop,
    updateLogLinks: noop,
    showUnavailable(unavailable) { assert.equal(unavailable, false); },
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
    ...overrides,
  });
  vm.runInContext(loaders, page);
  return page;
}

test("monitoring draws a ready chart before slow series, tables, and events", async () => {
  const latency = deferred();
  const timeline = deferred();
  const events = deferred();
  const draws = [];
  const page = monitoringPage({
    showEvents: true,
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
  });
  const loaded = vm.runInContext("loadAll()", page);
  await settle();
  assert.deepEqual(draws, [["requests", null]]);

  const overlay = { events: [{ ts: 60 }] };
  events.resolve(overlay);
  await settle();
  assert.deepEqual(draws, [["requests", null], ["requests", overlay]]);

  latency.resolve(series);
  timeline.resolve({});
  await loaded;
  assert.deepEqual(draws.at(-1), ["latency", overlay]);
  assert.equal(page.inFlight, false);
});

test("monitoring fetches charts on approach and refreshes only nearby charts", async () => {
  const names = [];
  const visible = new Set(["requests"]);
  const page = monitoringPage({
    chartNearViewport: (name) => visible.has(name),
    getJson(route, params) {
      if (route !== "/api/monitoring/series") return Promise.resolve({});
      names.push(params.chart);
      return Promise.resolve(series);
    },
  });
  await vm.runInContext("loadAll()", page);
  assert.deepEqual(names, ["requests"]);

  visible.delete("requests");
  visible.add("latency");
  await vm.runInContext("Promise.all([loadNearCharts(), loadNearCharts()])", page);
  assert.deepEqual(names, ["requests", "latency"]);
  assert.equal(page.lastCharts.latency.payload, series);

  await vm.runInContext("loadAll({refresh: true})", page);
  assert.deepEqual(names, ["requests", "latency", "latency"]);
});

test("monitoring discards a pending series when the user changes site", async () => {
  const old = deferred();
  const drawn = [];
  const page = monitoringPage({
    currentSite: "old",
    chartNearViewport: (name) => name === "requests",
    getJson(route, params) {
      if (route !== "/api/monitoring/series") return Promise.resolve({});
      return params.site === "old" ? old.promise : Promise.resolve(series);
    },
    redrawChart(name) { drawn.push([name, page.lastCharts[name].view]); },
  });
  const oldLoad = vm.runInContext("loadAll()", page);
  await settle();
  page.currentSite = "new";
  await vm.runInContext("loadAll()", page);
  old.resolve(series);
  await oldLoad;
  await settle();
  assert.deepEqual(drawn, [["requests", "1h|new|"]]);
});
