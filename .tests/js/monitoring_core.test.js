// Behaviour of the monitoring page's arithmetic (monitoring_core.js): which
// lines a chart draws, where its scale tops out, what a legend reading
// stands for, how an availability bar is cut up and how a drag becomes a
// period. Run with: node --test .tests/js/
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const core = require(path.join(__dirname, "../../docker/app/haproxy_admin/static/js/monitoring_core.js"));

const KiB = 1024;
const MiB = 1024 * KiB;
const GiB = 1024 * MiB;
const MINUTE = 60;
const HOUR = 3600;
const DAY = 86400;

const CPU_CHART = {
  name: "cpu",
  components: true,
  series: [
    {key: "cpu_avg", label: "Average", percent: true, summary: "mean"},
    {key: "cpu_max", label: "Peak", percent: true, summary: "max"},
    {key: "other", label: "Other processes", percent: true, summary: "mean", hidden: true}
  ]
};

const MEMORY_CHART = {
  name: "memory",
  components: true,
  series: [
    {key: "memory_avg", label: "Used", bytes: true, summary: "mean"},
    {key: "memory_total", label: "Total", bytes: true, summary: "last", dash: true}
  ]
};

const REQUESTS_CHART = {
  name: "requests",
  series: [{key: "requests", label: "Requests", rate: true}]
};

function parts(...names) {
  return names.map(([group, name]) => ({group, name, values: [1, 2], peak: 2}));
}

/* ---------- lines ---------- */

test("a chart without parts draws only its own lines", () => {
  assert.equal(core.seriesFor(REQUESTS_CHART, {components: parts(["service", "guardd"])}), REQUESTS_CHART.series);
});

test("each part of the gateway gets its own line, hidden until asked for", () => {
  const lines = core.seriesFor(CPU_CHART, {components: parts(["service", "guardd"], ["container", "authelia"])});
  const added = lines.slice(CPU_CHART.series.length);
  assert.deepEqual(added.map((line) => line.key), ["component:service:guardd", "component:container:authelia"]);
  for (const line of added) {
    assert.equal(line.hidden, true);
    assert.equal(line.component, true);
    assert.equal(line.percent, true);
    assert.equal(line.bytes, false);
  }
  const memory = core.seriesFor(MEMORY_CHART, {components: parts(["service", "guardd"])});
  assert.equal(memory[memory.length - 1].bytes, true);
});

test("a part keeps its colour whichever order the collector lists it in", () => {
  // Parts arrive busiest first, and the order changes with every refresh.
  const one = core.seriesFor(CPU_CHART, {components: parts(["service", "guardd"], ["service", "certd"])});
  const two = core.seriesFor(CPU_CHART, {components: parts(["service", "certd"], ["service", "guardd"])});
  const colour = (lines, key) => lines.find((line) => line.key === key).color;
  for (const key of ["component:service:guardd", "component:service:certd"]) {
    assert.equal(colour(one, key), colour(two, key));
  }
  assert.notEqual(colour(one, "component:service:guardd"), colour(one, "component:service:certd"));
});

test("a line is shown by its own default until the operator chooses", () => {
  const [average, , other] = CPU_CHART.series;
  assert.equal(core.lineVisible({}, "cpu", average), true);
  assert.equal(core.lineVisible({}, "cpu", other), false);
});

test("only a choice that differs from the default is kept", () => {
  const [average, , other] = CPU_CHART.series;
  let choices = core.lineChoicesAfter({}, "cpu", average, false);
  assert.deepEqual(choices, {cpu: {cpu_avg: false}});
  assert.equal(core.lineVisible(choices, "cpu", average), false);
  // Back to the default: nothing left to remember, so a later change of
  // default reaches this browser too.
  choices = core.lineChoicesAfter(choices, "cpu", average, true);
  assert.deepEqual(choices, {cpu: {}});
  choices = core.lineChoicesAfter(choices, "cpu", other, true);
  assert.deepEqual(choices, {cpu: {other: true}});
});

test("a choice on one chart leaves the others and the old choices alone", () => {
  const before = {memory: {memory_total: false}};
  const after = core.lineChoicesAfter(before, "cpu", CPU_CHART.series[0], false);
  assert.deepEqual(after, {memory: {memory_total: false}, cpu: {cpu_avg: false}});
  assert.deepEqual(before, {memory: {memory_total: false}});
});

/* ---------- scale ---------- */

test("the scale tops out at 1, 2 or 5 of the value's power of ten", () => {
  assert.equal(core.niceCeiling(0.7, false), 1);
  assert.equal(core.niceCeiling(1, false), 1);
  assert.equal(core.niceCeiling(1.3, false), 2);
  assert.equal(core.niceCeiling(44, false), 50);
  assert.equal(core.niceCeiling(51, false), 100);
  assert.equal(core.niceCeiling(180, false), 200);
});

test("an empty or broken chart still has a scale", () => {
  for (const value of [0, -5, NaN, undefined]) {
    assert.equal(core.niceCeiling(value, false), 1);
    assert.equal(core.niceCeiling(value, true), 1);
  }
});

test("bytes round in their own units, so the axis reads 1 and 2 GiB", () => {
  // A 2 GiB machine reports a little under 2 GiB in all.
  const top = core.niceCeiling(1.9 * GiB, true);
  assert.equal(top, 2 * GiB);
  assert.equal(top / 2, GiB);
  assert.equal(core.niceCeiling(4.66 * GiB, true), 5 * GiB);
  assert.equal(core.niceCeiling(700 * MiB, true), 1000 * MiB);
});

test("just under 1024 of a unit tops out at one of the next", () => {
  // 1010 MiB rounded to 2000 MiB, which the axis printed as 1.95 GiB.
  assert.equal(core.niceCeiling(1010 * MiB, true), GiB);
  assert.equal(core.niceCeiling(1023 * KiB, true), MiB);
  assert.equal(core.niceCeiling(1000 * MiB, true), 1000 * MiB);
});

test("counters become rates per second, whatever the resolution", () => {
  const payload = {resolution_seconds: 300, points: [0, 300], series: {requests: [600, 1500]}};
  const view = core.chartData(REQUESTS_CHART, payload);
  assert.deepEqual(view.datasets[0].values, [2, 5]);
  assert.equal(view.step, 300);
  assert.equal(view.top, 5);
});

test("a chart without a resolution counts per minute", () => {
  const view = core.chartData(REQUESTS_CHART, {points: [0], series: {requests: [120]}});
  assert.equal(view.step, 60);
  assert.deepEqual(view.datasets[0].values, [2]);
});

test("percentages are never divided by the bucket", () => {
  const payload = {resolution_seconds: 60, series: {cpu_avg: [40], cpu_max: [70]}};
  const view = core.chartData(CPU_CHART, payload);
  assert.deepEqual(view.datasets.map((set) => set.values[0]), [40, 70]);
});

test("hiding the big lines lets the small ones fill the scale", () => {
  const payload = {
    resolution_seconds: 60,
    series: {cpu_avg: [30], cpu_max: [90]},
    components: [{group: "service", name: "guardd", values: [3]}]
  };
  const everything = core.chartData(CPU_CHART, payload, () => true);
  assert.equal(everything.top, 100);
  const small = core.chartData(CPU_CHART, payload, (spec) => spec.component === true);
  assert.deepEqual(small.datasets.map((set) => set.spec.key), ["component:service:guardd"]);
  assert.equal(small.top, 5);
});

test("by default a chart draws the lines that are not hidden", () => {
  const payload = {series: {cpu_avg: [1], cpu_max: [2], other: [99]}};
  const view = core.chartData(CPU_CHART, payload);
  assert.deepEqual(view.datasets.map((set) => set.spec.key), ["cpu_avg", "cpu_max"]);
  assert.equal(view.top, 2);
});

test("time labels: first and last always, no more than fit, five at most", () => {
  assert.deepEqual(core.timeLabelIndexes(0, 500), []);
  assert.deepEqual(core.timeLabelIndexes(1, 500), [0]);
  assert.deepEqual(core.timeLabelIndexes(100, 540), [0, 25, 50, 74, 99]);
  // A phone in full screen: room for two.
  assert.deepEqual(core.timeLabelIndexes(100, 200), [0, 99]);
  assert.deepEqual(core.timeLabelIndexes(3, 2000), [0, 1, 2]);
});

/* ---------- legend ---------- */

test("a Peak line reads the highest over the period, and when it was", () => {
  // The legend used to show the last bucket: "Peak: 7" under a chart
  // that climbs to 44.
  const reading = core.legendReading({summary: "max"}, [3, 44, 12, 44, 7]);
  assert.deepEqual(reading, {value: 44, index: 1});
});

test("an Average line reads the mean over the period", () => {
  assert.deepEqual(core.legendReading({summary: "mean"}, [10, 20, 30]), {value: 20, index: null});
});

test("any other line reads its latest value", () => {
  assert.deepEqual(core.legendReading({summary: "last"}, [5, 6, 7]), {value: 7, index: null});
  assert.deepEqual(core.legendReading({}, [5, 6, "x"]), {value: 6, index: null});
});

test("readings skip what is not a number and survive an empty line", () => {
  assert.deepEqual(core.legendReading({summary: "max"}, ["x", 4, undefined]), {value: 4, index: 1});
  assert.equal(core.legendReading({summary: "mean"}, ["x", 4, undefined, 8]).value, 6);
  for (const summary of ["max", "mean", "last"]) {
    assert.deepEqual(core.legendReading({summary}, []), {value: 0, index: null});
  }
});

test("byte sizes are given in the largest unit below 1024", () => {
  assert.equal(core.formatBytes(0), "0 B");
  assert.equal(core.formatBytes(1023), "1023 B");
  assert.equal(core.formatBytes(1536), "1.5 KiB");
  assert.equal(core.formatBytes(2 * GiB), "2 GiB");
  assert.equal(core.formatBytes(-3 * MiB), "-3 MiB");
  assert.equal(core.formatBytes(5000 * GiB * 1024), "5000 TiB");
  for (const value of [NaN, undefined, "x", Infinity]) {
    assert.equal(core.formatBytes(value), "—");
  }
});

test("the page's own number format is used for the figure", () => {
  const russian = new Intl.NumberFormat("ru", {maximumFractionDigits: 2});
  assert.equal(core.formatBytes(1.5 * MiB, (value) => russian.format(value)), "1,5 MiB");
});

/* ---------- availability ---------- */

test("durations read the same in every language", () => {
  assert.equal(core.formatDuration(0), "0s");
  assert.equal(core.formatDuration(45), "45s");
  assert.equal(core.formatDuration(65), "1m 5s");
  assert.equal(core.formatDuration(2 * HOUR + 15 * MINUTE + 9), "2h 15m");
  assert.equal(core.formatDuration(3 * DAY + 4 * HOUR + 59), "3d 4h");
  assert.equal(core.formatDuration(-10), "0s");
  assert.equal(core.formatDuration("x"), "0s");
  assert.equal(core.formatDuration(44.6), "45s");
});

function span(state, start, seconds) {
  return {state, start, end: start + seconds};
}

// Outages of `down` seconds separated by `up` seconds, starting at `start`.
function flapping(start, count, down, up) {
  const spans = [];
  let at = start;
  for (let index = 0; index < count; index += 1) {
    spans.push(span("DOWN", at, down));
    at += down;
    if (index < count - 1) {
      spans.push(span("UP", at, up));
      at += up;
    }
  }
  return spans;
}

test("a run of short outages is one piece, drawn to scale", () => {
  // Sixty-nine outages, 24 minutes in all, each kept its minimum width and
  // painted nine hours of a day's bar red: 98% available looked 40% down.
  const outages = flapping(HOUR, 69, 21, 3 * MINUTE);
  const spans = [span("UP", 0, HOUR), ...outages, span("UP", outages[outages.length - 1].end, 10 * HOUR)];
  const pieces = core.timelinePieces(spans, DAY);
  assert.equal(pieces.length, 3);
  assert.equal(pieces[0].span.state, "UP");
  const run = pieces[1];
  assert.equal(run.flapping, true);
  assert.equal(run.outages, 69);
  assert.equal(run.down, 69 * 21);
  assert.equal(run.start, HOUR);
  assert.equal(run.end, outages[outages.length - 1].end);
  assert.equal(pieces[2].span.state, "UP");
});

test("one short outage alone is still an outage", () => {
  const spans = [span("UP", 0, HOUR), span("DOWN", HOUR, 30), span("UP", HOUR + 30, HOUR)];
  const pieces = core.timelinePieces(spans, DAY);
  assert.deepEqual(pieces.map((piece) => piece.span.state), ["UP", "DOWN", "UP"]);
});

test("a long outage or up time long enough to see ends a run", () => {
  const short = 60; // well under 0.6% of a day
  const spans = [
    span("DOWN", 0, short), span("UP", short, 60), span("DOWN", 2 * short, short),
    // Up for two hours: visible on a day's bar, so the run stops here.
    span("UP", 3 * short, 2 * HOUR),
    span("DOWN", 3 * short + 2 * HOUR, short),
    span("UP", 4 * short + 2 * HOUR, 60),
    span("DOWN", 5 * short + 2 * HOUR, 3 * HOUR)
  ];
  const pieces = core.timelinePieces(spans, DAY);
  assert.equal(pieces[0].flapping, true);
  assert.equal(pieces[0].outages, 2);
  assert.equal(pieces[1].span.state, "UP");
  // A lone short outage before the long one is drawn as itself.
  assert.deepEqual(pieces.slice(2).map((piece) => piece.span.state), ["DOWN", "UP", "DOWN"]);
});

test("what counts as short depends on the period shown", () => {
  const spans = flapping(0, 3, 5 * MINUTE, MINUTE);
  // Five minutes is a sliver of a day but a twelfth of an hour.
  assert.equal(core.timelinePieces(spans, DAY)[0].flapping, true);
  assert.equal(core.timelinePieces(spans, HOUR).length, spans.length);
});

test("an unstable stretch is striped in proportion to the time down", () => {
  assert.equal(core.flapStripe({start: 0, end: 1000, down: 500}), 5);
  assert.equal(core.flapStripe({start: 0, end: 1000, down: 300}), 3);
  // Never all red and never none: it was neither down nor up throughout.
  assert.equal(core.flapStripe({start: 0, end: 1000, down: 1}), 1);
  assert.equal(core.flapStripe({start: 0, end: 1000, down: 999}), core.FLAP_STRIPE_PX - 1);
  assert.equal(core.flapStripe({start: 5, end: 5, down: 0}), core.FLAP_STRIPE_PX - 1);
});

test("the total says how many outages it is made of", () => {
  const entry = {
    current_state: "UP",
    spans: [span("UP", 0, 100), span("DOWN", 100, 50), span("UP", 150, 50), span("MAINT", 200, 10), span("UP", 210, 90)]
  };
  assert.deepEqual(core.outageFacts(entry, 300), {count: 2, ongoingSeconds: null});
  assert.deepEqual(core.outageFacts({spans: []}, 300), {count: 0, ongoingSeconds: null});
});

test("an outage still going on says for how long", () => {
  const entry = {current_state: "DOWN", spans: [span("UP", 0, 200), span("DOWN", 200, 100)]};
  assert.deepEqual(core.outageFacts(entry, 300), {count: 1, ongoingSeconds: 100});
  // Down now, but the last outage in the list ended before the window did:
  // the list was cut, so how long it has lasted is not known.
  assert.equal(core.outageFacts(entry, 400).ongoingSeconds, null);
  // Recorded down to the end, but the server reports it up again.
  assert.equal(core.outageFacts(Object.assign({}, entry, {current_state: "UP"}), 300).ongoingSeconds, null);
});

/* ---------- backends ---------- */

const BACKENDS = [
  {label: "shop", bytes_total: 10},
  {label: "blog", bytes_total: 300},
  {label: "api", bytes_total: 10},
  {label: "cdn", bytes_total: 5000}
];

test("backends are busiest first unless asked otherwise, ties by name", () => {
  const labels = (order) => core.sortedBackends(BACKENDS, order).map((item) => item.label);
  assert.deepEqual(labels("desc"), ["cdn", "blog", "api", "shop"]);
  assert.deepEqual(labels(undefined), ["cdn", "blog", "api", "shop"]);
  assert.deepEqual(labels("asc"), ["api", "shop", "blog", "cdn"]);
  assert.deepEqual(labels("name"), ["api", "blog", "cdn", "shop"]);
  assert.equal(BACKENDS[0].label, "shop");
});

/* ---------- drag to zoom ---------- */

const GEOMETRY = {points: [1000, 1060, 1120, 1600], left: 50, plotWidth: 300};

test("a position on the chart is a time between the samples either side", () => {
  // Samples are evenly spaced on screen whatever their timestamps: the gap
  // before the last one is wider in time, not in pixels.
  assert.equal(core.timeAtX(GEOMETRY, 50), 1000);
  assert.equal(core.timeAtX(GEOMETRY, 150), 1060);
  assert.equal(core.timeAtX(GEOMETRY, 200), 1090);
  assert.equal(core.timeAtX(GEOMETRY, 300), 1360);
  assert.equal(core.timeAtX(GEOMETRY, 350), 1600);
});

test("a drag past either edge stops at the edge", () => {
  assert.equal(core.timeAtX(GEOMETRY, 0), 1000);
  assert.equal(core.timeAtX(GEOMETRY, 999), 1600);
  assert.equal(core.timeAtX({points: [42], left: 0, plotWidth: 10}, 7), 42);
});

test("a narrow selection still shows five minutes, centred on it", () => {
  assert.deepEqual(core.zoomWindow(10000, 10060), {since: 9880, until: 10180});
  assert.equal(core.MIN_ZOOM_SECONDS, 300);
});

test("a selection becomes whole seconds that contain it", () => {
  assert.deepEqual(core.zoomWindow(1000.4, 5000.2), {since: 1000, until: 5001});
});

test("each preset has its length, and anything else is a day", () => {
  assert.equal(core.rangeSeconds("1h"), HOUR);
  assert.equal(core.rangeSeconds("7d"), 7 * DAY);
  assert.equal(core.rangeSeconds("1y"), 365 * DAY);
  assert.equal(core.rangeSeconds("bogus"), DAY);
});
