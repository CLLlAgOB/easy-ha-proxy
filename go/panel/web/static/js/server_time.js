/* Display and calendar inputs use the gateway's zone, never the browser's.
 * Stored/API instants remain unchanged. This does not patch Date or Intl. */
(function (root, factory) {
  "use strict";
  const create = factory();
  if (typeof module === "object" && module.exports) module.exports = create;
  else root.EasyHaProxyTime = create(root.HAPROXY_ADMIN_TIME || {}, root.document.documentElement.lang || undefined);
})(typeof window !== "undefined" ? window : globalThis, function () {
  "use strict";
  return function create(config, language) {
    let zone = String(config.zone || "UTC");
    try { new Intl.DateTimeFormat("en", {timeZone: zone}).format(0); } catch (_) { zone = "UTC"; }
    const cache = new Map();
    const tick = () => typeof performance !== "undefined" ? performance.now() : Date.now();
    const started = tick(), baseNow = Number(config.now) || Date.now();
    function formatter(options) {
      const key = JSON.stringify(options || {});
      if (!cache.has(key)) cache.set(key, new Intl.DateTimeFormat(language, {hourCycle: "h23", ...options, timeZone: zone}));
      return cache.get(key);
    }
    const calendar = new Intl.DateTimeFormat("en-CA-u-nu-latn", {timeZone: zone, hourCycle: "h23",
      year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit"});
    function parts(value) {
      return Object.fromEntries(calendar.formatToParts(new Date(value)).filter((part) => part.type !== "literal").map((part) => [part.type, part.value]));
    }
    const utc = (p) => Date.UTC(Number(p.year), Number(p.month) - 1, Number(p.day), Number(p.hour), Number(p.minute), Number(p.second));
    function fromLocalInput(value) {
      const match = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?$/.exec(String(value));
      if (!match) return null;
      const wanted = {year: match[1], month: match[2], day: match[3], hour: match[4], minute: match[5], second: match[6] || "00"};
      const base = utc(wanted), check = new Date(base);
      if (check.getUTCFullYear() !== Number(wanted.year) || check.getUTCMonth() + 1 !== Number(wanted.month) ||
          check.getUTCDate() !== Number(wanted.day) || check.getUTCHours() !== Number(wanted.hour) ||
          check.getUTCMinutes() !== Number(wanted.minute) || check.getUTCSeconds() !== Number(wanted.second)) return null;
      const offsets = new Set([-36, 0, 36].map((hours) => { const sample = base + hours * 3600000; return utc(parts(sample)) - sample; }));
      const matches = [...offsets].map((offset) => base - offset).filter((candidate) => {
        const actual = parts(candidate); return Object.keys(wanted).every((key) => Number(actual[key]) === Number(wanted[key]));
      });
      // A repeated hour picks its first occurrence, as a native calendar
      // input does. A nonexistent local time is rejected instead of shifted.
      return matches.length ? Math.min(...matches) : null;
    }
    function toLocalInput(value) {
      const p = parts(value); return `${p.year}-${p.month}-${p.day}T${p.hour}:${p.minute}`;
    }
    function parse(value) {
      if (value instanceof Date) return Number.isFinite(value.getTime()) ? value : null;
      if (typeof value === "number") return Number.isFinite(value) ? new Date(value) : null;
      let text = String(value || "").trim();
      if (!text) return null;
      text = text.replace(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/, "$1-$2-$3T$4:$5:$6Z");
      // Legacy systemd strings are explicitly local to this gateway. New
      // timer APIs provide an epoch to avoid locale/DST ambiguity entirely.
      const native = /^(?:[A-Za-z]+ )?(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})(?:\.\d+)? ([A-Za-z0-9+:-]+)$/.exec(text);
      if (native) text = native[1] + "T" + native[2] + (["UTC", "GMT"].includes(native[3]) ? "Z"
        : /^[+-]\d{2}:?\d{2}$/.test(native[3]) ? native[3] : "");
      if (/^\d{4}-\d{2}-\d{2}$/.test(text)) text += "T00:00:00";
      const local = /^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?)(?:\.(\d+))?$/.exec(text);
      if (local) {
        const stamp = fromLocalInput(local[1]);
        return stamp === null ? null : new Date(stamp + Number((local[2] || "").slice(0, 3).padEnd(3, "0")));
      }
      const result = new Date(text); return Number.isFinite(result.getTime()) ? result : null;
    }
    function format(value, options, empty = "—") {
      const date = parse(value); return date ? formatter(options).format(date) : empty;
    }
    return Object.freeze({zone, formatter, parse, fromLocalInput, toLocalInput, now: () => baseNow + tick() - started,
      asDate: (value) => parse(value) || new Date(NaN),
      dateTime: (value, empty) => format(value, {dateStyle: "short", timeStyle: "medium"}, empty),
      date: (value, empty) => format(value, {dateStyle: "short"}, empty),
      time: (value, empty) => format(value, {hour: "2-digit", minute: "2-digit", second: "2-digit"}, empty)});
  };
});
