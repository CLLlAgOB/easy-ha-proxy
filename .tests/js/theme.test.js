"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const source = fs.readFileSync(path.join(__dirname, "../../docker/app/haproxy_admin/static/js/theme.js"), "utf8");

function boot({saved = null, dark = false, blocked = false} = {}) {
  const classes = new Set();
  const callbacks = {};
  const attrs = {};
  const stored = new Map(saved === null ? [] : [["theme", saved]]);
  const root = {dataset: {}, classList: {
    add(name) { classes.add(name); },
    toggle(name, enabled) { if (enabled) classes.add(name); else classes.delete(name); }
  }};
  let ready = false;
  const button = {setAttribute(name, value) { attrs[name] = value; }, addEventListener(name, fn) { callbacks["button:" + name] = fn; }};
  const media = {matches: dark, addEventListener(name, fn) { callbacks["media:" + name] = fn; }};
  const document = {documentElement: root,
    getElementById() { return ready ? button : null; },
    addEventListener(name, fn) { callbacks[name] = fn; }
  };
  const storage = {getItem(key) { return stored.get(key) || null; }, setItem(key, value) { stored.set(key, value); }};
  const window = {matchMedia() { return media; }, dispatchEvent() {}};
  Object.defineProperty(window, "localStorage", {get() { if (blocked) throw new Error("storage blocked"); return storage; }});
  vm.runInNewContext(source, {window, document, CustomEvent: class { constructor(type, options) {this.type = type; this.detail = options.detail;} }});
  return {root, classes, attrs, stored,
    ready() { ready = true; callbacks.DOMContentLoaded(); },
    click() { callbacks["button:click"](); },
    system(value) { media.matches = value; callbacks["media:change"](); }
  };
}

test("the system theme is applied before the DOM is ready", () => {
  const page = boot({dark: true});
  assert.equal(page.root.dataset.theme, "dark");
  page.ready();
  assert.equal(page.attrs["aria-pressed"], "true");
  page.system(false);
  assert.equal(page.root.dataset.theme, "light");
});
test("the existing preference wins over the system and clicking persists a choice", () => {
  const page = boot({saved: "light", dark: true});
  page.ready();
  assert.equal(page.root.dataset.theme, "light");
  page.click();
  assert.equal(page.root.dataset.theme, "dark");
  assert.equal(page.stored.get("theme"), "dark");
  page.system(false);
  assert.equal(page.root.dataset.theme, "dark");
  assert.equal(page.attrs["aria-pressed"], "true");
});
test("storage being unavailable does not prevent reading or switching the theme", () => {
  const page = boot({blocked: true, dark: true});
  page.ready();
  page.click();
  assert.equal(page.root.dataset.theme, "light");
  assert.equal(page.classes.has("light-theme"), true);
});
test("an unsupported saved value falls back to the system", () => {
  const page = boot({saved: "unsupported", dark: true});
  assert.equal(page.root.dataset.theme, "dark");
});
