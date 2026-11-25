// Behaviour of the page translator (i18n.js): what a catalogue entry may
// replace and where, what it must leave alone, and what that means with the
// real Russian catalogue. Run with: node --test .tests/js/
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");
const vm = require("node:vm");

const {russianCatalogue} = require("./catalogue.js");

const STATIC = path.join(__dirname, "../../go/panel/web/static/js");
const i18n = require(path.join(STATIC, "i18n.js"));
const monitoring = require(path.join(STATIC, "monitoring_core.js"));

const CYRILLIC = /[Ѐ-ӿ]/;
const LATIN_WORD = /[A-Za-z]{2,}/;

const RUSSIAN = russianCatalogue();
const real = i18n.createTranslator(RUSSIAN);

const t = i18n.createTranslator({
  "Save changes": "Сохранить изменения",
  "and": "и",
  "ban": "бан",
  "limit": "лимит",
  "rules": "правила",
  "local": "локальный",
  "Backend": "Бэкенд",
  "Backend traffic": "Трафик бэкендов",
  "differs from": "отличается от",
  "outages: {count}": "отключений: {count}",
  "OK": "OK"
});

/* ---------- the rules ---------- */

test("page labels only compile and run fallback patterns they actually contain", () => {
  let compiled = 0;
  let replaced = 0;
  class CountedRegExp extends RegExp {
    constructor(...args) {
      super(...args);
      compiled++;
    }
    [Symbol.replace](...args) {
      replaced++;
      return super[Symbol.replace](...args);
    }
  }
  const sandbox = {module: {exports: {}}, RegExp: CountedRegExp};
  vm.runInNewContext(fs.readFileSync(path.join(STATIC, "i18n.js"), "utf8"), sandbox);
  const messages = Object.fromEntries(Array.from({length: 1000}, (_, index) =>
    [`Unrelated phrase ${index}`, `Другая фраза ${index}`]
  ));
  messages["Backend traffic"] = "Трафик бэкендов";
  const translate = sandbox.module.exports.createTranslator(messages);
  // The catalogue is rebuilt on every navigation. Exact hits and machine
  // values must not compile or run thousands of Unicode boundary patterns.
  assert.equal(compiled, 0);
  assert.equal(translate("Backend traffic"), "Трафик бэкендов");
  assert.equal(translate("192.0.2.5"), "192.0.2.5");
  assert.equal(compiled, 0);
  assert.equal(replaced, 0);
  assert.equal(translate("Backend traffic: 5"), "Трафик бэкендов: 5");
  assert.equal(compiled, 1);
  assert.equal(replaced, 1);
  assert.equal(translate("Backend traffic: 6"), "Трафик бэкендов: 6");
  assert.equal(compiled, 1);
  assert.equal(replaced, 2);
});

test("a string the catalogue knows comes back translated whole", () => {
  assert.equal(t("Save changes"), "Сохранить изменения");
  // Markup breaks lines and indents; the catalogue key does not.
  assert.equal(t("  Save\n      changes "), "Сохранить изменения");
});

test("nothing to translate is an empty string, not 'null'", () => {
  assert.equal(t(null), "");
  assert.equal(t(undefined), "");
  assert.equal(t(0), "0");
});

test("a single word is replaced only where it stands as a word", () => {
  assert.equal(t("limit and ban"), "лимит и бан");
  assert.equal(t("limit, ban."), "лимит, бан.");
  // Identifiers and key=value fragments are machine data.
  for (const text of ["rate-limit", "ban_list", "ban=1", "mode=ban", "limit2", "banned"]) {
    assert.equal(t(text), text);
  }
});

test("a longer entry wins over the words inside it", () => {
  assert.equal(t("Backend traffic: 5"), "Трафик бэкендов: 5");
  assert.equal(t("Backend: OK"), "Бэкенд: OK");
});

test("a path or a domain is machine data, not words", () => {
  // Shown to an operator for a failed backup before the jobs table was
  // exempt: "haproxy_ban.правила", "/usr/локальный/bin".
  for (const text of ["etc/iptables/haproxy_ban.rules", "/usr/local/bin/update-geoip.sh",
                      "rules.example.test", "update.available"]) {
    assert.equal(t(text), text);
  }
  // A dot that ends the sentence still ends the word.
  assert.equal(t("ban."), "бан.");
});

test("a sentence known only in part stays whole in English", () => {
  // "the правило is switched выкл" in the alerts' history, and the broker's
  // "an applied image digest отличается от the reviewed update plan".
  for (const text of [
    "an applied image digest differs from the reviewed update plan",
    "standard and Android",
    "Backend: shop",
    "the rules are local"
  ]) {
    assert.equal(t(text), text);
  }
  // Names, acronyms, numbers, placeholders and machine data are not words
  // left untranslated.
  assert.equal(t("limit and HAProxy"), "лимит и HAProxy");
  assert.equal(t("ban 10.0.0.1 and limit 5"), "бан 10.0.0.1 и лимит 5");
  assert.equal(t("Backend: shop.example.test"), "Бэкенд: shop.example.test");
  // A quoted value is what someone typed; a field's path is a name.
  assert.equal(t("Backend: 'my shop'"), "Бэкенд: 'my shop'");
  assert.equal(t("sites[0].limit: ban"), "sites[0].limit: бан");
});

test("an English word a translation keeps may stay", () => {
  // A catalogue that keeps a word in English -- a product's name -- keeps it
  // in a sentence as well.
  const keeping = i18n.createTranslator({"Sign in": "Войти", "with": "через", "Authelia": "Authelia"});
  assert.equal(keeping("Sign in with Authelia"), "Войти через Authelia");
});

test("values go in after translation and are never translated", () => {
  assert.equal(t("outages: {count}", {count: 3}), "отключений: 3");
  // A site, a path or a daemon's word put into a sentence stays as given.
  assert.equal(t("outages: {count}", {count: "ban"}), "отключений: ban");
  assert.equal(t("Backend: {name}", {name: "local"}), "Бэкенд: local");
});

test("a placeholder without a value is left for the reader to see", () => {
  assert.equal(t("outages: {count}", {}), "отключений: {count}");
  assert.equal(t("{a} and {b}", {a: 1}), "1 и {b}");
});

test("a call with values does not change what the same text means without them", () => {
  assert.equal(t("outages: {count}", {count: 7}), "отключений: 7");
  assert.equal(t("outages: {count}"), "отключений: {count}");
  assert.equal(t("outages: {count}", {count: 8}), "отключений: 8");
});

test("each catalogue is its own translator", () => {
  const other = i18n.createTranslator({"and": "und", "salt": "Salz", "pepper": "Pfeffer"});
  assert.equal(other("salt and pepper"), "Salz und Pfeffer");
  assert.equal(t("salt and pepper"), "salt and pepper");
  assert.equal(i18n.createTranslator(undefined)("Save changes"), "Save changes");
});

/* ---------- what the page leaves alone ---------- */

function element(tagName, {attributes = {}, classes = [], parent = null} = {}) {
  return {
    tagName,
    parentElement: parent,
    hasAttribute: (name) => Object.prototype.hasOwnProperty.call(attributes, name),
    getAttribute: (name) =>
      Object.prototype.hasOwnProperty.call(attributes, name) ? attributes[name] : null,
    classList: {contains: (name) => classes.includes(name)}
  };
}

test("text is translated unless it or a container is marked as machine output", () => {
  const page = element("MAIN");
  assert.equal(i18n.isTranslationSkipped(element("SPAN", {parent: page})), false);
  for (const marked of [
    element("DIV", {attributes: {"data-i18n-skip": ""}, parent: page}),
    element("DIV", {attributes: {translate: "no"}, parent: page}),
    element("DIV", {classes: ["notranslate"], parent: page})
  ]) {
    const deep = element("SPAN", {parent: element("B", {parent: marked})});
    assert.equal(i18n.isTranslationSkipped(marked), true);
    assert.equal(i18n.isTranslationSkipped(deep), true);
  }
  assert.equal(
    i18n.isTranslationSkipped(element("DIV", {attributes: {translate: "yes"}, parent: page})),
    false
  );
});

test("code, preformatted text and form fields are never translated", () => {
  for (const tag of ["CODE", "PRE", "SCRIPT", "STYLE", "TEXTAREA"]) {
    const inside = element("SPAN", {parent: element(tag, {parent: element("MAIN")})});
    assert.equal(i18n.isTranslationSkipped(inside), true, tag);
  }
});

/* ---------- with the real catalogue ---------- */

test("a phrase is replaced only where it stands as whole words", () => {
  // "1 day" matched inside "21 days" and gave "21 деньs"; "7 days" inside
  // "27 days" read as a sentence of its own.
  const phrases = i18n.createTranslator({"1 day": "1 день", "7 days": "7 дней", "days": "дн"});
  assert.equal(phrases("21 days"), "21 дн");
  assert.equal(phrases("27 days"), "27 дн");
  assert.equal(phrases("1 day"), "1 день");
  for (const count of [1, 11, 21, 27, 31]) {
    assert.doesNotMatch(real(`${count} days`), /[А-Яа-яЁё]s/u);
  }
});

test("a translation passed through again comes back unchanged", () => {
  // The page is translated as it is parsed and again on DOMContentLoaded.
  // The second pass replaced the English words a translation keeps on purpose:
  // "DB-IP Country Lite" turned into "DB-IP Страна Lite", "host keys" into
  // "ключа хостаs".
  for (const key of [
    "The local DB-IP Country Lite database is used for country lookups and HAProxy access rules.",
    "SSH identity is excluded by default. Restoring host keys on another server duplicates its SSH fingerprint."
  ]) {
    const once = real(key);
    assert.notEqual(once, key);
    assert.equal(real(once), once);
  }
  const fresh = i18n.createTranslator({"limit": "лимит", "ban": "бан"});
  const replaced = fresh("limit, ban");
  assert.equal(replaced, "лимит, бан");
  assert.equal(fresh(replaced), replaced);
});

test("the real catalogue is loaded", () => {
  assert.ok(Object.keys(RUSSIAN).length > 1000);
  assert.equal(real("The update failed"), "Обновление не удалось");
});

test("every value put into a translated sentence reaches it", () => {
  const broken = [];
  for (const key of Object.keys(RUSSIAN)) {
    const names = Array.from(key.matchAll(/\{([a-zA-Z0-9_]+)\}/g), (match) => match[1]);
    if (!names.length) continue;
    const values = Object.fromEntries(names.map((name) => [name, `<${name}#42>`]));
    const result = real(key, values);
    if (names.some((name) => !result.includes(values[name]) || result.includes(`{${name}}`))) {
      broken.push(`${key} -> ${result}`);
    }
  }
  assert.deepEqual(broken, []);
});

test("durations, sizes and percentages come through untouched", () => {
  // Single-letter units are exactly what the fallback would match: if "h"
  // or "m" ever enters the catalogue, "2h 15m" stops reading the same.
  const readings = [];
  for (const seconds of [0, 9, 45, 61, 125, 3599, 3600, 3661, 7325, 86399, 86400, 90061, 864000]) {
    readings.push(monitoring.formatDuration(seconds));
  }
  for (const bytes of [0, 512, 1536, 1.5 * 1024 * 1024, 2 * 1024 ** 3, 3 * 1024 ** 4]) {
    readings.push(monitoring.formatBytes(bytes), `${monitoring.formatBytes(bytes)}/s`);
  }
  readings.push("44%", "0.5%", "100%", "UP · 99.5%", "DOWN · 12%", "MAINT · —");
  for (const reading of readings) {
    assert.equal(real(reading), reading);
  }
});

test("a daemon's sentence comes out in one language", () => {
  // With the real catalogue: whole in Russian when it is known, whole in
  // English when it is not -- never half of each.
  for (const text of [
    "an applied image digest differs from the reviewed update plan",
    "below the configured something else",
    "the rule is switched off for now"
  ]) {
    const result = real(text);
    assert.ok(!(CYRILLIC.test(result) && LATIN_WORD.test(result.replace(/\b[A-Z]{2,}\b/g, ""))), result);
  }
  assert.equal(real("the rule is switched off"), "условие выключено");
  assert.equal(real("/usr/local/bin/update-geoip.sh"), "/usr/local/bin/update-geoip.sh");
});
