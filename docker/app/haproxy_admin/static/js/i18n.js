/* Shared localization for static and dynamically generated interface text.
 *
 * createTranslator holds the rules -- what a catalogue entry may replace and
 * where -- and needs nothing from the page, so the tests in .tests/js/ load
 * this file and run them against the real catalogue. install() is the page:
 * it reads the catalogue the server put in HAPROXY_ADMIN_I18N and translates
 * the DOM as it changes.
 */
(function (root, factory) {
  "use strict";
  const api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    api.install(root);
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const skippedParents = new Set(["CODE", "PRE", "SCRIPT", "STYLE", "TEXTAREA"]);
  const translatableAttributes = [
    "title", "placeholder", "aria-label", "data-confirm", "data-empty-label"
  ];
  // A string without an exact catalog hit is scanned against every rule, which
  // is the expensive path. The same labels repeat across a page and on every
  // dynamically rendered row, so remember what each source string resolves to.
  const TRANSLATION_CACHE_LIMIT = 5000;

  // A word as a sentence has it: not part of an identifier, a key=value, a
  // path or a domain. A dot ends a word only where it ends a sentence too.
  const WORD_BEFORE = "(^|[^\\p{L}\\p{N}_=./-])";
  const WORD_AFTER = "(?=$|\\.(?![\\p{L}\\p{N}])|[^\\p{L}\\p{N}_=./-])";
  // A plain English word: lowercase, or capitalised. Acronyms and mixed case
  // -- HAProxy, TLS, IPv6 -- are names, not words to translate.
  // Field paths -- sites[0].cookie_attrs -- are names as well.
  const PLAIN_WORD = /(^|[^\p{L}\p{N}_=./[\]-])([A-Z]?[a-z]+)(?=$|\.(?![\p{L}\p{N}])|[^\p{L}\p{N}_=./[\]-])/gu;
  const PLACEHOLDER = /\{[A-Za-z0-9_]+\}/g;
  // A value quoted into a sentence is what someone typed, not a word of it.
  const QUOTED = /(^|[\s([:=,])(?:'[^'\n]*'|"[^"\n]*"|`[^`\n]*`|«[^»\n]*»)/g;

  function createTranslator(catalogue) {
    const messages = catalogue || {};
    const replacements = Object.entries(messages)
      .filter(([source, target]) => source && source !== target)
      .sort((left, right) => right[0].length - left[0].length)
      .map(([source, target]) => ({
        source,
        target,
        // A token-aware expression prevents short entries such as "and" from
        // changing letters in the middle of another word, a hyphenated
        // technical identifier, a machine-readable key=value fragment, a
        // path or a domain.
        pattern: /^[\p{L}\p{N}_-]+$/u.test(source)
          ? new RegExp(`${WORD_BEFORE}${escapeRegex(source)}${WORD_AFTER}`, "gu")
          : null
      }));
    // English words a translation keeps on purpose -- a product's name,
    // "backend" -- may stay in a translated sentence.
    const kept = new Set();
    Object.values(messages).forEach((target) => {
      for (const match of String(target).matchAll(/[A-Za-z]+/g)) kept.add(match[0]);
    });
    // Any other English word left after the known pieces were replaced means
    // the sentence was only partly known. Half a sentence in each language
    // reads worse than the whole of it in English, so it stays in English.
    function partlyKnown(text) {
      const bare = text.replace(PLACEHOLDER, " ").replace(QUOTED, "$1 ");
      for (const match of bare.matchAll(PLAIN_WORD)) {
        if (match[2].length >= 2 && !kept.has(match[2])) return true;
      }
      return false;
    }
    const translationCache = new Map();

    return function translate(value, params) {
      if (value == null) return "";
      const source = String(value);
      if (!params) {
        const cached = translationCache.get(source);
        if (cached !== undefined) return cached;
      }
      const normalized = source.replace(/\s+/g, " ").trim();
      let result = Object.prototype.hasOwnProperty.call(messages, source)
        ? messages[source]
        : (Object.prototype.hasOwnProperty.call(messages, normalized)
            ? messages[normalized]
            : source);

      if (result === source) {
        for (const item of replacements) {
          if (item.pattern) {
            result = result.replace(item.pattern, (match, prefix) => prefix + item.target);
          } else if (result.includes(item.source)) {
            result = result.split(item.source).join(item.target);
          }
        }
        if (result !== source && partlyKnown(result)) result = source;
      }
      if (!params) {
        if (translationCache.size >= TRANSLATION_CACHE_LIMIT) translationCache.clear();
        translationCache.set(source, result);
      }

      if (params) {
        result = result.replace(/\{([a-zA-Z0-9_]+)\}/g, (match, key) =>
          Object.prototype.hasOwnProperty.call(params, key) ? String(params[key]) : match
        );
      }
      return result;
    };
  }

  // Machine output -- paths, logs, signatures, a daemon's own words -- is
  // marked on itself or an ancestor and left exactly as it is.
  function isTranslationSkipped(element) {
    for (let current = element; current; current = current.parentElement) {
      if (skippedParents.has(current.tagName)) return true;
      if (current.hasAttribute("data-i18n-skip")) return true;
      if (current.getAttribute("translate") === "no") return true;
      if (current.classList.contains("notranslate")) return true;
    }
    return false;
  }

  function install(window) {
    const document = window.document;
    const config = window.HAPROXY_ADMIN_I18N || {};
    const translate = createTranslator(config.messages);

    function translateTextNode(node) {
      if (!node.parentElement || isTranslationSkipped(node.parentElement)) return;
      const original = node.nodeValue || "";
      const leading = original.match(/^\s*/)[0];
      const trailing = original.match(/\s*$/)[0];
      const content = original.slice(leading.length, original.length - trailing.length || undefined);
      if (!content) return;
      const translated = translate(content);
      if (translated !== content) node.nodeValue = leading + translated + trailing;
    }

    function translateElement(element) {
      if (!(element instanceof window.Element)) return;
      if (isTranslationSkipped(element)) return;
      for (const attribute of translatableAttributes) {
        if (!element.hasAttribute(attribute)) continue;
        const source = element.getAttribute(attribute);
        const translated = translate(source);
        if (translated !== source) element.setAttribute(attribute, translated);
      }
    }

    function translateTree(root) {
      if (root.nodeType === window.Node.TEXT_NODE) {
        translateTextNode(root);
        return;
      }
      if (!(root instanceof window.Element) && root !== document) return;
      if (root instanceof window.Element && isTranslationSkipped(root)) return;
      if (root instanceof window.Element) translateElement(root);

      const walker = document.createTreeWalker(
        root,
        window.NodeFilter.SHOW_ELEMENT | window.NodeFilter.SHOW_TEXT
      );
      let node;
      while ((node = walker.nextNode())) {
        if (node.nodeType === window.Node.TEXT_NODE) translateTextNode(node);
        else translateElement(node);
      }
    }

    const observer = new window.MutationObserver((changes) => {
      observer.disconnect();
      for (const change of changes) {
        for (const node of change.addedNodes) translateTree(node);
        if (change.type === "characterData") translateTextNode(change.target);
      }
      observer.observe(document.documentElement, {childList: true, subtree: true, characterData: true});
    });

    window.i18n = Object.freeze({
      language: config.language || "en",
      languages: config.languages || [],
      t: translate,
      translateTree
    });
    window.t = translate;

    const originalAlert = window.alert.bind(window);
    const originalConfirm = window.confirm.bind(window);
    const originalPrompt = window.prompt.bind(window);
    window.alert = (message) => originalAlert(translate(message));
    window.confirm = (message) => originalConfirm(translate(message));
    window.prompt = (message, defaultValue) => originalPrompt(translate(message), defaultValue);

    observer.observe(document.documentElement, {childList: true, subtree: true, characterData: true});
    document.addEventListener("DOMContentLoaded", () => translateTree(document));
  }

  return {createTranslator, isTranslationSkipped, install};
});
