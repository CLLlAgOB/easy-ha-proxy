/* Shared localization for static and dynamically generated interface text. */
(function () {
  "use strict";

  const config = window.HAPROXY_ADMIN_I18N || {};
  const messages = config.messages || {};
  const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const replacements = Object.entries(messages)
    .filter(([source, target]) => source && source !== target)
    .sort((left, right) => right[0].length - left[0].length)
    .map(([source, target]) => ({
      source,
      target,
      // A token-aware expression prevents short entries such as "and" from
      // changing letters in the middle of another word, a hyphenated
      // technical identifier, or a machine-readable key=value fragment.
      pattern: /^[\p{L}\p{N}_-]+$/u.test(source)
        ? new RegExp(`(^|[^\\p{L}\\p{N}_=-])${escapeRegex(source)}(?=$|[^\\p{L}\\p{N}_=-])`, "gu")
        : null
    }));
  const translatableAttributes = [
    "title", "placeholder", "aria-label", "data-confirm", "data-empty-label"
  ];
  const skippedParents = new Set(["CODE", "PRE", "SCRIPT", "STYLE", "TEXTAREA"]);

  function isTranslationSkipped(element) {
    for (let current = element; current; current = current.parentElement) {
      if (skippedParents.has(current.tagName)) return true;
      if (current.hasAttribute("data-i18n-skip")) return true;
      if (current.getAttribute("translate") === "no") return true;
      if (current.classList.contains("notranslate")) return true;
    }
    return false;
  }

  function translate(value, params) {
    if (value == null) return "";
    const source = String(value);
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
    }

    if (params) {
      result = result.replace(/\{([a-zA-Z0-9_]+)\}/g, (match, key) =>
        Object.prototype.hasOwnProperty.call(params, key) ? String(params[key]) : match
      );
    }
    return result;
  }

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
    if (!(element instanceof Element)) return;
    if (isTranslationSkipped(element)) return;
    for (const attribute of translatableAttributes) {
      if (!element.hasAttribute(attribute)) continue;
      const source = element.getAttribute(attribute);
      const translated = translate(source);
      if (translated !== source) element.setAttribute(attribute, translated);
    }
  }

  function translateTree(root) {
    if (root.nodeType === Node.TEXT_NODE) {
      translateTextNode(root);
      return;
    }
    if (!(root instanceof Element) && root !== document) return;
    if (root instanceof Element && isTranslationSkipped(root)) return;
    if (root instanceof Element) translateElement(root);

    const walker = document.createTreeWalker(
      root,
      NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT
    );
    let node;
    while ((node = walker.nextNode())) {
      if (node.nodeType === Node.TEXT_NODE) translateTextNode(node);
      else translateElement(node);
    }
  }

  const observer = new MutationObserver((changes) => {
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
})();
