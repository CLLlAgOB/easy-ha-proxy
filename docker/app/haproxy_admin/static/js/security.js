/* Shared CSRF plumbing and small page-wide security helpers. */
(function () {
  "use strict";

  window.escapeHtml = function escapeHtml(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, (char) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;"
    })[char]);
  };

  window.countryFlagMarkup = function countryFlagMarkup(value) {
    const code = String(value || "").trim().toLowerCase();
    if (!/^[a-z]{2}$/.test(code)) {
      return '<span class="country-flag country-flag-unknown"></span>';
    }
    const base = String(window.HAPROXY_ADMIN_FLAG_BASE || "");
    const source = `${base}${encodeURIComponent(code)}.svg`;
    return `<img class="country-flag" src="${window.escapeHtml(source)}" alt="" loading="lazy">`;
  };

  const token = () => {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") || "" : "";
  };

  const originalFetch = window.fetch.bind(window);
  window.fetch = function (input, init) {
    const options = Object.assign({}, init || {});
    const method = String(options.method || "GET").toUpperCase();
    const url = typeof input === "string" ? input : input.url;
    const target = new URL(url, window.location.href);

    if (
      target.origin === window.location.origin &&
      !["GET", "HEAD", "OPTIONS", "TRACE"].includes(method)
    ) {
      const headers = new Headers(options.headers || {});
      headers.set("X-CSRFToken", token());
      options.headers = headers;
      options.credentials = options.credentials || "same-origin";
    }
    return originalFetch(input, options);
  };

  const savedTheme = localStorage.getItem("theme") || "dark";
  if (savedTheme === "light") {
    document.documentElement.classList.add("light-theme");
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll("form").forEach((form) => {
      const method = String(form.method || "get").toLowerCase();
      if (method !== "post" || form.querySelector('input[name="csrf_token"]')) {
        return;
      }
      const hidden = document.createElement("input");
      hidden.type = "hidden";
      hidden.name = "csrf_token";
      hidden.value = token();
      form.appendChild(hidden);
    });

    document.addEventListener("submit", (event) => {
      const form = event.target;
      if (!(form instanceof HTMLFormElement) || !form.dataset.confirm) {
        return;
      }
      if (!window.confirm(form.dataset.confirm)) {
        event.preventDefault();
      }
    });

    const themeToggle = document.getElementById("theme-toggle");
    if (themeToggle) {
      themeToggle.addEventListener("click", () => {
        const classes = document.documentElement.classList;
        const light = classes.toggle("light-theme");
        localStorage.setItem("theme", light ? "light" : "dark");
      });
    }
  });
})();
