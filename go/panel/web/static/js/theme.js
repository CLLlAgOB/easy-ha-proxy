/* One theme owner, applied before the stylesheet to avoid a startup flash. */
(function () {
  "use strict";
  const root = document.documentElement;
  const system = window.matchMedia("(prefers-color-scheme: dark)");
  let preference = null;
  try {
    const saved = window.localStorage.getItem("theme");
    if (saved === "light" || saved === "dark") preference = saved;
  } catch (_error) { /* The system theme also works with storage disabled. */ }
  root.classList.add("js");

  function apply(theme) {
    root.dataset.theme = theme;
    root.classList.toggle("light-theme", theme === "light");
    const button = document.getElementById("theme-toggle");
    if (button) {
      button.setAttribute("aria-pressed", String(theme === "dark"));
      const label = theme === "dark" ? "Switch to light theme" : "Switch to dark theme";
      button.title = typeof window.t === "function" ? window.t(label) : label;
    }
    window.dispatchEvent(new CustomEvent("themechange", {detail: {theme}}));
  }
  apply(preference || (system.matches ? "dark" : "light"));
  system.addEventListener("change", () => {
    if (!preference) apply(system.matches ? "dark" : "light");
  });
  document.addEventListener("DOMContentLoaded", () => {
    apply(root.dataset.theme);
    const button = document.getElementById("theme-toggle");
    if (!button) return;
    button.addEventListener("click", () => {
      preference = root.dataset.theme === "dark" ? "light" : "dark";
      try { window.localStorage.setItem("theme", preference); } catch (_error) { /* optional */ }
      apply(preference);
    });
  });
})();
