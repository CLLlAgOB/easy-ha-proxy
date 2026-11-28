/* Persistent navigation on desktop, an accessible drawer on small screens. */
(function () {
  "use strict";
  document.addEventListener("DOMContentLoaded", () => {
    const sidebar = document.getElementById("app-sidebar");
    const workspace = document.getElementById("app-workspace");
    const trigger = document.getElementById("nav-toggle");
    const close = document.getElementById("nav-close");
    const backdrop = document.getElementById("nav-backdrop");
    const skipLink = document.querySelector(".skip-link");
    if (!sidebar || !workspace || !trigger || !backdrop) return;
    const narrow = window.matchMedia("(max-width: 1023px)");
    const groups = [...sidebar.querySelectorAll("details.nav-group")];
    let opened = false;
    let stored = {};
    try { stored = JSON.parse(localStorage.getItem("ehp-nav-sections") || "{}"); } catch (_error) { /* optional */ }
    if (!stored || typeof stored !== "object") stored = {};
    groups.forEach(group => {
      const key = group.dataset.navGroup;
      // The current location stays discoverable even if it was collapsed
      // on the previous page. Other sections remember the user's choice.
      if (!group.querySelector('[aria-current="page"]') && stored[key] === true) group.open = true;
      group.addEventListener("toggle", () => {
        stored[key] = group.open;
        try { localStorage.setItem("ehp-nav-sections", JSON.stringify(stored)); } catch (_error) { /* optional */ }
      });
    });

    function setOpen(value, restoreFocus) {
      opened = Boolean(value && narrow.matches);
      sidebar.classList.toggle("sidebar-open", opened);
      sidebar.inert = narrow.matches && !opened;
      workspace.inert = opened;
      if (skipLink) skipLink.inert = opened;
      backdrop.hidden = !opened;
      document.body.classList.toggle("navigation-open", opened);
      trigger.setAttribute("aria-expanded", String(opened));
      if (opened) {
        sidebar.setAttribute("role", "dialog");
        sidebar.setAttribute("aria-modal", "true");
        window.requestAnimationFrame(() => {
          if (opened && close) close.focus({preventScroll: true});
        });
      } else {
        sidebar.removeAttribute("role");
        sidebar.removeAttribute("aria-modal");
        if (restoreFocus) trigger.focus();
      }
    }
    trigger.addEventListener("click", () => setOpen(!opened, false));
    if (close) close.addEventListener("click", () => setOpen(false, true));
    backdrop.addEventListener("click", () => setOpen(false, true));
    sidebar.addEventListener("click", event => {
      if (opened && event.target.closest("a[href]")) setOpen(false, true);
    });
    narrow.addEventListener("change", () => setOpen(false, narrow.matches && sidebar.contains(document.activeElement)));
    document.addEventListener("keydown", event => {
      if (!opened) return;
      if (event.key === "Escape") {
        event.preventDefault();
        setOpen(false, true);
      } else if (event.key === "Tab") {
        const targets = [...sidebar.querySelectorAll('a[href], button, summary, [tabindex="0"]')]
          .filter(element => {
            const collapsed = element.closest("details:not([open])");
            return element.getClientRects().length && !element.disabled
              && (!collapsed || collapsed.querySelector("summary") === element);
          });
        if (!targets.length) return;
        const first = targets[0];
        const last = targets[targets.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault(); last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault(); first.focus();
        }
      }
    });
    setOpen(false, false);
  });
})();
