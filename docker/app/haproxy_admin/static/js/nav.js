/* Conveniences for the grouped header navigation.
 *
 * The menus are <details>, so they already open, close, and take keyboard
 * focus with no script at all. This adds only the three behaviours that
 * genuinely need one, and the page is usable without it.
 */
(function () {
  "use strict";

  document.addEventListener("DOMContentLoaded", function () {
    var groups = Array.prototype.slice.call(
      document.querySelectorAll("nav.nav-groups details.nav-group")
    );
    if (!groups.length) return;

    function closeAll(except) {
      groups.forEach(function (group) {
        if (group !== except) group.open = false;
      });
    }

    groups.forEach(function (group) {
      // Opening one closes the rest, so two menus never overlap.
      group.addEventListener("toggle", function () {
        if (group.open) closeAll(group);
      });
    });

    // Clicking anywhere else closes the open menu, which is what every
    // other menu on every other page does.
    document.addEventListener("click", function (event) {
      var inside = groups.some(function (group) {
        return group.contains(event.target);
      });
      if (!inside) closeAll(null);
    });

    document.addEventListener("keydown", function (event) {
      if (event.key !== "Escape") return;
      var open = groups.filter(function (group) {
        return group.open;
      });
      if (!open.length) return;
      closeAll(null);
      // Focus goes back to the control that opened it, or the keyboard user
      // is left standing where the menu used to be.
      var summary = open[0].querySelector("summary");
      if (summary) summary.focus();
    });
  });
})();
