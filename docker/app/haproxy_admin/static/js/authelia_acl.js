// The UI for switching the rule groups by domain, and tracking the active domain
(function () {
  function showGroup(targetId) {
    var groups = document.querySelectorAll(".domain-group-wrapper");
    var activeDomain = "";

    groups.forEach(function (el) {
      if (el.id === targetId) {
        el.style.display = "";
        activeDomain = el.getAttribute("data-domain") || "";
      } else {
        el.style.display = "none";
      }
    });

    var pills = document.querySelectorAll(".domain-pill");
    pills.forEach(function (btn) {
      var t = btn.getAttribute("data-domain-target");
      if (t === targetId) {
        btn.classList.add("active");
      } else {
        btn.classList.remove("active");
      }
    });

    // Update the hidden field, so the server knows the active domain
    var hidden = document.getElementById("active_group_domain");
    if (hidden) {
      hidden.value = activeDomain;
    }
  }

  function init() {
    var pills = document.querySelectorAll(".domain-pill");
    var groups = document.querySelectorAll(".domain-group-wrapper");

    if (!groups.length) {
      return;
    }

    // Attach the handlers to the tabs
    pills.forEach(function (btn) {
      btn.addEventListener("click", function (ev) {
        ev.preventDefault();
        var target = btn.getAttribute("data-domain-target");
        if (target) {
          showGroup(target);
        }
      });
    });

    // Choose the starting group.
    // desiredDomain may be:
    //   - a specific domain "ha.example.com"
    //   - an empty string "" -> the group "New / without a domain"
    //   - null -> no domain given -> the first visible one / the first in order
    var hidden = document.getElementById("active_group_domain");
    var desiredDomain = hidden ? hidden.value : null;

    var initialId = null;

    // If the hidden field exists (even holding an empty string),
    // look for exactly that group by data-domain first.
    if (desiredDomain !== null) {
      Array.prototype.forEach.call(groups, function (el) {
        if (initialId) {
          return;
        }
        var dom = el.getAttribute("data-domain") || "";
        if (dom === desiredDomain) {
          initialId = el.id;
        }
      });
    }

    // If that group was not found, take the first visible one
    if (!initialId) {
      Array.prototype.forEach.call(groups, function (el) {
        if (!initialId && el.style.display !== "none") {
          initialId = el.id;
        }
      });
    }

    // If none is visible (or all were hidden), just the first in the list
    if (!initialId && groups.length) {
      initialId = groups[0].id;
    }

    if (initialId) {
      showGroup(initialId);
    }
  }

  // Exported globally, just in case
  window.AutheliaAclUI = {
    showGroup: showGroup,
  };

  document.addEventListener("DOMContentLoaded", init);
})();
