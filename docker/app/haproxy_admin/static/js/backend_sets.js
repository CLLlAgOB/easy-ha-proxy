/* Backend set pickers.
 *
 * Editors (site, TCP proxy): with a set chosen the manual server table is
 * hidden and the set's addresses are shown instead; switching back to
 * manual addresses shows the table again, still holding the list the entry
 * had. The editors ask window.backendSetChoice() when they build what they
 * save.
 *
 * Short "add" forms: a select with class js-backend-set-quick hides the
 * address field named in data-host-field (and its "<id>-group" wrapper)
 * while a set is chosen; the port field stays.
 */
(function () {
  "use strict";

  // style.display rather than the hidden attribute: a class that sets
  // display (as .btn does) would win over [hidden].
  function show(element, visible) {
    if (element) element.style.display = visible ? "" : "none";
  }

  document.querySelectorAll("select.js-backend-set-quick").forEach(function (quick) {
    var ids = (quick.getAttribute("data-host-field") || "").split(/\s+/).filter(Boolean);
    var fields = ids.map(function (id) {
      var host = document.getElementById(id);
      return { host: host, group: document.getElementById(id + "-group"),
               required: !!(host && host.required) };
    });
    function refreshQuick() {
      var chosen = !!quick.value;
      fields.forEach(function (field) {
        show(field.group || field.host, !chosen);
        if (field.host && field.required) field.host.required = !chosen;
      });
    }
    quick.addEventListener("change", refreshQuick);
    refreshQuick();
  });

  var select = document.getElementById("field-servers-preset");
  if (!select) return;
  var portGroup = document.getElementById("backend-set-port-group");
  var portInput = document.getElementById("field-servers-preset-port");
  var manual = document.getElementById("backend-manual");
  var addButton = document.getElementById("btn-add-backend");
  var previews = document.querySelectorAll(".backend-set-preview");

  function refresh() {
    var name = select.value;
    show(manual, !name);
    show(addButton, !name);
    show(portGroup, !!name);
    previews.forEach(function (box) {
      box.hidden = false;
      show(box, box.getAttribute("data-set") === name);
    });
  }

  window.backendSetChoice = function () {
    var name = select.value;
    if (!name) return null;
    var port = parseInt((portInput && portInput.value || "").trim(), 10);
    if (!port || port < 1 || port > 65535) {
      throw new Error("Set the backend port for the backend set (1-65535)");
    }
    return { name: name, port: port };
  };

  select.addEventListener("change", refresh);
  refresh();
})();
