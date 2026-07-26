// static/js/haproxy_tcp.js
// JS for страницы редактирования TCP proxies HAProxy:
// - показ/скрытие блока удаления
// - динамический list backend-servers
// - сохранение TCP proxies through /haproxy/tcp/save (JSON API)

(function () {
  try {
    console.log("[haproxy_tcp] script loaded");

    var editForm = document.getElementById("tcp-edit-form");
    if (!editForm) {
      return;
    }

    var saveStatus = document.getElementById("tcp-save-status");

    function setSaveStatus(text, isError) {
      if (!saveStatus) return;
      saveStatus.textContent = text || "";
      saveStatus.style.color = isError ? "#c0392b" : "";
    }

    // -------- Блок удаления TCP proxies --------
    var btnShowDel = document.getElementById("btn-show-delete");
    var deleteBox = document.getElementById("delete-confirm");
    var btnCancelDel = document.getElementById("btn-delete-cancel");

    if (btnShowDel && deleteBox && btnCancelDel) {
      btnShowDel.addEventListener("click", function () {
        deleteBox.style.display = "block";
      });
      btnCancelDel.addEventListener("click", function () {
        deleteBox.style.display = "none";
      });
    }

    // -------- Backend servers (таблица) --------
    var backendsBody = document.getElementById("tcp-backends-body");
    var btnAddBackend = document.getElementById("btn-add-backend");

    function addBackendRow(initial) {
      if (!backendsBody) return;
      var tr = document.createElement("tr");
      tr.className = "tcp-backend-row";
      tr.innerHTML =
        '<td><input type="text" class="form-input tcp-backend-name" placeholder="srv1"></td>' +
        '<td><input type="text" class="form-input tcp-backend-host" placeholder="10.0.0.10"></td>' +
        '<td><input type="number" min="1" max="65535" class="form-input tcp-backend-port" placeholder="6690"></td>' +
        '<td style="text-align:center;"><input type="checkbox" class="tcp-backend-backup"></td>' +
        '<td style="text-align:center;"><button type="button" class="btn btn-small btn-backend-remove" title="Delete backend">✕</button></td>';

      backendsBody.appendChild(tr);

      if (initial) {
        if (initial.name) tr.querySelector(".tcp-backend-name").value = initial.name;
        if (initial.host) tr.querySelector(".tcp-backend-host").value = initial.host;
        if (initial.port) tr.querySelector(".tcp-backend-port").value = initial.port;
        if (initial.backup) tr.querySelector(".tcp-backend-backup").checked = true;
      }

      var btnRemove = tr.querySelector(".btn-backend-remove");
      if (btnRemove) {
        btnRemove.addEventListener("click", function () {
          tr.remove();
        });
      }
    }

    if (btnAddBackend) {
      btnAddBackend.addEventListener("click", function () {
        addBackendRow();
      });
    }

    // If no ни одной строки backend'ов, добавим пустую by default
    if (backendsBody && backendsBody.querySelectorAll("tr").length === 0) {
      addBackendRow();
    } else if (backendsBody) {
      // Привязываем обработчики удаления to уже существующим строкам
      backendsBody.querySelectorAll(".btn-backend-remove").forEach(function (btn) {
        btn.addEventListener("click", function () {
          var tr = btn.closest("tr");
          if (tr) tr.remove();
        });
      });
    }

    // -------- Сбор данных формы in JSON --------
    function buildTcpPayloadFromForm(form) {
      var tcp = {};

      function textById(id) {
        var el = document.getElementById(id);
        return el ? el.value.trim() : "";
      }

      function numById(id) {
        var el = document.getElementById(id);
        if (!el) return undefined;
        var v = el.value.trim();
        if (!v) return undefined;
        var n = Number(v);
        return n;
      }

      tcp.name = textById("field-name");
      tcp.bind_ip = textById("field-bind-ip");

      var bindPort = numById("field-bind-port");
      if (bindPort !== undefined) {
        if (Number.isNaN(bindPort)) {
          throw new Error("Invalid bind_port value");
        }
        tcp.bind_port = bindPort;
      }

      tcp.backend_host = textById("field-backend-host");
      var backendPort = numById("field-backend-port");
      if (backendPort !== undefined) {
        if (Number.isNaN(backendPort)) {
          throw new Error("Invalid backend_port value");
        }
        tcp.backend_port = backendPort;
      }

      var balanceEl = document.getElementById("field-balance");
      if (balanceEl && balanceEl.value.trim()) {
        tcp.balance = balanceEl.value.trim();
      }

      var interEl = document.getElementById("field-inter");
      if (interEl && interEl.value.trim()) {
        tcp.inter = interEl.value.trim();
      }

      var ztEl = document.getElementById("field-zero-trust");
      if (ztEl) {
        tcp.zero_trust = !!ztEl.checked;
      }

      var banEl = document.getElementById("field-ban-check");
      if (banEl) {
        tcp.ban_check = !!banEl.checked;
      }

      var sslEl = document.getElementById("field-ssl-check");
      if (sslEl) {
        tcp.ssl_check = !!sslEl.checked;
      }

      // Backend servers
      var servers = [];
      if (backendsBody) {
        var rows = backendsBody.querySelectorAll("tr.tcp-backend-row");
        var idx = 0;
        rows.forEach(function (row) {
          idx += 1;
          var nameInput = row.querySelector(".tcp-backend-name");
          var hostInput = row.querySelector(".tcp-backend-host");
          var portInput = row.querySelector(".tcp-backend-port");
          var backupInput = row.querySelector(".tcp-backend-backup");

          var host = hostInput && hostInput.value.trim();
          var portStr = portInput && portInput.value.trim();

          if (!host && !portStr) {
            return; // пустая line
          }

          var port = parseInt(portStr, 10);
          if (!port || port <= 0 || port > 65535) {
            throw new Error("Invalid backend port on row " + idx);
          }

          var srv = {
            host: host,
            port: port
          };

          var nameVal = nameInput && nameInput.value.trim();
          if (nameVal) srv.name = nameVal;

          if (backupInput && backupInput.checked) {
            srv.backup = true;
          }

          servers.push(srv);
        });
      }

      if (servers.length > 0) {
        tcp.servers = servers;
      }

      var payload = {
        tcp: tcp,
        original_name: editForm.getAttribute("data-original-name") || tcp.name
      };
      return payload;
    }

    // -------- Сабмит формы: POST /haproxy/tcp/save --------
    editForm.addEventListener("submit", function (ev) {
      ev.preventDefault();

      if (!editForm.checkValidity()) {
        editForm.reportValidity();
        return;
      }

      var payload;
      try {
        payload = buildTcpPayloadFromForm(editForm);
      } catch (e) {
        console.error("Failed to prepare TCP proxy data:", e);
        setSaveStatus(e.message || String(e), true);
        return;
      }

      if (!payload.tcp.name) {
        setSaveStatus("TCP proxy name is required", true);
        return;
      }

      setSaveStatus("Saving...", false);

      fetch("/haproxy/tcp/save", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Requested-With": "XMLHttpRequest"
        },
        body: JSON.stringify(payload)
      })
        .then(function (resp) {
          if (!resp.ok) {
            throw new Error("HTTP " + resp.status);
          }
          return resp.json();
        })
        .then(function (data) {
          if (!data) {
            throw new Error("Empty server response");
          }
          if (data.ok) {
            setSaveStatus(data.message || "Saved", false);
            document.dispatchEvent(
              new CustomEvent("easy-ha-proxy:config-state-changed")
            );

            // If имя поменялось — обновляем URL
            var newName = payload.tcp.name;
            var oldName = payload.original_name || newName;
            if (newName && oldName && newName !== oldName) {
              var cur = window.location.pathname;
              var newPath = cur.replace(
                "/" + encodeURIComponent(oldName) + "/edit",
                "/" + encodeURIComponent(newName) + "/edit"
              );
              if (newPath !== cur) {
                window.location.replace(newPath);
              }
            }
          } else {
            setSaveStatus(data.error || "Failed to save TCP proxy", true);
          }
        })
        .catch(function (err) {
          console.error("Failed to save TCP proxy:", err);
          setSaveStatus("Failed to save TCP proxy: " + (err.message || err), true);
        });
    });
  } catch (e) {
    console.error("[haproxy_tcp] init error", e);
  }
})();
