// static/js/haproxy_certs.js

document.addEventListener("DOMContentLoaded", function () {
  try {
    // -------------------------------
    // Подтверждение удаления HAProxy-сертификата
    // -------------------------------
    var hapForms = document.querySelectorAll("form.cert-delete-haproxy");
    hapForms.forEach(function (form) {
      form.addEventListener("submit", function (ev) {
        var domain = form.getAttribute("data-domain") || "";
        var msg = domain
          ? "Delete the HAProxy certificate for domain " + domain + "?"
          : "Delete this HAProxy certificate?";
        if (!window.confirm(msg)) {
          ev.preventDefault();
        }
      });
    });

    // -------------------------------
    // Подтверждение удаления LE-lineage
    // -------------------------------
    var leForms = document.querySelectorAll("form.cert-delete-le");
    leForms.forEach(function (form) {
      form.addEventListener("submit", function (ev) {
        var lineage = form.getAttribute("data-lineage") || "";
        var msg = lineage
          ? "Permanently delete the Let's Encrypt certificate " + lineage + "?"
          : "Permanently delete the Let's Encrypt certificate?";
        if (!window.confirm(msg)) {
          ev.preventDefault();
        }
      });
    });

    // -------------------------------
    // Восстановление from backup: file-picker + блокировка кнопки
    // -------------------------------
    var backupFileInput  = document.getElementById("backup_file");
    var backupChooseBtn  = document.getElementById("backup_choose_btn");
    var backupFileName   = document.getElementById("backup_file_name");
    var backupRestoreBtn = document.getElementById("backup_restore_btn");

    if (backupFileInput && backupChooseBtn && backupFileName && backupRestoreBtn) {
      // Открываем системный диалог выбора файла
      backupChooseBtn.addEventListener("click", function () {
        backupFileInput.click();
      });

      // При выборе файла обновляем подпись and включаем/отключаем кнопку
      backupFileInput.addEventListener("change", function () {
        var file = backupFileInput.files && backupFileInput.files[0];
        var name = file ? file.name : "";
        backupFileName.textContent = name || "No file selected";
        backupRestoreBtn.disabled = !name;
      });
    }
    // -------------------------------
    // One upload field, sorted by what the file turns out to be.
    //
    // Two steps on purpose: the same file is sent once to be described and
    // once to be acted on. The gateway therefore never holds an unexamined
    // upload between two requests, and the operator sees what a file is
    // before anything is installed.
    // -------------------------------
    var materialFile = document.getElementById("material-file");
    var materialReport = document.getElementById("material-report");
    var importBtn = document.getElementById("material-import");

    function csrfToken() {
      var meta = document.querySelector('meta[name="csrf-token"]');
      return meta ? meta.getAttribute("content") || "" : "";
    }

    function line(text, tone) {
      var div = document.createElement("div");
      if (tone) div.style.color = "var(--" + tone + ")";
      div.textContent = text;
      return div;
    }

    function describe(payload) {
      materialReport.textContent = "";
      materialReport.appendChild(line("Format: " + (payload.format || "?")));
      (payload.authorities || []).forEach(function (ca) {
        materialReport.appendChild(
          line(
            (ca.self_signed ? "Root authority: " : "Intermediate authority: ") +
              ca.subject + "  (until " + ca.not_after + ")"
          )
        );
      });
      var server = payload.server_certificate;
      if (server) {
        materialReport.appendChild(
          line(
            "Server certificate: " + server.subject +
              (server.dns_names && server.dns_names.length
                ? "  [" + server.dns_names.join(", ") + "]"
                : "") +
              "  (until " + server.not_after + ")"
          )
        );
      }
      (payload.problems || []).forEach(function (text) {
        materialReport.appendChild(line("! " + text, "error"));
      });
      (payload.actions || []).forEach(function (text) {
        materialReport.appendChild(line("Will " + text, "success"));
      });
      (payload.completed || []).forEach(function (text) {
        materialReport.appendChild(line("Done: " + text, "success"));
      });
    }

    function materialBody() {
      var body = new FormData();
      body.append("file", materialFile.files[0]);
      body.append("password", document.getElementById("material-password").value);
      body.append("name", document.getElementById("material-ca-name").value.trim());
      body.append("domain", document.getElementById("material-domain").value.trim());
      return body;
    }

    function send(path, body, done) {
      fetch(path, {
        method: "POST",
        credentials: "same-origin",
        headers: { "X-CSRFToken": csrfToken(), Accept: "application/json" },
        body: body
      })
        .then(function (response) { return response.json(); })
        .then(done)
        .catch(function (err) {
          materialReport.textContent = "";
          materialReport.appendChild(line(String(err), "error"));
        });
    }

    if (materialFile && materialReport && importBtn) {
      document.getElementById("material-choose").addEventListener("click", function () {
        materialFile.click();
      });
      materialFile.addEventListener("change", function () {
        var file = materialFile.files && materialFile.files[0];
        document.getElementById("material-name").textContent =
          file ? file.name : "No file selected";
        importBtn.hidden = true;
        materialReport.textContent = "";
      });

      document.getElementById("material-inspect").addEventListener("click", function () {
        if (!materialFile.files || !materialFile.files[0]) {
          materialReport.textContent = "";
          materialReport.appendChild(line("Select a file first.", "error"));
          return;
        }
        materialReport.textContent = "…";
        send("/haproxy/certs/inspect", materialBody(), function (payload) {
          describe(payload);
          if (!payload.ok) {
            materialReport.appendChild(line(payload.error || "Unreadable file", "error"));
            importBtn.hidden = true;
            return;
          }
          importBtn.hidden = !(payload.actions && payload.actions.length);
        });
      });

      importBtn.addEventListener("click", function () {
        materialReport.textContent = "…";
        var body = materialBody();
        if (importBtn.dataset.replace === "yes") body.append("replace", "true");
        send("/haproxy/certs/import", body, function (payload) {
          describe(payload);
          if (payload.ok) {
            importBtn.hidden = true;
            delete importBtn.dataset.replace;
            window.setTimeout(function () { window.location.reload(); }, 1200);
            return;
          }
          materialReport.appendChild(line(payload.error || "It was not installed", "error"));
          if (payload.needs_replace) {
            importBtn.dataset.replace = "yes";
            importBtn.textContent = "Replace and install";
          }
        });
      });
    }
  } catch (e) {
    console.error("[haproxy_certs] JS error:", e);
  }
});
