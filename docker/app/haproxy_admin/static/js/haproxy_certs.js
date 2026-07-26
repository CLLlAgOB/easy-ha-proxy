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
  } catch (e) {
    console.error("[haproxy_certs] JS error:", e);
  }
});
