/* Full encrypted backup and disaster-recovery workflow. */
(function () {
  "use strict";

  const t = window.t || ((value) => String(value));
  const app = document.getElementById("backup-app");
  if (!app) return;

  const endpoints = {
    status: app.dataset.statusUrl,
    create: app.dataset.createUrl,
    upload: app.dataset.uploadUrl,
    inspect: app.dataset.inspectUrlTemplate,
    stage: app.dataset.stageUrlTemplate,
    restore: app.dataset.restoreUrl,
    remove: app.dataset.deleteUrl,
    download: app.dataset.downloadUrlTemplate
  };
  const terminalStates = new Set(["completed", "failed", "cancelled", "interrupted", "rolled_back", "rollback_failed"]);
  const dateFormat = new Intl.DateTimeFormat(document.documentElement.lang || undefined, {
    dateStyle: "medium",
    timeStyle: "medium"
  });
  const OPERATION_JOB_KEY = "easy_ha_proxy_backup_operation_job";
  const INSPECTION_JOB_KEY = "easy_ha_proxy_backup_inspection_job";
  const SELECTED_JOB_KEY = "easy_ha_proxy_backup_selected_job";
  const LOG_OPEN_KEY = "easy_ha_proxy_backup_log_open";
  const operationLabels = {
    backup: "Creating encrypted backup",
    inspect: "Verifying backup archive",
    restore: "Restoring and reconciling server"
  };
  let currentUploadId = "";
  let currentInspectionJobId = storageGet(INSPECTION_JOB_KEY) || "";
  let currentOperationJobId = storageGet(OPERATION_JOB_KEY) || "";
  let currentManifest = null;
  let stagedBackupId = "";
  let stagingStoredBackup = false;
  let selectedJobId = storageGet(SELECTED_JOB_KEY) || "";
  let activeJobSnapshot = null;
  let lastJobsHtml = "";
  let pollTimer = null;
  let logViewMode = "log";
  let renderedJobId = "";
  let renderedHadLog = false;

  function byId(id) { return document.getElementById(id); }
  function escape(value) { return window.escapeHtml(String(value == null ? "" : value)); }
  function storageGet(key) {
    try { return window.sessionStorage.getItem(key); }
    catch (_error) { return null; }
  }
  function storageSet(key, value) {
    try {
      if (value) window.sessionStorage.setItem(key, value);
      else window.sessionStorage.removeItem(key);
    } catch (_error) {
      // The host-side job list remains authoritative when storage is unavailable.
    }
  }
  function setMessage(id, message, ok, technical) {
    const element = byId(id);
    if (!element) return;
    element.textContent = message || "";
    element.classList.toggle("success", Boolean(message) && ok === true);
    element.classList.toggle("error", Boolean(message) && ok === false);
    element.classList.toggle("notranslate", technical === true);
    if (technical === true) {
      element.setAttribute("translate", "no");
      element.setAttribute("data-i18n-skip", "");
    } else {
      element.removeAttribute("translate");
      element.removeAttribute("data-i18n-skip");
    }
  }
  function formatDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : dateFormat.format(date);
  }
  function formatBytes(value) {
    let size = Number(value);
    if (!Number.isFinite(size) || size < 0) return "—";
    const units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let index = 0;
    while (size >= 1024 && index < units.length - 1) { size /= 1024; index += 1; }
    return `${size.toLocaleString(document.documentElement.lang || undefined, {maximumFractionDigits: index ? 1 : 0})} ${units[index]}`;
  }
  async function requestJson(url, options) {
    const response = await fetch(url, options || {});
    let payload;
    try { payload = await response.json(); }
    catch (_error) { throw new Error(`${t("Unexpected server response")} (${response.status})`); }
    if (!response.ok || payload.ok === false) {
      const error = new Error(payload.error || payload.message || `${t("Request failed")} (${response.status})`);
      error.status = response.status;
      throw error;
    }
    return payload;
  }
  function postJson(url, payload) {
    return requestJson(url, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload)
    });
  }
  function jobId(job) { return String(job.id || job.job_id || ""); }
  function jobState(job) { return String(job.status || job.state || "unknown"); }
  function jobManifest(job) {
    if (job.manifest && typeof job.manifest === "object") return job.manifest;
    if (job.result && job.result.manifest && typeof job.result.manifest === "object") return job.result.manifest;
    return null;
  }

  function renderManifest(manifest) {
    currentManifest = manifest;
    byId("backup-inspection").hidden = !manifest;
    if (!manifest) {
      updateRestoreButton();
      return;
    }
    byId("backup-source-host").textContent = manifest.hostname || "—";
    byId("backup-created-at").textContent = formatDate(manifest.created_at);
    byId("backup-machine").textContent = manifest.machine || "—";
    const expandedSize = Number(manifest.payload_expanded_bytes || 0) +
      Number(manifest.ssh_payload_expanded_bytes || 0);
    byId("backup-expanded-size").textContent = expandedSize > 0 ? formatBytes(expandedSize) : "—";
    byId("backup-quiesced-state").textContent = manifest.quiesced ? t("Yes") : t("No");
    byId("backup-ssh-state").textContent = manifest.ssh_included ? t("Yes") : t("No");
    if (!manifest.ssh_included) byId("backup-restore-ssh").checked = false;
    updateScopeControls();
    updateRestoreButton();
  }

  function renderBackups(backups) {
    const body = byId("backup-artifacts-body");
    if (!Array.isArray(backups) || !backups.length) {
      body.innerHTML = `<tr><td colspan="5" class="muted">${escape(t("No full backups are stored on this server."))}</td></tr>`;
      return;
    }
    body.innerHTML = backups.map((backup) => {
      const id = String(backup.id || backup.backup_id || "");
      const manifest = backup.manifest || {};
      const archiveUrl = endpoints.download.replace("BACKUP_ID", encodeURIComponent(id));
      return `<tr>
        <td>${escape(formatDate(backup.created_at || manifest.created_at))}</td>
        <td class="mono notranslate" translate="no" data-i18n-skip>${escape(manifest.hostname || backup.hostname || "—")}</td>
        <td>${escape(formatBytes(backup.size || backup.size_bytes))}</td>
        <td>${escape((manifest.ssh_included || backup.ssh_included) ? t("Yes") : t("No"))}</td>
        <td class="backup-actions">
          <button class="btn btn-small" type="button" data-restore-backup="${escape(id)}">${escape(t("Restore"))}</button>
          <a class="btn btn-small" href="${escape(archiveUrl)}">${escape(t("Download archive"))}</a>
          <a class="btn btn-small" href="${escape(archiveUrl + "?checksum=1")}">${escape(t("SHA-256"))}</a>
          <button class="btn btn-small btn-danger" type="button" data-delete-backup="${escape(id)}">${escape(t("Delete"))}</button>
        </td>
      </tr>`;
    }).join("");
  }

  function markSelectedRow() {
    document.querySelectorAll("[data-job-id]").forEach((row) => {
      row.classList.toggle("job-row-selected", row.dataset.jobId === selectedJobId);
    });
  }
  function renderJobs(jobs) {
    const body = byId("backup-jobs-body");
    const active = (jobs || []).find((job) => !terminalStates.has(jobState(job))) || null;
    activeJobSnapshot = active;
    let html;
    if (!Array.isArray(jobs) || !jobs.length) {
      html = `<tr><td colspan="4" class="muted">${escape(t("No backup jobs yet."))}</td></tr>`;
    } else {
      html = jobs.map((job) => {
        const id = jobId(job);
        const state = jobState(job);
        const result = job.error || job.message || (state === "completed" ? t("Completed successfully") : "—");
        return `<tr data-job-id="${escape(id)}" tabindex="0">
          <td>${escape(formatDate(job.started_at || job.created_at))}</td>
          <td>${escape(t(String(job.operation || job.action || "—")))}</td>
          <td><span class="backup-job-state backup-job-state--${escape(state)}">${escape(t(state))}</span></td>
          <td class="notranslate" translate="no" data-i18n-skip>${escape(result)}</td>
        </tr>`;
      }).join("");
    }
    // Re-rendering identical rows would destroy focus and text selection on
    // every poll, so only touch the DOM when the table content changed.
    if (html !== lastJobsHtml) {
      body.innerHTML = html;
      lastJobsHtml = html;
    }
    markSelectedRow();
    renderProgress(active);
    return Boolean(active);
  }

  function renderProgress(active) {
    const wrap = byId("backup-progress");
    if (!active) {
      wrap.hidden = true;
      return;
    }
    wrap.hidden = false;
    const operation = String(active.operation || active.action || "");
    byId("backup-progress-label").textContent =
      t(operationLabels[operation] || "Working…");
    renderElapsed();
  }
  function renderElapsed() {
    if (!activeJobSnapshot) return;
    const started = new Date(activeJobSnapshot.started_at || activeJobSnapshot.created_at || Date.now());
    const seconds = Math.max(0, Math.floor((Date.now() - started.getTime()) / 1000));
    const minutes = Math.floor(seconds / 60);
    byId("backup-progress-elapsed").textContent =
      `${minutes}:${String(seconds % 60).padStart(2, "0")}`;
  }

  function adoptInspection(job) {
    if (!job || currentManifest) return;
    const manifest = jobManifest(job);
    if ((job.operation === "inspect" || job.action === "inspect") && jobState(job) === "completed" && manifest) {
      currentInspectionJobId = jobId(job);
      currentUploadId = String(job.upload_id || (job.result && job.result.upload_id) || currentUploadId);
      renderManifest(manifest);
      if (stagedBackupId) setStoredBackupMode("");
      setMessage("backup-upload-status", t("Backup verified. Review the source details before restoring."), true);
    }
  }

  function jobLogText(job) {
    const output = job.output && typeof job.output === "object" ? job.output : {};
    return [output.stdout, output.stderr, job.log, job.stderr]
      .filter(Boolean).join("\n").trim();
  }
  function jobDetailsText(job) {
    // Metadata view: everything except the bulky raw log streams.
    const clone = {};
    for (const [key, value] of Object.entries(job)) {
      if (key !== "output") clone[key] = value;
    }
    const output = job.output && typeof job.output === "object" ? job.output : null;
    if (output) {
      const meta = {};
      for (const [key, value] of Object.entries(output)) {
        if (!["log", "stdout", "stderr"].includes(key)) meta[key] = value;
      }
      if (Object.keys(meta).length) clone.output = meta;
    }
    return JSON.stringify(clone, null, 2);
  }
  function showJob(job) {
    if (!job) return;
    const log = byId("backup-job-log");
    const id = jobId(job);
    const text = jobLogText(job);
    // The job list strips logs; never downgrade an already shown log to the
    // empty placeholder for the same job.
    if (logViewMode === "log" && !text && renderedJobId === id && renderedHadLog) return;
    const next = logViewMode === "details"
      ? jobDetailsText(job)
      : (text || t("The job has not produced output yet."));
    const mode = byId("backup-log-mode");
    if (mode) {
      mode.textContent = logViewMode === "details"
        ? t("job details — click the job again for its log")
        : t("log output — click the job again for details");
    }
    renderedJobId = id;
    renderedHadLog = Boolean(text);
    if (log.textContent === next) return;
    const stick = log.scrollTop + log.clientHeight >= log.scrollHeight - 8;
    const keep = log.scrollTop;
    log.textContent = next;
    log.scrollTop = stick ? log.scrollHeight : keep;
  }

  function focusJobLog(id) {
    // A newly started job becomes the selected one and its live log is
    // brought into view immediately.
    if (id) {
      selectedJobId = id;
      storageSet(SELECTED_JOB_KEY, selectedJobId);
    }
    logViewMode = "log";
    markSelectedRow();
    const details = byId("backup-log-details");
    details.open = true;
    storageSet(LOG_OPEN_KEY, "1");
    details.scrollIntoView({behavior: "smooth", block: "start"});
  }

  let detailFetchId = "";
  async function renderShownJob(listJob) {
    showJob(listJob);
    // The list payload strips logs; fetch the full job for the log view.
    const id = jobId(listJob);
    if (logViewMode !== "log" || jobLogText(listJob) || detailFetchId === id) return;
    detailFetchId = id;
    try {
      const payload = await requestJson(`${endpoints.status}?job_id=${encodeURIComponent(id)}`);
      const jobs = Array.isArray(payload.jobs) ? payload.jobs : [];
      const job = jobs.find((item) => jobId(item) === id) || payload.job;
      if (job) showJob(job);
    } catch (_error) {
      // The next poll retries; the placeholder stays meanwhile.
    } finally {
      detailFetchId = "";
    }
  }

  function showOperationResult(job) {
    if (!job || jobId(job) !== currentOperationJobId) return;
    const state = jobState(job);
    if (!terminalStates.has(state)) return;
    storageSet(OPERATION_JOB_KEY, "");
    const operation = String(job.operation || job.action || "");
    if (!new Set(["backup", "restore"]).has(operation)) return;
    if (state === "completed" && operation === "backup") {
      setMessage("backup-create-status", t("Backup completed successfully. Download the archive and checksum below."), true);
    } else if (state === "completed" && operation === "restore") {
      setMessage("backup-restore-status", t("Restore completed successfully. The server is running with the restored managed state."), true);
    } else {
      const target = operation === "backup" ? "backup-create-status" : "backup-restore-status";
      setMessage(target, `${t("Operation failed")}: ${job.error || state}`, false, true);
    }
  }

  async function refreshStatus(options) {
    const quiet = options && options.quiet;
    try {
      const payload = await requestJson(endpoints.status);
      const jobs = Array.isArray(payload.jobs) ? payload.jobs : [];
      renderBackups(payload.backups || []);
      const active = renderJobs(jobs);
      if (selectedJobId && !jobs.some((job) => jobId(job) === selectedJobId)) {
        selectedJobId = "";
        storageSet(SELECTED_JOB_KEY, "");
        markSelectedRow();
      }
      // A job explicitly opened by the user stays on screen; otherwise follow
      // the operation this page started, then the verification, then the rest.
      const shown = jobs.find((job) => jobId(job) === selectedJobId) ||
        jobs.find((job) => jobId(job) === currentOperationJobId) ||
        jobs.find((job) => jobId(job) === currentInspectionJobId) ||
        jobs.find((job) => !terminalStates.has(jobState(job))) ||
        jobs[0];
      if (shown) renderShownJob(shown);
      adoptInspection(jobs.find((job) => jobId(job) === currentInspectionJobId));
      const tracked = jobs.find((job) => jobId(job) === currentOperationJobId);
      if (tracked) showOperationResult(tracked);
      setMessage("backup-service-status", active
        ? t("A backup or restore operation is running. Temporary connection errors are expected while services restart.")
        : t("Full-backup service is ready."), true);
      schedulePoll(active ? 1800 : 10000);
      return payload;
    } catch (error) {
      const reconnecting = Boolean(currentOperationJobId);
      if (!quiet || reconnecting) {
        setMessage(
          "backup-service-status",
          reconnecting
            ? t("The backup service is temporarily unavailable. Reconnecting…")
            : error.message,
          false,
          !reconnecting
        );
      }
      schedulePoll(2500);
      return null;
    }
  }

  function schedulePoll(delay) {
    window.clearTimeout(pollTimer);
    pollTimer = window.setTimeout(() => refreshStatus({quiet: true}), delay);
  }

  function clearPasswords() {
    byId("backup-passphrase").value = "";
    byId("backup-passphrase-show").checked = false;
    byId("backup-passphrase").type = "password";
  }

  async function createBackup(event) {
    event.preventDefault();
    const passphrase = byId("backup-passphrase").value;
    if (passphrase.length < 12) { setMessage("backup-create-status", t("Use a passphrase of at least 12 characters."), false); return; }
    const button = byId("backup-create-button");
    button.disabled = true;
    setMessage("backup-create-status", t("Scheduling encrypted backup…"));
    try {
      const payload = await postJson(endpoints.create, {
        passphrase,
        include_ssh: byId("backup-include-ssh").checked,
        quiesce: byId("backup-quiesce").checked
      });
      clearPasswords();
      currentOperationJobId = String(payload.job_id || payload.id || "");
      storageSet(OPERATION_JOB_KEY, currentOperationJobId);
      setMessage("backup-create-status", t("Backup scheduled. The page may be briefly unavailable while services are paused."), true);
      byId("backup-job-log").textContent = `job_id=${payload.job_id || payload.id || "unknown"}`;
      focusJobLog(currentOperationJobId);
      schedulePoll(800);
    } catch (error) { setMessage("backup-create-status", error.message, false, true); }
    finally { button.disabled = false; }
  }

  function setStoredBackupMode(backupId) {
    stagedBackupId = String(backupId || "");
    const fileInput = byId("backup-restore-file");
    if (stagedBackupId) fileInput.value = "";
    fileInput.required = !stagedBackupId;
    byId("backup-inspect-button").textContent = stagedBackupId
      ? t("Verify stored backup")
      : t("Upload and verify backup");
  }

  function resetRestoreConfirmation() {
    byId("backup-replace-confirm").checked = false;
    byId("backup-restore-confirmation").value = "";
    updateRestoreButton();
  }

  async function stageStoredBackup(backupId) {
    if (stagingStoredBackup) return;
    stagingStoredBackup = true;
    const inspectButton = byId("backup-inspect-button");
    inspectButton.disabled = true;
    currentUploadId = "";
    currentInspectionJobId = "";
    storageSet(INSPECTION_JOB_KEY, "");
    renderManifest(null);
    resetRestoreConfirmation();
    setStoredBackupMode("");
    byId("backup-restore-passphrase").value = "";
    setMessage("backup-upload-status", t("Staging stored backup…"));
    try {
      const stageUrl = endpoints.stage.replace("BACKUP_ID", encodeURIComponent(backupId));
      const staged = await postJson(stageUrl, {});
      const uploadId = String(staged.upload_id || "");
      if (!/^[a-f0-9]{32}$/.test(uploadId)) {
        throw new Error(t("The backup service returned an invalid staged upload identifier."));
      }
      currentUploadId = uploadId;
      setStoredBackupMode(backupId);
      setMessage(
        "backup-upload-status",
        t("Stored backup staged. Enter its passphrase and click Verify stored backup."),
        true
      );
      byId("backup-restore-passphrase").focus();
      byId("backup-inspect-form").scrollIntoView({behavior: "smooth", block: "center"});
    } catch (error) {
      setMessage("backup-upload-status", error.message, false, true);
    } finally {
      stagingStoredBackup = false;
      inspectButton.disabled = false;
    }
  }

  async function uploadAndInspect(event) {
    event.preventDefault();
    const file = byId("backup-restore-file").files[0];
    const passphrase = byId("backup-restore-passphrase").value;
    const useStoredBackup = Boolean(stagedBackupId && currentUploadId);
    if (!useStoredBackup && !file) { setMessage("backup-upload-status", t("Choose an encrypted backup file."), false); return; }
    if (passphrase.length < 12) { setMessage("backup-upload-status", t("Use a passphrase of at least 12 characters."), false); return; }
    const button = byId("backup-inspect-button");
    button.disabled = true;
    renderManifest(null);
    resetRestoreConfirmation();
    currentInspectionJobId = "";
    storageSet(INSPECTION_JOB_KEY, "");
    setMessage("backup-upload-status", useStoredBackup
      ? t("Verifying stored backup…")
      : t("Uploading encrypted backup…"));
    try {
      if (!useStoredBackup) {
        currentUploadId = "";
        const uploaded = await requestJson(endpoints.upload, {
          method: "POST",
          headers: {"Content-Type": "application/octet-stream", "X-Backup-Filename": file.name},
          body: file
        });
        currentUploadId = uploaded.upload_id;
        setMessage("backup-upload-status", t("Upload complete. Verifying encryption and archive checksums…"));
      }
      const inspectUrl = endpoints.inspect.replace("UPLOAD_ID", encodeURIComponent(currentUploadId));
      const inspection = await postJson(inspectUrl, {passphrase});
      currentInspectionJobId = inspection.job_id || inspection.id || "";
      currentOperationJobId = currentInspectionJobId;
      storageSet(INSPECTION_JOB_KEY, currentInspectionJobId);
      storageSet(OPERATION_JOB_KEY, currentOperationJobId);
      byId("backup-restore-passphrase").value = "";
      setMessage("backup-upload-status", t("Verification scheduled. The archive will not be applied yet."), true);
      schedulePoll(700);
    } catch (error) { setMessage("backup-upload-status", error.message, false, true); }
    finally { button.disabled = false; }
  }

  function updateRestoreButton() {
    byId("backup-restore-button").disabled = !(
      currentManifest && currentUploadId && currentInspectionJobId &&
      byId("backup-replace-confirm").checked &&
      byId("backup-restore-confirmation").value.trim() === "RESTORE"
    );
  }

  function selectedRestoreScope() {
    return document.querySelector('input[name="backup_restore_scope"]:checked')?.value || "full";
  }
  function updateScopeControls() {
    const configScope = selectedRestoreScope() === "config";
    const sshAvailable = Boolean(currentManifest && currentManifest.ssh_included);
    const sshCheckbox = byId("backup-restore-ssh");
    // Keep the option visible so its state is explicit, but make it
    // unusable when the archive has no keys or the scope excludes them.
    sshCheckbox.disabled = configScope || !sshAvailable;
    if (sshCheckbox.disabled) sshCheckbox.checked = false;
    byId("backup-restore-ssh-row").hidden = false;
    byId("backup-restore-ssh-row").classList.toggle(
      "backup-option-disabled", sshCheckbox.disabled
    );
  }

  async function restoreBackup() {
    const passphrase = byId("backup-restore-passphrase").value;
    if (passphrase.length < 12) {
      setMessage("backup-restore-status", t("Enter the backup passphrase again to start restore."), false);
      byId("backup-restore-passphrase").focus();
      return;
    }
    const configScope = selectedRestoreScope() === "config";
    const question = configScope
      ? t("Restore only sites and certificates from this backup now?")
      : t("Start full restore now? The application will disconnect while managed state is replaced.");
    if (!window.confirm(question)) return;
    const button = byId("backup-restore-button");
    button.disabled = true;
    setMessage("backup-restore-status", t("Scheduling restore…"));
    try {
      const result = await postJson(endpoints.restore, {
        upload_id: currentUploadId,
        inspection_job_id: currentInspectionJobId,
        passphrase,
        restore_ssh: configScope ? false : byId("backup-restore-ssh").checked,
        confirmation: "RESTORE",
        scope: selectedRestoreScope()
      });
      currentOperationJobId = String(result.job_id || result.id || "");
      storageSet(OPERATION_JOB_KEY, currentOperationJobId);
      byId("backup-restore-passphrase").value = "";
      resetRestoreConfirmation();
      setMessage("backup-restore-status", t("Restore started. Temporary disconnects are expected; this page will keep reconnecting."), true);
      byId("backup-job-log").textContent = `job_id=${result.job_id || result.id || "unknown"}`;
      focusJobLog(currentOperationJobId);
      schedulePoll(700);
    } catch (error) {
      setMessage("backup-restore-status", error.message, false, true);
      updateRestoreButton();
    }
  }

  async function deleteBackup(id) {
    if (window.prompt(t("Type DELETE to remove this server-side backup."), "") !== "DELETE") return;
    try {
      await postJson(endpoints.remove, {kind: "backup", id, confirmation: "DELETE"});
      await refreshStatus();
    } catch (error) { setMessage("backup-service-status", error.message, false, true); }
  }

  byId("backup-create-form").addEventListener("submit", createBackup);
  byId("backup-passphrase-show").addEventListener("change", () => {
    byId("backup-passphrase").type =
      byId("backup-passphrase-show").checked ? "text" : "password";
  });
  byId("backup-inspect-form").addEventListener("submit", uploadAndInspect);
  byId("backup-restore-file").addEventListener("change", () => {
    if (!byId("backup-restore-file").files.length) return;
    setStoredBackupMode("");
    currentUploadId = "";
    currentInspectionJobId = "";
    storageSet(INSPECTION_JOB_KEY, "");
    renderManifest(null);
    resetRestoreConfirmation();
    setMessage("backup-upload-status", "");
  });
  byId("backup-restore-button").addEventListener("click", restoreBackup);
  document.querySelectorAll('input[name="backup_restore_scope"]').forEach((input) => {
    input.addEventListener("change", updateScopeControls);
  });
  byId("backup-replace-confirm").addEventListener("change", updateRestoreButton);
  byId("backup-restore-confirmation").addEventListener("input", updateRestoreButton);
  byId("backup-artifacts-body").addEventListener("click", (event) => {
    const restoreButton = event.target.closest("[data-restore-backup]");
    if (restoreButton) {
      stageStoredBackup(restoreButton.dataset.restoreBackup);
      return;
    }
    const deleteButton = event.target.closest("[data-delete-backup]");
    if (deleteButton) deleteBackup(deleteButton.dataset.deleteBackup);
  });
  byId("backup-jobs-body").addEventListener("click", (event) => {
    const row = event.target.closest("[data-job-id]");
    if (!row) return;
    if (selectedJobId === row.dataset.jobId) {
      // Second click on the same job switches between log and details.
      logViewMode = logViewMode === "log" ? "details" : "log";
    } else {
      selectedJobId = row.dataset.jobId;
      logViewMode = "log";
    }
    storageSet(SELECTED_JOB_KEY, selectedJobId);
    markSelectedRow();
    byId("backup-log-details").open = true;
    storageSet(LOG_OPEN_KEY, "1");
    requestJson(`${endpoints.status}?job_id=${encodeURIComponent(row.dataset.jobId)}`)
      .then((payload) => showJob(payload.job || (payload.jobs || [])[0] || payload))
      .catch((error) => setMessage("backup-service-status", error.message, false, true));
  });
  byId("backup-log-details").addEventListener("toggle", () => {
    storageSet(LOG_OPEN_KEY, byId("backup-log-details").open ? "1" : "");
  });
  if (storageGet(LOG_OPEN_KEY)) byId("backup-log-details").open = true;
  window.setInterval(renderElapsed, 1000);

  refreshStatus();
})();
