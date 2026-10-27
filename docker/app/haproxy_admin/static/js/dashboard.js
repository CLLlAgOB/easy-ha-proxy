/* dashboard.js -- the main page's logic */

const Dashboard = (() => {
  /* ─────────── internal state ─────────── */
  let auto = false, tblTimer = null, connTimer = null;

  // Ban reasons by HAProxy's codes (var(txn.ban_code) / gpt0)
  // 10 -> ERR_LIMIT_SITE
  // 20 -> ERR_LIMIT_OTHER
  // 30 -> RATE_LIMIT_SITE
  const BAN_REASON_LABELS = {
    10: 'Too many 4xx errors for the site (ERR_LIMIT_SITE)',
    20: 'Too many 4xx errors for other requests without SNI (ERR_LIMIT_OTHER)',
    30: 'Site request rate limit exceeded (RATE_LIMIT_SITE)',
    // 40 is the adaptive engine's own, and it is the one an operator is most
    // likely to question -- a ban placed by scoring rather than by a rule
    // they can point at in the configuration. Without a label here it showed
    // as a bare "40", which explains nothing and looks like a fault.
    40: 'Adaptive protection: scored as hostile (ADAPTIVE_BAN)'
  };


  /* ──────────── utilities ──────────── */
  function formatDuration(sec) {
    sec = +sec || 0;
    if (sec < 60) return `${sec} sec`;
    if (sec < 3600) return `${Math.floor(sec / 60)} min`;
    if (sec < 86400) return `${Math.floor(sec / 3600)} hr`;
    return `${Math.floor(sec / 86400)} days`;
  }
  function badge(text, cls) {
    return `<span class="status-badge ${cls}">${escapeHtml(text)}</span>`;
  }

  /* ───────────— render-helpers ─────────── */
  function renderTable(containerId, data, metaId = null) {
    const el = document.getElementById(containerId);
    if (!el) return;

    if (!data || !data.rows?.length) {
      el.innerHTML = `<div class="no-data">No data</div>`;
      if (metaId && document.getElementById(metaId)) {
        document.getElementById(metaId).textContent = '0 entries';
      }
      return;
    }

    const headers = Array.isArray(data.headers) ? data.headers : [];

    // Find the TTL/Expires index by the header's name, rather than hard-coding i === 2
    const ttlIdx = headers.findIndex(h =>
      typeof h === 'string' && /ttl|expire|expires/i.test(h)
    );

    // For "Blocked IPs": sort by the TTL column (if found)
    if (containerId === 'ban' && Array.isArray(data?.rows) && ttlIdx >= 0) {
      data = Object.assign({}, data, {
        rows: data.rows.slice().sort((a, b) => {
          const av = Number(a?.[ttlIdx]) || 0;
          const bv = Number(b?.[ttlIdx]) || 0;
          // Longest time left first. This used to mean "newest first", when
          // every row carried the table's own countdown; adaptive bans now
          // show the engine's schedule instead, so the two are not the same.
          return bv - av;
        })
      });
    }

    // Metadata (used / size)
    if (metaId && data.meta && document.getElementById(metaId)) {
      const { used = 0, size = 0 } = data.meta;
      const pct = size ? Math.round((used / size) * 100) : 0;
      document.getElementById(metaId).textContent = `${used} from ${size} (${pct} %)`;
    }

    let html = '<table class="data-table"><thead><tr>';
    headers.forEach(h => html += `<th>${escapeHtml(h)}</th>`);
    html += '</tr></thead><tbody>';

    data.rows.forEach(r => {
      html += '<tr>';

      r.forEach((cell, i) => {
        let v = cell;

        // 1) The first column is an IP -> a link
        if (i === 0) {
          const ip = String(cell || '');
          v = `<a href="/ip/${encodeURIComponent(ip)}" target="_blank" rel="noopener" class="ip-cell">${escapeHtml(ip)}</a>`;
        }

        // 2) Status in the ban table: draw a badge
        else if (containerId === 'ban' && i === 1) {
          v = badge(cell, cell === 'Blocked' ? 'status-blocked' : 'status-normal');
        }

        // 3) The errors column in the common err table
        else if (containerId === 'err' && i === 1) {
          const n = +cell || 0;
          v = badge(
            `${n} errors`,
            n > 5 ? 'status-blocked' : n > 1 ? 'status-warning' : 'status-normal'
          );
        }

        // 4) The TTL/Expires column, made human-readable
        else if (ttlIdx >= 0 && i === ttlIdx) {
          // Say where the number comes from. For an adaptive ban it is the
          // engine's schedule; for everything else it is the stick table's
          // own lifetime -- which, for an adaptive ban, reads as days about a
          // ban that lifts within the hour.
          let source = '';
          if (containerId === 'ban') {
            const scheduled = (data.meta && data.meta.expiry_from_schedule) || [];
            source = scheduled.includes(String(r[0]))
              ? 'By the adaptive protection schedule'
              : 'Stick table lifetime';
          }
          const title = source ? ` title="${escapeHtml(source)}"` : '';
          v = `<span${title}>${formatDuration(cell)}</span>`;
        }

        // 5) The ban reason (should a "Reason" column be added)
        else if (
          containerId === 'ban' &&
          typeof headers[i] === 'string' &&
          /reason/i.test(headers[i])
        ) {
          // a numeric code: try to decode it
          const num = Number(cell);
          if (!isNaN(num) && BAN_REASON_LABELS[num]) {
            v = BAN_REASON_LABELS[num];
          } else {
            v = escapeHtml(cell ?? '');
          }
        }
        else {
          v = escapeHtml(v ?? '');
        }

        html += `<td>${v}</td>`;
      });

      html += '</tr>';
    });

    html += '</tbody></table>';
    el.innerHTML = html;

    // For the ban table and the others: add flags by IP with one batch request
    if (Array.isArray(data?.rows) && typeof window.decorateFlags === 'function') {
      window.decorateFlags(containerId, data.rows, 0);
    }
  }


  // Adds flags to the IP column of ANY table
  window.decorateFlags = async function (containerId, rows, ipIndex = 0) {
    try {
      // Collect the addresses from the given column
      const ips = Array.from(new Set(
        rows.map(r => String(r?.[ipIndex] || '').trim())
      )).filter(Boolean);
      if (!ips.length) return;

      const resp = await fetch('/api/country-batch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ips })
      });
      const map = await resp.json();

      const tbody = document.querySelector(`#${containerId} table tbody`);
      if (!tbody) return;

      Array.from(tbody.querySelectorAll('tr')).forEach((tr, idx) => {
        const td = tr.children[ipIndex];
        if (!td) return;

        // find the IP as the link's or the cell's text
        const link = td.querySelector('a.ip-cell');
        const ip = link ? link.textContent.trim() : (rows[idx]?.[ipIndex] || '').toString().trim();
        if (!ip) return;

        // a flag already? do not add another
        if (td.querySelector('.country-flag')) return;

        const rawCc = String(map[ip] || '').toLowerCase();
        const cc = /^[a-z]{2}$/.test(rawCc) ? rawCc : '';
        const flag = window.countryFlagMarkup(cc);

        // Put the flag before the cell's content.
        // insertAdjacentHTML does not recreate the other nodes: rewriting
        // innerHTML cancelled flag images still loading
        // (NS_BINDING_ABORTED) when the tables refreshed.
        td.insertAdjacentHTML('afterbegin', flag);
      });
    } catch (e) {
      console.warn('decorateFlags:', e);
    }
  };


  // CONNECTIONS: just the IP, the country and the count
  function renderConnectionsAggregated(containerId, list, metaId, total) {
    const el = document.getElementById(containerId);
    if (!el) return;

    if (!list?.length) {
      el.innerHTML = '<div class="no-data">No active connections</div>';
      if (metaId && document.getElementById(metaId)) {
        document.getElementById(metaId).textContent = `0 / ${total || 0}`;
      }
      return;
    }

    if (metaId && document.getElementById(metaId)) {
      document.getElementById(metaId).textContent = `${list.length} IP / ${total || 0} connections`;
    }

    let h = '<table class="data-table"><thead><tr>' +
      '<th>IP</th><th>Country</th><th>Count</th>' +
      '</tr></thead><tbody>';
    list.forEach(c => {
      const rawCc = String(c.country || '').toLowerCase();
      const cc = /^[a-z]{2}$/.test(rawCc) ? rawCc : '';
      const flag = window.countryFlagMarkup(cc);
      h += `<tr>
              <td><span class="ip-cell">${escapeHtml(c.src_ip)}</span></td>
              <td>${flag}<span class="country-code">${escapeHtml(cc.toUpperCase())}</span></td>
              <td>${escapeHtml(c.count)}</td>
            </tr>`;
    });
    el.innerHTML = h + '</tbody></table>';
  }

  function renderAttackers(list, elId) {
    const el = document.getElementById(elId);
    if (!el) return;
    if (!list?.length) {
      el.innerHTML = '<div class="loading">No data</div>';
      return;
    }
    let h = '<table class="data-table"><thead><tr>' +
      '<th>IP</th><th>Country</th><th>Count</th></tr></thead><tbody>';
    list.forEach(a => {
      const rawCc = String(a.country || '').toLowerCase();
      const cc = /^[a-z]{2}$/.test(rawCc) ? rawCc : '';
      const ip = String(a.ip || '');
      const flag = window.countryFlagMarkup(cc);
      h += `<tr>
            <td><a href="/ip/${encodeURIComponent(ip)}" target="_blank" rel="noopener" class="ip-cell">${escapeHtml(ip)}</a></td>
            <td>${flag}<span class="country-code">${escapeHtml(cc.toUpperCase())}</span></td>
            <td>${escapeHtml(a.count)}</td>
          </tr>`;
    });
    h += '</tbody></table>';
    el.innerHTML = h;
  }

  function prettifyErrTableName(name) {
    const n = String(name || '');
    // Unnamed or broken names (nosni/other)
    if (n === 'tbl_err_nosni' || n === 'tbl_err_other') return 'No SNI / invalid name';
    // Remove the common prefix
    let s = n.replace(/^tbl_err_/, '');
    // Dots instead of underscores, for domains in the form rdg_example_com
    s = s.replace(/_/g, '.');
    return s;
  }

  function recordWord(n) {
    const abs = Math.abs(Number(n) || 0);
    const last = abs % 10;
    const lastTwo = abs % 100;
    if (last === 1 && lastTwo !== 11) return 'entry';
    if (last >= 2 && last <= 4 && (lastTwo < 12 || lastTwo > 14)) return 'entries';
    return 'entries';
  }

  function parseWhitelistEntries(raw) {
    return String(raw || '')
      .split(/\r?\n/)
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'));
  }

  function renderWhitelistEntries(listId, metaId, raw, emptyText, kind) {
    const box = document.getElementById(listId);
    const meta = document.getElementById(metaId);
    if (!box) return [];

    const text = String(raw || '').trim();
    const isMessage = text.startsWith('(') && text.endsWith(')') && !text.includes('\n');
    const entries = isMessage ? [] : parseWhitelistEntries(text);

    if (meta) meta.textContent = `${entries.length} ${recordWord(entries.length)}`;

    if (isMessage) {
      box.innerHTML = `<div class="no-data">${escapeHtml(text)}</div>`;
      return entries;
    }

    if (!entries.length) {
      box.innerHTML = `<div class="no-data">${escapeHtml(emptyText)}</div>`;
      return entries;
    }

    box.innerHTML = `<ul class="whitelist-items">${
      entries.map(entry => `
        <li>
          <code>${escapeHtml(entry)}</code>
          <button
            type="button"
            class="btn whitelist-remove"
            data-whitelist-action="remove"
            data-whitelist-kind="${escapeHtml(kind)}"
            data-whitelist-entry="${escapeHtml(entry)}"
          >Delete</button>
        </li>
      `).join('')
    }</ul>`;
    return entries;
  }

  function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  }

  async function loadWhitelists(manual = false) {
    const btn = document.getElementById('whitelists-refresh');
    const meta = document.getElementById('whitelists-meta');

    if (manual && btn) {
      btn.disabled = true;
      btn.textContent = 'Refreshing…';
    }
    if (meta) meta.textContent = 'Loading…';
    ['whitelist-geo-list', 'whitelist-global-list'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.innerHTML = '<div class="loading">Loading…</div>';
    });

    try {
      const r = await fetch('/api/whitelists');
      const j = await r.json();
      if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);

      setText('whitelist-geo-path', 'Path: ' + (j.geo_file_path || '—'));
      setText('whitelist-global-path', 'Path: ' + (j.global_file_path || '—'));
      setText('whitelist-geo-runtime', String(j.geo_runtime || '(no data)').trim() || '(empty)');
      setText('whitelist-global-runtime', String(j.global_runtime || '(no data)').trim() || '(empty)');

      const geoEntries = renderWhitelistEntries(
        'whitelist-geo-list',
        'whitelist-geo-meta',
        j.geo_file,
        'GEO allow list is empty',
        'geo'
      );
      const globalEntries = renderWhitelistEntries(
        'whitelist-global-list',
        'whitelist-global-meta',
        j.global_file,
        'GLOBAL allow list is empty',
        'global'
      );

      if (meta) {
        const total = geoEntries.length + globalEntries.length;
        meta.textContent = `Total ${total} ${recordWord(total)}: GEO ${geoEntries.length}, GLOBAL ${globalEntries.length}`;
      }
    } catch (e) {
      console.error(e);
      if (meta) meta.textContent = 'Error';
      ['whitelist-geo-list', 'whitelist-global-list'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.innerHTML = `<div class="error">Error: ${escapeHtml(e.message)}</div>`;
      });
      setText('whitelist-geo-runtime', 'ERROR: ' + e.message);
      setText('whitelist-global-runtime', 'ERROR: ' + e.message);
    } finally {
      if (manual && btn) {
        btn.disabled = false;
        btn.textContent = 'Refresh';
      }
    }
  }

  function whitelistEndpoint(kind) {
    return kind === 'global' ? '/api/whitelist-global' : '/api/whitelist';
  }

  function whitelistResultId(kind) {
    return kind === 'global' ? 'whitelist-global-result' : 'whitelist-result';
  }

  function whitelistInputId(kind) {
    return kind === 'global' ? 'whitelist-global-ip' : 'whitelist-ip';
  }

  async function submitWhitelistChange(kind, value, options = {}) {
    const res = document.getElementById(options.resultId || whitelistResultId(kind));
    const input = document.getElementById(options.inputId || whitelistInputId(kind));
    const button = options.button || null;
    const originalButtonText = button ? button.textContent : '';

    if (res) {
      res.textContent = options.pendingText || 'Sending…';
      res.className = 'result-message';
    }
    if (button) {
      button.disabled = true;
      button.textContent = options.buttonPendingText || originalButtonText;
    }

    try {
      const r = await fetch(whitelistEndpoint(kind), {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `ip=${encodeURIComponent(value)}`
      });
      const txt = (await r.text()) || '';

      if (!r.ok) {
        if (res) {
          res.textContent = 'Error: ' + txt;
          res.className = 'result-message error';
        }
        return false;
      }

      if (res) {
        res.textContent = txt.trim() || 'OK';
        res.className = 'result-message success';
      }
      if (input && options.clearInput) input.value = '';

      loadWhitelists();
      setTimeout(loadWhitelists, 2000);
      setTimeout(loadTables, 2000);

      setTimeout(() => {
        if (res) {
          res.textContent = '';
          res.className = 'result-message';
        }
      }, 5000);
      return true;
    } catch (e) {
      if (res) {
        res.textContent = 'Network error: ' + e.message;
        res.className = 'result-message error';
      }
      return false;
    } finally {
      if (button) {
        button.disabled = false;
        button.textContent = originalButtonText;
      }
    }
  }

  /* ───────────— API ─────────── */
  async function loadTables(manual = false) {
    const btn = document.getElementById('refresh-btn');
    if (manual && btn) btn.classList.add('loading');

    try {
      const r = await fetch('/api/tables');
      const j = await r.json();

      // as before: one combined errors table
      renderTable('ban', j.ban, 'ban-meta');
      renderTable('err', j.err, 'err-meta');

      // NEW: a separate errors table for every stick table
      const errHost = document.getElementById('err');
      if (errHost) {
        // the container for the sub-tables
        let sub = document.getElementById('err-subtables');
        if (!sub) {
          sub = document.createElement('div');
          sub.id = 'err-subtables';
          sub.style.marginTop = '10px';
          errHost.parentElement.appendChild(sub);
        }
        sub.innerHTML = '';

        // READ THE SITE FILTER FROM THE URL: ?site=rdg.domain.local
        const siteFilter = (new URLSearchParams(location.search).get('site') || '').trim();
        const toTblName = (d) => 'tbl_err_' + d.replace(/[^A-Za-z0-9_]/g, '_'); // as in backend

        if (Array.isArray(j.err_multi) && j.err_multi.length) {
          // If a site is given, work out the name of its stick table
          const onlyName = siteFilter ? toTblName(siteFilter) : null;

          let rendered = 0;
          j.err_multi.forEach(item => {
            const name = String(item.name || '');
            const rows = item?.table?.rows || [];

            // With the site filter on, an empty section of THIS SITE is hidden (not rendered)
            if (onlyName && name === onlyName && rows.length === 0) {
              // nothing is added: the section is hidden
              return;
            }

            // With the filter on, show only the matching site (and only if it has data)
            if (onlyName && name !== onlyName) {
              return;
            }

            // Without a filter, show every non-empty one (empty ones could be allowed too)
            if (!onlyName && rows.length === 0) {
              // empty ones are skipped, so they do not clutter the UI
              return;
            }

            const safeId = 'err_' + name.replace(/[^A-Za-z0-9_]/g, '_');
            const h = document.createElement('h4');
            h.textContent = prettifyErrTableName(name) || 'unknown';
            sub.appendChild(h);
            const div = document.createElement('div');
            div.id = safeId;
            sub.appendChild(div);
            renderTable(safeId, item.table);
            rendered++;
          });

          // If nothing was drawn for the chosen site, show a tidy placeholder
          if (rendered === 0) {
            const p = document.createElement('div');
            p.className = 'no-data';
            p.textContent = siteFilter
              ? `No failed requests for site ${siteFilter}`
              : 'No data by errors';
            sub.appendChild(p);
          }
        }
      }
      if (manual && btn) {
        btn.classList.remove('loading');
        btn.classList.add('success');
        setTimeout(() => btn.classList.remove('success'), 1500);
      }
    } catch (e) {
      console.error(e);
      ['ban', 'err'].forEach(id => {
        const box = document.getElementById(id);
        if (box) box.innerHTML = `<div class="error">Error: ${escapeHtml(e.message)}</div>`;
      });
      if (manual && btn) btn.classList.remove('loading', 'success');
    }
  }


  async function fetchConnections() {
    const box = document.getElementById('connections');
    if (box) box.innerHTML = '<div class="loading">Loading…</div>';
    try {
      const r = await fetch('/api/connections');
      const j = await r.json();
      renderConnectionsAggregated('connections', j.list || [], 'conn-meta', j.total);
    } catch (e) {
      console.error(e);
      if (box) box.innerHTML = `<div class="error">Error: ${escapeHtml(e.message)}</div>`;
    }
  }

  async function fetchAttackers() {
    ['top-400', 'top-451'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.innerHTML = '<div class="loading">Loading…</div>';
    });
    try {
      const r = await fetch('/api/attackers');
      const j = await r.json();
      renderAttackers(j.code_400, 'top-400');
      renderAttackers(j.code_451, 'top-451');
    } catch (e) {
      console.error(e);
      ['top-400', 'top-451'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.innerHTML = `<div class="error">Error: ${escapeHtml(e.message)}</div>`;
      });
    }
  }

  // ─────────── Authorized IPs (tbl_ip_auth) ───────────
  async function loadIpAuth(manual = false) {
    const containerId = 'ip-auth';
    const metaId = 'ip-auth-meta';

    const box = document.getElementById(containerId);
    if (!box) return;

    if (manual) {
      box.innerHTML = '<div class="loading">Loading…</div>';
      const metaEl = document.getElementById(metaId);
      if (metaEl) metaEl.textContent = 'Loading…';
    }

    try {
      const r = await fetch('/api/ip_auth');
      if (!r.ok) throw new Error('HTTP ' + r.status);

      const j = await r.json();
      const rows = j.rows || [];
      const meta = j.meta || {};
      const headers = j.headers || ['IP', 'Flag', 'TTL (sec)'];

      // no table, or the feature is off
      if (meta.error === 'table_missing') {
        box.innerHTML = '<div class="no-data">The tbl_ip_auth table is missing or the feature is disabled.</div>';
        const metaEl = document.getElementById(metaId);
        if (metaEl) metaEl.textContent = '0 entries';
        return;
      }

      if (!rows.length) {
        box.innerHTML = '<div class="no-data">No active entries.</div>';
        const metaEl = document.getElementById(metaId);
        if (metaEl) metaEl.textContent = '0 entries';
        return;
      }

      // meta information at the top
      const metaEl = document.getElementById(metaId);
      if (metaEl) {
        const used = meta.used || rows.length;
        const size = meta.size || used;
        const pct = size ? Math.round((used / size) * 100) : 0;
        metaEl.textContent = `${used} from ${size} (${pct} %)`;
      }

      // render the table by hand (so it does not depend on renderTable)
      let html = '<table class="data-table"><thead><tr>';
      headers.forEach(h => { html += `<th>${escapeHtml(h)}</th>`; });
      html += '</tr></thead><tbody>';

      rows.forEach(rw => {
        const ip = String(rw[0] ?? '');
        const flag = rw[1] ?? '';
        const ttl = rw[2] ?? 0;

        html += '<tr>';

        // the IP as a link to /ip/<ip>
        html += `<td><a href="/ip/${encodeURIComponent(ip)}" target="_blank" rel="noopener" class="ip-cell">${escapeHtml(ip)}</a></td>`;
        // Flag (gpc0)
        html += `<td>${escapeHtml(flag)}</td>`;
        // TTL in a readable form through formatDuration (sec -> min/hr/days)
        html += `<td><span>${formatDuration(ttl)}</span></td>`;

        html += '</tr>';
      });

      html += '</tbody></table>';
      box.innerHTML = html;

      // after rendering, add flags by IP if the function is available
      if (typeof window.decorateFlags === 'function') {
        window.decorateFlags(containerId, rows, 0);
      }
    } catch (e) {
      console.error(e);
      box.innerHTML = `<div class="error">Error: ${escapeHtml(e.message)}</div>`;
      const metaEl = document.getElementById(metaId);
      if (metaEl) metaEl.textContent = 'Error';
    }
  }

  /* ─────────── forms ─────────── */
  function initForms() {
    const getEl = id => document.getElementById(id);

    // Unban
    const unbanForm = getEl('unban-form');
    if (unbanForm) {
      unbanForm.addEventListener('submit', async ev => {
        ev.preventDefault();
        const ip = getEl('ip').value.trim();
        const res = getEl('unban-result');
        if (!ip) return (res.textContent = 'Enter an IP address', res.className = 'error');

        res.textContent = 'Sending…'; res.className = '';
        try {
          const r = await fetch('/api/unban', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `ip=${encodeURIComponent(ip)}`
          });
          const txt = await r.text();
          if (r.ok) {
            res.textContent = 'Success!'; res.className = 'success';
            getEl('ip').value = '';
            loadTables();
          } else {
            res.textContent = 'Error: ' + txt; res.className = 'error';
          }
        } catch (e) {
          res.textContent = 'Network error: ' + e.message; res.className = 'error';
        }
      });
    }

    // GEO whitelist (toggle)
    const wlGeoForm = getEl('whitelist-form');
    if (wlGeoForm) {
      wlGeoForm.addEventListener('submit', async ev => {
        ev.preventDefault();
        const ip = getEl('whitelist-ip').value.trim();
        const res = getEl('whitelist-result');

        if (!ip) {
          res.textContent = 'Enter an IP address or network';
          res.className = 'result-message error';
          return;
        }

        await submitWhitelistChange('geo', ip, { clearInput: true });
      });
    }

    // The global allow-list (toggle)
    const wlGlobalForm = getEl('whitelist-global-form');
    if (wlGlobalForm) {
      wlGlobalForm.addEventListener('submit', async ev => {
        ev.preventDefault();
        const ip = getEl('whitelist-global-ip').value.trim();
        const res = getEl('whitelist-global-result');

        if (!ip) {
          res.textContent = 'Enter an IP address or network';
          res.className = 'result-message error';
          return;
        }

        await submitWhitelistChange('global', ip, { clearInput: true });
      });
    }

    const whitelistsPanel = getEl('whitelists-panel');
    if (whitelistsPanel) {
      whitelistsPanel.addEventListener('click', async ev => {
        const target = ev.target instanceof Element ? ev.target : ev.target.parentElement;
        const btn = target?.closest('[data-whitelist-action="remove"]');
        if (!btn) return;

        const kind = btn.dataset.whitelistKind || 'geo';
        const entry = btn.dataset.whitelistEntry || '';
        if (!entry) return;
        if (!window.confirm(`Delete ${entry} from whitelist?`)) return;

        await submitWhitelistChange(kind, entry, {
          button: btn,
          pendingText: 'Deleting…',
          buttonPendingText: 'Deleting…'
        });
      });
    }
  }

  /* ─────────── auto-refresh ─────────── */
  function startAuto() {
    if (!tblTimer) tblTimer = setInterval(() => loadTables(false), 5000);
    if (!connTimer) connTimer = setInterval(fetchConnections, 10000);
  }
  function stopAuto() {
    clearInterval(tblTimer); tblTimer = null;
    clearInterval(connTimer); connTimer = null;
  }

  /* ─────────── start-up ─────────── */
  function init() {
    loadTables();
    fetchAttackers();
    fetchConnections();
    loadIpAuth();   // <- load the authorised addresses at start
    loadWhitelists();
    initForms();

    const autoBtn = document.getElementById('auto-btn');
    if (autoBtn) {
      autoBtn.onclick = () => {
        auto = !auto;
        auto ? startAuto() : stopAuto();
        autoBtn.textContent = `Auto-refresh: ${auto ? 'on' : 'off'}`;
      };
    }
    const ipAuthBtn = document.getElementById('ip-auth-refresh');
    if (ipAuthBtn) {
      ipAuthBtn.onclick = () => loadIpAuth(true);
    }
    const whitelistsBtn = document.getElementById('whitelists-refresh');
    if (whitelistsBtn) {
      whitelistsBtn.onclick = () => loadWhitelists(true);
    }

    // Replaces inline onclick="Dashboard.x()" so the CSP can drop
    // 'unsafe-inline' from script-src.
    const actions = {
      manualRefresh: () => { loadTables(true); loadWhitelists(true); },
      fetchAttackers,
      fetchConnections
    };
    document.querySelectorAll('[data-dashboard-action]').forEach((button) => {
      const handler = actions[button.dataset.dashboardAction];
      if (handler) button.addEventListener('click', () => handler());
    });
  }
  return {
    init,
    manualRefresh: () => {
      loadTables(true);
      loadWhitelists(true);
    },
    fetchAttackers,
    fetchConnections
  };
})();

document.addEventListener('DOMContentLoaded', Dashboard.init);
