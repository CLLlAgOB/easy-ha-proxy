
let autoRefreshInterval = null;

function formatConnectionTime(secOrStr) {
  let sec = 0;
  if (typeof secOrStr === "string" && !/^\d+$/.test(secOrStr)) {
    const rx = /(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?/;
    const m = rx.exec(secOrStr) || [];
    sec = (parseInt(m[1] || 0) * 3600) +
      (parseInt(m[2] || 0) * 60) +
      (parseInt(m[3] || 0));
  } else {
    sec = parseInt(secOrStr) || 0;
  }
  if (sec < 60) return `${sec} sec`;
  if (sec < 3600) return `${Math.floor(sec / 60)} min`;
  if (sec < 86400) return `${Math.floor(sec / 3600)} hr`;
  return `${Math.floor(sec / 86400)} days`;
}

function renderConnectionsTable(containerId, conns, metaId = null) {
  const c = document.getElementById(containerId);
  if (!conns || !conns.length) {
    c.innerHTML = '<div class="no-data">No active connections</div>';
    if (metaId) document.getElementById(metaId).textContent = '0';
    return;
  }
  if (metaId) document.getElementById(metaId).textContent = `${conns.length}`;

  let h = '<table class="data-table"><thead><tr>' +
    '<th>IP</th><th>Country</th><th>Port</th><th>Server</th><th>Duration</th>' +
    '</tr></thead><tbody>';
  conns.forEach(cn => {
    const country = /^[a-z]{2}$/i.test(String(cn.country || '')) ? String(cn.country).toLowerCase() : '';
    const ip = String(cn.src_ip || '');
    const flag = window.countryFlagMarkup(country);
    h += `<tr>
      <td><a href="/ip/${encodeURIComponent(ip)}" target="_blank" rel="noopener" class="ip-cell">${escapeHtml(ip)}</a></td>
      <td>${flag}<span class="country-code">${escapeHtml(country.toUpperCase())}</span></td>
      <td>${escapeHtml(cn.src_port || 'N/A')}</td>
      <td>${escapeHtml(cn.srv || cn.be || 'N/A')}</td>
      <td>${escapeHtml(cn.age_raw || formatConnectionTime(cn.duration))}</td>
    </tr>`;
  });
  c.innerHTML = h + '</tbody></table>';
}

async function fetchConnections() {
  const btn = document.getElementById('refresh-btn');
  try {
    btn.classList.add('loading');
    document.getElementById('connections').innerHTML = '<div class="loading">Loading…</div>';

    const r = await fetch('/api/connections');
    if (!r.ok) throw new Error(`Error ${r.status}`);
    const j = await r.json();
    if (j.error) throw new Error(j.error);

    const all = [...j.rdg, ...j.mail];
    renderConnectionsTable('connections', all, 'overall-meta');

    btn.classList.remove('loading');
    btn.classList.add('success');
    setTimeout(() => btn.classList.remove('success'), 1500);
  } catch (e) {
    console.error(e);
    document.getElementById('connections').innerHTML = `<div class="error">Error: ${escapeHtml(e.message)}</div>`;
    btn.classList.remove('loading');
  }
}

function toggleAutoRefresh() {
  if (autoRefreshInterval) {
    clearInterval(autoRefreshInterval);
    autoRefreshInterval = null;
    document.getElementById('auto-btn').textContent = 'Auto-refresh: off';
  } else {
    autoRefreshInterval = setInterval(fetchConnections, 10000);
    document.getElementById('auto-btn').textContent = 'Auto-refresh: on';
  }
}

document.addEventListener('DOMContentLoaded', () => {
  fetchConnections();

  // Add кнопку автообновления
  const autoBtn = document.createElement('button');
  autoBtn.id = 'auto-btn';
  autoBtn.className = 'btn';
  autoBtn.textContent = 'Auto-refresh: off';
  autoBtn.onclick = toggleAutoRefresh;

  const controls = document.querySelector('.controls');
  if (controls) {
    controls.appendChild(autoBtn);
  }
});
