// static/js/sites.js
(function () {
  function render(list) {
    const ul = document.getElementById('sites-list');
    const meta = document.getElementById('sites-meta');
    if (!ul) return;

    if (!Array.isArray(list) || list.length === 0) {
      ul.innerHTML = '<li class="muted">No data</li>';
      if (meta) meta.textContent = '';
      return;
    }

    // sort: red -> yellow -> green, then by site
    const order = { red: 0, yellow: 1, green: 2 };
    list.sort((a, b) => (order[a.status] - order[b.status]) || String(a.site).localeCompare(String(b.site)));

    ul.replaceChildren();
    list.forEach(it => {
      const li = document.createElement('li');
      const lamp = document.createElement('span');
      lamp.className = `lamp ${['red', 'yellow', 'green'].includes(it.status) ? it.status : 'red'}`;
      const name = document.createElement('span');
      name.className = 'site-name';
      name.title = String(it.backend || '');
      // A site's names open the site; a TCP proxy is a port and the gateway's
      // own services are not for opening, so those stay plain text. The
      // server hands over only checked host names; this checks again.
      const hosts = it.kind === 'site' && Array.isArray(it.hosts)
        ? it.hosts.filter((host) => /^[a-z0-9.-]{1,253}$/i.test(String(host)))
        : [];
      if (hosts.length) {
        hosts.forEach((host, index) => {
          if (index) name.append(', ');
          const link = document.createElement('a');
          link.className = 'site-link';
          link.href = `https://${host}/`;
          link.target = '_blank';
          link.rel = 'noopener noreferrer';
          link.textContent = host;
          name.append(link);
        });
      } else {
        name.textContent = String(it.site || it.backend || '');
      }
      if (it.kind === 'system') li.classList.add('site-system');
      const cnt = document.createElement('span');
      cnt.className = 'counts';
      cnt.textContent = `${Number(it.up) || 0}/${Number(it.total) || 0}`;
      li.append(lamp, name, cnt);
      ul.appendChild(li);
    });

    if (meta) {
      const g = list.filter(x => x.status === 'green').length;
      const y = list.filter(x => x.status === 'yellow').length;
      const r = list.filter(x => x.status === 'red').length;
      meta.innerHTML = `<span class="badge-dot green"></span>${g} · <span class="badge-dot yellow"></span>${y} · <span class="badge-dot red"></span>${r}`;
    }
  }

  async function load() {
    const ul = document.getElementById('sites-list');
    if (!ul) return;
    ul.innerHTML = '<li class="muted">Loading…</li>';
    try {
      const resp = await fetch('/api/backends', { cache: 'no-store' });
      const data = await resp.json();
      render((data && data.items) ? data.items : []);
    } catch (e) {
      ul.innerHTML = '<li class="muted">Loading error</li>';
    }
  }

  // run once the DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', load);
  } else {
    load();
  }

  // bind to the usual "renew" buttons, if any
  const attach = () => {
    const candidates = [
      '[data-action="refresh"]',
      '.btn-refresh',
      '#refresh',
      '#manual-refresh'
    ];
    const btn = document.querySelector(candidates.join(','));
    if (btn) btn.addEventListener('click', load);
  };
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', attach);
  } else {
    attach();
  }

  // just in case: the function is exported globally (it can be called from the console)
  window.fetchSitesStatus = load;
})();

// compact mode is on by default (and the choice is remembered)
document.addEventListener('DOMContentLoaded', () => {
  const panel = document.getElementById('sites-panel');
  if (!panel) return;
  // restore the previous choice, or switch it on by default
  const saved = localStorage.getItem('sites-compact');
  if (saved === '1' || saved === null) panel.classList.add('compact');

  const btn = document.getElementById('toggle-compact');
  if (btn) {
    btn.addEventListener('click', () => {
      panel.classList.toggle('compact');
      localStorage.setItem('sites-compact', panel.classList.contains('compact') ? '1' : '0');
    });
  }
});
