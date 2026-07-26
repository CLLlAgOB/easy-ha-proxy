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
      name.textContent = String(it.site || it.backend || '');
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

  // запуск when готовности DOM
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', load);
  } else {
    load();
  }

  // привязка to типовым кнопкам “renew”, if есть
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

  // on всякий — экспорт функции in глобал (можно дергать from консоли)
  window.fetchSitesStatus = load;
})();

// включаем compact by default (and помним выбор)
document.addEventListener('DOMContentLoaded', () => {
  const panel = document.getElementById('sites-panel');
  if (!panel) return;
  // восстановить прошлый выбор or включить by default
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
