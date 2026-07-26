// static/js/authelia_users.js
(function () {
  'use strict';

  const searchInput = document.getElementById('user-search');
  const tbody = document.getElementById('users-tbody');
  const meta = document.getElementById('users-meta');

  if (!tbody) return;

  const rows = Array.from(tbody.querySelectorAll('tr[data-search-text]'));
  const total = rows.length;

  function applyFilter() {
    const q = (searchInput && searchInput.value || '').toLowerCase().trim();
    let visible = 0;

    rows.forEach(row => {
      const text = row.getAttribute('data-search-text') || '';
      const match = !q || text.indexOf(q) !== -1;
      row.style.display = match ? '' : 'none';
      if (match) visible++;
    });

    if (meta) {
      if (!q) {
        meta.textContent = `Total users: ${total}`;
      } else {
        meta.textContent = `Found: ${visible} of ${total}`;
      }
    }
  }

  // навигация by клику on line (кроме кнопок/форм)
  rows.forEach(row => {
    const href = row.getAttribute('data-edit-url');
    if (!href) return;

    row.addEventListener('click', function (e) {
      // not реагируем, if клик by кнопке/ссылке/форме
      if (e.target.closest('button, a, form, input, select, textarea')) {
        return;
      }
      window.location.href = href;
    });
  });

  if (searchInput) {
    searchInput.addEventListener('input', applyFilter);
  }

  // начальное состояние метки
  applyFilter();
})();
