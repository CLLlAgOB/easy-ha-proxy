// UI for переключения групп правил by доменам + трекинг активного domain
(function () {
  function showGroup(targetId) {
    var groups = document.querySelectorAll(".domain-group-wrapper");
    var activeDomain = "";

    groups.forEach(function (el) {
      if (el.id === targetId) {
        el.style.display = "";
        activeDomain = el.getAttribute("data-domain") || "";
      } else {
        el.style.display = "none";
      }
    });

    var pills = document.querySelectorAll(".domain-pill");
    pills.forEach(function (btn) {
      var t = btn.getAttribute("data-domain-target");
      if (t === targetId) {
        btn.classList.add("active");
      } else {
        btn.classList.remove("active");
      }
    });

    // Обновляем hidden-field, чтобы server знал активный domain
    var hidden = document.getElementById("active_group_domain");
    if (hidden) {
      hidden.value = activeDomain;
    }
  }

  function init() {
    var pills = document.querySelectorAll(".domain-pill");
    var groups = document.querySelectorAll(".domain-group-wrapper");

    if (!groups.length) {
      return;
    }

    // Навешиваем обработчики on табы
    pills.forEach(function (btn) {
      btn.addEventListener("click", function (ev) {
        ev.preventDefault();
        var target = btn.getAttribute("data-domain-target");
        if (target) {
          showGroup(target);
        }
      });
    });

    // Выбираем стартовую группу.
    // desiredDomain may be:
    //   - конкретный domain "ha.example.com"
    //   - пустая line "" → группа "New / without a domain"
    //   - null → domain not defined → берём первую видимую / первую by порядку
    var hidden = document.getElementById("active_group_domain");
    var desiredDomain = hidden ? hidden.value : null;

    var initialId = null;

    // If hidden есть (in том числе, if там пустая line) —
    // сначала пытаемся найти именно эту группу by data-domain.
    if (desiredDomain !== null) {
      Array.prototype.forEach.call(groups, function (el) {
        if (initialId) {
          return;
        }
        var dom = el.getAttribute("data-domain") || "";
        if (dom === desiredDomain) {
          initialId = el.id;
        }
      });
    }

    // If not нашли конкретную группу — берём первую видимую
    if (!initialId) {
      Array.prototype.forEach.call(groups, function (el) {
        if (!initialId && el.style.display !== "none") {
          initialId = el.id;
        }
      });
    }

    // If and видимых no (or all были hidden) — просто первую by списку
    if (!initialId && groups.length) {
      initialId = groups[0].id;
    }

    if (initialId) {
      showGroup(initialId);
    }
  }

  // На всякий случай экспортируем in глобал
  window.AutheliaAclUI = {
    showGroup: showGroup,
  };

  document.addEventListener("DOMContentLoaded", init);
})();
