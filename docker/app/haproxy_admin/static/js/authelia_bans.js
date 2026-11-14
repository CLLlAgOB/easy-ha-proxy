document.addEventListener('DOMContentLoaded', function () {
  function goWithParam(key, value) {
    try {
      var url = new URL(window.location.href);
      if (value) {
        url.searchParams.set(key, value);
      } else {
        url.searchParams.delete(key);
      }
      window.location.href = url.toString();
    } catch (e) {
      console.error('authelia_bans: URL error', e);
    }
  }

  var ipButtons = document.querySelectorAll('.js-authelia-log-ip');
  ipButtons.forEach(function (el) {
    el.addEventListener('click', function () {
      var ip = el.getAttribute('data-ip');
      if (ip) {
        goWithParam('log_ip', ip);
      }
    });
  });

  var userButtons = document.querySelectorAll('.js-authelia-log-user');
  userButtons.forEach(function (el) {
    el.addEventListener('click', function () {
      var user = el.getAttribute('data-user');
      if (user) {
        goWithParam('log_user', user);
      }
    });
  });
});
