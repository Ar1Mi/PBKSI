document.querySelectorAll('[data-countdown]').forEach(function (el) {
  var left = parseInt(el.dataset.countdown, 10);
  function fmt(s) {
    if (s <= 0) return 'wygasł';
    var h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), sec = s % 60;
    return (h ? h + ' h ' : '') + (h || m ? m + ' min ' : '') + sec + ' s';
  }
  el.textContent = fmt(left);
  setInterval(function () { left -= 1; el.textContent = fmt(left); }, 1000);
});
