(function () {
  // ─── Inline confirm (two-click pattern) ──────────────────────────────────
  // Buttons with data-confirm show a "¿Seguro?" state instead of browser dialog.
  document.addEventListener('click', function (e) {
    const btn = e.target.closest('[data-confirm]');
    if (!btn) return;
    if (btn.dataset.confirmPending === '1') return; // second click → let the form submit

    e.preventDefault();
    e.stopPropagation();

    const original = btn.innerHTML;
    btn.dataset.confirmPending = '1';
    btn.innerHTML = '¿Seguro? Pulsa de nuevo.';
    btn.classList.add('confirm-pending');

    let timer;

    function reset() {
      btn.dataset.confirmPending = '';
      btn.innerHTML = original;
      btn.classList.remove('confirm-pending');
      document.removeEventListener('click', outsideClick, true);
      clearTimeout(timer);
    }

    const outsideClick = (ev) => {
      if (!btn.contains(ev.target)) reset();
    };

    timer = setTimeout(reset, 4000);
    setTimeout(() => document.addEventListener('click', outsideClick, true), 0);
  }, true);

  // ─── Toast auto-dismiss ───────────────────────────────────────────────────
  function dismissToast(toast) {
    toast.classList.add('is-hiding');
    setTimeout(function () { toast.remove(); }, 280);
  }

  document.querySelectorAll('.toast').forEach(function (toast) {
    var btn = toast.querySelector('.toast__close');
    if (btn) btn.addEventListener('click', function () { dismissToast(toast); });
    setTimeout(function () { dismissToast(toast); }, 4500);
  });

  // ─── Form validation: touch tracking ─────────────────────────────────────
  // Adds .touched on blur so :invalid CSS only fires after user has visited a field.
  document.addEventListener('blur', function (e) {
    const el = e.target;
    if (!['INPUT', 'SELECT', 'TEXTAREA'].includes(el.tagName)) return;
    if (['hidden', 'checkbox', 'radio', 'color'].includes(el.type)) return;
    el.classList.add('touched');
  }, true);

  // Mark all fields as touched on submit so required fields visibly validate.
  document.addEventListener('submit', function (e) {
    e.target
      .querySelectorAll('input:not([type="hidden"]):not([type="checkbox"]):not([type="radio"]):not([type="color"]), select, textarea')
      .forEach(el => el.classList.add('touched'));
  }, true);
})();
