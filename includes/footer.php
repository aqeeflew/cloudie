</main><!-- .main -->
</div><!-- .app -->

<!-- ===== Confirm dialog (window.clConfirm) ===== -->
<div class="clc-backdrop" id="clcBackdrop" aria-hidden="true">
  <div class="clc-card" id="clcCard" role="alertdialog" aria-modal="true" aria-labelledby="clcTitle" aria-describedby="clcMsg" data-tone="danger">
    <div class="clc-ico" id="clcIco" aria-hidden="true"></div>
    <h3 class="clc-title" id="clcTitle">Are you sure?</h3>
    <div class="clc-item" id="clcItem" hidden>
      <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M7 3h7l5 5v13H7z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/><path d="M14 3v5h5" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/></svg>
      <span id="clcItemText"></span>
    </div>
    <p class="clc-msg" id="clcMsg"></p>
    <div class="clc-note" id="clcNote" hidden>
      <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.8"/><path d="M12 8h.01M12 11v5" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
      <span id="clcNoteText"></span>
    </div>
    <div class="clc-actions">
      <button type="button" class="btn btn-cloudie-outline" id="clcCancel">Cancel</button>
      <button type="button" class="btn btn-danger clc-go" id="clcOk">Continue</button>
    </div>
  </div>
</div>
<script>
/* window.clConfirm({title, item, message, note, confirmText, cancelText, tone:'danger'|'warn'}) -> Promise<boolean>
   Accessible modal: focus starts on Cancel (safe default), Tab is trapped, Esc and a click outside cancel,
   focus returns to the element that opened it. Falls back to the browser's confirm() if the markup is missing. */
(function () {
  var back = document.getElementById('clcBackdrop'), card = document.getElementById('clcCard');
  var ICONS = {
    danger: '<svg viewBox="0 0 24 24" fill="none"><path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><path d="M10 11v5M14 11v5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
    warn:   '<svg viewBox="0 0 24 24" fill="none"><path d="M12 3l9 16H3z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M12 9v4m0 3h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>'
  };
  var busy = false;

  window.clConfirm = function (o) {
    o = o || {};
    if (!back || !card || busy) {
      return Promise.resolve(window.confirm((o.title || 'Are you sure?') + (o.message ? '\n\n' + o.message : '')));
    }
    busy = true;
    var opener = document.activeElement;
    var tone = o.tone === 'warn' ? 'warn' : 'danger';
    card.setAttribute('data-tone', tone);
    document.getElementById('clcIco').innerHTML = ICONS[tone];
    document.getElementById('clcTitle').textContent = o.title || 'Are you sure?';
    var item = document.getElementById('clcItem');
    item.hidden = !o.item;
    document.getElementById('clcItemText').textContent = o.item || '';
    document.getElementById('clcMsg').textContent = o.message || '';
    var note = document.getElementById('clcNote');
    note.hidden = !o.note;
    document.getElementById('clcNoteText').textContent = o.note || '';
    var ok = document.getElementById('clcOk'), cancel = document.getElementById('clcCancel');
    ok.textContent = o.confirmText || 'Continue';
    cancel.textContent = o.cancelText || 'Cancel';

    return new Promise(function (resolve) {
      function close(result) {
        document.removeEventListener('keydown', onKey, true);
        back.removeEventListener('mousedown', onBack);
        ok.removeEventListener('click', onOk);
        cancel.removeEventListener('click', onCancel);
        back.classList.remove('open');
        back.setAttribute('aria-hidden', 'true');
        document.body.classList.remove('clc-lock');
        busy = false;
        if (opener && opener.focus) { try { opener.focus(); } catch (e) {} }
        resolve(result);
      }
      function onOk() { close(true); }
      function onCancel() { close(false); }
      function onBack(e) { if (e.target === back) close(false); }
      function onKey(e) {
        if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); close(false); return; }
        if (e.key === 'Tab') {                                  // keep focus inside the dialog
          var f = [cancel, ok];
          var i = f.indexOf(document.activeElement);
          e.preventDefault();
          f[(i + (e.shiftKey ? f.length - 1 : 1)) % f.length].focus();
        }
      }
      ok.addEventListener('click', onOk);
      cancel.addEventListener('click', onCancel);
      back.addEventListener('mousedown', onBack);
      document.addEventListener('keydown', onKey, true);
      document.body.classList.add('clc-lock');
      back.setAttribute('aria-hidden', 'false');
      back.classList.add('open');
      cancel.focus();
      setTimeout(function () { if (document.activeElement !== cancel) cancel.focus(); }, 60);
    });
  };
})();
</script>
</body>
</html>
