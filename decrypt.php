<?php
/**
 * decrypt.php
 * -----------
 * Common decryption gateway for view / download / delete actions.
 *
 * Flow:
 *   GET  ?action=...&id=<file_id>          -> show "enter key" form
 *   POST (with valid key)                  -> perform the requested action
 *
 * The AES key is verified by comparing SHA-256 hashes (we never persist
 * the key itself).
 */

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/aes.php';
require_once __DIR__ . '/includes/storage.php';

require_login();
$user = current_user();

$action  = $_GET['action'] ?? $_POST['action'] ?? 'view';
$file_id = (int)($_GET['id'] ?? $_POST['id'] ?? 0);

if (!in_array($action, ['view', 'download', 'delete'], true) || $file_id <= 0) {
    flash_set('error', 'Invalid request.');
    header('Location: dashboard.php'); exit;
}

// Look up the file (and key metadata) - must belong to current user
$stmt = db()->prepare(
    "SELECT f.file_id, f.file_name, f.stored_name, f.file_type, f.file_size,
            k.key_id, k.key_hash, k.iv_b64
     FROM files f
     INNER JOIN file_keys k ON k.file_id = f.file_id
     WHERE f.file_id = ? AND f.user_id = ?
     LIMIT 1");
$stmt->execute([$file_id, $user['user_id']]);
$rec = $stmt->fetch();
if (!$rec) {
    flash_set('error', 'File not found.');
    header('Location: dashboard.php'); exit;
}

$storedName = $rec['stored_name'];
$err        = null;

// -----------------------------------------------------------
// POST -> perform action
// -----------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf'] ?? null)) {
        $err = 'Invalid request.';
    } else {
        $keyHex = trim($_POST['aes_key'] ?? '');
        $rawKey = key_from_hex($keyHex);

        if ($rawKey === null) {
            $err = 'AES key must be 64 hexadecimal characters.';
        } elseif (!hash_equals($rec['key_hash'], hash_aes_key($rawKey))) {
            $err = 'That key does not match this file.';
            log_action($user['user_id'], 'DECRYPT_FAIL',
                       (int)$rec['file_id'], (int)$rec['key_id'],
                       'wrong key');
        } else {
            $iv     = base64_decode($rec['iv_b64']);
            $cipher = storage_get_encrypted($storedName);
            $plain  = $cipher === null
                    ? null
                    : aes_decrypt_string($cipher, $rawKey, $iv);
            if ($plain === null) {
                $err = 'Decryption failed - the file may be corrupted.';
            } else {
                log_action($user['user_id'], strtoupper($action),
                           (int)$rec['file_id'], (int)$rec['key_id']);

                if ($action === 'view' || $action === 'download') {
                    $mime = mime_content_type_for($rec['file_type']);
                    $disp = $action === 'view' ? 'inline' : 'attachment';
                    header('Content-Type: ' . $mime);
                    header('Content-Length: ' . strlen($plain));
                    header(sprintf('Content-Disposition: %s; filename="%s"',
                                   $disp,
                                   addslashes($rec['file_name'])));
                    header('X-Content-Type-Options: nosniff');
                    echo $plain;
                    exit;
                }

                // delete
                storage_delete_encrypted($storedName);
                db()->prepare("DELETE FROM files WHERE file_id = ?")
                    ->execute([(int)$rec['file_id']]);
                flash_set('success', 'File deleted.');
                header('Location: dashboard.php'); exit;
            }
        }
    }
}

// -----------------------------------------------------------
// GET -> render key form
// -----------------------------------------------------------
$pageTitle = ucfirst($action) . ' file';
$copy = [
  'view'     => ['Open file',     'Enter the key to decrypt this file and view it in your browser.', 'View file',        'btn-cloudie'],
  'download' => ['Download file', 'Enter the key to decrypt this file and download the original.',   'Download file',    'btn-cloudie'],
  'delete'   => ['Delete file',   'Enter the key to confirm you own this file, then delete it.',     'Decrypt & delete', 'btn-danger'],
];
[$heading, $lead, $btnText, $btnClass] = $copy[$action];
require_once __DIR__ . '/includes/header.php';
?>
<div class="row justify-content-center">
  <div class="col-lg-7">
    <div class="cl-card">
      <h2 class="mb-1"><?= e($heading) ?></h2>
      <p class="text-muted mb-3"><?= e($lead) ?></p>

      <div class="dk-file">
        <span class="dk-file-name"><?= e($rec['file_name']) ?></span>
        <span class="dk-file-meta"><?= e(strtoupper($rec['file_type'])) ?> &middot; <?= e(cl_fmt_bytes((int)$rec['file_size'])) ?></span>
      </div>

      <?php if ($action === 'delete'): ?>
        <div class="alert alert-danger">
          <strong>This permanently deletes the file.</strong> The encrypted copy and its key record
          are removed and cannot be recovered.
        </div>
      <?php endif; ?>

      <?php if ($err): ?>
        <div class="alert alert-danger" role="alert" id="keyErr"><?= e($err) ?></div>
      <?php endif; ?>

      <form method="post" id="keyForm" autocomplete="off">
        <input type="hidden" name="csrf"   value="<?= e(csrf_token()) ?>">
        <input type="hidden" name="action" value="<?= e($action) ?>">
        <input type="hidden" name="id"     value="<?= (int)$file_id ?>">

        <label for="aesKeyInput">Your AES key (64 characters, 0-9 and a-f)</label>
        <div class="dk-field">
          <input type="password" name="aes_key" id="aesKeyInput" class="form-control dk-input"
                 placeholder="Paste or scan your key"
                 pattern="[0-9a-fA-F]{64}" maxlength="64" required autofocus
                 spellcheck="false" autocapitalize="off" autocorrect="off" autocomplete="off">
          <button type="button" class="dk-icon" id="keyToggle" aria-label="Show key" title="Show / hide key">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none"><path d="M2 12s3.6-6.5 10-6.5S22 12 22 12s-3.6 6.5-10 6.5S2 12 2 12z" stroke="currentColor" stroke-width="1.6"/><circle cx="12" cy="12" r="2.6" stroke="currentColor" stroke-width="1.6"/></svg>
          </button>
        </div>
        <div class="dk-status" id="keyStatus" aria-live="polite">0 / 64 characters</div>

        <div class="dk-tools">
          <button type="button" class="btn btn-cloudie-outline btn-sm" id="keyPaste">Paste from clipboard</button>
          <button type="button" class="btn btn-cloudie-outline btn-sm" id="qrCamBtn">
            <svg viewBox="0 0 24 24" width="15" height="15" fill="none"><path d="M4 8a2 2 0 0 1 2-2h1.2l1.1-1.6A2 2 0 0 1 10 3.5h4a2 2 0 0 1 1.7.9L16.8 6H18a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><circle cx="12" cy="12.5" r="3.2" stroke="currentColor" stroke-width="1.6"/></svg>
            Scan QR
          </button>
          <button type="button" class="btn btn-cloudie-outline btn-sm" id="qrFileBtn">
            <svg viewBox="0 0 24 24" width="15" height="15" fill="none"><rect x="3" y="3" width="18" height="18" rx="2.5" stroke="currentColor" stroke-width="1.6"/><circle cx="9" cy="9" r="1.8" stroke="currentColor" stroke-width="1.5"/><path d="M4 17l5-5 4 4 3-3 4 4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>
            Upload QR image
          </button>
          <input type="file" id="qrFileInput" accept="image/*" class="d-none">
        </div>

        <div class="qr-scan">
          <div class="qr-cam-wrap d-none" id="qrCamWrap">
            <video id="qrVideo" playsinline muted autoplay></video>
            <div class="qr-cam-hint">Point the camera at your Cloudie key QR…</div>
            <button type="button" class="btn btn-cloudie-outline btn-sm" id="qrCamStop">Stop camera</button>
          </div>
          <div id="qrScanMsg" class="qr-scan-msg d-none" role="status"></div>
        </div>

        <details class="dk-help">
          <summary>Where do I find my key?</summary>
          <p>
            It was shown once right after you uploaded the file (as text and a QR code), and a copy was
            emailed to <strong><?= e((string)($user['email'] ?? 'your account email')) ?></strong>.
            Cloudie stores only a SHA-256 hash of it, so it cannot be shown again or recovered.
          </p>
        </details>

        <div class="d-flex justify-content-between mt-4">
          <a href="dashboard.php" class="btn btn-cloudie-outline">Cancel</a>
          <button type="submit" class="btn <?= $btnClass ?>" id="keySubmit" disabled><?= e($btnText) ?></button>
        </div>
      </form>
    </div>
  </div>
</div>

<style>
.dk-file{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;
  background:var(--panel);border:1px solid var(--line-2);border-radius:12px;padding:12px 14px;margin-bottom:16px}
.dk-file-name{font-weight:600;word-break:break-all}
.dk-file-meta{font-family:'JetBrains Mono';font-size:12px;color:var(--txt-faint);flex:none}
.dk-field{position:relative}
.dk-input{font-family:'JetBrains Mono',monospace;font-size:13px;padding-right:46px}
.dk-icon{position:absolute;right:8px;top:50%;transform:translateY(-50%);width:30px;height:30px;
  display:grid;place-items:center;background:none;border:none;cursor:pointer;color:var(--txt-faint);border-radius:8px}
.dk-icon:hover{color:var(--cyan);background:var(--panel-2)}
.dk-status{font-size:12.5px;margin-top:7px;color:var(--txt-faint)}
.dk-status.ok{color:var(--green)}
.dk-status.bad{color:var(--red)}
.dk-tools{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}
.qr-scan{margin-top:4px}
.qr-cam-wrap{text-align:center;margin-top:12px}
#qrVideo{width:100%;max-width:340px;border-radius:12px;border:1px solid var(--line-2);
  background:#000;display:block;margin:0 auto 8px}
.qr-cam-hint{font-size:12.5px;color:var(--txt-faint);margin-bottom:10px}
.qr-scan-msg{margin-top:10px;font-size:13px;font-weight:500}
.qr-scan-msg.ok{color:var(--green)}
.qr-scan-msg.bad{color:var(--red)}
#aesKeyInput.key-found{border-color:var(--green);box-shadow:0 0 0 3px rgba(52,224,161,.15)}
.dk-help{margin-top:16px;font-size:13px;color:var(--txt-dim)}
.dk-help summary{cursor:pointer;color:var(--cyan);font-weight:500}
.dk-help p{margin-top:8px;line-height:1.5}
.btn[disabled]{opacity:.45;cursor:not-allowed;transform:none;box-shadow:none}
</style>

<script src="assets/js/jsQR.js"></script>
<script>
(function () {
  var input     = document.getElementById('aesKeyInput');
  var camBtn    = document.getElementById('qrCamBtn');
  var camStop   = document.getElementById('qrCamStop');
  var camWrap   = document.getElementById('qrCamWrap');
  var video     = document.getElementById('qrVideo');
  var fileBtn   = document.getElementById('qrFileBtn');
  var fileInput = document.getElementById('qrFileInput');
  var msgEl     = document.getElementById('qrScanMsg');

  var canvas = document.createElement('canvas');
  var ctx    = canvas.getContext('2d', { willReadFrequently: true });
  var stream = null, rafId = null;

  function setMsg(kind, text) {
    msgEl.textContent = text;
    msgEl.classList.remove('d-none', 'ok', 'bad');
    msgEl.classList.add(kind);
  }

  // The QR encodes the 64-hex key on its own; be lenient in case the user
  // made their own QR from the downloaded .txt (key surrounded by text).
  function extractKey(text) {
    var m = /(^|[^0-9a-fA-F])([0-9a-fA-F]{64})(?![0-9a-fA-F])/.exec(String(text));
    return m ? m[2].toLowerCase() : null;
  }

  function applyKey(key) {
    stopCam();
    input.value = key;
    input.dispatchEvent(new Event('input'));
    input.classList.add('key-found');
    var submitBtn = input.form.querySelector('button[type="submit"]');
    setMsg('ok', 'Key read from QR — press “'
                 + (submitBtn ? submitBtn.textContent.trim() : 'Submit')
                 + '” to continue.');
    if (submitBtn) submitBtn.focus();
  }

  function decodePixels(opts) {
    var data = ctx.getImageData(0, 0, canvas.width, canvas.height);
    return jsQR(data.data, data.width, data.height, opts);
  }

  // ---------- live camera scan ----------
  function tick() {
    if (!stream) return;
    if (video.readyState >= video.HAVE_ENOUGH_DATA && video.videoWidth > 0) {
      canvas.width  = video.videoWidth;
      canvas.height = video.videoHeight;
      ctx.drawImage(video, 0, 0);
      var code = decodePixels({ inversionAttempts: 'dontInvert' });
      if (code && code.data) {
        var key = extractKey(code.data);
        if (key) { applyKey(key); return; }
        setMsg('bad', 'A QR was detected, but it does not contain a Cloudie key. Still scanning…');
      }
    }
    rafId = requestAnimationFrame(tick);
  }

  function startCam() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      setMsg('bad', 'Camera is not available here (needs HTTPS or localhost). '
                  + 'Use “Upload QR image” instead.');
      return;
    }
    navigator.mediaDevices.getUserMedia({
      video: { facingMode: 'environment' }, audio: false
    }).then(function (s) {
      stream = s;
      video.srcObject = s;
      camWrap.classList.remove('d-none');
      msgEl.classList.add('d-none');
      video.play().catch(function () {});
      tick();
    }).catch(function () {
      setMsg('bad', 'Could not open the camera — check browser permissions, '
                  + 'or use “Upload QR image” instead.');
    });
  }

  function stopCam() {
    if (rafId) { cancelAnimationFrame(rafId); rafId = null; }
    if (stream) { stream.getTracks().forEach(function (t) { t.stop(); }); stream = null; }
    video.srcObject = null;
    camWrap.classList.add('d-none');
  }

  camBtn.addEventListener('click', function () { stream ? stopCam() : startCam(); });
  camStop.addEventListener('click', stopCam);
  window.addEventListener('pagehide', stopCam);
  input.form.addEventListener('submit', stopCam);

  // ---------- decode an uploaded QR image ----------
  fileBtn.addEventListener('click', function () { fileInput.click(); });
  fileInput.addEventListener('change', function () {
    var file = fileInput.files && fileInput.files[0];
    if (!file) return;
    stopCam();
    var url = URL.createObjectURL(file);
    var img = new Image();
    img.onload = function () {
      URL.revokeObjectURL(url);
      // try a downscaled pass first for huge photos, then full resolution
      var maxSide = Math.max(img.naturalWidth, img.naturalHeight);
      var scales  = maxSide > 1600 ? [1600 / maxSide, 1] : [1];
      var code = null;
      for (var i = 0; i < scales.length && !code; i++) {
        canvas.width  = Math.round(img.naturalWidth  * scales[i]);
        canvas.height = Math.round(img.naturalHeight * scales[i]);
        ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
        code = decodePixels({ inversionAttempts: 'attemptBoth' });
      }
      if (code && code.data) {
        var key = extractKey(code.data);
        if (key) applyKey(key);
        else setMsg('bad', 'A QR was found, but it does not contain a valid 64-character key.');
      } else {
        setMsg('bad', 'No QR code found in that image. Try a sharper, closer picture of the QR.');
      }
      fileInput.value = '';
    };
    img.onerror = function () {
      URL.revokeObjectURL(url);
      setMsg('bad', 'Could not read that file as an image.');
      fileInput.value = '';
    };
    img.src = url;
  });

  input.addEventListener('input', function () { input.classList.remove('key-found'); });
})();
</script>
<script>
(function () {
  var input  = document.getElementById('aesKeyInput');
  var status = document.getElementById('keyStatus');
  var submit = document.getElementById('keySubmit');
  var form   = document.getElementById('keyForm');
  var toggle = document.getElementById('keyToggle');
  var paste  = document.getElementById('keyPaste');
  var err    = document.getElementById('keyErr');

  function refresh() {
    var v = input.value.trim();
    var ok = /^[0-9a-fA-F]{64}$/.test(v);
    var bad = v.length > 0 && /[^0-9a-fA-F]/.test(v);
    submit.disabled = !ok;
    status.className = 'dk-status' + (ok ? ' ok' : (bad ? ' bad' : ''));
    status.textContent = ok ? '\u2713 Key format looks right'
      : bad ? '\u2717 Only 0-9 and a-f are allowed'
      : v.length + ' / 64 characters';
  }
  input.addEventListener('input', refresh);
  refresh();
  if (err) input.focus();

  toggle.addEventListener('click', function () {
    var show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    toggle.setAttribute('aria-label', show ? 'Hide key' : 'Show key');
  });

  if (navigator.clipboard && navigator.clipboard.readText) {
    paste.addEventListener('click', function () {
      navigator.clipboard.readText().then(function (t) {
        var m = /[0-9a-fA-F]{64}/.exec(t || '');
        input.value = m ? m[0] : (t || '').trim().slice(0, 64);
        refresh();
        input.focus();
      }).catch(function () {
        status.className = 'dk-status bad';
        status.textContent = 'Could not read the clipboard \u2014 paste into the box with Ctrl+V.';
      });
    });
  } else {
    paste.style.display = 'none';
  }

  // brief busy state; downloads do not reload the page, so re-enable shortly
  form.addEventListener('submit', function () {
    var label = submit.textContent;
    submit.disabled = true;
    submit.textContent = 'Decrypting\u2026';
    setTimeout(function () { submit.textContent = label; refresh(); }, 4000);
  });
})();
</script>
<?php require_once __DIR__ . '/includes/footer.php';

/**
 * Pick a sensible Content-Type for the original extension.
 */
function mime_content_type_for(string $ext): string {
    static $map = [
        'pdf'  => 'application/pdf',
        'txt'  => 'text/plain; charset=utf-8',
        'csv'  => 'text/csv; charset=utf-8',
        'png'  => 'image/png',
        'jpg'  => 'image/jpeg',
        'jpeg' => 'image/jpeg',
        'doc'  => 'application/msword',
        'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'xls'  => 'application/vnd.ms-excel',
        'xlsx' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'ppt'  => 'application/vnd.ms-powerpoint',
        'pptx' => 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'zip'  => 'application/zip',
        'rar'  => 'application/vnd.rar',
    ];
    return $map[strtolower($ext)] ?? 'application/octet-stream';
}