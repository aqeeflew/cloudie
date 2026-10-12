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
    "SELECT f.file_id, f.file_name, f.stored_name, f.file_type,
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
require_once __DIR__ . '/includes/header.php';
?>
<div class="row justify-content-center">
  <div class="col-lg-7">
    <div class="cl-card">
      <h3 class="mb-1">Decrypt file using AES</h3>
      <p class="text-muted">
        Action: <strong><?= e(strtoupper($action)) ?></strong>
        &middot; File: <strong><?= e($rec['file_name']) ?></strong>
      </p>

      <?php if ($err): ?>
        <div class="alert alert-danger"><?= e($err) ?></div>
      <?php endif; ?>

      <form method="post">
        <input type="hidden" name="csrf"   value="<?= e(csrf_token()) ?>">
        <input type="hidden" name="action" value="<?= e($action) ?>">
        <input type="hidden" name="id"     value="<?= (int)$file_id ?>">

        <label>Paste your AES key (64 hex chars)</label>
        <input type="text" name="aes_key" id="aesKeyInput" class="form-control"
               placeholder="e.g. 7f3c…d2"
               pattern="[0-9a-fA-F]{64}" required autofocus>
        <div class="form-text">
          Or use the QR code you saved at upload time — scan it with your
          camera or upload the QR image, and the key is filled in for you.
        </div>

        <div class="qr-scan mt-3">
          <div class="d-flex flex-wrap gap-2">
            <button type="button" class="btn btn-cloudie-outline btn-sm" id="qrCamBtn">
              <svg viewBox="0 0 24 24" width="15" height="15" fill="none"><path d="M4 8a2 2 0 0 1 2-2h1.2l1.1-1.6A2 2 0 0 1 10 3.5h4a2 2 0 0 1 1.7.9L16.8 6H18a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><circle cx="12" cy="12.5" r="3.2" stroke="currentColor" stroke-width="1.6"/></svg>
              Scan QR with camera
            </button>
            <button type="button" class="btn btn-cloudie-outline btn-sm" id="qrFileBtn">
              <svg viewBox="0 0 24 24" width="15" height="15" fill="none"><rect x="3" y="3" width="18" height="18" rx="2.5" stroke="currentColor" stroke-width="1.6"/><circle cx="9" cy="9" r="1.8" stroke="currentColor" stroke-width="1.5"/><path d="M4 17l5-5 4 4 3-3 4 4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>
              Upload QR image
            </button>
            <input type="file" id="qrFileInput" accept="image/*" class="d-none">
          </div>

          <div class="qr-cam-wrap d-none" id="qrCamWrap">
            <video id="qrVideo" playsinline muted autoplay></video>
            <div class="qr-cam-hint">Point the camera at your Cloudie key QR…</div>
            <button type="button" class="btn btn-cloudie-outline btn-sm" id="qrCamStop">Stop camera</button>
          </div>

          <div id="qrScanMsg" class="qr-scan-msg d-none" role="status"></div>
        </div>

        <div class="d-flex justify-content-between mt-4">
          <a href="dashboard.php" class="btn btn-cloudie-outline">Cancel</a>
          <button type="submit" class="btn btn-cloudie">
            <?php switch ($action) {
                  case 'view':     echo 'View file';     break;
                  case 'download': echo 'Download file'; break;
                  case 'delete':   echo 'Decrypt & delete'; break;
            } ?>
          </button>
        </div>
      </form>
    </div>
  </div>
</div>

<style>
.qr-scan{border:1px dashed var(--line-2);border-radius:12px;padding:14px 16px}
.qr-scan .btn svg{flex:none}
.qr-cam-wrap{text-align:center;margin-top:12px}
#qrVideo{width:100%;max-width:340px;border-radius:12px;border:1px solid var(--line-2);
  background:#000;display:block;margin:0 auto 8px}
.qr-cam-hint{font-size:12.5px;color:var(--txt-faint);margin-bottom:10px}
.qr-scan-msg{margin-top:10px;font-size:13px;font-weight:500}
.qr-scan-msg.ok{color:var(--green)}
.qr-scan-msg.bad{color:var(--red)}
#aesKeyInput.key-found{border-color:var(--green);box-shadow:0 0 0 3px rgba(52,224,161,.15)}
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