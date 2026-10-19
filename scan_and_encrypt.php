<?php
/**
 * scan_and_encrypt.php
 * --------------------
 * Upload workflow with VirusTotal-primary / AI-supporting detection:
 *
 *     1. validate the upload
 *     2. send file to Flask scanner (VT primary, RF supporting)
 *     3. decide on the combined verdict:
 *          - malicious / error  -> REJECT, never stored
 *          - suspicious         -> ENCRYPT + store, tagged "suspicious"
 *          - clean              -> ENCRYPT + store, tagged "clean"
 *     4. show the AES key + QR
 *
 * The cleartext is removed as soon as encryption succeeds.
 */

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/aes.php';
require_once __DIR__ . '/includes/storage.php';
require_once __DIR__ . '/includes/scanner.php';
require_once __DIR__ . '/includes/qr.php';
require_once __DIR__ . '/includes/mailer.php';

require_login();
$user = current_user();

// ---------------------------------------------------------------
// 1. Validate
// ---------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] !== 'POST'
    || !verify_csrf($_POST['csrf'] ?? null)) {
    flash_set('error', 'Invalid request.');
    header('Location: upload.php'); exit;
}
if (empty($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
    flash_set('error', 'File upload failed. Please try again.');
    header('Location: upload.php'); exit;
}
$f = $_FILES['file'];

if ($f['size'] <= 0 || $f['size'] > MAX_UPLOAD_BYTES) {
    flash_set('error', 'File is empty or exceeds the size limit.');
    header('Location: upload.php'); exit;
}
$origName = basename($f['name']);
$ext      = strtolower(pathinfo($origName, PATHINFO_EXTENSION));
if ($ext === '' || !in_array($ext, ALLOWED_EXT, true)) {
    flash_set('error', 'That file type is not allowed.');
    header('Location: upload.php'); exit;
}

$tmpPath = UPLOAD_DIR . uniqid('up_', true) . '.' . $ext;
if (!move_uploaded_file($f['tmp_name'], $tmpPath)) {
    flash_set('error', 'Could not save the upload.');
    header('Location: upload.php'); exit;
}

// ---------------------------------------------------------------
// 2. Scan (Flask: VirusTotal primary + Random Forest supporting)
// ---------------------------------------------------------------
$scan = scan_file_with_ai($tmpPath, $origName);
if (!$scan['ok']) {
    @unlink($tmpPath);
    error_log('scan failed: ' . ($scan['error'] ?? 'unknown'));   // technical detail stays in the log
    flash_set('error', 'The malware scan could not be completed, so your file was not stored. '
                     . 'Please try again in a minute. If it keeps happening, try a smaller file.');
    header('Location: upload.php'); exit;
}
$report  = $scan['data'];

// Combined verdict from the engine: 'clean' | 'suspicious' | 'malicious' | 'error'
$verdict = strtolower((string)($report['verdict'] ?? 'error'));
if (!in_array($verdict, ['clean', 'suspicious', 'malicious', 'error'], true)) {
    $verdict = 'error';
}
$md5 = $report['file_md5'] ?? md5_file($tmpPath);

log_action($user['user_id'], 'SCAN', null, null,
           'verdict=' . $verdict
           . ' prob='  . ($report['probability_malicious'] ?? '?'));

// helper: format a 0..1 probability as a percentage string
$probRaw = $report['probability_malicious'] ?? null;
$probPct = is_numeric($probRaw)
         ? round(((float)$probRaw <= 1 ? (float)$probRaw * 100 : (float)$probRaw), 1)
         : null;

// ---------------------------------------------------------------
// 3. Reject if malicious (VT flagged it) or if it could not be evaluated
// ---------------------------------------------------------------
if ($verdict === 'malicious' || $verdict === 'error') {
    @unlink($tmpPath);

    if ($verdict === 'malicious') {
        // Full threat report — same renderer as view_report.php, in
        // "rejected" mode (nothing stored, no key). The report is only
        // in memory here, so the download link embeds it as a data URI.
        $report['file_md5']  = $report['file_md5']  ?? $md5;
        $report['file_size'] = $report['file_size'] ?? (int)$f['size'];
        $rejected = true;
        $fileId   = null;
        $keyHex   = null;
        $qrSrc    = null;

        $reportJson = json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        $safeName   = preg_replace('/[^A-Za-z0-9._-]/', '_', $origName);

        $pageTitle = 'Threat detected';
        require_once __DIR__ . '/includes/header.php'; ?>

    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.6rem;margin-bottom:1.4rem">
      <div>
        <h2 style="margin:0;font-size:1.25rem">Threat report</h2>
        <div style="font-size:12.5px;color:var(--txt-faint);margin-top:2px">
          Scanned <?= e(date('Y-m-d H:i')) ?> &middot; upload blocked, nothing was stored
        </div>
      </div>
      <div style="display:flex;flex-wrap:wrap;gap:.5rem">
        <a href="data:application/json;base64,<?= base64_encode($reportJson) ?>"
           download="cloudie-report-<?= e($safeName) ?>.json"
           class="btn btn-sm btn-cloudie-outline" title="Download raw JSON report">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none"><path d="M12 16V4M8 12l4 4 4-4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M5 20h14" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
          .json
        </a>
        <a href="upload.php" class="btn btn-sm btn-cloudie">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none"><path d="M12 8v13M16 12l-4-4-4 4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M20 6H4" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
          Upload another file
        </a>
      </div>
    </div>

    <?php
        require __DIR__ . '/includes/scan_report.php';
        require_once __DIR__ . '/includes/footer.php';
        exit;
    }

    // verdict === 'error' → the scanner gave no usable verdict, so there
    // is no meaningful report to show; keep this screen short.
    $pageTitle = 'Scan inconclusive';
    require_once __DIR__ . '/includes/header.php'; ?>

    <div class="row justify-content-center">
      <div class="col-lg-8">
        <div class="cl-card">
          <div class="vbanner vb-info">
            <div class="vb-ico">
              <svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.7"/><path d="M12 8h.01M12 12v4" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"/></svg>
            </div>
            <div>
              <div class="vb-main">VirusTotal error &mdash; file could not be verified</div>
              <div class="vb-sub">
                VirusTotal did not return a result for
                <strong><?= e($origName) ?></strong>, so Cloudie did not store it.
                This can be a temporary rate limit or timeout. Please try again in a minute.
              </div>
            </div>
          </div>

          <div class="mt-4" style="display:flex;gap:.6rem;flex-wrap:wrap">
            <a href="upload.php" class="btn btn-cloudie">Try again</a>
            <a href="dashboard.php" class="btn btn-cloudie-outline">Back to my files</a>
          </div>
        </div>
      </div>
    </div>

    <?php require_once __DIR__ . '/includes/footer.php';
    exit;
}

// At this point $verdict is 'clean' or 'suspicious' — both get stored.
$isSuspicious = ($verdict === 'suspicious');

// ---------------------------------------------------------------
// 4. Encrypt + persist
// ---------------------------------------------------------------
$rawKey = generate_aes_key();
$iv     = generate_iv();
$encName = uniqid('enc_', true) . '.bin';

// Encrypt to bytes in memory, then persist via the storage layer.
// On Cloud Run this uploads to Cloud Storage (GCS); on XAMPP it writes
// to ENCRYPTED_DIR. decrypt.php reads it back the same way.
$cipherBytes = aes_encrypt_file_to_string($tmpPath, $rawKey, $iv);
if ($cipherBytes === null) {
    @unlink($tmpPath);
    flash_set('error', 'Encryption failed.');
    header('Location: upload.php'); exit;
}
if (!storage_put_encrypted($encName, $cipherBytes)) {
    @unlink($tmpPath);
    flash_set('error', 'Could not store the encrypted file.');
    header('Location: upload.php'); exit;
}
@unlink($tmpPath);   // never keep cleartext on disk

// The scan can take up to ~85 s (VirusTotal polling). The DB connection opened
// at login may have been dropped meanwhile ("MySQL server has gone away"), so
// check it and reconnect before the insert.
try {
    db()->query('SELECT 1');
} catch (Throwable $e) {
    error_log('DB connection lost during scan, reconnecting: ' . $e->getMessage());
    db(true);
}

try {
    $pdo = db();
    $pdo->beginTransaction();
    $stmt = $pdo->prepare(
        "INSERT INTO files
            (user_id, file_name, stored_name, file_type, file_size,
             file_md5, is_clean, verdict, scan_report)
         VALUES (?,?,?,?,?,?,?,?,?)");
    $stmt->execute([
        $user['user_id'],
        $origName,
        $encName,
        $ext,
        (int)$f['size'],
        $md5,
        $isSuspicious ? 0 : 1,   // is_clean: 0 for suspicious, 1 for clean
        $verdict,                // 'clean' | 'suspicious'
        json_encode($report, JSON_UNESCAPED_SLASHES),
    ]);
    $fileId = (int)$pdo->lastInsertId();

    $pdo->prepare(
        "INSERT INTO file_keys (user_id, file_id, key_hash, iv_b64)
         VALUES (?,?,?,?)"
    )->execute([
        $user['user_id'],
        $fileId,
        hash_aes_key($rawKey),
        base64_encode($iv),
    ]);
    $keyId = (int)$pdo->lastInsertId();

    $pdo->commit();
    log_action($user['user_id'], 'ENCRYPT', $fileId, $keyId,
               'AES-256-CBC; verdict=' . $verdict . '; size=' . $f['size']);
} catch (Throwable $e) {
    error_log('scan_and_encrypt store failed: ' . $e->getMessage());
    try {
        if (db()->inTransaction()) db()->rollBack();
    } catch (Throwable $rb) {
        error_log('rollback failed: ' . $rb->getMessage());   // connection already dead
    }
    storage_delete_encrypted($encName);
    flash_set('error', 'Could not store encrypted file.');
    header('Location: upload.php'); exit;
}

// ---------------------------------------------------------------
// 5. Show the AES key + QR (this is the ONLY time the user sees it)
// ---------------------------------------------------------------
$keyHex   = key_to_hex($rawKey);
$qrSrc    = qr_image_src($keyHex);

// Best-effort: email the key to the file owner. Never blocks the upload —
// send_key_email() returns false quietly if mail is disabled/misconfigured.
$emailSent = send_key_email(
    (string)($user['email'] ?? ''),
    (string)($user['username'] ?? ''),
    $origName,
    $keyHex,
    $fileId
);

// Per-detector summary for the result chips (VirusTotal is the primary detector)
$vtInfo      = is_array($report['virustotal'] ?? null) ? $report['virustotal'] : [];
$vtAvailable = !empty($vtInfo['available']);
$vtChip      = $vtAvailable
             ? 'VirusTotal ' . (int)($vtInfo['malicious'] ?? 0) . '/' . (int)($vtInfo['total'] ?? 0) . ' flagged'
             : 'VirusTotal: no result';
$aiChip      = ($probPct !== null && !empty($report['is_pdf']))
             ? 'AI ' . $probPct . '% malicious'
             : '';

$pageTitle = $isSuspicious ? 'Stored with warning' : 'Upload successful';
// The key is shown only on this response; a theme-toggle navigation would lose it.
$hideThemeToggle = true;
require_once __DIR__ . '/includes/header.php';
?>
<div class="row justify-content-center">
  <div class="col-lg-8">
    <div class="cl-card qr-card text-center">

      <?php if ($isSuspicious): ?>
      <div class="success-head">
        <span class="success-ico warn">
          <svg viewBox="0 0 24 24" fill="none"><path d="M12 3l9 16H3z" stroke="currentColor" stroke-width="1.9" stroke-linejoin="round"/><path d="M12 9v4m0 3h.01" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg>
        </span>
        <h2 class="m-0">Stored, but flagged suspicious</h2>
        <p class="text-muted m-0">
          <strong><?= e($origName) ?></strong> <?= $vtAvailable ? 'was cleared by VirusTotal, but' : 'got no result from VirusTotal, and' ?>
          the AI structural analyzer flagged it. It was encrypted with AES-256
          and stored, and is tagged <strong>Suspicious</strong> in your vault.
        </p>
      </div>
      <?php else: ?>
      <div class="success-head">
        <span class="success-ico">
          <svg viewBox="0 0 24 24" fill="none"><path d="M5 13l4 4L19 7" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>
        </span>
        <h2 class="m-0">File secured</h2>
        <p class="text-muted m-0">
          <strong><?= e($origName) ?></strong> was scanned
          (<?= $vtAvailable ? 'VirusTotal: clean' : 'VirusTotal: no result' ?>; AI analysis: no flag),
          encrypted with AES-256, and stored.
        </p>
      </div>
      <?php endif; ?>

      <!-- pipeline status -->
      <div class="pipeline">
        <div class="step done"><span class="sdot"></span>Scanned</div>
        <?php if ($isSuspicious): ?>
          <div class="step warn"><span class="sdot"></span>Suspicious (AI)</div>
        <?php else: ?>
          <div class="step done"><span class="sdot"></span>Clean · <?= e($vtChip) ?><?= $aiChip !== '' ? ' · ' . e($aiChip) : '' ?></div>
        <?php endif; ?>
        <div class="step done"><span class="sdot"></span>Encrypted</div>
        <div class="step done"><span class="sdot"></span>Stored</div>
      </div>

      <?php if ($isSuspicious): ?>
      <div class="alert alert-warning" style="text-align:left">
        <strong>Why is this flagged?</strong> <?= $vtAvailable
          ? "VirusTotal's signature engines did not detect a known threat"
          : 'VirusTotal returned no result for this file' ?>, but Cloudie's AI found structural features
        (e.g. embedded JavaScript or auto-run actions) often seen in malicious
        PDFs. Open it with caution.
      </div>
      <?php endif; ?>

      <div class="key-section">
        <h5 class="mb-1">Your AES key</h5>
        <p class="text-muted small mb-3">
          Save this key. <strong>You need it to view, download, and also to delete this file.</strong>
          Cloudie stores only a SHA-256 hash of it, so if you lose it the file can't be recovered
          or deleted.
          <?php if ($emailSent): ?>
            <br>A copy has also been sent to <strong><?= e((string)($user['email'] ?? '')) ?></strong>.
          <?php endif; ?>
        </p>

        <?php if ($qrSrc !== ''): ?>
          <img src="<?= e($qrSrc) ?>" alt="AES key QR" class="my-3">
        <?php endif; ?>

        <div class="key-box mb-3" id="keyBox"><?= e($keyHex) ?></div>

        <div class="d-flex flex-wrap gap-2 justify-content-center">
          <button class="btn btn-cloudie-outline" onclick="copyKey()">Copy key</button>
          <a class="btn btn-cloudie-outline"
             href="data:application/octet-stream;base64,<?= base64_encode("Cloudie AES key for: $origName\n$keyHex\n") ?>"
             download="cloudie-key-<?= e($fileId) ?>.txt">Download key (.txt)</a>
          <a class="btn btn-cloudie-outline" href="view_report.php?id=<?= (int)$fileId ?>">View report</a>
          <a class="btn btn-cloudie" href="dashboard.php" id="goFiles"
             aria-disabled="true" tabindex="-1"
             style="opacity:.45;pointer-events:none">Go to my files</a>
        </div>

        <label class="key-saved">
          <input type="checkbox" id="keySaved">
          <span>I have saved my key (copied it, downloaded it, or stored the QR).</span>
        </label>
      </div>
    </div>
  </div>
</div>

<style>
/* success screen styling (uses theme vars from header.php) */
.success-head{display:flex;flex-direction:column;text-align:center;gap:10px;
  align-items:center;margin-bottom:22px}
.success-ico{width:60px;height:60px;border-radius:15px;display:grid;
  place-items:center;flex:none;background:rgba(52,224,161,.14);color:var(--green)}
.success-ico svg{width:30px;height:30px}
.success-ico.warn{background:rgba(255,194,75,.16);color:var(--amber)}

.pipeline{display:flex;flex-wrap:wrap;justify-content:center;gap:10px;margin:4px 0 24px}
.step{display:inline-flex;align-items:center;gap:7px;font-size:12.5px;font-weight:600;
  color:var(--txt-dim);background:var(--panel);border:1px solid var(--line);
  border-radius:99px;padding:7px 14px}
.step.done{color:var(--green);border-color:rgba(52,224,161,.3);background:rgba(52,224,161,.08)}
.step.warn{color:var(--amber);border-color:rgba(255,194,75,.35);background:rgba(255,194,75,.10)}
.sdot{width:7px;height:7px;border-radius:50%;background:currentColor}

.alert-warning{background:rgba(255,194,75,.1);border:1px solid rgba(255,194,75,.3);
  color:var(--amber);border-radius:12px;padding:12px 16px;font-size:14px;margin-bottom:16px}

.key-section{border-top:1px solid var(--line);padding-top:22px;margin-top:6px}
.key-saved{display:flex;align-items:flex-start;justify-content:center;gap:10px;
  margin-top:18px;font-size:13.5px;font-weight:500;color:var(--txt);cursor:pointer;text-align:left}
.key-saved input{margin-top:3px;flex:none}
</style>

<script>
// The key exists only on this page: warn before leaving until the user confirms.
(function () {
  var box = document.getElementById('keySaved');
  var go  = document.getElementById('goFiles');
  function guard(e) { e.preventDefault(); e.returnValue = ''; }
  window.addEventListener('beforeunload', guard);
  box.addEventListener('change', function () {
    if (box.checked) {
      window.removeEventListener('beforeunload', guard);
      go.style.opacity = ''; go.style.pointerEvents = '';
      go.removeAttribute('aria-disabled'); go.removeAttribute('tabindex');
    } else {
      window.addEventListener('beforeunload', guard);
      go.style.opacity = '.45'; go.style.pointerEvents = 'none';
      go.setAttribute('aria-disabled', 'true'); go.setAttribute('tabindex', '-1');
    }
  });
})();
function copyKey() {
  navigator.clipboard.writeText(document.getElementById('keyBox').innerText);
  alert('Key copied to clipboard.');
}
</script>
<?php require_once __DIR__ . '/includes/footer.php';