<?php
require_once __DIR__ . '/includes/auth.php';
require_login();

$pageTitle = 'Upload';
require_once __DIR__ . '/includes/header.php';
?>
<div class="row justify-content-center">
  <div class="col-lg-9">
    <div class="cl-card">
      <h3 class="mb-3">Upload a file</h3>
      <p class="text-muted">
        Files are scanned with the AI malware analyzer first. Only files
        verified as clean are encrypted with AES-256 and stored.
      </p>

      <form method="post" action="scan_and_encrypt.php"
            enctype="multipart/form-data" id="uploadForm">
        <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">

        <label for="fileInput" class="dropzone d-block" id="dropzone">
          <div style="font-size:2.4rem">&#128228;</div>
          <div class="mt-2"><strong>Drag a file here</strong> or click to choose</div>
          <small class="text-muted d-block mt-2">
            Allowed: <?= e(implode(', ', ALLOWED_EXT)) ?>
            &middot; max <?= number_format(MAX_UPLOAD_BYTES / 1024 / 1024) ?> MB
          </small>
          <input id="fileInput" type="file" name="file" hidden required>
          <div id="fileName" class="mt-3 small fw-bold"></div>
        </label>

        <div class="d-flex justify-content-between mt-4">
          <a href="dashboard.php" class="btn btn-cloudie-outline">Cancel</a>
          <button type="submit" class="btn btn-cloudie" id="submitBtn">
            Scan &amp; encrypt
          </button>
        </div>
      </form>
    </div>
  </div>
</div>

<!-- scan progress overlay -->
<div class="scanov" id="scanOverlay" hidden>
  <div class="scanov-card">
    <h3 class="m-0">Securing your file</h3>
    <div class="scanov-file" id="scanFile"></div>
    <ol class="scanov-steps">
      <li data-step="upload">
        <span class="ss-ico"></span>
        <div><div class="ss-t">Upload</div><div class="ss-s">Sending the file to Cloudie</div></div>
      </li>
      <li data-step="scan">
        <span class="ss-ico"></span>
        <div><div class="ss-t">Malware scan</div><div class="ss-s">VirusTotal + AI analysis &middot; usually 5&ndash;60&nbsp;s</div></div>
      </li>
      <li data-step="encrypt">
        <span class="ss-ico"></span>
        <div><div class="ss-t">Encrypt</div><div class="ss-s">AES-256-CBC &middot; the key is shown only to you</div></div>
      </li>
      <li data-step="store">
        <span class="ss-ico"></span>
        <div><div class="ss-t">Store</div><div class="ss-s">Encrypted blob saved to your vault</div></div>
      </li>
    </ol>
    <div class="scanov-foot">Elapsed <span id="scanElapsed">0&nbsp;s</span> &middot; keep this tab open</div>
  </div>
</div>

<style>
.scanov{position:fixed;inset:0;z-index:60;display:grid;place-items:center;
  background:rgba(5,8,18,.72);backdrop-filter:blur(6px)}
[data-theme="light"] .scanov{background:rgba(240,244,252,.8)}
.scanov[hidden]{display:none}
.scanov-card{width:min(440px,92vw);background:linear-gradient(160deg,var(--panel-2),var(--panel));
  border:1px solid var(--line-2);border-radius:var(--radius);padding:26px 28px;
  box-shadow:0 24px 80px rgba(0,0,0,.45)}
.scanov-file{font-family:'JetBrains Mono';font-size:12.5px;color:var(--txt-dim);
  margin:8px 0 16px;word-break:break-all}
.scanov-steps{list-style:none;padding:0;margin:0}
.scanov-steps li{display:flex;gap:13px;align-items:flex-start;padding:9px 0;
  opacity:.45;transition:opacity .3s}
.scanov-steps li.active,.scanov-steps li.done{opacity:1}
.ss-ico{width:26px;height:26px;border-radius:50%;border:2px solid var(--line-2);
  flex:none;display:grid;place-items:center;font-size:13px;margin-top:1px}
li.active .ss-ico{border-color:var(--cyan);border-top-color:transparent;
  animation:ssspin .8s linear infinite}
li.done .ss-ico{border-color:rgba(52,224,161,.5);background:rgba(52,224,161,.12);color:var(--green)}
li.done .ss-ico::before{content:'\2713';font-weight:700}
.ss-t{font-weight:600;font-size:14px;color:var(--txt)}
li.active .ss-t{color:var(--cyan)}
li.done .ss-t{color:var(--green)}
.ss-s{font-size:12px;color:var(--txt-faint);margin-top:1px}
.scanov-foot{margin-top:16px;padding-top:15px;border-top:1px solid var(--line);
  font-size:12.5px;color:var(--txt-dim)}
#scanElapsed{font-family:'JetBrains Mono';color:var(--txt)}
@keyframes ssspin{to{transform:rotate(360deg)}}
</style>

<script>
(function () {
  const dz   = document.getElementById('dropzone');
  const fi   = document.getElementById('fileInput');
  const lbl  = document.getElementById('fileName');
  const form = document.getElementById('uploadForm');
  const btn  = document.getElementById('submitBtn');

  fi.addEventListener('change', () => {
    lbl.textContent = fi.files.length ? fi.files[0].name : '';
  });
  ['dragenter','dragover'].forEach(ev =>
    dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.add('hover'); }));
  ['dragleave','drop'].forEach(ev =>
    dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.remove('hover'); }));
  dz.addEventListener('drop', e => {
    if (e.dataTransfer.files.length) {
      fi.files = e.dataTransfer.files;
      lbl.textContent = fi.files[0].name;
    }
  });
  // --- staged progress overlay ---
  const ov      = document.getElementById('scanOverlay');
  const ovFile  = document.getElementById('scanFile');
  const elapsed = document.getElementById('scanElapsed');
  const steps   = {};
  ov.querySelectorAll('[data-step]').forEach(li => { steps[li.dataset.step] = li; });
  let timer = null, uploadTimer = null;

  function setStep(name, state) {
    steps[name].classList.remove('active', 'done');
    if (state) steps[name].classList.add(state);
  }
  function fmtSize(b) {
    if (b >= 1048576) return (b / 1048576).toFixed(1) + ' MB';
    if (b >= 1024)    return (b / 1024).toFixed(0)    + ' KB';
    return b + ' B';
  }

  form.addEventListener('submit', () => {
    btn.disabled = true;
    btn.textContent = 'Analyzing…';

    const f = fi.files[0];
    ovFile.textContent = f ? f.name + ' · ' + fmtSize(f.size) : '';
    ov.hidden = false;
    setStep('upload', 'active');

    // upload duration estimate (~1.5 MB/s, clamped); the scan is the long phase.
    // Encrypt + store stay pending — the result page shows the completed pipeline.
    const est = Math.min(6000, Math.max(500, f ? f.size / 1500 : 500));
    uploadTimer = setTimeout(() => {
      setStep('upload', 'done');
      setStep('scan', 'active');
    }, est);

    const t0 = Date.now();
    timer = setInterval(() => {
      elapsed.textContent = Math.round((Date.now() - t0) / 1000) + ' s';
    }, 1000);
  });

  // if the browser restores this page from the back/forward cache,
  // clear the overlay so the form is usable again
  window.addEventListener('pageshow', e => {
    if (!e.persisted) return;
    clearInterval(timer);
    clearTimeout(uploadTimer);
    ov.hidden = true;
    elapsed.textContent = '0 s';
    Object.keys(steps).forEach(k => setStep(k, null));
    btn.disabled = false;
    btn.textContent = 'Scan & encrypt';
  });
})();
</script>
<?php require_once __DIR__ . '/includes/footer.php'; ?>
