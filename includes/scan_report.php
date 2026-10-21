<?php
/**
 * scan_report.php (partial)
 * Renders the AI + VirusTotal scan report card.
 *
 * Expected variables (set by the including page):
 *   $report   array   JSON decoded scan data
 *   $rejected bool    true = file was flagged and not stored
 *   $origName string  original filename
 *   $fileId   ?int    file ID (null when not yet saved)
 *   $keyHex   ?string AES key hex (only on first-show after upload)
 *   $qrSrc    ?string data-URI of QR image
 */

$ai         = $report['ai']         ?? [];
$vt         = $report['virustotal'] ?? [];
$combined   = $report['combined']   ?? [];
$features   = $report['features']   ?? [];
$indicators = $report['indicators'] ?? [];

// Probabilities are stored as 0-1 fractions
$probMal   = (float)($ai['probability_malicious'] ?? 0);
$probClean = (float)($ai['probability_clean']     ?? max(0, 1 - $probMal));
if ($probMal   > 1) $probMal   /= 100;
if ($probClean > 1) $probClean /= 100;

$finalVerdict = strtoupper($report['verdict'] ?? 'UNKNOWN');

// colour scheme: ok | danger | warn | info
if ($finalVerdict === 'CLEAN') {
    $scheme = 'ok';
} elseif ($finalVerdict === 'MALICIOUS') {
    $scheme = 'danger';
} elseif ($finalVerdict === 'SUSPICIOUS') {
    $scheme = 'warn';
} else {
    $scheme = 'info';
}

$aiVerdict = strtoupper($ai['verdict'] ?? 'UNKNOWN');
if ($aiVerdict === 'CLEAN')          $aiScheme = 'rt-ok';
elseif ($aiVerdict === 'MALICIOUS')  $aiScheme = 'rt-danger';
elseif ($aiVerdict === 'SUSPICIOUS') $aiScheme = 'rt-warn';
else                                  $aiScheme = '';

$vtVerdict = strtoupper($vt['verdict'] ?? 'UNKNOWN');
if ($vtVerdict === 'CLEAN')          $vtScheme = 'rt-ok';
elseif ($vtVerdict === 'MALICIOUS')  $vtScheme = 'rt-danger';
elseif ($vtVerdict === 'SUSPICIOUS') $vtScheme = 'rt-warn';
else                                  $vtScheme = '';

// SVG icons keyed by colour scheme
$vbIcons = [
    'ok'     => '<svg viewBox="0 0 24 24" fill="none"><path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M9 12l2 2 4-4" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    'danger' => '<svg viewBox="0 0 24 24" fill="none"><path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M12 8v4M12 16h.01" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"/></svg>',
    'warn'   => '<svg viewBox="0 0 24 24" fill="none"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M12 9v4M12 17h.01" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"/></svg>',
    'info'   => '<svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.7"/><path d="M12 8h.01M12 12v4" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"/></svg>',
];

// PDF features to highlight in the summary table.
// Keys MUST match the trained feature names (feature_extractor.py FEATURE_NAMES).
$highlight = [
    'pdf_size'     => 'File size (KB)',
    'pages'        => 'Pages',
    'JS'           => 'JavaScript (/JS)',
    'Javascript'   => 'JavaScript blocks (/JavaScript)',
    'OpenAction'   => 'Auto-run on open (/OpenAction)',
    'launch'       => 'Launch external (/Launch)',
    'EmbeddedFile' => 'Embedded file payloads (/EmbeddedFile)',
    'isEncrypted'  => 'Encrypted PDF',
];

function _pct(float $x): string {
    if ($x > 1) $x /= 100;
    return number_format($x * 100, 2) . '%';
}
function _fx($v): string {
    if ($v === null || $v === '') return '—';
    $f = (float)$v;
    return ($f == floor($f) && abs($f) < 1e12) ? number_format($f, 0, '.', '') : rtrim(rtrim(number_format($f, 2, '.', ''), '0'), '.');
}
function _ts(int $t): string {
    return $t ? date('Y-m-d H:i', $t) : '—';
}
?>

<div class="row justify-content-center">
<div class="col-lg-10">
<div class="cl-card">

  <!-- ══ VERDICT BANNER ══════════════════════════════════════════ -->
  <div class="vbanner vb-<?= $scheme ?>">
    <div class="vb-ico"><?= $vbIcons[$scheme] ?></div>
    <div>
      <div class="vb-main">
        <?php if ($rejected): ?>
          File rejected &mdash; <?= e($finalVerdict) ?>
        <?php else: ?>
          <?= e($finalVerdict) ?>
        <?php endif; ?>
      </div>
      <div class="vb-sub">
        <strong><?= e($origName) ?></strong>
        <?php if (!empty($combined['reason'])): ?>
          &nbsp;&middot;&nbsp;<?= e($combined['reason']) ?>
        <?php elseif (!$rejected): ?>
          &nbsp;&middot;&nbsp;Passed all detectors and stored with AES-256-CBC encryption.
        <?php endif; ?>
      </div>
    </div>
  </div>

  <!-- ══ VERDICT SUMMARY ════════════════════════════════════════ -->
  <div class="rpt-section mt-4">
    <svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.7"/><path d="M9 12l2 2 4-4" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"/></svg>
    Verdict summary
  </div>
  <div class="rpt-grid-summary">

    <!-- Final / combined -->
    <div class="rt rt-<?= $scheme ?>">
      <div class="rt-lbl">Final verdict (combined)</div>
      <div class="rt-val"><?= e($finalVerdict) ?></div>
      <?php if (!empty($combined['reason'])): ?>
        <div style="font-size:13px;color:var(--txt-dim);margin-top:.4rem"><?= e($combined['reason']) ?></div>
      <?php endif; ?>
      <?php if (!empty($combined['sources'])): ?>
        <div style="display:flex;gap:4px;flex-wrap:wrap;margin-top:.5rem">
          <?php foreach ($combined['sources'] as $s): ?>
            <span class="rpt-badge rpt-badge-src"><?= e($s) ?></span>
          <?php endforeach; ?>
        </div>
      <?php endif; ?>
    </div>

    <!-- AI -->
    <div class="rt <?= $aiScheme ?>">
      <div class="rt-lbl">AI verdict</div>
      <div class="rt-val"><?= e($aiVerdict) ?></div>
      <div style="font-size:12.5px;color:var(--txt-faint);margin-top:.4rem">
        <?= e($ai['engine'] ?? 'ML model') ?>
        <?php if (!empty($ai['n_trees'])): ?>
          &nbsp;&middot;&nbsp;<?= (int)$ai['n_trees'] ?> trees
        <?php endif; ?>
      </div>
    </div>

    <!-- VirusTotal -->
    <div class="rt <?= $vtScheme ?>">
      <div class="rt-lbl">VirusTotal verdict</div>
      <div class="rt-val"><?= e($vtVerdict) ?></div>
      <div style="font-size:12.5px;color:var(--txt-faint);margin-top:.4rem">
        <?php if (!empty($vt['available'])): ?>
          <?= (int)($vt['malicious'] ?? 0) ?>/<?= (int)($vt['total'] ?? 0) ?> engines flagged
        <?php else: ?>
          <?= e($vt['note'] ?? 'No data') ?>
        <?php endif; ?>
      </div>
    </div>

  </div><!-- /rpt-grid-summary -->

  <!-- ══ AI MALWARE ANALYZER ════════════════════════════════════ -->
  <div class="rpt-section">
    <svg viewBox="0 0 24 24" fill="none"><rect x="3" y="3" width="18" height="18" rx="3" stroke="currentColor" stroke-width="1.7"/><path d="M7 12h4m2 0h4M12 7v4m0 2v4" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>
    AI malware analyzer
  </div>
  <div class="rpt-grid-2">

    <div class="rt">
      <div class="rt-lbl">Probability malicious</div>
      <div class="rt-val" style="color:var(--red)"><?= _pct($probMal) ?></div>
      <div class="rpt-progress">
        <span class="rpt-bar rpt-bar-red" style="width:<?= min(100, $probMal * 100) ?>%"></span>
      </div>
    </div>

    <div class="rt">
      <div class="rt-lbl">Probability clean</div>
      <div class="rt-val" style="color:var(--green)"><?= _pct($probClean) ?></div>
      <div class="rpt-progress">
        <span class="rpt-bar rpt-bar-green" style="width:<?= min(100, $probClean * 100) ?>%"></span>
      </div>
    </div>

  </div>

  <!-- ══ WHY THIS AI SCORE (explainable AI) ═════════════════════ -->
  <?php $expl = $report['explanation'] ?? null; ?>
  <?php if (is_array($expl) && !empty($expl['top'])): ?>
  <div class="rpt-section">
    <svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.7"/><path d="M12 8h.01M12 12v4" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"/></svg>
    Why this AI score
  </div>
  <p style="font-size:13px;color:var(--txt-dim);margin:0 0 .7rem">
    Starting from a neutral <?= round(((float)($expl['base_rate'] ?? 0.5)) * 100) ?>%, these features moved the
    model's malicious score the most (percentage points).
  </p>
  <div class="rpt-table-wrap" style="overflow-x:auto">
    <table class="rpt-table">
      <tr style="font-size:11.5px;color:var(--txt-faint)">
        <td>Feature</td><td>This file</td><td>Typical benign</td><td>Typical malicious</td><td style="text-align:right">Effect</td>
      </tr>
      <?php foreach ($expl['top'] as $x):
            $pts   = round(((float)($x['effect'] ?? 0)) * 100);
            $isMal = ($x['direction'] ?? '') === 'malicious'; ?>
        <tr>
          <th>
            <?= e((string)($x['meaning'] ?? $x['feature'] ?? '')) ?>
            <span style="color:var(--txt-faint);font-family:'JetBrains Mono';font-size:.72rem;font-weight:400;margin-left:4px"><?= e((string)($x['feature'] ?? '')) ?></span>
          </th>
          <td style="font-family:'JetBrains Mono';font-size:.85rem"><?= e(_fx($x['value'] ?? null)) ?></td>
          <td style="font-family:'JetBrains Mono';font-size:.85rem;color:var(--txt-dim)"><?= e(_fx($x['typical_benign'] ?? null)) ?></td>
          <td style="font-family:'JetBrains Mono';font-size:.85rem;color:var(--txt-dim)"><?= e(_fx($x['typical_malicious'] ?? null)) ?></td>
          <td style="text-align:right;font-weight:600;white-space:nowrap;color:<?= $isMal ? 'var(--red)' : 'var(--green)' ?>">
            <?= $isMal ? '&#9650; +' : '&#9660; ' ?><?= (int)$pts ?> pts
          </td>
        </tr>
      <?php endforeach; ?>
    </table>
  </div>
  <?php foreach (($expl['caveats'] ?? []) as $cv): ?>
    <div style="font-size:13px;margin-top:.7rem;padding:12px 16px;border-radius:12px;background:rgba(255,194,75,.1);border:1px solid rgba(255,194,75,.3);color:var(--amber)"><?= e((string)$cv) ?></div>
  <?php endforeach; ?>
  <p style="font-size:12px;color:var(--txt-faint);margin:.6rem 0 0"><?= e((string)($expl['note'] ?? '')) ?></p>
  <?php endif; ?>

  <!-- ══ VIRUSTOTAL ══════════════════════════════════════════════ -->
  <div class="rpt-section">
    <svg viewBox="0 0 24 24" fill="none"><circle cx="11" cy="11" r="7" stroke="currentColor" stroke-width="1.7"/><path d="m20 20-3.2-3.2" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>
    VirusTotal
  </div>

  <?php if (empty($vt['available'])): ?>
    <div class="rpt-note">
      <?= e($vt['note'] ?? 'No VirusTotal data available for this file.') ?>
    </div>
  <?php else: ?>

    <!-- Count tiles -->
    <div class="rpt-grid-4">

      <?php $mal = (int)($vt['malicious'] ?? 0); ?>
      <div class="rt <?= $mal > 0 ? 'rt-danger' : '' ?>" style="text-align:center;padding:1.1rem">
        <div class="rt-val" style="font-size:2rem;<?= $mal > 0 ? 'color:var(--red)' : 'color:var(--txt)' ?>"><?= $mal ?></div>
        <div class="rt-lbl" style="margin-top:4px">Malicious</div>
      </div>

      <?php $sus = (int)($vt['suspicious'] ?? 0); ?>
      <div class="rt <?= $sus > 0 ? 'rt-warn' : '' ?>" style="text-align:center;padding:1.1rem">
        <div class="rt-val" style="font-size:2rem;<?= $sus > 0 ? 'color:var(--amber)' : 'color:var(--txt)' ?>"><?= $sus ?></div>
        <div class="rt-lbl" style="margin-top:4px">Suspicious</div>
      </div>

      <div class="rt" style="text-align:center;padding:1.1rem">
        <div class="rt-val" style="font-size:2rem;color:var(--green)"><?= (int)($vt['harmless'] ?? 0) ?></div>
        <div class="rt-lbl" style="margin-top:4px">Harmless</div>
      </div>

      <div class="rt" style="text-align:center;padding:1.1rem">
        <div class="rt-val" style="font-size:2rem"><?= (int)($vt['total'] ?? 0) ?></div>
        <div class="rt-lbl" style="margin-top:4px">Total engines</div>
      </div>

    </div>

    <!-- Metadata row -->
    <div class="rpt-meta-row">
      <span>First seen: <strong><?= e(_ts((int)($vt['first_seen'] ?? 0))) ?></strong></span>
      <span>Last analysed: <strong><?= e(_ts((int)($vt['last_seen'] ?? 0))) ?></strong></span>
      <?php if (!empty($vt['permalink'])): ?>
        <a href="<?= e($vt['permalink']) ?>" target="_blank" rel="noopener">
          View on VirusTotal
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6M15 3h6v6M10 14L21 3" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
        </a>
      <?php endif; ?>
    </div>

    <!-- Flagged engines -->
    <?php if (!empty($vt['flagged'])): ?>
      <div style="font-size:11.5px;letter-spacing:.08em;text-transform:uppercase;color:var(--txt-faint);font-weight:600;margin-top:1.1rem">
        Engines that flagged this file
        <span class="rpt-badge rpt-badge-cnt ms-1"><?= count($vt['flagged']) ?></span>
      </div>
      <ul class="vt-eng-list">
        <?php foreach ($vt['flagged'] as $f): ?>
          <li class="vt-eng-item">
            <span class="vt-eng-name"><?= e($f['engine'] ?? '—') ?></span>
            <span style="display:flex;align-items:center;gap:.5rem">
              <span class="vt-eng-result"><?= e($f['result'] ?? '') ?></span>
              <?php if (!empty($f['category'])): ?>
                <span class="vt-eng-cat"><?= e($f['category']) ?></span>
              <?php endif; ?>
            </span>
          </li>
        <?php endforeach; ?>
      </ul>
    <?php endif; ?>

  <?php endif; ?>

  <!-- ══ FILE METADATA ══════════════════════════════════════════ -->
  <div class="rpt-section">
    <svg viewBox="0 0 24 24" fill="none"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/><path d="M13 2v7h7" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/></svg>
    File metadata
  </div>
  <div class="rpt-table-wrap">
    <table class="rpt-table">
      <tr><th>Filename</th><td><?= e($origName) ?></td></tr>
      <tr><th>MD5</th><td class="mono"><?= e($report['file_md5'] ?? '—') ?></td></tr>
      <tr><th>SHA-256</th><td class="mono"><?= e($report['file_sha256'] ?? '—') ?></td></tr>
      <tr><th>Size</th><td><?= number_format((int)($report['file_size'] ?? 0)) ?> bytes</td></tr>
      <tr><th>Type</th><td><?= !empty($report['is_pdf']) ? 'PDF document' : 'Non-PDF' ?></td></tr>
    </table>
  </div>

  <!-- ══ SUSPICIOUS CAPABILITIES ════════════════════════════════ -->
  <div class="rpt-section">
    <svg viewBox="0 0 24 24" fill="none"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M12 9v4M12 17h.01" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"/></svg>
    Suspicious capabilities
    <span class="rpt-badge rpt-badge-cnt"><?= count($indicators) ?></span>
  </div>

  <?php if (empty($indicators)): ?>
    <div class="rpt-empty">
      <svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.7"/><path d="M9 12l2 2 4-4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
      No risky PDF capabilities detected.
    </div>
  <?php else: ?>
    <ul class="ind-list">
      <?php foreach ($indicators as $ind): ?>
        <li class="ind-item">
          <span class="ind-name"><?= e(is_array($ind) ? ($ind['name'] ?? '?') : $ind) ?></span>
          <?php $desc = is_array($ind) ? ($ind['description'] ?? '') : ''; ?>
          <?php if ($desc): ?>
            <span class="ind-desc"><?= e($desc) ?></span>
          <?php endif; ?>
        </li>
      <?php endforeach; ?>
    </ul>
  <?php endif; ?>

  <!-- ══ KEY FEATURES ═══════════════════════════════════════════ -->
  <div class="rpt-section">
    <svg viewBox="0 0 24 24" fill="none"><rect x="3" y="3" width="18" height="18" rx="2" stroke="currentColor" stroke-width="1.7"/><path d="M3 9h18M9 21V9" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>
    Key features
  </div>
  <div class="rpt-table-wrap">
    <table class="rpt-table">
      <?php foreach ($highlight as $k => $label):
            $val = $features[$k] ?? 0; ?>
        <tr>
          <th>
            <?= e($label) ?>
            <span style="color:var(--txt-faint);font-family:'JetBrains Mono';font-size:.75rem;font-weight:400;margin-left:4px"><?= e($k) ?></span>
          </th>
          <td style="font-family:'JetBrains Mono';font-size:.85rem"><?= e((string)$val) ?></td>
        </tr>
      <?php endforeach; ?>
    </table>
  </div>

  <button class="btn btn-sm btn-cloudie-outline mt-3"
          id="featToggle" onclick="rptToggleFeatures()" style="gap:6px">
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none"><path d="M12 5v14M5 12h14" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg>
    Show all <?= count($features) ?> features
  </button>

  <div id="allFeatures" class="rpt-collapse mt-2">
    <div class="rpt-table-wrap">
      <table class="rpt-table">
        <?php foreach ($features as $k => $v): ?>
          <tr>
            <th style="font-family:'JetBrains Mono';font-weight:500;font-size:.8rem"><?= e($k) ?></th>
            <td style="font-family:'JetBrains Mono';font-size:.8rem"><?= e((string)$v) ?></td>
          </tr>
        <?php endforeach; ?>
      </table>
    </div>
  </div>

  <!-- ══ BOTTOM ACTIONS ══════════════════════════════════════════ -->
  <?php if ($rejected): ?>

    <hr class="rpt-hr">
    <div class="alert alert-danger">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" style="margin-right:6px;vertical-align:middle"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" stroke="currentColor" stroke-width="1.8"/><path d="M12 9v4M12 17h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
      This file was <strong>deleted from the server</strong> and was not encrypted or stored.
    </div>
    <div style="display:flex;gap:.6rem;flex-wrap:wrap">
      <a href="upload.php" class="btn btn-cloudie">Upload a different file</a>
      <a href="dashboard.php" class="btn btn-cloudie-outline">Go to dashboard</a>
    </div>

  <?php elseif ($keyHex): ?>

    <hr class="rpt-hr">
    <h4 style="text-align:center;margin-bottom:.5rem">Your AES-256 decryption key</h4>
    <p style="text-align:center;color:var(--txt-dim);font-size:13.5px;max-width:460px;margin:0 auto .9rem">
      Save this key now &mdash; it is required to view, download, or delete this file.
      We do not store it; if you lose it, the file cannot be recovered.
    </p>
    <?php if (!empty($qrSrc)): ?>
    <div style="text-align:center">
      <img src="<?= e($qrSrc) ?>" alt="AES key QR code" class="qr-img my-3">
    </div>
    <?php endif; ?>
    <div class="key-box mb-3" id="keyBox"><?= e($keyHex) ?></div>
    <div style="display:flex;flex-wrap:wrap;gap:.6rem;justify-content:center">
      <button class="btn btn-cloudie-outline" onclick="rptCopyKey()">Copy key</button>
      <a class="btn btn-cloudie-outline"
         href="data:application/octet-stream;base64,<?= base64_encode("Cloudie AES key for: $origName\nFile ID: $fileId\n$keyHex\n") ?>"
         download="cloudie-key-<?= (int)$fileId ?>.txt">Download key (.txt)</a>
      <a class="btn btn-cloudie" href="dashboard.php">Go to my files</a>
    </div>
    <script>
    function rptCopyKey() {
      navigator.clipboard.writeText(document.getElementById('keyBox').innerText)
        .then(function(){ alert('Key copied to clipboard.'); });
    }
    </script>

  <?php endif; ?>

</div><!-- /cl-card -->
</div><!-- /col-lg-10 -->
</div><!-- /row -->

<script>
function rptToggleFeatures() {
  var el  = document.getElementById('allFeatures');
  var btn = document.getElementById('featToggle');
  var open = el.classList.toggle('open');
  var svgPlus  = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none"><path d="M12 5v14M5 12h14" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg>';
  var svgMinus = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none"><path d="M5 12h14" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg>';
  btn.innerHTML = (open ? svgMinus + ' Hide features' : svgPlus + ' Show all <?= count($features) ?> features');
}
</script>
