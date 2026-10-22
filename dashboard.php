<?php
require_once __DIR__ . '/includes/auth.php';
require_login();
$user = current_user();

$pageTitle = 'My files';

$stmt = db()->prepare(
    "SELECT f.file_id, f.file_name, f.file_type, f.file_size,
            f.is_clean, f.verdict, f.uploaded_at,
            fo.folder_id, fo.folder_name, fo.color AS folder_color
     FROM files f
     LEFT JOIN folders fo ON fo.folder_id = f.folder_id
     WHERE f.user_id = ?
     ORDER BY f.uploaded_at DESC");
$stmt->execute([$user['user_id']]);
$files = $stmt->fetchAll();

// quick counts for the summary cards
$total      = count($files);
$clean      = 0;
$suspicious = 0;
$bytes      = 0;
foreach ($files as $f) {
    $v = strtolower((string)($f['verdict'] ?? ((int)$f['is_clean'] === 1 ? 'clean' : 'suspicious')));
    if ($v === 'clean')           $clean++;
    elseif ($v === 'suspicious')  $suspicious++;
    $bytes += (int)$f['file_size'];
}

require_once __DIR__ . '/includes/header.php';

function fmt_size(int $b): string {
    if ($b >= 1024*1024) return number_format($b/1024/1024, 2) . ' MB';
    if ($b >= 1024)      return number_format($b/1024, 1)      . ' KB';
    return $b . ' B';
}

// icon + colour class per file type
function type_class(string $ext): string {
    $ext = strtolower($ext);
    if (in_array($ext, ['png','jpg','jpeg','gif','webp'])) return 't-img';
    if (in_array($ext, ['pdf']))                            return 't-pdf';
    if (in_array($ext, ['zip','rar','7z','tar','gz']))      return 't-zip';
    return 't-doc';
}

// normalise a row to one of: clean | suspicious
function row_verdict(array $row): string {
    $v = strtolower((string)($row['verdict'] ?? ''));
    if (in_array($v, ['clean', 'suspicious'], true)) return $v;
    return ((int)$row['is_clean'] === 1) ? 'clean' : 'suspicious';
}
?>
<style>
/* dashboard-only extras */
.summary{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:28px}
.scard{background:linear-gradient(160deg,var(--panel-2),var(--panel));
  border:1px solid var(--line);border-radius:var(--radius);padding:18px 20px}
.scard-ico{width:38px;height:38px;border-radius:11px;display:grid;place-items:center;margin-bottom:14px}
.scard-ico svg{width:20px;height:20px}
.scard .k{font-family:'Space Grotesk';font-weight:700;font-size:26px;line-height:1;letter-spacing:-.02em}
.scard .l{font-size:12.5px;color:var(--txt-dim);margin-top:7px}
.i-green{background:rgba(52,224,161,.13);color:var(--green)}
.i-cyan{background:rgba(39,211,224,.13);color:var(--cyan)}
.i-violet{background:rgba(123,92,255,.15);color:var(--violet)}
.i-amber{background:rgba(255,194,75,.14);color:var(--amber)}
.ftype{width:36px;height:36px;border-radius:10px;display:inline-grid;place-items:center;
  vertical-align:middle;margin-right:12px}
.ftype svg{width:18px;height:18px}
.t-pdf{background:rgba(255,93,108,.13);color:var(--red)}
.t-img{background:rgba(123,92,255,.14);color:var(--violet)}
.t-doc{background:rgba(39,211,224,.13);color:var(--cyan)}
.t-zip{background:rgba(255,194,75,.14);color:var(--amber)}
.fn-main{font-weight:500}
.fcol{font-family:'JetBrains Mono';font-size:13px;color:var(--txt-dim)}
.empty{text-align:center;padding:40px 20px}
.empty svg{width:46px;height:46px;color:var(--txt-faint);margin-bottom:14px}
.v-susp{background:rgba(255,194,75,.14);color:var(--amber)}
.fa-group{display:flex;align-items:center;justify-content:flex-end;gap:5px;flex-wrap:wrap}
.fa-sep{width:1px;height:20px;background:var(--line-2);margin:0 3px;flex:none}
@media(max-width:1200px){.summary{grid-template-columns:repeat(2,1fr)}}
@media(max-width:1000px){.summary{grid-template-columns:1fr}}
</style>

<div class="d-flex align-items-center justify-content-between mb-3">
  <h2 class="m-0">My encrypted files</h2>
  <a href="upload.php" class="btn btn-cloudie">
    <svg viewBox="0 0 24 24" width="16" height="16" fill="none"><path d="M12 5v14M5 12h14" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg>
    Upload
  </a>
</div>

<p class="small mb-3"><strong>Suspicious</strong> = VirusTotal found nothing, but the AI flagged structural features of the file. It is stored and encrypted; open it with caution. Malicious files are blocked and never stored.</p>

<!-- summary cards -->
<div class="summary">
  <div class="scard">
    <div class="scard-ico i-green"><svg viewBox="0 0 24 24" fill="none"><path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M9 12l2 2 4-4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
    <div class="k"><?= (int)$clean ?></div>
    <div class="l">Clean (VirusTotal + AI)</div>
  </div>
  <div class="scard">
    <div class="scard-ico i-amber"><svg viewBox="0 0 24 24" fill="none"><path d="M12 3l9 16H3z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/><path d="M12 9v4m0 3h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg></div>
    <div class="k"><?= (int)$suspicious ?></div>
    <div class="l">Suspicious (AI flagged)</div>
  </div>
  <div class="scard">
    <div class="scard-ico i-violet"><svg viewBox="0 0 24 24" fill="none"><rect x="5" y="11" width="14" height="9" rx="2" stroke="currentColor" stroke-width="1.7"/><path d="M8 11V8a4 4 0 0 1 8 0v3" stroke="currentColor" stroke-width="1.7"/></svg></div>
    <div class="k"><?= fmt_size($bytes) ?></div>
    <div class="l">Encrypted at rest (AES-256-CBC)</div>
  </div>
  <div class="scard">
    <div class="scard-ico i-cyan"><svg viewBox="0 0 24 24" fill="none"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z" stroke="currentColor" stroke-width="1.6"/></svg></div>
    <div class="k"><?= (int)$total ?></div>
    <div class="l">Total files in your vault</div>
  </div>
</div>

<?php if (!$files): ?>
  <div class="cl-card empty">
    <svg viewBox="0 0 24 24" fill="none"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z" stroke="currentColor" stroke-width="1.6"/></svg>
    <h3>Your vault is empty</h3>
    <p class="text-muted">Upload a file and Cloudie will scan it, then encrypt it with AES-256.</p>
    <a href="upload.php" class="btn btn-cloudie mt-3">Upload your first file</a>
  </div>
<?php else: ?>
<div class="file-table">
  <table>
    <thead>
      <tr>
        <th>Name</th>
        <th>Size</th>
        <th>Verdict</th>
        <th>Uploaded</th>
        <th class="text-end">Actions</th>
      </tr>
    </thead>
    <tbody>
    <?php foreach ($files as $row): $rv = row_verdict($row); ?>
      <tr class="file-row">
        <td data-label="Name">
          <span class="ftype <?= type_class($row['file_type']) ?>">
            <svg viewBox="0 0 24 24" fill="none"><path d="M6 2h8l4 4v16H6z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M14 2v4h4" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/></svg>
          </span>
          <span class="fn-main"><?= e($row['file_name']) ?></span>
          <?php if ($row['folder_id']): $fc=['cyan'=>'rgba(39,211,224,.18)','violet'=>'rgba(123,92,255,.18)','green'=>'rgba(52,224,161,.18)','amber'=>'rgba(255,194,75,.18)','red'=>'rgba(255,93,108,.18)'][$row['folder_color']] ?? 'rgba(39,211,224,.18)'; $fctext=['cyan'=>'var(--cyan)','violet'=>'var(--violet)','green'=>'var(--green)','amber'=>'var(--amber)','red'=>'var(--red)'][$row['folder_color']] ?? 'var(--cyan)'; ?>
          <a href="folder.php?id=<?= (int)$row['folder_id'] ?>"
             class="folder-chip"
             style="background:<?= $fc ?>;color:<?= $fctext ?>">
            <svg viewBox="0 0 24 24" width="11" height="11" fill="none"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/></svg>
            <?= e($row['folder_name']) ?>
          </a>
          <?php endif; ?>
        </td>
        <td class="fcol" data-label="Size"><?= e(fmt_size((int)$row['file_size'])) ?></td>
        <td data-label="Verdict">
          <?php if ($rv === 'suspicious'): ?>
            <span class="verdict v-susp" title="VirusTotal found nothing, but the AI flagged structural features. Stored; open with caution.">
              <svg viewBox="0 0 24 24" fill="none"><path d="M12 3l9 16H3z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M12 9v4m0 3h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>Suspicious
            </span>
          <?php else: ?>
            <span class="verdict v-clean">
              <svg viewBox="0 0 24 24" fill="none"><path d="M5 13l4 4L19 7" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg>Clean
            </span>
          <?php endif; ?>
        </td>
        <td class="fcol" data-label="Uploaded"><?= e(date('M j, Y', strtotime($row['uploaded_at']))) ?></td>
        <td data-label="Actions">
          <div class="fa-group">
            <a href="decrypt.php?action=view&id=<?= (int)$row['file_id'] ?>"
               class="btn btn-sm btn-cloudie" title="View decrypted file">
              <svg viewBox="0 0 24 24" width="13" height="13" fill="none"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" stroke="currentColor" stroke-width="1.8"/><circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="1.8"/></svg>
              View
            </a>
            <a href="decrypt.php?action=download&id=<?= (int)$row['file_id'] ?>"
               class="btn btn-sm btn-cloudie-outline" title="Download decrypted file">
              <svg viewBox="0 0 24 24" width="13" height="13" fill="none"><path d="M12 16V4m0 12-4-4m4 4 4-4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><path d="M5 20h14" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
              Download
            </a>
            <a href="view_report.php?id=<?= (int)$row['file_id'] ?>"
               class="btn btn-sm btn-cloudie-outline btn-ico" aria-label="View scan report" title="View scan report">
              <svg viewBox="0 0 24 24" width="13" height="13" fill="none"><path d="M9 5H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-2" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><rect x="9" y="3" width="6" height="4" rx="1" stroke="currentColor" stroke-width="1.8"/><path d="M9 12h6M9 15h4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
              <span class="lbl">Report</span>
            </a>
            <span class="fa-sep"></span>
            <a href="decrypt.php?action=delete&id=<?= (int)$row['file_id'] ?>"
               class="btn btn-sm btn-danger btn-ico" aria-label="Delete file" title="Delete file"
               data-delete-name="<?= e($row['file_name']) ?>">
              <svg viewBox="0 0 24 24" width="13" height="13" fill="none"><path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
              <span class="lbl">Delete</span>
            </a>
          </div>
        </td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
</div>

<div class="cl-card empty d-none" id="searchEmpty">
  <svg viewBox="0 0 24 24" fill="none"><circle cx="11" cy="11" r="7" stroke="currentColor" stroke-width="1.6"/><path d="m20 20-3.2-3.2" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>
  <h3>No matches</h3>
  <p class="text-muted">No files match &ldquo;<span id="searchEmptyQ"></span>&rdquo;. Try a different name, folder or verdict.</p>
</div>
<?php endif; ?>

<script>
document.querySelectorAll('[data-delete-name]').forEach(function(a){
  a.addEventListener('click',function(e){
    e.preventDefault();
    var link = this, href = link.getAttribute('href');
    clConfirm({
      title: 'Delete this file?',
      item: link.getAttribute('data-delete-name'),
      message: 'This permanently removes the encrypted file and its key record. It cannot be undone.',
      note: 'Next you will be asked for the file\u2019s AES key to confirm.',
      confirmText: 'Continue to delete'
    }).then(function(yes){ if (yes) window.location.href = href; });
  });
});

// live vault search (topbar input rendered by header.php on this page)
(function(){
  var q      = document.getElementById('vaultSearch');
  var table  = document.querySelector('.file-table');
  var empty  = document.getElementById('searchEmpty');
  var emptyQ = document.getElementById('searchEmptyQ');
  if (!q || !table) return;

  var rows = Array.prototype.slice.call(table.querySelectorAll('.file-row'));
  // pre-compute the searchable text (name + folder + verdict) per row
  rows.forEach(function(r){
    var name    = r.querySelector('.fn-main');
    var folder  = r.querySelector('.folder-chip');
    var verdict = r.querySelector('.verdict');
    r.dataset.search = [
      name    ? name.textContent    : '',
      folder  ? folder.textContent  : '',
      verdict ? verdict.textContent : ''
    ].join(' ').toLowerCase();
  });

  q.addEventListener('input', function(){
    var term  = q.value.trim().toLowerCase();
    var shown = 0;
    rows.forEach(function(r){
      var hit = !term || r.dataset.search.indexOf(term) !== -1;
      r.style.display = hit ? '' : 'none';
      if (hit) shown++;
    });
    table.style.display = shown ? '' : 'none';
    emptyQ.textContent = q.value.trim();
    empty.classList.toggle('d-none', shown > 0);
  });

  q.addEventListener('keydown', function(e){
    if (e.key === 'Escape'){
      q.value = '';
      q.dispatchEvent(new Event('input'));
      q.blur();
    }
  });
})();
</script>
<?php require_once __DIR__ . '/includes/footer.php'; ?>