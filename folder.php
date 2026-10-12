<?php
require_once __DIR__ . '/includes/auth.php';
require_login();
$user = current_user();

$folder_id = (int)($_GET['id'] ?? 0);
if ($folder_id <= 0) { header('Location: dashboard.php'); exit; }

// Verify folder belongs to this user
$stmt = db()->prepare("SELECT * FROM folders WHERE folder_id = ? AND user_id = ?");
$stmt->execute([$folder_id, $user['user_id']]);
$folder = $stmt->fetch();
if (!$folder) { header('Location: dashboard.php'); exit; }

// Handle POST actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf'] ?? '')) {
        flash_set('error', 'Invalid request.');
    } else {
        $act = $_POST['action'] ?? '';
        $fid = (int)($_POST['file_id'] ?? 0);

        if ($act === 'add' && $fid > 0) {
            $s = db()->prepare("UPDATE files SET folder_id=? WHERE file_id=? AND user_id=?");
            $s->execute([$folder_id, $fid, $user['user_id']]);
        } elseif ($act === 'remove' && $fid > 0) {
            $s = db()->prepare("UPDATE files SET folder_id=NULL WHERE file_id=? AND user_id=? AND folder_id=?");
            $s->execute([$fid, $user['user_id'], $folder_id]);
        } elseif ($act === 'delete_folder') {
            $s = db()->prepare("UPDATE files SET folder_id=NULL WHERE folder_id=? AND user_id=?");
            $s->execute([$folder_id, $user['user_id']]);
            $s = db()->prepare("DELETE FROM folders WHERE folder_id=? AND user_id=?");
            $s->execute([$folder_id, $user['user_id']]);
            flash_set('success', 'Folder "' . $folder['folder_name'] . '" deleted.');
            header('Location: dashboard.php'); exit;
        } elseif ($act === 'rename') {
            $newName = trim($_POST['new_name'] ?? '');
            if ($newName !== '' && mb_strlen($newName) <= 100) {
                $s = db()->prepare("UPDATE folders SET folder_name=? WHERE folder_id=? AND user_id=?");
                $s->execute([$newName, $folder_id, $user['user_id']]);
                $folder['folder_name'] = $newName;
            }
        }
    }
    header('Location: folder.php?id=' . $folder_id); exit;
}

$pageTitle = $folder['folder_name'];

// Files IN this folder
$stmt = db()->prepare(
    "SELECT file_id, file_name, file_type, file_size, is_clean, verdict, uploaded_at
     FROM files WHERE user_id=? AND folder_id=? ORDER BY uploaded_at DESC"
);
$stmt->execute([$user['user_id'], $folder_id]);
$files = $stmt->fetchAll();

// Files NOT in this folder (for the Add panel)
$stmt = db()->prepare(
    "SELECT file_id, file_name, file_type
     FROM files WHERE user_id=? AND (folder_id IS NULL OR folder_id!=?) ORDER BY uploaded_at DESC"
);
$stmt->execute([$user['user_id'], $folder_id]);
$otherFiles = $stmt->fetchAll();

require_once __DIR__ . '/includes/header.php';

function fmt_size(int $b): string {
    if ($b >= 1024*1024) return number_format($b/1024/1024,2).' MB';
    if ($b >= 1024)      return number_format($b/1024,1).' KB';
    return $b.' B';
}
function type_class(string $ext): string {
    $e = strtolower($ext);
    if (in_array($e,['png','jpg','jpeg','gif','webp'])) return 't-img';
    if ($e==='pdf') return 't-pdf';
    if (in_array($e,['zip','rar','7z','tar','gz']))     return 't-zip';
    return 't-doc';
}
function row_verdict(array $row): string {
    $v = strtolower((string)($row['verdict'] ?? ''));
    if (in_array($v,['clean','suspicious'],true)) return $v;
    return ((int)$row['is_clean']===1)?'clean':'suspicious';
}

$colorVar = ['cyan'=>'var(--cyan)','violet'=>'var(--violet)','green'=>'var(--green)',
             'amber'=>'var(--amber)','red'=>'var(--red)'];
$fcolor = $colorVar[$folder['color']] ?? 'var(--cyan)';
?>
<style>
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
.v-susp{background:rgba(255,194,75,.14);color:var(--amber)}
.fa-group{display:flex;align-items:center;justify-content:flex-end;gap:5px;flex-wrap:wrap}
.fa-sep{width:1px;height:20px;background:var(--line-2);margin:0 3px;flex:none}
/* add-files panel */
.add-panel{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);
  margin-top:24px;overflow:hidden}
.add-panel-head{display:flex;align-items:center;justify-content:space-between;
  padding:14px 20px;cursor:pointer;user-select:none}
.add-panel-head h4{margin:0;font-size:14px;color:var(--txt-dim);font-family:'Space Grotesk';
  font-weight:600;display:flex;align-items:center;gap:8px}
.add-panel-body{border-top:1px solid var(--line);max-height:0;overflow:hidden;transition:max-height .3s ease}
.add-panel-body.open{max-height:420px;overflow-y:auto}
.add-row{display:flex;align-items:center;gap:12px;padding:11px 20px;border-bottom:1px solid var(--line)}
.add-row:last-child{border-bottom:none}
.add-row:hover{background:var(--panel-2)}
.add-fn{flex:1;font-size:13.5px;font-weight:500;color:var(--txt);overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
.add-ft{font-size:11.5px;color:var(--txt-faint);font-family:'JetBrains Mono';flex:none}
.empty-add{padding:18px 20px;color:var(--txt-faint);font-size:13.5px}
.folder-header{display:flex;align-items:center;gap:14px;margin-bottom:24px}
.folder-icon-lg{width:46px;height:46px;border-radius:13px;display:grid;place-items:center;flex:none}
.folder-icon-lg svg{width:26px;height:26px}
@media(max-width:1200px){.summary{grid-template-columns:repeat(2,1fr)}}
@media(max-width:1000px){.summary{grid-template-columns:1fr}}
</style>

<?php $csrf = csrf_token(); ?>

<!-- Folder header -->
<div class="d-flex align-items-center justify-content-between mb-3">
  <div class="folder-header" style="margin-bottom:0">
    <div class="folder-icon-lg" style="background:rgba(<?= $folder['color']==='cyan'?'39,211,224':($folder['color']==='violet'?'123,92,255':($folder['color']==='green'?'52,224,161':($folder['color']==='amber'?'255,194,75':'255,93,108'))) ?>,.15)">
      <svg viewBox="0 0 24 24" fill="none" style="color:<?= $fcolor ?>">
        <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/>
      </svg>
    </div>
    <div>
      <h2 class="m-0" id="folderTitle"><?= e($folder['folder_name']) ?></h2>
      <a href="dashboard.php" class="small" style="color:var(--txt-faint)">← All files</a>
    </div>
  </div>
  <div class="d-flex gap-2">
    <button class="btn btn-sm btn-cloudie-outline" id="renameBtn">
      <svg viewBox="0 0 24 24" width="13" height="13" fill="none"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="M18.5 2.5a2.12 2.12 0 0 1 3 3L12 15l-4 1 1-4z" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
      Rename
    </button>
    <form method="POST">
      <input type="hidden" name="csrf" value="<?= $csrf ?>">
      <input type="hidden" name="action" value="delete_folder">
      <button type="submit" class="btn btn-sm btn-danger"
              onclick="return confirm('Delete folder &quot;<?= e($folder['folder_name']) ?>&quot;?\n\nFiles will NOT be deleted — they move back to your vault.')">
        <svg viewBox="0 0 24 24" width="13" height="13" fill="none"><path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
        Delete folder
      </button>
    </form>
  </div>
</div>

<!-- Rename form (hidden by default) -->
<div id="renameForm" style="display:none;margin-bottom:16px">
  <form method="POST" class="d-flex gap-2">
    <input type="hidden" name="csrf" value="<?= $csrf ?>">
    <input type="hidden" name="action" value="rename">
    <input type="text" name="new_name" class="form-control" value="<?= e($folder['folder_name']) ?>" maxlength="100" required style="max-width:280px">
    <button type="submit" class="btn btn-cloudie">Save</button>
    <button type="button" class="btn btn-cloudie-outline" id="cancelRename">Cancel</button>
  </form>
</div>

<!-- Files in this folder -->
<?php if (empty($files)): ?>
  <div class="cl-card" style="text-align:center;padding:40px 20px">
    <svg viewBox="0 0 24 24" width="44" height="44" fill="none" style="color:var(--txt-faint);margin-bottom:14px"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z" stroke="currentColor" stroke-width="1.6"/></svg>
    <h3>This folder is empty</h3>
    <p class="text-muted">Add files from your vault using the panel below.</p>
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
        </td>
        <td class="fcol" data-label="Size"><?= fmt_size((int)$row['file_size']) ?></td>
        <td data-label="Verdict">
          <?php if ($rv==='suspicious'): ?>
            <span class="verdict v-susp"><svg viewBox="0 0 24 24" fill="none"><path d="M12 3l9 16H3z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M12 9v4m0 3h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>Suspicious</span>
          <?php else: ?>
            <span class="verdict v-clean"><svg viewBox="0 0 24 24" fill="none"><path d="M5 13l4 4L19 7" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg>Clean</span>
          <?php endif; ?>
        </td>
        <td class="fcol" data-label="Uploaded"><?= e(date('M j, Y',strtotime($row['uploaded_at']))) ?></td>
        <td data-label="Actions">
          <div class="fa-group">
            <a href="view_report.php?id=<?= (int)$row['file_id'] ?>" class="btn btn-sm btn-cloudie-outline" title="View scan report">
              <svg viewBox="0 0 24 24" width="13" height="13" fill="none"><path d="M9 5H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-2" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><rect x="9" y="3" width="6" height="4" rx="1" stroke="currentColor" stroke-width="1.8"/><path d="M9 12h6M9 15h4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
              Report
            </a>
            <a href="decrypt.php?action=view&id=<?= (int)$row['file_id'] ?>" class="btn btn-sm btn-cloudie-outline" title="View file">
              <svg viewBox="0 0 24 24" width="13" height="13" fill="none"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" stroke="currentColor" stroke-width="1.8"/><circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="1.8"/></svg>
              View
            </a>
            <a href="decrypt.php?action=download&id=<?= (int)$row['file_id'] ?>" class="btn btn-sm btn-cloudie-outline" title="Download">
              <svg viewBox="0 0 24 24" width="13" height="13" fill="none"><path d="M12 16V4m0 12-4-4m4 4 4-4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><path d="M5 20h14" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
              Download
            </a>
            <span class="fa-sep"></span>
            <form method="POST" style="display:inline">
              <input type="hidden" name="csrf" value="<?= $csrf ?>">
              <input type="hidden" name="action" value="remove">
              <input type="hidden" name="file_id" value="<?= (int)$row['file_id'] ?>">
              <button type="submit" class="btn btn-sm btn-cloudie-outline" title="Remove from folder"
                style="color:var(--amber);border-color:rgba(255,194,75,.3)">
                <svg viewBox="0 0 24 24" width="13" height="13" fill="none"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/><path d="M9 12h6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
                Remove
              </button>
            </form>
            <span class="fa-sep"></span>
            <a href="decrypt.php?action=delete&id=<?= (int)$row['file_id'] ?>"
               class="btn btn-sm btn-danger" title="Delete file permanently"
               data-delete-name="<?= e($row['file_name']) ?>">
              <svg viewBox="0 0 24 24" width="13" height="13" fill="none"><path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
              Delete
            </a>
          </div>
        </td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
</div>
<?php endif; ?>

<!-- Add files panel -->
<div class="add-panel">
  <div class="add-panel-head" id="addPanelHead">
    <h4>
      <svg viewBox="0 0 24 24" width="16" height="16" fill="none"><path d="M12 5v14M5 12h14" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
      Add files to this folder
      <span class="count" style="font-family:'JetBrains Mono';font-size:11px"><?= count($otherFiles) ?></span>
    </h4>
    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" id="addPanelArrow"><path d="M6 9l6 6 6-6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
  </div>
  <div class="add-panel-body" id="addPanelBody">
    <?php if (empty($otherFiles)): ?>
      <div class="empty-add">All your vault files are already in this folder.</div>
    <?php else: foreach ($otherFiles as $of): ?>
      <div class="add-row">
        <span class="ftype <?= type_class($of['file_type']) ?>" style="width:28px;height:28px;border-radius:7px;margin-right:0">
          <svg viewBox="0 0 24 24" fill="none" width="14" height="14"><path d="M6 2h8l4 4v16H6z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/></svg>
        </span>
        <span class="add-fn"><?= e($of['file_name']) ?></span>
        <span class="add-ft"><?= strtoupper(e($of['file_type'])) ?></span>
        <form method="POST">
          <input type="hidden" name="csrf" value="<?= $csrf ?>">
          <input type="hidden" name="action" value="add">
          <input type="hidden" name="file_id" value="<?= (int)$of['file_id'] ?>">
          <button type="submit" class="btn btn-sm btn-cloudie">
            <svg viewBox="0 0 24 24" width="12" height="12" fill="none"><path d="M12 5v14M5 12h14" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg>
            Add
          </button>
        </form>
      </div>
    <?php endforeach; endif; ?>
  </div>
</div>

<script>
// delete confirmation
document.querySelectorAll('[data-delete-name]').forEach(function(a){
  a.addEventListener('click',function(e){
    if(!confirm('Delete "'+this.getAttribute('data-delete-name')+'"?\n\nThis cannot be undone.')) e.preventDefault();
  });
});
// rename toggle
document.getElementById('renameBtn').addEventListener('click',function(){
  var f=document.getElementById('renameForm');
  f.style.display = f.style.display==='none' ? 'block' : 'none';
  if(f.style.display==='block') f.querySelector('input[name="new_name"]').focus();
});
document.getElementById('cancelRename').addEventListener('click',function(){
  document.getElementById('renameForm').style.display='none';
});
// add-files panel toggle
document.getElementById('addPanelHead').addEventListener('click',function(){
  var body=document.getElementById('addPanelBody'),
      arrow=document.getElementById('addPanelArrow');
  body.classList.toggle('open');
  arrow.style.transform = body.classList.contains('open') ? 'rotate(180deg)' : '';
});
</script>
<?php require_once __DIR__ . '/includes/footer.php'; ?>
