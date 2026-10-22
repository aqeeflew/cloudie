<?php
/**
 * audit.php — the user's own audit trail with a live integrity check.
 *
 * Every entry is sealed into a hash chain (includes/audit.php). This page re-computes the chain from
 * the database on every visit and says whether anything was edited, removed, inserted or reordered.
 */
require_once __DIR__ . '/includes/auth.php';
require_login();
$user = current_user();

$result = audit_verify((int)$user['user_id']);
$rows   = $result['rows'];
$byId   = [];
foreach ($result['problems'] as $p) {
    if ($p['act_id'] !== null) $byId[$p['act_id']][] = $p;
}
$recent = array_slice(array_reverse($rows), 0, 30);   // newest first
$ok     = $result['ok'];

$pageTitle = 'Audit trail';
require_once __DIR__ . '/includes/header.php';
?>
<div class="row justify-content-center">
  <div class="col-lg-10">

    <div class="cl-card" style="margin-bottom:1rem">
      <h2 class="mb-1">Audit trail</h2>
      <p class="text-muted mb-3">
        Every sign-in, scan, key entry, download and deletion on your account is written to a log.
        Each entry is <strong>cryptographically linked to the one before it</strong> (HMAC-SHA256), so editing,
        removing, inserting or reordering an entry breaks the chain, and this page shows it.
      </p>

      <?php if ($ok): ?>
        <div style="display:flex;gap:.9rem;align-items:center;padding:14px 16px;border-radius:14px;
                    background:rgba(52,224,161,.10);border:1px solid rgba(52,224,161,.35)">
          <span style="width:38px;height:38px;border-radius:11px;display:grid;place-items:center;flex:none;
                       background:rgba(52,224,161,.18);color:var(--green)">
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none"><path d="M5 13l4 4L19 7" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg>
          </span>
          <div>
            <div style="font-weight:700;color:var(--green)">Chain intact</div>
            <div style="font-size:13px;color:var(--txt-dim)">
              <?= (int)$result['sealed'] ?> sealed entr<?= $result['sealed'] === 1 ? 'y' : 'ies' ?> verified just now.
              <?php if ($result['head']): ?>Chain head <code><?= e(substr($result['head'], 0, 16)) ?>&hellip;</code><?php endif; ?>
            </div>
          </div>
        </div>
      <?php else: ?>
        <div style="padding:14px 16px;border-radius:14px;background:rgba(255,93,108,.10);border:1px solid rgba(255,93,108,.4)">
          <div style="display:flex;gap:.9rem;align-items:center">
            <span style="width:38px;height:38px;border-radius:11px;display:grid;place-items:center;flex:none;
                         background:rgba(255,93,108,.18);color:var(--red)">
              <svg viewBox="0 0 24 24" width="20" height="20" fill="none"><path d="M12 3l9 16H3z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M12 9v4m0 3h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
            </span>
            <div>
              <div style="font-weight:700;color:var(--red)">Tampering detected</div>
              <div style="font-size:13px;color:var(--txt-dim)"><?= count($result['problems']) ?> problem<?= count($result['problems']) === 1 ? '' : 's' ?> found in your audit trail.</div>
            </div>
          </div>
          <ul style="margin:.8rem 0 0;padding-left:1.2rem;font-size:13px;color:var(--txt)">
            <?php foreach ($result['problems'] as $p): ?>
              <li>
                <?php if ($p['act_id'] !== null): ?><strong>Entry #<?= (int)$p['act_id'] ?>:</strong> <?php endif; ?>
                <?= e($p['message']) ?>
              </li>
            <?php endforeach; ?>
          </ul>
        </div>
      <?php endif; ?>

      <div style="display:flex;flex-wrap:wrap;gap:.7rem;margin-top:1rem">
        <?php
          $tiles = [
              ['Sealed entries', (string)(int)$result['sealed']],
              ['Earlier entries (before sealing)', (string)(int)$result['legacy']],
              ['Seal', audit_keyed() ? 'Server secret (HMAC)' : 'Development key'],
          ];
          foreach ($tiles as [$k, $v]): ?>
          <div style="flex:1 1 160px;padding:.7rem .9rem;border-radius:12px;border:1px solid var(--line);background:var(--panel)">
            <div style="font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--txt-faint)"><?= e($k) ?></div>
            <div style="font-weight:700;margin-top:2px"><?= e($v) ?></div>
          </div>
        <?php endforeach; ?>
      </div>
      <?php if (!audit_keyed()): ?>
        <p class="text-muted" style="font-size:12.5px;margin:.8rem 0 0">
          This environment has no audit secret configured (local development), so the seal uses a built-in key.
          In production the seal key lives in Secret Manager, so the database alone is not enough to forge entries.
        </p>
      <?php endif; ?>
    </div>

    <div class="cl-card">
      <h5 class="mb-3">Recent activity</h5>
      <?php if (!$recent): ?>
        <p class="text-muted mb-0">No activity recorded yet.</p>
      <?php else: ?>
      <div style="overflow-x:auto">
        <table class="rpt-table" style="width:100%;min-width:560px">
          <tr style="font-size:11.5px;color:var(--txt-faint)">
            <td>#</td><td>When (UTC)</td><td>Event</td><td>Details</td><td style="text-align:right">Seal</td>
          </tr>
          <?php foreach ($recent as $r):
                $id = (int)$r['act_id'];
                $bad = isset($byId[$id]);
                $sealed = !empty($r['row_hash']); ?>
            <tr<?= $bad ? ' style="background:rgba(255,93,108,.08)"' : '' ?>>
              <td style="font-family:'JetBrains Mono',monospace;font-size:.8rem;color:var(--txt-faint)"><?= $id ?></td>
              <td style="font-family:'JetBrains Mono',monospace;font-size:.8rem;white-space:nowrap"><?= e((string)$r['act_time']) ?></td>
              <td><?= e(audit_label((string)$r['act_type'])) ?></td>
              <td style="color:var(--txt-dim);font-size:.85rem"><?= e((string)($r['details'] ?? '')) ?></td>
              <td style="text-align:right;white-space:nowrap">
                <?php if ($bad): ?>
                  <span style="color:var(--red);font-weight:700">&#10005; broken</span>
                <?php elseif ($sealed): ?>
                  <span style="color:var(--green);font-weight:700" title="<?= e((string)$r['row_hash']) ?>">&#10003; <code><?= e(substr((string)$r['row_hash'], 0, 8)) ?></code></span>
                <?php else: ?>
                  <span style="color:var(--txt-faint)" title="Written before sealing was introduced">&mdash; earlier</span>
                <?php endif; ?>
              </td>
            </tr>
          <?php endforeach; ?>
        </table>
      </div>
      <p class="text-muted" style="font-size:12.5px;margin:.9rem 0 0">
        Showing the latest <?= count($recent) ?> of <?= count($rows) ?> entries. Verification covers all of them.
      </p>
      <?php endif; ?>
    </div>

    <div class="cl-card" style="margin-top:1rem">
      <h5 class="mb-2">What this does and does not protect</h5>
      <ul style="margin:0;padding-left:1.2rem;font-size:13.5px;color:var(--txt-dim);line-height:1.6">
        <li><strong>Detects</strong> an entry that was edited, removed from the middle, inserted, or reordered.</li>
        <li><strong>Detects</strong> removal of the most recent entries, through a separate sealed chain head.</li>
        <li><strong>Does not stop</strong> someone who has both the database and the server's secret key from rewriting history.</li>
        <li>Entries written before sealing existed are shown as &ldquo;earlier&rdquo; and are not covered.</li>
      </ul>
    </div>

  </div>
</div>
<?php require_once __DIR__ . '/includes/footer.php'; ?>
