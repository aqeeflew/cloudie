<?php
/**
 * rescan.php
 * ----------
 * POST mode=one&id=<file_id>  "Re-check now" on the report page; redirects back with a message.
 * POST mode=auto              Sent by My files on load: re-checks the user's one most overdue file
 *                             in the background and answers with JSON.
 *
 * VirusTotal's free quota (about 4 requests/min) is shared with uploads, and an upload without a
 * VirusTotal answer is refused. So re-checks are capped at 2/min for the whole app, and the
 * automatic one yields: it runs only if no re-check happened in the last minute and this
 * user did not just upload.
 */

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/ratelimit.php';
require_once __DIR__ . '/includes/rescan.php';

require_login();
$user = current_user();
$uid  = (int)$user['user_id'];
$mode = $_POST['mode'] ?? '';

$COLS = "file_id, verdict, is_clean, file_md5, scan_report, recheck_verdict, recheck_hits, recheck_total";

if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !in_array($mode, ['one', 'auto'], true)) {
    header('Location: dashboard.php'); exit;
}

// -----------------------------------------------------------
// Automatic background re-check
// -----------------------------------------------------------
if ($mode === 'auto') {
    header('Content-Type: application/json; charset=utf-8');
    if (!verify_csrf($_POST['csrf'] ?? null)) {
        http_response_code(403);
        echo json_encode(['status' => 'denied']); exit;
    }
    session_write_close();   // a VirusTotal call must not hold up the user's other pages

    if (rl_blocked('rescan_all', 'app', 1, 60)[0] || rl_blocked('upload_user', (string)$uid, 1, 120)[0]) {
        echo json_encode(['status' => 'skipped']); exit;
    }
    $st = db()->prepare(
        "SELECT $COLS FROM files
         WHERE user_id = ? AND COALESCE(recheck_at, uploaded_at) < DATE_SUB(NOW(), INTERVAL " . RESCAN_STALE_HOURS . " HOUR)
         ORDER BY COALESCE(recheck_at, uploaded_at) ASC LIMIT 1");
    $st->execute([$uid]);
    $row = $st->fetch();
    if (!$row) {
        echo json_encode(['status' => 'none']); exit;
    }
    rl_hit('rescan_all', 'app');
    $r = rescan_file($uid, $row, false);
    echo json_encode(['status' => $r['status'], 'changed' => $r['changed']]);
    exit;
}

// -----------------------------------------------------------
// Manual re-check of one file
// -----------------------------------------------------------
$file_id = (int)($_POST['id'] ?? 0);
$back    = 'view_report.php?id=' . $file_id;

if (!verify_csrf($_POST['csrf'] ?? null)) {
    flash_set('error', 'Invalid request.');
    header('Location: ' . $back); exit;
}

$st = db()->prepare("SELECT $COLS FROM files WHERE file_id = ? AND user_id = ? LIMIT 1");
$st->execute([$file_id, $uid]);
$row = $st->fetch();
if (!$row) {
    flash_set('error', 'File not found.');
    header('Location: dashboard.php'); exit;
}

[$blocked, $wait] = rl_blocked('rescan_user', (string)$uid);
if (!$blocked) {
    [$blocked, $wait] = rl_blocked('rescan_all', 'app');
}
if ($blocked) {
    flash_set('error', 'Too many re-checks right now, to protect the VirusTotal quota. Try again in ' . rl_wait_text($wait) . '.');
    header('Location: ' . $back); exit;
}
rl_hit('rescan_user', (string)$uid);
rl_hit('rescan_all', 'app');

$r = rescan_file($uid, $row, true);
if ($r['status'] === 'error') {
    flash_set('error', $r['reason'] === 'rate_limited'
        ? 'VirusTotal quota is used up for now, so nothing changed. Try again in about a minute.'
        : 'VirusTotal could not be reached, so nothing changed. Try again later.');
} elseif ($r['status'] === 'unknown') {
    flash_set('success', 'VirusTotal does not have a report for this file, so its verdict stays as it is.');
} elseif ($r['changed']) {
    if ($r['worse']) {
        flash_set('error', 'New finding: VirusTotal now flags this file. See below.');
    } else {
        flash_set('success', rescan_flagged_later($r['row'])
            ? 'Fewer VirusTotal engines flag this file now, so the later flag was lowered.'
            : 'VirusTotal no longer flags this file, so the later flag was removed.');
    }
} else {
    flash_set('success', 'Re-checked: no change. VirusTotal ' . (int)$r['row']['recheck_hits'] . '/' . (int)$r['row']['recheck_total'] . ' engines flagged it.');
}
header('Location: ' . $back);
exit;
