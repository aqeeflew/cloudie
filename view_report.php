<?php
/**
 * view_report.php
 * ---------------
 * Shows the stored AI/VirusTotal scan report for a file the user owns.
 *
 *   GET ?id=<file_id>              -> render the report on screen
 *   GET ?id=<file_id>&dl=json      -> download the raw report as JSON
 *   GET ?id=<file_id>&dl=txt       -> download a human-readable text summary
 *
 * The report is read from files.scan_report (saved at upload time), so no
 * AES key is required — this page never decrypts the file itself.
 */

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/db.php';

require_login();
$user = current_user();

$file_id = (int)($_GET['id'] ?? 0);
$dl      = $_GET['dl'] ?? null;

if ($file_id <= 0) {
    flash_set('error', 'Invalid request.');
    header('Location: dashboard.php'); exit;
}

// Fetch the file + its stored report — must belong to the current user
$stmt = db()->prepare(
    "SELECT file_id, file_name, file_type, file_size, file_md5,
            is_clean, scan_report, uploaded_at
     FROM files
     WHERE file_id = ? AND user_id = ?
     LIMIT 1");
$stmt->execute([$file_id, $user['user_id']]);
$rec = $stmt->fetch();

if (!$rec) {
    flash_set('error', 'File not found.');
    header('Location: dashboard.php'); exit;
}

$report = json_decode($rec['scan_report'] ?? '', true);
if (!is_array($report)) {
    $report = [];   // older rows may have no stored report
}

// ---------------------------------------------------------------
// Downloads
// ---------------------------------------------------------------
if ($dl === 'json') {
    log_action($user['user_id'], 'REPORT_DOWNLOAD', $file_id, null, 'json');
    $safe = preg_replace('/[^A-Za-z0-9._-]/', '_', $rec['file_name']);
    header('Content-Type: application/json; charset=utf-8');
    header('Content-Disposition: attachment; filename="cloudie-report-' . $safe . '.json"');
    echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

if ($dl === 'txt') {
    log_action($user['user_id'], 'REPORT_DOWNLOAD', $file_id, null, 'txt');
    $safe = preg_replace('/[^A-Za-z0-9._-]/', '_', $rec['file_name']);
    header('Content-Type: text/plain; charset=utf-8');
    header('Content-Disposition: attachment; filename="cloudie-report-' . $safe . '.txt"');
    echo build_text_report($rec, $report);
    exit;
}

// ---------------------------------------------------------------
// Variables expected by includes/scan_report.php
// ---------------------------------------------------------------
$origName = $rec['file_name'];
$rejected = ((int)$rec['is_clean'] !== 1);  // stored files are clean; defensive
$fileId   = (int)$rec['file_id'];
$keyHex   = null;   // we never show the key here
$qrSrc    = null;

// Make sure the partial has the basic file metadata even on older rows
$report['file_md5']  = $report['file_md5']  ?? $rec['file_md5'];
$report['file_size'] = $report['file_size'] ?? (int)$rec['file_size'];

$pageTitle = 'Scan report · ' . $rec['file_name'];
require_once __DIR__ . '/includes/header.php';
?>
<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.6rem;margin-bottom:1.4rem">
  <div>
    <h2 style="margin:0;font-size:1.25rem">Scan report</h2>
    <div style="font-size:12.5px;color:var(--txt-faint);margin-top:2px">
      Uploaded <?= htmlspecialchars(date('Y-m-d H:i', strtotime($rec['uploaded_at']))) ?>
    </div>
  </div>
  <div style="display:flex;flex-wrap:wrap;gap:.5rem">
    <a href="view_report.php?id=<?= $fileId ?>&dl=txt"
       class="btn btn-sm btn-cloudie-outline" title="Download plain-text report">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none"><path d="M12 16V4M8 12l4 4 4-4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M5 20h14" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
      .txt
    </a>
    <a href="view_report.php?id=<?= $fileId ?>&dl=json"
       class="btn btn-sm btn-cloudie-outline" title="Download raw JSON report">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none"><path d="M12 16V4M8 12l4 4 4-4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M5 20h14" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
      .json
    </a>
    <a href="dashboard.php" class="btn btn-sm btn-cloudie">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none"><path d="M19 12H5M5 12l7-7M5 12l7 7" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
      My files
    </a>
  </div>
</div>

<?php
require_once __DIR__ . '/includes/scan_report.php';
require_once __DIR__ . '/includes/footer.php';

/**
 * Build a plain-text version of the report for download.
 */
function build_text_report(array $rec, array $report): string {
    $ai  = $report['ai']         ?? [];
    $vt  = $report['virustotal'] ?? [];
    $cmb = $report['combined']   ?? [];

    $nl   = "\r\n";
    $line = str_repeat('=', 56) . $nl;

    $out  = $line;
    $out .= 'CLOUDIE — AI MALWARE SCAN REPORT' . $nl;
    $out .= $line;
    $out .= 'File name   : ' . ($rec['file_name'] ?? '-') . $nl;
    $out .= 'File type   : ' . ($rec['file_type'] ?? '-') . $nl;
    $out .= 'File size   : ' . number_format((int)($rec['file_size'] ?? 0)) . ' bytes' . $nl;
    $out .= 'Uploaded at : ' . ($rec['uploaded_at'] ?? '-') . $nl;
    $out .= 'MD5         : ' . ($report['file_md5'] ?? $rec['file_md5'] ?? '-') . $nl;
    $out .= 'SHA-256     : ' . ($report['file_sha256'] ?? '-') . $nl;
    $out .= $nl;

    $out .= 'FINAL VERDICT : ' . strtoupper($report['verdict'] ?? 'unknown') . $nl;
    if (!empty($cmb['reason'])) {
        $out .= 'Reason        : ' . $cmb['reason'] . $nl;
    }
    $out .= $nl;

    $out .= '-- AI MALWARE ANALYZER --' . $nl;
    $out .= 'Verdict               : ' . strtoupper($ai['verdict'] ?? ($report['verdict'] ?? '-')) . $nl;
    $pm = $ai['probability_malicious'] ?? $report['probability_malicious'] ?? null;
    if (is_numeric($pm)) {
        $pmPct = ((float)$pm <= 1 ? (float)$pm * 100 : (float)$pm);
        $out .= 'Probability malicious : ' . number_format($pmPct, 2) . '%' . $nl;
    }
    $out .= 'Engine                : ' . ($ai['engine'] ?? $report['engine'] ?? 'Random Forest') . $nl;
    $out .= $nl;

    $out .= '-- VIRUSTOTAL --' . $nl;
    if (!empty($vt['available'])) {
        $out .= 'Verdict     : ' . strtoupper($vt['verdict'] ?? '-') . $nl;
        $out .= 'Malicious   : ' . (int)($vt['malicious']   ?? 0) . $nl;
        $out .= 'Suspicious  : ' . (int)($vt['suspicious']  ?? 0) . $nl;
        $out .= 'Harmless    : ' . (int)($vt['harmless']    ?? 0) . $nl;
        $out .= 'Total engines: ' . (int)($vt['total']      ?? 0) . $nl;
    } else {
        $out .= ($vt['note'] ?? 'No VirusTotal data available.') . $nl;
    }
    $out .= $nl;

    $inds = $report['indicators'] ?? [];
    $out .= '-- SUSPICIOUS CAPABILITIES (' . count($inds) . ') --' . $nl;
    if ($inds) {
        foreach ($inds as $ind) {
            if (is_array($ind)) {
                $out .= '  - ' . ($ind['name'] ?? '?')
                      . ': ' . ($ind['description'] ?? '') . $nl;
            } else {
                $out .= '  - ' . $ind . $nl;
            }
        }
    } else {
        $out .= '  None detected.' . $nl;
    }
    $out .= $nl . $line;
    $out .= 'Generated by Cloudie on ' . date('Y-m-d H:i:s') . $nl;

    return $out;
}