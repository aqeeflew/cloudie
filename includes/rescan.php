<?php
/**
 * includes/rescan.php
 * -------------------
 * Retroactive re-check: asks VirusTotal what it says TODAY about a file that was
 * clean when it was stored. Only the hash recorded at upload is sent, so this works
 * without the AES key and the file is never decrypted.
 *
 * The result lives in files.recheck_* and never overwrites files.verdict or
 * files.scan_report: the upload result stays on record, and a later clean result
 * lifts a flag (a false alarm is reversible). The page verdict is the worse of the two.
 */
require_once __DIR__ . '/scanner.php';

const RESCAN_STALE_HOURS = 24;

function rescan_rank(string $verdict): int {
    return ['clean' => 0, 'suspicious' => 1, 'malicious' => 2][$verdict] ?? 0;
}

/** Verdict recorded at upload; older rows have only is_clean. */
function rescan_upload_verdict(array $row): string {
    $v = strtolower((string)($row['verdict'] ?? ''));
    if (in_array($v, ['clean', 'suspicious'], true)) return $v;
    return ((int)($row['is_clean'] ?? 1) === 1) ? 'clean' : 'suspicious';
}

/** What the user sees: the worse of the upload verdict and the latest re-check. */
function rescan_effective(array $row): string {
    $up = rescan_upload_verdict($row);
    $re = strtolower((string)($row['recheck_verdict'] ?? ''));
    return rescan_rank($re) > rescan_rank($up) ? $re : $up;
}

/** True when a re-check found something the upload scan did not. */
function rescan_flagged_later(array $row): bool {
    return rescan_rank(rescan_effective($row)) > rescan_rank(rescan_upload_verdict($row));
}

/** A malicious re-check quarantines the file: no inline view, download only after a warning. */
function rescan_quarantined(array $row): bool {
    return rescan_effective($row) === 'malicious';
}

/** Hash to look up: SHA-256 from the stored report, else the MD5 of older rows. '' if neither. */
function rescan_hash(?string $scan_report, ?string $file_md5): string {
    $report = json_decode((string)$scan_report, true);
    $sha = is_array($report) ? strtolower((string)($report['file_sha256'] ?? '')) : '';
    if (preg_match('/\A[0-9a-f]{64}\z/', $sha)) return $sha;
    $md5 = strtolower((string)$file_md5);
    return preg_match('/\A[0-9a-f]{32}\z/', $md5) ? $md5 : '';
}

/** Flask /vt_lookup URL, next to the /scan URL. */
function rescan_lookup_url(): string {
    return preg_replace('~/(scan|analyze)$~', '', SCANNER_URL) . '/vt_lookup';
}

/** Ask Flask about one hash. Returns its JSON, or status=error when there is no usable answer. */
function rescan_lookup(string $hash): array {
    $url  = rescan_lookup_url();
    $auth = scanner_auth_headers($url);
    if (!$auth['ok']) return ['status' => 'error', 'reason' => 'unavailable'];

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => json_encode(['hash' => $hash]),
        CURLOPT_HTTPHEADER     => array_merge(['Content-Type: application/json'], $auth['headers']),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 45,    // Flask: lookup + optional reanalysis request, 20 s each
        CURLOPT_CONNECTTIMEOUT => 10,
    ]);
    $body = curl_exec($ch);
    curl_close($ch);

    $json = is_string($body) ? json_decode($body, true) : null;
    if (!is_array($json) || !in_array($json['status'] ?? '', ['ok', 'unknown', 'error'], true)) {
        return ['status' => 'error', 'reason' => 'unavailable'];
    }
    return $json;
}

/**
 * Re-check one file row (file_id, verdict, is_clean, file_md5, scan_report, recheck_verdict)
 * and store the answer. status=error and status=unknown leave the recorded verdict as it is:
 * no answer is never read as clean. Returns ['status', 'changed', 'row', 'reason'].
 */
function rescan_file(int $user_id, array $row, bool $manual): array {
    $hash = rescan_hash($row['scan_report'] ?? null, $row['file_md5'] ?? null);
    if ($hash === '') return ['status' => 'error', 'reason' => 'no_hash', 'changed' => false, 'row' => $row];

    $res = rescan_lookup($hash);
    if ($res['status'] === 'error') {
        return ['status' => 'error', 'reason' => (string)($res['reason'] ?? 'unavailable'),
                'changed' => false, 'row' => $row];
    }

    $file_id = (int)$row['file_id'];
    if ($res['status'] === 'unknown') {
        db()->prepare("UPDATE files SET recheck_at = NOW() WHERE file_id = ? AND user_id = ?")
            ->execute([$file_id, $user_id]);
        if ($manual) log_action($user_id, 'RESCAN', $file_id, null, 'VirusTotal does not know this hash');
        return ['status' => 'unknown', 'reason' => '', 'changed' => false, 'row' => $row];
    }

    $before  = rescan_effective($row);
    $verdict = in_array($res['verdict'] ?? '', ['clean', 'suspicious', 'malicious'], true)
             ? $res['verdict'] : 'clean';
    $hits    = (int)($res['positives'] ?? 0);
    $total   = (int)($res['total'] ?? 0);
    $last    = (int)($res['last_analysis'] ?? 0);

    db()->prepare(
        "UPDATE files SET recheck_at = NOW(), recheck_verdict = ?, recheck_hits = ?, recheck_total = ?,
                          recheck_analysed_at = ?
         WHERE file_id = ? AND user_id = ?")
       ->execute([$verdict, $hits, $total, $last > 0 ? gmdate('Y-m-d H:i:s', $last) : null, $file_id, $user_id]);

    $row['recheck_verdict'] = $verdict;
    $row['recheck_hits']    = $hits;
    $row['recheck_total']   = $total;
    $after   = rescan_effective($row);
    $changed = $after !== $before;
    $worse   = rescan_rank($after) > rescan_rank($before);
    $details = "VirusTotal $hits/$total; verdict $before -> $after";
    if ($changed) {
        log_action($user_id, $worse ? 'RESCAN_FLAGGED' : 'RESCAN_CLEARED', $file_id, null, $details);
    } elseif ($manual) {
        log_action($user_id, 'RESCAN', $file_id, null, $details);
    }
    return ['status' => 'ok', 'reason' => '', 'changed' => $changed, 'worse' => $worse, 'row' => $row];
}
