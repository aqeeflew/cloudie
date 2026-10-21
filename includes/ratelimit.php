<?php
/**
 * includes/ratelimit.php
 * ----------------------
 * Small DB-backed rate limiter (sliding window).
 *
 * State lives in the `rate_limits` table, not in the PHP session: on Cloud Run
 * each instance has its own session files, so session counters could be
 * bypassed by simply hitting another instance.
 *
 *   rl_blocked($bucket, $key, $max, $windowSec)  -> [bool blocked, int retryAfterSec]
 *   rl_hit($bucket, $key)                        -> record one event
 *   rl_clear($bucket, $key)                      -> forget the events (e.g. after a successful login)
 *
 * Keys are hashed before they are stored, so no usernames, emails or IPs are
 * kept in clear text in this table.
 */

require_once __DIR__ . '/db.php';

/** Policies: bucket => [max events, window in seconds]. Change values here. */
const RL_POLICY = [
    'login_acct'  => [5, 900],     // failed passwords per account in 15 min
    'login_ip'    => [20, 900],    // failed passwords per IP in 15 min
    'otp_fail'    => [10, 3600],   // wrong OTP codes per account per hour (resend cannot reset this)
    'otp_send'    => [5, 3600],    // OTP emails per account per hour
    'verify_send' => [5, 3600],    // verification emails per IP per hour
    'register_ip' => [8, 3600],    // sign-up attempts per IP per hour
    'upload_user' => [10, 600],    // uploads (scans) per user per 10 min (protects the VirusTotal quota)
];

/** Create the table if it does not exist (idempotent, once per request). */
function db_ensure_ratelimit(): void {
    static $done = false;
    if ($done) return;
    $done = true;
    try {
        db()->exec(
            "CREATE TABLE IF NOT EXISTS rate_limits (
                id         BIGINT AUTO_INCREMENT PRIMARY KEY,
                bucket     VARCHAR(32)  NOT NULL,
                k          CHAR(64)     NOT NULL,
                created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
                KEY idx_rl (bucket, k, created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
        );
    } catch (Throwable $t) {
        error_log('db_ensure_ratelimit: ' . $t->getMessage());
    }
}

/**
 * Client IP. Behind Cloud Run the TCP peer is Google's front end (a private
 * address) and the real client is the LAST entry of X-Forwarded-For (earlier
 * entries can be forged by the client). A public REMOTE_ADDR is used as is.
 */
function client_ip(): string {
    $remote = $_SERVER['REMOTE_ADDR'] ?? '';
    $public = filter_var($remote, FILTER_VALIDATE_IP,
                         FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
    if ($public) return $remote;

    $xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
    if ($xff !== '') {
        $parts = array_map('trim', explode(',', $xff));
        $last  = end($parts);
        if (filter_var($last, FILTER_VALIDATE_IP) !== false) return $last;
    }
    return $remote !== '' ? $remote : '0.0.0.0';
}

function rl_key(string $raw): string {
    return hash('sha256', strtolower(trim($raw)));
}

/** Is this bucket/key over its limit? Returns [blocked, seconds until it frees up]. */
function rl_blocked(string $bucket, string $raw_key, ?int $max = null, ?int $window = null): array {
    [$pmax, $pwin] = RL_POLICY[$bucket];
    $max    = $max    ?? $pmax;
    $window = $window ?? $pwin;
    try {
        db_ensure_ratelimit();
        $st = db()->prepare(
            "SELECT COUNT(*) AS n,
                    TIMESTAMPDIFF(SECOND, NOW(), DATE_ADD(MIN(created_at), INTERVAL ? SECOND)) AS retry
               FROM rate_limits
              WHERE bucket = ? AND k = ?
                AND created_at > DATE_SUB(NOW(), INTERVAL ? SECOND)");
        $st->execute([$window, $bucket, rl_key($raw_key), $window]);
        $r = $st->fetch();
        if ((int)$r['n'] >= $max) {
            return [true, max(1, (int)$r['retry'])];
        }
    } catch (Throwable $t) {
        // If the limiter itself fails, do not lock everybody out; log it.
        error_log('rl_blocked: ' . $t->getMessage());
    }
    return [false, 0];
}

function rl_hit(string $bucket, string $raw_key): void {
    try {
        db_ensure_ratelimit();
        db()->prepare("INSERT INTO rate_limits (bucket, k) VALUES (?, ?)")
            ->execute([$bucket, rl_key($raw_key)]);
        if (random_int(1, 100) === 1) {   // occasional housekeeping
            db()->exec("DELETE FROM rate_limits WHERE created_at < DATE_SUB(NOW(), INTERVAL 1 DAY)");
        }
    } catch (Throwable $t) {
        error_log('rl_hit: ' . $t->getMessage());
    }
}

function rl_clear(string $bucket, string $raw_key): void {
    try {
        db_ensure_ratelimit();
        db()->prepare("DELETE FROM rate_limits WHERE bucket = ? AND k = ?")
            ->execute([$bucket, rl_key($raw_key)]);
    } catch (Throwable $t) {
        error_log('rl_clear: ' . $t->getMessage());
    }
}

/** "about 3 minutes" / "30 seconds" for user messages. */
function rl_wait_text(int $seconds): string {
    if ($seconds < 90) return $seconds . ' second' . ($seconds === 1 ? '' : 's');
    $m = (int)ceil($seconds / 60);
    return $m . ' minute' . ($m === 1 ? '' : 's');
}
