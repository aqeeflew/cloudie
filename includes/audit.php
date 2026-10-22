<?php
/**
 * includes/audit.php
 * ------------------
 * Tamper-evident audit trail (hash chain sealed with HMAC).
 *
 * Every row of `actions` is linked to the previous row of the same user:
 *
 *     row_hash = HMAC-SHA256(secret, canonical(prev_hash, user, type, file, key, details, time))
 *
 * so editing a row, deleting one from the middle, inserting one, or reordering them breaks the chain.
 * A per-user "head" (`audit_heads`: sequence number, last hash, and an HMAC over both) also catches
 * deletion of the most recent rows.
 *
 * What it does NOT protect against: someone who has BOTH database write access AND the server secret
 * (AUDIT_HMAC_KEY from Secret Manager) can rewrite history. Without the secret, the database alone
 * is not enough to forge entries.
 *
 * Rows written before this feature existed (row_hash NULL) are "legacy": shown, not sealed.
 */

require_once __DIR__ . '/config.php';

const AUDIT_GENESIS = '0000000000000000000000000000000000000000000000000000000000000000';

/** Secret used to seal the chain. Production: AUDIT_HMAC_KEY from Secret Manager. */
function audit_key(): string {
    $k = defined('AUDIT_HMAC_KEY') ? AUDIT_HMAC_KEY : '';
    return $k !== '' ? $k : 'cloudie-local-dev-audit-key';
}

/** True when a real secret is configured (not the local development fallback). */
function audit_keyed(): bool {
    return defined('AUDIT_HMAC_KEY') && AUDIT_HMAC_KEY !== '';
}

/** Unambiguous encoding of the fields that are sealed. */
function audit_canonical(string $prev, int $user_id, string $type, ?int $file_ref, ?int $key_ref,
                         ?string $details, string $time): string {
    return json_encode([$prev, $user_id, $type, $file_ref, $key_ref, $details, $time],
                       JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
}

function audit_hash(string $prev, int $user_id, string $type, ?int $file_ref, ?int $key_ref,
                    ?string $details, string $time): string {
    return hash_hmac('sha256', audit_canonical($prev, $user_id, $type, $file_ref, $key_ref, $details, $time),
                     audit_key());
}

/** HMAC over the head state (user, sequence, last hash). */
function audit_head_mac(int $user_id, int $seq, string $head): string {
    return hash_hmac('sha256', json_encode(['head', $user_id, $seq, $head]), audit_key());
}

/**
 * Pure verification of one user's chain. $rows = that user's `actions` rows ordered by act_id,
 * $head = the `audit_heads` row or null. No database access, so it is unit-testable.
 *
 * Returns ['ok' => bool, 'sealed' => int, 'legacy' => int, 'head' => ?string,
 *          'problems' => [['act_id' => ?int, 'kind' => string, 'message' => string], ...]]
 */
function audit_verify_rows(int $user_id, array $rows, ?array $head): array {
    $problems = [];
    $legacy = 0;
    $sealed = 0;
    $prev = AUDIT_GENESIS;
    $expectedSeq = 1;
    $started = false;

    foreach ($rows as $r) {
        $id = (int)$r['act_id'];
        if (empty($r['row_hash'])) {
            if ($started) {
                $problems[] = ['act_id' => $id, 'kind' => 'unsealed',
                               'message' => 'An entry without a seal appears inside the sealed chain (inserted or its seal was removed).'];
            } else {
                $legacy++;
            }
            continue;
        }
        $started = true;
        $seq = (int)$r['chain_seq'];

        if ($seq !== $expectedSeq) {
            $problems[] = ['act_id' => $id, 'kind' => 'missing',
                           'message' => 'Sequence jumps from ' . ($expectedSeq - 1) . ' to ' . $seq
                                      . ': entries were removed or reordered before this one.'];
            $expectedSeq = $seq;
        }
        if (!hash_equals($prev, (string)$r['prev_hash'])) {
            $problems[] = ['act_id' => $id, 'kind' => 'link',
                           'message' => 'This entry is not linked to the one before it (chain broken).'];
        }
        $fileRef = ($r['file_ref'] === null || $r['file_ref'] === '') ? null : (int)$r['file_ref'];
        $keyRef  = ($r['key_ref']  === null || $r['key_ref']  === '') ? null : (int)$r['key_ref'];
        $calc = audit_hash((string)$r['prev_hash'], $user_id, (string)$r['act_type'], $fileRef, $keyRef,
                           $r['details'] === null ? null : (string)$r['details'], (string)$r['act_time']);
        if (!hash_equals($calc, (string)$r['row_hash'])) {
            $problems[] = ['act_id' => $id, 'kind' => 'edited',
                           'message' => 'The content of this entry does not match its seal (edited).'];
        }
        $prev = (string)$r['row_hash'];
        $expectedSeq = $seq + 1;
        $sealed++;
    }

    $lastSeq = $expectedSeq - 1;
    if ($head === null) {
        if ($sealed > 0) {
            $problems[] = ['act_id' => null, 'kind' => 'head',
                           'message' => 'The chain head record is missing.'];
        }
    } else {
        $hSeq = (int)$head['seq'];
        $okMac = hash_equals(audit_head_mac($user_id, $hSeq, (string)$head['head']), (string)$head['mac']);
        if (!$okMac) {
            $problems[] = ['act_id' => null, 'kind' => 'head',
                           'message' => 'The chain head record was altered.'];
        } elseif ($hSeq !== ($sealed > 0 ? $lastSeq : 0) || !hash_equals($sealed > 0 ? $prev : AUDIT_GENESIS, (string)$head['head'])) {
            $problems[] = ['act_id' => null, 'kind' => 'tail',
                           'message' => 'The most recent entries are missing: the chain ends at entry '
                                      . ($sealed > 0 ? $lastSeq : 0) . ' but the sealed head says ' . $hSeq . '.'];
        }
    }

    return ['ok' => !$problems, 'sealed' => $sealed, 'legacy' => $legacy,
            'head' => $sealed > 0 ? $prev : null, 'problems' => $problems];
}

/** Create the columns/table the first time (idempotent, cheap check first). */
function db_ensure_audit(): void {
    static $done = false;
    if ($done) return;
    $done = true;
    try {
        $has = db()->query("SHOW COLUMNS FROM actions LIKE 'row_hash'")->fetch();
        if (!$has) {
            try {
                db()->exec(
                    "ALTER TABLE actions
                       ADD COLUMN file_ref   INT      NULL,
                       ADD COLUMN key_ref    INT      NULL,
                       ADD COLUMN chain_seq  INT      NULL,
                       ADD COLUMN prev_hash  CHAR(64) NULL,
                       ADD COLUMN row_hash   CHAR(64) NULL,
                       ADD KEY idx_actions_chain (user_id, act_id)");
            } catch (PDOException $e) {
                if ((int)($e->errorInfo[1] ?? 0) !== 1060 && (int)($e->errorInfo[1] ?? 0) !== 1061) throw $e;
            }
        }
        db()->exec(
            "CREATE TABLE IF NOT EXISTS audit_heads (
                user_id INT       NOT NULL PRIMARY KEY,
                seq     INT       NOT NULL DEFAULT 0,
                head    CHAR(64)  NOT NULL,
                mac     CHAR(64)  NOT NULL,
                CONSTRAINT fk_audit_head_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
             ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
    } catch (Throwable $t) {
        error_log('db_ensure_audit: ' . $t->getMessage());
        throw $t;   // log_action() falls back to a plain insert
    }
}

/**
 * Append one sealed entry for the user. Throws on failure (log_action() handles the fallback).
 *
 * Concurrency: entries of one user must be appended one at a time (each needs the previous hash).
 * The head row is locked with SELECT ... FOR UPDATE. The head row is created OUTSIDE the transaction:
 * an INSERT IGNORE on an existing row takes a shared lock, and several transactions that then try to
 * upgrade it to an exclusive lock deadlock (found by a 25-process stress test). A deadlock is still
 * retried a few times as a safety net.
 */
function audit_append(int $user_id, string $type, ?int $file_id, ?int $key_id, ?string $details): void {
    db_ensure_audit();
    $pdo = db();

    // 1) make sure the head row exists (plain read first, so the common case takes no lock at all)
    $has = $pdo->prepare("SELECT 1 FROM audit_heads WHERE user_id = ?");
    $has->execute([$user_id]);
    if (!$has->fetchColumn()) {
        $pdo->prepare("INSERT IGNORE INTO audit_heads (user_id, seq, head, mac) VALUES (?,?,?,?)")
            ->execute([$user_id, 0, AUDIT_GENESIS, audit_head_mac($user_id, 0, AUDIT_GENESIS)]);
    }

    // 2) append under a row lock, retrying on deadlock / lock wait timeout
    $own = !$pdo->inTransaction();
    $attempts = $own ? 5 : 1;
    for ($try = 1; ; $try++) {
        if ($own) $pdo->beginTransaction();
        try {
            $st = $pdo->prepare("SELECT seq, head FROM audit_heads WHERE user_id = ? FOR UPDATE");
            $st->execute([$user_id]);
            $h = $st->fetch();
            if (!$h) throw new RuntimeException('audit head row is missing');

            $seq  = (int)$h['seq'] + 1;
            $prev = (string)$h['head'];
            $time = gmdate('Y-m-d H:i:s');
            $hash = audit_hash($prev, $user_id, $type, $file_id, $key_id, $details, $time);

            $pdo->prepare(
                "INSERT INTO actions (user_id, file_id, key_id, act_type, details, act_time,
                                      file_ref, key_ref, chain_seq, prev_hash, row_hash)
                 VALUES (?,?,?,?,?,?,?,?,?,?,?)"
            )->execute([$user_id, $file_id, $key_id, $type, $details, $time,
                        $file_id, $key_id, $seq, $prev, $hash]);

            $pdo->prepare("UPDATE audit_heads SET seq = ?, head = ?, mac = ? WHERE user_id = ?")
                ->execute([$seq, $hash, audit_head_mac($user_id, $seq, $hash), $user_id]);

            if ($own) $pdo->commit();
            return;
        } catch (Throwable $t) {
            if ($own && $pdo->inTransaction()) {
                try { $pdo->rollBack(); } catch (Throwable $ignored) {}
            }
            $code = ($t instanceof PDOException) ? (int)($t->errorInfo[1] ?? 0) : 0;
            if ($own && $try < $attempts && ($code === 1213 || $code === 1205)) {
                usleep(random_int(15000, 90000) * $try);   // back off, then try again
                continue;
            }
            throw $t;
        }
    }
}

/** Load and verify the chain of one user. */
function audit_verify(int $user_id): array {
    db_ensure_audit();
    $st = db()->prepare(
        "SELECT act_id, act_type, details, act_time, file_ref, key_ref, chain_seq, prev_hash, row_hash
           FROM actions WHERE user_id = ? ORDER BY act_id ASC");
    $st->execute([$user_id]);
    $rows = $st->fetchAll();
    $hs = db()->prepare("SELECT seq, head, mac FROM audit_heads WHERE user_id = ?");
    $hs->execute([$user_id]);
    $head = $hs->fetch() ?: null;
    $res = audit_verify_rows($user_id, $rows, $head);
    $res['rows'] = $rows;
    return $res;
}

/** Friendly names for the event codes. */
function audit_label(string $type): string {
    static $m = [
        'REGISTER' => 'Account created', 'VERIFY_EMAIL' => 'Email verified', 'LOGIN' => 'Signed in',
        'LOGOUT' => 'Signed out', 'SCAN' => 'File scanned', 'ENCRYPT' => 'File encrypted and stored',
        'VIEW' => 'File opened', 'DOWNLOAD' => 'File downloaded', 'DELETE' => 'File deleted',
        'DECRYPT_FAIL' => 'Wrong key entered', 'INTEGRITY_FAIL' => 'Integrity check failed',
        'PROFILE_UPDATE' => 'Profile updated', 'PASSWORD_CHANGE' => 'Password changed',
        'REPORT_DOWNLOAD' => 'Scan report downloaded',
    ];
    return $m[$type] ?? $type;
}
