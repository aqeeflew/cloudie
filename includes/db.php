<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/audit.php';

function db(bool $fresh = false): PDO {
    static $pdo = null;
    if ($fresh) $pdo = null;   // drop a dead connection and reconnect
    if ($pdo === null) {
        // Build the DSN. On Cloud Run we connect to Cloud SQL over a Unix
        // socket whose path is injected as DB_HOST (e.g. /cloudsql/<conn>).
        // PDO needs "unix_socket=" for a socket path (NOT "host=", which makes
        // PDO attempt a DNS lookup). We follow Google's documented DSN format
        // exactly: dbname first, then unix_socket. Locally, DB_HOST is a normal
        // TCP host (127.0.0.1) and uses host=.
        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ];

        if (strlen(DB_HOST) > 0 && DB_HOST[0] === '/') {
            // Unix socket (Cloud SQL). Order matches Google's official sample:
            //   mysql:dbname=...;unix_socket=/cloudsql/<conn>
            $dsn = sprintf('mysql:dbname=%s;unix_socket=%s;charset=%s',
                           DB_NAME, DB_HOST, DB_CHARSET);
        } else {
            // TCP host (local XAMPP / direct IP)
            $dsn = sprintf('mysql:host=%s;dbname=%s;charset=%s',
                           DB_HOST, DB_NAME, DB_CHARSET);
        }

        $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
    }
    return $pdo;
}

/**
 * Idempotent: creates the folders table and the folder_id column on files
 * if they don't exist. Safe to call on every request.
 */
function db_ensure_folders(): void {
    static $done = false;
    if ($done) return;
    $done = true;
    try {
        db()->exec(
            "CREATE TABLE IF NOT EXISTS folders (
                folder_id   INT AUTO_INCREMENT PRIMARY KEY,
                user_id     INT NOT NULL,
                folder_name VARCHAR(100) NOT NULL,
                color       VARCHAR(20)  NOT NULL DEFAULT 'cyan',
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                KEY idx_folder_user (user_id),
                CONSTRAINT fk_folder_user
                    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
        );
        // Add folder_id to files — MySQL error 1060 means column already exists; ignore it
        try {
            db()->exec("ALTER TABLE files ADD COLUMN folder_id INT NULL DEFAULT NULL");
            db()->exec(
                "ALTER TABLE files ADD CONSTRAINT fk_file_folder
                 FOREIGN KEY (folder_id) REFERENCES folders(folder_id) ON DELETE SET NULL"
            );
        } catch (PDOException $e) {
            if ((int)($e->errorInfo[1] ?? 0) !== 1060) throw $e;
        }
        // Add verdict to files (clean|suspicious from the scan pipeline);
        // old rows stay NULL and fall back to is_clean in the UI
        try {
            db()->exec("ALTER TABLE files ADD COLUMN verdict VARCHAR(20) NULL DEFAULT NULL AFTER is_clean");
        } catch (PDOException $e) {
            if ((int)($e->errorInfo[1] ?? 0) !== 1060) throw $e;
        }
    } catch (Throwable $t) {
        error_log('db_ensure_folders: ' . $t->getMessage());
    }
}

/**
 * Idempotent: adds the email-verification and login-OTP columns to the
 * authentication table. Accounts that existed before this feature shipped
 * are grandfathered in as verified. Safe to call on every request.
 */
function db_ensure_auth(): void {
    static $done = false;
    if ($done) return;
    $done = true;
    try {
        try {
            db()->exec(
                "ALTER TABLE authentication
                   ADD COLUMN email_verified TINYINT(1)  NOT NULL DEFAULT 0,
                   ADD COLUMN verify_token   VARCHAR(64)  NULL,
                   ADD COLUMN otp_hash       VARCHAR(255) NULL,
                   ADD COLUMN otp_expires    DATETIME     NULL,
                   ADD COLUMN otp_attempts   TINYINT      NOT NULL DEFAULT 0"
            );
            // Columns were just created: keep pre-existing accounts usable.
            db()->exec("UPDATE authentication SET email_verified = 1");
        } catch (PDOException $e) {
            if ((int)($e->errorInfo[1] ?? 0) !== 1060) throw $e;  // 1060 = column exists
        }
    } catch (Throwable $t) {
        error_log('db_ensure_auth: ' . $t->getMessage());
    }
}

function log_action(int $user_id,
                    string $act_type,
                    ?int $file_id = null,
                    ?int $key_id  = null,
                    ?string $details = null): void {
    try {
        // Normal path: a sealed entry in the tamper-evident chain (includes/audit.php)
        audit_append($user_id, $act_type, $file_id, $key_id, $details);
        return;
    } catch (Throwable $e) {
        error_log('audit_append failed, falling back to a plain row: ' . $e->getMessage());
    }
    // Fallback: never lose the event (the verify page will show it as an unsealed entry)
    try {
        $stmt = db()->prepare(
            "INSERT INTO actions (user_id, file_id, key_id, act_type, details)
             VALUES (?,?,?,?,?)"
        );
        $stmt->execute([$user_id, $file_id, $key_id, $act_type, $details]);
    } catch (Throwable $e) {
        error_log('log_action failed: ' . $e->getMessage());
    }
}