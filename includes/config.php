<?php
// =============================================================
// Cloudie - Secure Cloud Storage with AI Malware Analyzer
// config.php
//
// Environment-portable: runs unchanged on XAMPP (local disk +
// hardcoded dev defaults) and on Cloud Run (Cloud Storage +
// secrets/settings injected as environment variables). Anything
// sensitive is read from getenv() first, falling back to a
// local-dev value so your XAMPP setup keeps working.
// =============================================================

// Tiny helper: env var with a fallback default.
function env_or(string $key, string $default): string {
    $v = getenv($key);
    return ($v === false || $v === '') ? $default : $v;
}

// ---- Database ----
// On Cloud Run we connect to Cloud SQL over its Unix socket:
//   /cloudsql/<INSTANCE_CONNECTION_NAME>
// Locally we keep 127.0.0.1. DB_HOST is taken from the env when present.
define('DB_HOST',    env_or('DB_HOST', '127.0.0.1'));
define('DB_NAME',    env_or('DB_NAME', 'cloudie_db'));
define('DB_USER',    env_or('DB_USER', 'root'));
define('DB_PASS',    env_or('DB_PASS', ''));
define('DB_CHARSET', 'utf8mb4');

// ---- Flask AI scanner endpoint ----
// In the cloud this becomes the cloudie-flask Cloud Run URL.
define('SCANNER_URL',     env_or('SCANNER_URL',    'http://127.0.0.1:5000/scan'));
define('SCANNER_HEALTH',  env_or('SCANNER_HEALTH', 'http://127.0.0.1:5000/health'));
define('SCANNER_TIMEOUT', 60);   // seconds

// ---- Cloud Storage ----
// USE_CLOUD_STORAGE=true makes encrypted blobs live in GCS_BUCKET.
// Leave it unset/false locally to use the disk path below.
define('USE_CLOUD_STORAGE', filter_var(
    env_or('USE_CLOUD_STORAGE', 'false'),
    FILTER_VALIDATE_BOOLEAN
));
define('GCP_PROJECT_ID', env_or('GCP_PROJECT_ID', 'cloudie-499914'));
define('GCS_BUCKET',     env_or('GCS_BUCKET',     'cloudie-499914-files'));

// ---- Email (Gmail SMTP via PHPMailer) ----
// MAIL_ENABLED gates the whole feature. Credentials come from the
// environment in the cloud (SMTP_PASS is injected from Secret Manager);
// locally you can set them here via the defaults if you ever want email
// on XAMPP. send_key_email() fails silently if anything is missing, so
// an unset password simply disables email without breaking uploads.
define('MAIL_ENABLED', filter_var(
    env_or('MAIL_ENABLED', 'false'),
    FILTER_VALIDATE_BOOLEAN
));
define('SMTP_HOST',      env_or('SMTP_HOST',      'smtp.gmail.com'));
define('SMTP_PORT', (int) env_or('SMTP_PORT',      '587'));
define('SMTP_SECURE',    env_or('SMTP_SECURE',    'tls'));   // 'tls' or 'ssl'
define('SMTP_USER',      env_or('SMTP_USER',      ''));       // your gmail address
define('SMTP_PASS',      env_or('SMTP_PASS',      ''));       // gmail App Password (from Secret Manager)
define('SMTP_FROM',      env_or('SMTP_FROM',      env_or('SMTP_USER', '')));
define('SMTP_FROM_NAME', env_or('SMTP_FROM_NAME', 'Cloudie'));

// ---- Storage paths (used when USE_CLOUD_STORAGE is false) ----
define('UPLOAD_DIR',    __DIR__ . '/../uploads/');     // raw temp uploads (deleted after scan)
define('ENCRYPTED_DIR', __DIR__ . '/../encrypted/');   // ciphertext blobs (local only)
define('KEY_DIR',       __DIR__ . '/../keys/');        // QR images (transient)

// ---- Crypto ----
define('AES_CIPHER',  'aes-256-cbc');
define('AES_KEY_LEN', 32);     // 32 bytes -> 256 bit
define('AES_IV_LEN',  16);

// ---- Limits ----
define('MAX_UPLOAD_BYTES', 50 * 1024 * 1024);     // 50 MB
define('STORAGE_QUOTA_BYTES',                      // per-user vault quota (sidebar meter)
       (int) env_or('STORAGE_QUOTA_BYTES', (string)(1024 * 1024 * 1024)));  // 1 GB
define('ALLOWED_EXT', ['pdf','doc','docx','xls','xlsx','ppt','pptx',
                       'txt','csv','png','jpg','jpeg','zip','rar']);

// ---- Login OTP (2FA) & email verification ----
// The OTP is emailed after a correct password; when MAIL_ENABLED is false
// (local XAMPP) the code is shown on screen instead so login still works.
define('OTP_TTL_MINUTES',    10);   // code validity window
define('OTP_MAX_ATTEMPTS',    5);   // wrong codes before restarting login
define('OTP_RESEND_SECONDS', 60);   // minimum gap between resends

// ---- Session ----
if (session_status() === PHP_SESSION_NONE) {
    // Harden the session cookie
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();
}

// ---- Make sure LOCAL storage dirs exist ----
// On Cloud Run the temp upload dir still needs to exist (cleartext is
// written there for one request during scanning), but the persistent
// encrypted/ and keys/ dirs are only used in local mode.
$dirs = USE_CLOUD_STORAGE ? [UPLOAD_DIR] : [UPLOAD_DIR, ENCRYPTED_DIR, KEY_DIR];
foreach ($dirs as $dir) {
    if (!is_dir($dir)) {
        @mkdir($dir, 0775, true);
    }
}

// ---- Error reporting (disable display in production) ----
$displayErrors = env_or('DISPLAY_ERRORS', '1');
ini_set('display_errors', $displayErrors);
ini_set('log_errors', '1');
error_reporting(E_ALL);