<?php
require_once __DIR__ . '/db.php';

/**
 * Theme toggle (?theme=dark|light). Runs here, before any page logic, so pages
 * that redirect early (folder, view_report, decrypt) still honour it. Keeps the
 * rest of the query string (e.g. ?id=3) and only ever redirects to the same
 * script by relative name.
 */
function cl_apply_theme_param(): void {
    if ($_SERVER['REQUEST_METHOD'] !== 'GET'
        || !isset($_GET['theme'])
        || !in_array($_GET['theme'], ['dark', 'light'], true)) {
        return;
    }
    setcookie('cloudie_theme', $_GET['theme'], time() + 60 * 60 * 24 * 365, '/');
    $rest = $_GET;
    unset($rest['theme']);
    $qs = http_build_query($rest);
    header('Location: ' . basename($_SERVER['SCRIPT_NAME']) . ($qs !== '' ? '?' . $qs : ''));
    exit;
}
cl_apply_theme_param();

function current_user(): ?array {
    if (empty($_SESSION['user_id'])) return null;
    static $cached = null;
    if ($cached !== null) return $cached;
    $stmt = db()->prepare("SELECT user_id, username, email, phone_num
                           FROM users WHERE user_id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $cached = $stmt->fetch() ?: null;
    return $cached;
}

function require_login(): void {
    if (!current_user()) {
        header('Location: login.php');
        exit;
    }
    db_ensure_folders();
}

function flash_set(string $key, string $msg): void {
    $_SESSION['_flash'][$key] = $msg;
}

function flash_get(string $key): ?string {
    if (empty($_SESSION['_flash'][$key])) return null;
    $msg = $_SESSION['_flash'][$key];
    unset($_SESSION['_flash'][$key]);
    return $msg;
}

function csrf_token(): string {
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function verify_csrf(?string $token): bool {
    return !empty($token)
        && !empty($_SESSION['csrf'])
        && hash_equals($_SESSION['csrf'], $token);
}

function e(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/** Absolute URL to a file in the app root (for links inside emails). */
function app_url(string $path = ''): string {
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host   = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $dir    = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/')), '/');
    return $scheme . '://' . $host . $dir . '/' . ltrim($path, '/');
}
