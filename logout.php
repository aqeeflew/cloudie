<?php
require_once __DIR__ . '/includes/auth.php';

// Logout is a state change, so it needs POST + CSRF (a plain GET link or an
// <img src="logout.php"> on another site must not be able to log the user out).
if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !verify_csrf($_POST['csrf'] ?? null)) {
    header('Location: ' . (current_user() ? 'dashboard.php' : 'login.php'));
    exit;
}

if ($u = current_user()) {
    log_action($u['user_id'], 'LOGOUT');
}
$_SESSION = [];
if (ini_get('session.use_cookies')) {
    $p = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
              $p['path'], $p['domain'], $p['secure'], $p['httponly']);
}
session_destroy();
header('Location: login.php');
exit;
