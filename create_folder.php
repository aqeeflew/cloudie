<?php
require_once __DIR__ . '/includes/auth.php';
require_login();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: dashboard.php'); exit;
}
if (!verify_csrf($_POST['csrf'] ?? '')) {
    flash_set('error', 'Invalid request. Please try again.');
    header('Location: dashboard.php'); exit;
}

$name  = trim($_POST['folder_name'] ?? '');
$valid = ['cyan','violet','green','amber','red'];
$color = in_array($_POST['color'] ?? '', $valid, true) ? $_POST['color'] : 'cyan';

if ($name === '' || mb_strlen($name) > 100) {
    flash_set('error', 'Folder name must be 1–100 characters.');
    header('Location: dashboard.php'); exit;
}

$user = current_user();
try {
    $stmt = db()->prepare("INSERT INTO folders (user_id, folder_name, color) VALUES (?,?,?)");
    $stmt->execute([$user['user_id'], $name, $color]);
    header('Location: folder.php?id=' . (int)db()->lastInsertId()); exit;
} catch (Throwable $e) {
    flash_set('error', 'Could not create folder.');
    header('Location: dashboard.php'); exit;
}
