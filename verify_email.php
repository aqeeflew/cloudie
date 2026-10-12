<?php
/**
 * verify_email.php
 * ----------------
 * Confirms a new account's email address. The link arrives by email as
 *   verify_email.php?uid=<user_id>&token=<verify_token>
 *
 * On success the account is marked verified and the welcome email is sent.
 * Tokens are single-use: they are cleared as soon as verification succeeds.
 */

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/mailer.php';

db_ensure_auth();

$uid   = (int)($_GET['uid'] ?? 0);
$token = trim($_GET['token'] ?? '');

$state = 'invalid';   // invalid | already | success

if ($uid > 0 && $token !== '') {
    $stmt = db()->prepare(
        "SELECT a.auth_id, a.email_verified, a.verify_token,
                u.username, u.email
         FROM authentication a
         INNER JOIN users u ON u.user_id = a.user_id
         WHERE a.user_id = ?
         LIMIT 1");
    $stmt->execute([$uid]);
    $row = $stmt->fetch();

    if ($row) {
        if ((int)$row['email_verified'] === 1) {
            $state = 'already';
        } elseif (!empty($row['verify_token'])
                  && hash_equals($row['verify_token'], $token)) {
            db()->prepare(
                "UPDATE authentication
                    SET email_verified = 1, verify_token = NULL
                  WHERE user_id = ?")->execute([$uid]);
            log_action($uid, 'VERIFY_EMAIL', null, null, 'Email address confirmed');
            send_welcome_email((string)$row['email'], (string)$row['username']);
            $state = 'success';
        }
    }
}

$pageTitle = 'Verify email';
require_once __DIR__ . '/includes/header.php';
?>
<div class="row justify-content-center">
  <div class="col-lg-6">
    <div class="cl-card text-center" style="padding:40px 32px">

      <?php if ($state === 'success'): ?>
        <div style="width:60px;height:60px;border-radius:16px;margin:0 auto 18px;
                    display:grid;place-items:center;background:rgba(52,224,161,.14);color:var(--green)">
          <svg viewBox="0 0 24 24" width="30" height="30" fill="none"><path d="M5 13l4 4L19 7" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>
        </div>
        <h2>Email verified</h2>
        <p class="text-muted">Your address is confirmed. You can now log in to your vault.</p>
        <a href="login.php" class="btn btn-cloudie mt-3">Log in</a>

      <?php elseif ($state === 'already'): ?>
        <div style="width:60px;height:60px;border-radius:16px;margin:0 auto 18px;
                    display:grid;place-items:center;background:rgba(39,211,224,.13);color:var(--cyan)">
          <svg viewBox="0 0 24 24" width="30" height="30" fill="none"><path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M9 12l2 2 4-4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
        </div>
        <h2>Already verified</h2>
        <p class="text-muted">This email address was already confirmed — just log in.</p>
        <a href="login.php" class="btn btn-cloudie mt-3">Log in</a>

      <?php else: ?>
        <div style="width:60px;height:60px;border-radius:16px;margin:0 auto 18px;
                    display:grid;place-items:center;background:rgba(255,93,108,.13);color:var(--red)">
          <svg viewBox="0 0 24 24" width="30" height="30" fill="none"><path d="M12 3l9 16H3z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M12 9v4m0 3h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
        </div>
        <h2>Invalid verification link</h2>
        <p class="text-muted">
          This link is invalid or has already been used. Try logging in — if your
          email still needs verification, you can request a new link there.
        </p>
        <a href="login.php" class="btn btn-cloudie-outline mt-3">Back to log in</a>
      <?php endif; ?>

    </div>
  </div>
</div>
<?php require_once __DIR__ . '/includes/footer.php'; ?>
