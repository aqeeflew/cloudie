<?php
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/mailer.php';
require_once __DIR__ . '/includes/ratelimit.php';
require_once __DIR__ . '/includes/validate.php';

db_ensure_auth();

if (current_user()) { header('Location: dashboard.php'); exit; }

$pageTitle = 'Sign up';
$err = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf'] ?? null)) {
        $err = 'Invalid request.';
    } elseif (($rl = rl_blocked('register_ip', client_ip()))[0]) {
        $err = 'Too many sign-up attempts from your network. Please try again in '
             . rl_wait_text($rl[1]) . '.';
    } else {
        rl_hit('register_ip', client_ip());
        $username = trim($_POST['username'] ?? '');
        $email    = trim($_POST['email'] ?? '');
        $phone    = trim($_POST['phone']    ?? '');
        $pass     = $_POST['password']      ?? '';
        $confirm  = $_POST['confirm']       ?? '';

        if ($username === '' || $email === '' || $pass === '') {
            $err = 'Username, email and password are required.';
        } elseif (($m = validate_username($username)) !== null) {
            $err = $m;
        } elseif (($m = validate_email($email)) !== null) {
            $err = $m;
        } elseif (($m = validate_phone($phone)) !== null) {
            $err = $m;
        } elseif (($m = validate_password($pass, $username, $email)) !== null) {
            $err = $m;
        } elseif ($pass !== $confirm) {
            $err = 'Passwords do not match.';
        } else {
            try {
                $pdo = db();
                $pdo->beginTransaction();

                $stmt = $pdo->prepare(
                    "INSERT INTO users (username, password_hash, email, phone_num)
                     VALUES (?,?,?,?)");
                $stmt->execute([
                    $username,
                    password_hash($pass, PASSWORD_BCRYPT),
                    $email,
                    $phone ?: null,
                ]);
                $uid = (int)$pdo->lastInsertId();

                $verifyToken = bin2hex(random_bytes(32));
                $pdo->prepare(
                    "INSERT INTO authentication
                        (user_id, email, token, email_verified, verify_token)
                     VALUES (?,?,?,0,?)"
                )->execute([$uid, $email, bin2hex(random_bytes(16)), $verifyToken]);

                $pdo->commit();
                log_action($uid, 'REGISTER', null, null, 'Account created');

                // Email verification: send the confirm link. If mail is
                // disabled or fails (local XAMPP), auto-verify so the new
                // account is never locked out; the welcome email is sent
                // after verification instead.
                $link = app_url('verify_email.php?uid=' . $uid . '&token=' . $verifyToken);
                if (send_verification_email($email, $username, $link)) {
                    flash_set('success',
                        'Account created. We sent a verification link to '
                        . $email . ' — confirm it, then log in.');
                } else {
                    db()->prepare(
                        "UPDATE authentication
                            SET email_verified = 1, verify_token = NULL
                          WHERE user_id = ?")->execute([$uid]);
                    send_welcome_email($email, $username);
                    flash_set('success', 'Account created. You can log in now.');
                }
                header('Location: login.php'); exit;
            } catch (PDOException $e) {
                if (db()->inTransaction()) db()->rollBack();
                if ($e->getCode() === '23000') {
                    $err = 'That username or email is already taken.';
                } else {
                    error_log($e->getMessage());
                    $err = 'Could not create your account. Please try again.';
                }
            }
        }
    }
}

require_once __DIR__ . '/includes/header.php';
?>
<div class="auth-wrap">
  <div class="auth-card">

    <!-- Brand / value panel -->
    <aside class="auth-aside">
      <div class="auth-aside-glow"></div>
      <div class="auth-aside-inner">
        <div class="auth-badge">Create your account</div>
        <h2 class="auth-aside-title">Join<br>Cloudie.</h2>
        <p class="auth-aside-sub">
          Files are scanned (VirusTotal first, then structure checks, plus an AI analyzer for PDFs) and
          encrypted with AES-256. You receive the key; only its hash is stored.
        </p>
        <ul class="auth-points">
          <li>
            <svg viewBox="0 0 24 24" fill="none"><path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M9 12l2 2 4-4" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>
            VirusTotal + structure checks (+ AI for PDFs)
          </li>
          <li>
            <svg viewBox="0 0 24 24" fill="none"><path d="M6 10V8a6 6 0 0 1 12 0v2M5 10h14v10H5z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/></svg>
            AES-256-CBC encryption
          </li>
          <li>
            <svg viewBox="0 0 24 24" fill="none"><path d="M4 7h16M4 12h16M4 17h10" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>
            Per-file scan reports
          </li>
        </ul>
      </div>
    </aside>

    <!-- Form panel -->
    <div class="auth-form">
      <div class="auth-form-head">
        <h1>Sign up</h1>
        <p>It only takes a moment to get started.</p>
      </div>

      <?php if ($err): ?>
        <div class="alert alert-danger"><?= e($err) ?></div>
      <?php endif; ?>

      <form method="post">
        <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">

        <div class="field">
          <label for="regUser">Username</label>
          <div class="input-icon">
            <svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="8" r="3.6" stroke="currentColor" stroke-width="1.6"/><path d="M5 20a7 7 0 0 1 14 0" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>
            <input type="text" name="username" id="regUser" class="form-control" required
                   minlength="<?= USERNAME_MIN ?>" maxlength="<?= USERNAME_MAX ?>" autocomplete="username"
                   value="<?= e($_POST['username'] ?? '') ?>" placeholder="Pick a username">
          </div>
        </div>

        <div class="field">
          <label for="regEmail">Email</label>
          <div class="input-icon">
            <svg viewBox="0 0 24 24" fill="none"><rect x="3" y="5" width="18" height="14" rx="2.5" stroke="currentColor" stroke-width="1.6"/><path d="m4 7 8 6 8-6" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/></svg>
            <input type="email" name="email" id="regEmail" class="form-control" required
                   maxlength="<?= EMAIL_MAX ?>" autocomplete="email"
                   value="<?= e($_POST['email'] ?? '') ?>" placeholder="you@example.com">
          </div>
        </div>

        <div class="field">
          <label for="regPhone">Phone <span style="color:var(--txt-faint);font-weight:400">(optional)</span></label>
          <div class="input-icon">
            <svg viewBox="0 0 24 24" fill="none"><path d="M6 4h3l2 5-2.5 1.5a11 11 0 0 0 5 5L15 13l5 2v3a2 2 0 0 1-2 2A16 16 0 0 1 4 6a2 2 0 0 1 2-2z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/></svg>
            <input type="tel" name="phone" id="regPhone" class="form-control"
                   maxlength="20" autocomplete="tel"
                   value="<?= e($_POST['phone'] ?? '') ?>" placeholder="012-3456789">
          </div>
        </div>

        <div class="field-row">
          <div class="field" style="margin-bottom:0">
            <label for="pw">Password</label>
            <div class="input-icon">
              <svg viewBox="0 0 24 24" fill="none"><rect x="5" y="11" width="14" height="9" rx="2" stroke="currentColor" stroke-width="1.6"/><path d="M8 11V8a4 4 0 0 1 8 0v3" stroke="currentColor" stroke-width="1.6"/></svg>
              <input type="password" name="password" id="pw" class="form-control"
                     minlength="<?= PASSWORD_MIN ?>" maxlength="<?= PASSWORD_MAX ?>" autocomplete="new-password"
                     required placeholder="8+ characters">
              <button type="button" class="pw-toggle" data-target="pw" aria-label="Show password">
                <svg viewBox="0 0 24 24" fill="none"><path d="M2 12s3.6-6.5 10-6.5S22 12 22 12s-3.6 6.5-10 6.5S2 12 2 12z" stroke="currentColor" stroke-width="1.6"/><circle cx="12" cy="12" r="2.6" stroke="currentColor" stroke-width="1.6"/></svg>
              </button>
            </div>
          </div>
          <div class="field" style="margin-bottom:0">
            <label for="pw2">Confirm</label>
            <div class="input-icon">
              <svg viewBox="0 0 24 24" fill="none"><rect x="5" y="11" width="14" height="9" rx="2" stroke="currentColor" stroke-width="1.6"/><path d="M8 11V8a4 4 0 0 1 8 0v3" stroke="currentColor" stroke-width="1.6"/></svg>
              <input type="password" name="confirm" id="pw2" class="form-control"
                     minlength="<?= PASSWORD_MIN ?>" maxlength="<?= PASSWORD_MAX ?>" autocomplete="new-password"
                     required placeholder="Repeat">
              <button type="button" class="pw-toggle" data-target="pw2" aria-label="Show password">
                <svg viewBox="0 0 24 24" fill="none"><path d="M2 12s3.6-6.5 10-6.5S22 12 22 12s-3.6 6.5-10 6.5S2 12 2 12z" stroke="currentColor" stroke-width="1.6"/><circle cx="12" cy="12" r="2.6" stroke="currentColor" stroke-width="1.6"/></svg>
              </button>
            </div>
          </div>
        </div>

        <button type="submit" class="btn btn-cloudie w-100 auth-submit">Create account</button>
        <p style="font-size:12px;color:var(--txt-faint);margin:.9rem 0 0;line-height:1.5">
          Privacy: files are encrypted before they are stored. To scan a file, Cloudie checks its hash with VirusTotal first;
          a file VirusTotal has never seen is uploaded to VirusTotal for analysis. Avoid scanning highly sensitive files.
        </p>
      </form>

      <p class="auth-alt">Already have an account? <a href="login.php">Log in</a></p>
    </div>

  </div>
</div>

<?php require_once __DIR__ . '/includes/auth_ui.php'; ?>
<?php require_once __DIR__ . '/includes/footer.php'; ?>