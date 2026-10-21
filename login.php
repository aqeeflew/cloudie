<?php
/**
 * login.php — two-step login:
 *   Stage 1  username/email + password  (rejected if email not verified)
 *   Stage 2  6-digit OTP emailed to the account (expires, limited attempts)
 *
 * When MAIL_ENABLED is false (local XAMPP) the OTP cannot be emailed, so it
 * is displayed on screen with a dev-mode notice — login never locks out.
 */
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/mailer.php';
require_once __DIR__ . '/includes/ratelimit.php';

db_ensure_auth();

if (current_user()) { header('Location: dashboard.php'); exit; }

$pageTitle = 'Log in';
$err   = null;
$info  = null;
$stage = 'credentials';        // credentials | otp
$devOtp = null;                // code shown on screen when email is unavailable
$otpEmailMasked   = '';
$showResendVerify = false;

/** a••• @domain — enough to recognise the address without exposing it */
function mask_email(string $e): string {
    $at = strpos($e, '@');
    if ($at === false || $at === 0) return $e;
    return substr($e, 0, 1) . '•••' . substr($e, $at);
}

/**
 * Store a fresh hashed OTP for the user and try to email it.
 * Returns [bool $emailSent, string $code].
 */
function otp_issue(int $uid, string $email, string $username): array {
    $code = str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    db()->prepare(
        "UPDATE authentication
            SET otp_hash = ?,
                otp_expires = DATE_ADD(NOW(), INTERVAL " . (int)OTP_TTL_MINUTES . " MINUTE),
                otp_attempts = 0
          WHERE user_id = ?"
    )->execute([password_hash($code, PASSWORD_DEFAULT), $uid]);
    $_SESSION['otp_last_sent'] = time();
    rl_hit('otp_send', (string)$uid);
    return [send_otp_email($email, $username, $code), $code];
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    // fresh visit: drop any half-finished OTP login
    unset($_SESSION['otp_uid'], $_SESSION['otp_last_sent']);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf'] ?? null)) {
        $err = 'Invalid request.';
    } else {
        $action = $_POST['action'] ?? 'credentials';

        // ------------------------------------------------------------
        // Stage 2: check the submitted OTP
        // ------------------------------------------------------------
        if ($action === 'verify_otp') {
            $uid = (int)($_SESSION['otp_uid'] ?? 0);
            [$otpLocked, $otpWait] = $uid > 0 ? rl_blocked('otp_fail', (string)$uid) : [false, 0];
            if ($uid <= 0) {
                $err = 'Your session expired — please log in again.';
            } elseif ($otpLocked) {
                unset($_SESSION['otp_uid']);
                $err = 'Too many incorrect codes. Please try again in ' . rl_wait_text($otpWait) . '.';
            } else {
                $stmt = db()->prepare(
                    "SELECT a.otp_hash, a.otp_attempts,
                            (a.otp_expires IS NULL OR a.otp_expires < NOW()) AS expired,
                            u.username, u.email
                     FROM authentication a
                     INNER JOIN users u ON u.user_id = a.user_id
                     WHERE a.user_id = ? LIMIT 1");
                $stmt->execute([$uid]);
                $a = $stmt->fetch();
                $code = preg_replace('/\D/', '', $_POST['otp'] ?? '');

                if (!$a || empty($a['otp_hash']) || (int)$a['expired'] === 1) {
                    unset($_SESSION['otp_uid']);
                    $err = 'That code has expired — please log in again.';
                } elseif ((int)$a['otp_attempts'] >= OTP_MAX_ATTEMPTS) {
                    unset($_SESSION['otp_uid']);
                    $err = 'Too many incorrect codes — please log in again.';
                } elseif ($code !== '' && password_verify($code, $a['otp_hash'])) {
                    db()->prepare(
                        "UPDATE authentication
                            SET otp_hash = NULL, otp_expires = NULL, otp_attempts = 0,
                                last_login = NOW(), token = ?
                          WHERE user_id = ?")
                       ->execute([bin2hex(random_bytes(16)), $uid]);
                    unset($_SESSION['otp_uid'], $_SESSION['otp_last_sent']);
                    rl_clear('otp_fail', (string)$uid);
                    session_regenerate_id(true);
                    $_SESSION['user_id'] = $uid;
                    log_action($uid, 'LOGIN', null, null, 'password + OTP');
                    header('Location: dashboard.php'); exit;
                } else {
                    rl_hit('otp_fail', (string)$uid);
                    db()->prepare(
                        "UPDATE authentication SET otp_attempts = otp_attempts + 1
                          WHERE user_id = ?")->execute([$uid]);
                    $left = OTP_MAX_ATTEMPTS - ((int)$a['otp_attempts'] + 1);
                    if ($left <= 0) {
                        unset($_SESSION['otp_uid']);
                        $err = 'Too many incorrect codes — please log in again.';
                    } else {
                        $err = 'Incorrect code. ' . $left . ' attempt' . ($left === 1 ? '' : 's') . ' left.';
                        $stage = 'otp';
                        $otpEmailMasked = mask_email((string)$a['email']);
                    }
                }
            }

        // ------------------------------------------------------------
        // Stage 2: resend the OTP
        // ------------------------------------------------------------
        } elseif ($action === 'resend_otp') {
            $uid = (int)($_SESSION['otp_uid'] ?? 0);
            if ($uid <= 0) {
                $err = 'Your session expired — please log in again.';
            } else {
                $stmt = db()->prepare(
                    "SELECT username, email FROM users WHERE user_id = ? LIMIT 1");
                $stmt->execute([$uid]);
                $u = $stmt->fetch();
                if (!$u) {
                    unset($_SESSION['otp_uid']);
                    $err = 'Your session expired — please log in again.';
                } elseif (($rl = rl_blocked('otp_send', (string)$uid))[0]) {
                    $stage = 'otp';
                    $otpEmailMasked = mask_email((string)$u['email']);
                    $err = 'Too many codes requested. Please try again in ' . rl_wait_text($rl[1]) . '.';
                } elseif (time() - (int)($_SESSION['otp_last_sent'] ?? 0) < OTP_RESEND_SECONDS) {
                    $stage = 'otp';
                    $otpEmailMasked = mask_email((string)$u['email']);
                    $err = 'Please wait a moment before requesting another code.';
                } else {
                    [$sent, $code] = otp_issue($uid, (string)$u['email'], (string)$u['username']);
                    $stage = 'otp';
                    $otpEmailMasked = mask_email((string)$u['email']);
                    if ($sent) {
                        $info = 'A new code has been issued.';
                    } elseif (!MAIL_ENABLED) {
                        $info = 'A new code has been issued.';
                        $devOtp = $code;          // local dev only: email is switched off
                    } else {
                        // email is ON but delivery failed: fail closed, never reveal the code
                        $err = 'We could not email your code. Please try "Resend code" again in a minute.';
                    }
                }
            }

        // ------------------------------------------------------------
        // Resend the email-verification link (account not yet verified)
        // ------------------------------------------------------------
        } elseif ($action === 'resend_verify') {
            $login = trim($_POST['login'] ?? '');
            [$vLocked] = rl_blocked('verify_send', client_ip());
            if ($login !== '' && !$vLocked) {
                rl_hit('verify_send', client_ip());
                $stmt = db()->prepare(
                    "SELECT u.user_id, u.username, u.email, a.email_verified
                     FROM users u
                     INNER JOIN authentication a ON a.user_id = u.user_id
                     WHERE u.username = ? OR u.email = ?
                     LIMIT 1");
                $stmt->execute([$login, $login]);
                $u = $stmt->fetch();
                if ($u && (int)$u['email_verified'] !== 1) {
                    $vt = bin2hex(random_bytes(32));
                    db()->prepare(
                        "UPDATE authentication SET verify_token = ? WHERE user_id = ?")
                       ->execute([$vt, (int)$u['user_id']]);
                    send_verification_email(
                        (string)$u['email'], (string)$u['username'],
                        app_url('verify_email.php?uid=' . (int)$u['user_id'] . '&token=' . $vt));
                }
            }
            // neutral response either way — don't reveal whether the account exists
            $info = 'If that account exists and is unverified, a new verification link has been sent.';

        // ------------------------------------------------------------
        // Stage 1: username/email + password
        // ------------------------------------------------------------
        } else {
            $login = trim($_POST['login'] ?? '');
            $pass  = $_POST['password']    ?? '';

            // Brute-force protection: too many recent failures for this account or this IP
            [$lockAcct, $waitAcct] = rl_blocked('login_acct', $login);
            [$lockIp,   $waitIp]   = rl_blocked('login_ip', client_ip());
            if ($lockAcct || $lockIp) {
                $err = 'Too many failed attempts. Please try again in '
                     . rl_wait_text(max($waitAcct, $waitIp)) . '.';
                error_log('rate_limit: login blocked (acct=' . ($lockAcct ? 'y' : 'n') . ', ip=' . ($lockIp ? 'y' : 'n') . ')');
            } else {
            $stmt = db()->prepare(
                "SELECT u.user_id, u.username, u.email, u.password_hash,
                        a.email_verified
                 FROM users u
                 LEFT JOIN authentication a ON a.user_id = u.user_id
                 WHERE u.username = ? OR u.email = ?
                 LIMIT 1");
            $stmt->execute([$login, $login]);
            $row = $stmt->fetch();

            if ($row && password_verify($pass, $row['password_hash'])) {
                rl_clear('login_acct', $login);
                // accounts older than the authentication table: create the row
                if ($row['email_verified'] === null) {
                    db()->prepare(
                        "INSERT INTO authentication (user_id, email, token, email_verified)
                         VALUES (?,?,?,1)")
                       ->execute([(int)$row['user_id'], $row['email'],
                                  bin2hex(random_bytes(16))]);
                    $row['email_verified'] = 1;
                }

                if ((int)$row['email_verified'] !== 1) {
                    $err = 'Please verify your email address first — check your inbox for the link.';
                    $showResendVerify = true;
                } elseif (($rlOtp = rl_blocked('otp_send', (string)$row['user_id']))[0]) {
                    $err = 'Too many codes requested. Please try again in ' . rl_wait_text($rlOtp[1]) . '.';
                } else {
                    $_SESSION['otp_uid'] = (int)$row['user_id'];
                    [$sent, $code] = otp_issue((int)$row['user_id'],
                                               (string)$row['email'],
                                               (string)$row['username']);
                    $stage = 'otp';
                    $otpEmailMasked = mask_email((string)$row['email']);
                    if (!$sent) {
                        if (!MAIL_ENABLED) {
                            $devOtp = $code;      // local dev only: email is switched off
                        } else {
                            // email is ON but delivery failed: fail closed, never reveal the code
                            $err = 'We could not email your code. Please try "Resend code" again in a minute.';
                        }
                    }
                }
            } else {
                rl_hit('login_acct', $login);
                rl_hit('login_ip', client_ip());
                $err = 'Invalid credentials.';
            }
            }   // end: not rate-limited
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
        <div class="auth-badge">Secure cloud storage</div>
        <h2 class="auth-aside-title">Welcome<br>back.</h2>
        <p class="auth-aside-sub">
          Your files are scanned, encrypted with AES-256, and locked behind a
          key issued to you.
        </p>
        <ul class="auth-points">
          <li>
            <svg viewBox="0 0 24 24" fill="none"><path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M9 12l2 2 4-4" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>
            VirusTotal scan + AI analysis for PDFs
          </li>
          <li>
            <svg viewBox="0 0 24 24" fill="none"><path d="M6 10V8a6 6 0 0 1 12 0v2M5 10h14v10H5z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/></svg>
            AES-256-CBC, only a key hash stored
          </li>
          <li>
            <svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.6"/><path d="M12 7v5l3 2" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>
            VirusTotal as primary detector
          </li>
        </ul>
      </div>
    </aside>

    <!-- Form panel -->
    <div class="auth-form">
      <?php if ($stage === 'otp'): ?>

      <!-- ============ STAGE 2: one-time code ============ -->
      <div class="auth-form-head">
        <h1>Two-step verification</h1>
        <p>
          <?php if ($devOtp !== null): ?>
            Enter the code below to finish signing in.
          <?php else: ?>
            We emailed a 6-digit code to <strong><?= e($otpEmailMasked) ?></strong>.
          <?php endif; ?>
        </p>
      </div>

      <?php if ($err): ?><div class="alert alert-danger"><?= e($err) ?></div><?php endif; ?>
      <?php if ($info): ?><div class="alert alert-success"><?= e($info) ?></div><?php endif; ?>

      <?php if ($devOtp !== null): ?>
        <div class="alert alert-warning">
          Email is disabled in this environment (<code>MAIL_ENABLED=false</code>),
          so your one-time code is shown here instead:
          <div class="otp-dev-code" id="devOtp"><?= e($devOtp) ?></div>
        </div>
      <?php endif; ?>

      <form method="post">
        <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
        <input type="hidden" name="action" value="verify_otp">
        <div class="field">
          <label for="otpCode">6-digit code</label>
          <input type="text" name="otp" id="otpCode" class="form-control otp-input"
                 inputmode="numeric" autocomplete="one-time-code"
                 pattern="[0-9]{6}" maxlength="6" required autofocus
                 placeholder="••••••">
        </div>
        <button type="submit" class="btn btn-cloudie w-100 auth-submit">Verify &amp; log in</button>
      </form>

      <form method="post" class="otp-resend">
        <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
        <input type="hidden" name="action" value="resend_otp">
        <button type="submit" class="otp-link">Resend code</button>
      </form>
      <p class="auth-alt"><a href="login.php">&larr; Back to login</a></p>

      <style>
        .otp-input{text-align:center;font-family:'JetBrains Mono',monospace;
          font-size:24px;letter-spacing:.4em}
        .otp-dev-code{font-family:'JetBrains Mono',monospace;font-size:26px;
          letter-spacing:.3em;margin-top:8px;text-align:center}
        .alert-warning{background:rgba(255,194,75,.1);border:1px solid rgba(255,194,75,.3);
          color:var(--amber);border-radius:12px;padding:12px 16px;font-size:14px;margin-bottom:16px}
        .otp-resend{margin-top:14px;text-align:center}
        .otp-link{background:none;border:none;color:var(--cyan);cursor:pointer;
          font-size:13.5px;font-family:'Inter',sans-serif;padding:0}
        .otp-link:hover{text-decoration:underline}
      </style>

      <?php else: ?>

      <!-- ============ STAGE 1: credentials ============ -->
      <div class="auth-form-head">
        <h1>Log in</h1>
        <p>Access your secure cloud storage.</p>
      </div>

      <?php if ($err): ?>
        <div class="alert alert-danger">
          <?= e($err) ?>
          <?php if ($showResendVerify): ?>
            <form method="post" style="margin-top:8px">
              <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
              <input type="hidden" name="action" value="resend_verify">
              <input type="hidden" name="login" value="<?= e($_POST['login'] ?? '') ?>">
              <button type="submit" class="otp-link" style="background:none;border:none;color:var(--cyan);cursor:pointer;font-size:13px;padding:0">
                Resend verification email</button>
            </form>
          <?php endif; ?>
        </div>
      <?php endif; ?>
      <?php if ($info): ?><div class="alert alert-success"><?= e($info) ?></div><?php endif; ?>

      <form method="post">
        <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">

        <div class="field">
          <label for="loginId">Username or email</label>
          <div class="input-icon">
            <svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="8" r="3.6" stroke="currentColor" stroke-width="1.6"/><path d="M5 20a7 7 0 0 1 14 0" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>
            <input type="text" name="login" id="loginId" class="form-control" required
                   autofocus value="<?= e($_POST['login'] ?? '') ?>"
                   placeholder="you@example.com">
          </div>
        </div>

        <div class="field">
          <label for="pw">Password</label>
          <div class="input-icon">
            <svg viewBox="0 0 24 24" fill="none"><rect x="5" y="11" width="14" height="9" rx="2" stroke="currentColor" stroke-width="1.6"/><path d="M8 11V8a4 4 0 0 1 8 0v3" stroke="currentColor" stroke-width="1.6"/></svg>
            <input type="password" name="password" id="pw" class="form-control" required
                   placeholder="Your password">
            <button type="button" class="pw-toggle" data-target="pw" aria-label="Show password">
              <svg viewBox="0 0 24 24" fill="none"><path d="M2 12s3.6-6.5 10-6.5S22 12 22 12s-3.6 6.5-10 6.5S2 12 2 12z" stroke="currentColor" stroke-width="1.6"/><circle cx="12" cy="12" r="2.6" stroke="currentColor" stroke-width="1.6"/></svg>
            </button>
          </div>
        </div>

        <button type="submit" class="btn btn-cloudie w-100 auth-submit">Log in</button>
      </form>

      <p class="auth-alt">New here? <a href="register.php">Create an account</a></p>

      <?php endif; ?>
    </div>

  </div>
</div>

<?php require_once __DIR__ . '/includes/auth_ui.php'; ?>
<?php require_once __DIR__ . '/includes/footer.php'; ?>