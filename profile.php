<?php
/**
 * profile.php
 * -----------
 * Account page reached from the topbar avatar. Two independent forms:
 *
 *   1. Account details — username, email, phone. Saving requires the
 *      current password. If the email changes and mail is enabled, the new
 *      address must be re-verified (link emailed; blocks the NEXT login,
 *      not the current session). When mail is off it stays verified.
 *
 *   2. Change password — current + new + confirm, bcrypt-hashed.
 *
 * Every change is written to the actions audit log.
 */

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/mailer.php';
require_once __DIR__ . '/includes/validate.php';

require_login();
db_ensure_auth();
$user = current_user();
$uid  = (int)$user['user_id'];

$errDetails = null;
$errPass    = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf'] ?? null)) {
        $errDetails = 'Invalid request.';
    } else {
        $action = $_POST['action'] ?? '';

        // current hash + email straight from the DB (session copy may lag)
        $stmt = db()->prepare(
            "SELECT username, email, password_hash FROM users WHERE user_id = ?");
        $stmt->execute([$uid]);
        $dbUser = $stmt->fetch();

        // ------------------------------------------------------------
        // 1. Account details
        // ------------------------------------------------------------
        if ($action === 'details') {
            $username = trim($_POST['username'] ?? '');
            $email    = trim($_POST['email']    ?? '');
            $phone    = trim($_POST['phone']    ?? '');
            $pass     = $_POST['current_password'] ?? '';

            // Same rules as sign-up (includes/validate.php). A username is only checked when it CHANGES, so accounts
            // created before the rules existed can still save their other details.
            $usernameChanged = $dbUser && $username !== (string)$dbUser['username'];
            if ($username === '') {
                $errDetails = 'Username is required.';
            } elseif ($usernameChanged && ($m = validate_username($username)) !== null) {
                $errDetails = $m;
            } elseif (($m = validate_email($email)) !== null) {
                $errDetails = $m;
            } elseif (($m = validate_phone($phone)) !== null) {
                $errDetails = $m;
            } elseif (!$dbUser || !password_verify($pass, $dbUser['password_hash'])) {
                $errDetails = 'Your current password is incorrect.';
            } else {
                $emailChanged = strcasecmp($email, (string)$dbUser['email']) !== 0;
                try {
                    $pdo = db();
                    $pdo->beginTransaction();
                    $pdo->prepare(
                        "UPDATE users SET username = ?, email = ?, phone_num = ?
                          WHERE user_id = ?")
                        ->execute([$username, $email, $phone ?: null, $uid]);
                    $pdo->prepare(
                        "UPDATE authentication SET email = ? WHERE user_id = ?")
                        ->execute([$email, $uid]);
                    $pdo->commit();

                    $note = 'Profile updated.';
                    if ($emailChanged) {
                        // new address must prove itself before the next login
                        $vt   = bin2hex(random_bytes(32));
                        $link = app_url('verify_email.php?uid=' . $uid . '&token=' . $vt);
                        if (send_verification_email($email, $username, $link)) {
                            db()->prepare(
                                "UPDATE authentication
                                    SET email_verified = 0, verify_token = ?
                                  WHERE user_id = ?")->execute([$vt, $uid]);
                            $note = 'Profile updated. We sent a verification link to '
                                  . $email . ' — confirm it before your next login.';
                        } else {
                            // mail unavailable (local dev): keep the account usable
                            db()->prepare(
                                "UPDATE authentication
                                    SET email_verified = 1, verify_token = NULL
                                  WHERE user_id = ?")->execute([$uid]);
                        }
                    }

                    log_action($uid, 'PROFILE_UPDATE', null, null,
                               'details updated' . ($emailChanged ? ' (email changed)' : ''));
                    flash_set('success', $note);
                    header('Location: profile.php'); exit;
                } catch (PDOException $e) {
                    if (db()->inTransaction()) db()->rollBack();
                    if ($e->getCode() === '23000') {
                        $errDetails = 'That username or email is already taken.';
                    } else {
                        error_log($e->getMessage());
                        $errDetails = 'Could not save your changes. Please try again.';
                    }
                }
            }

        // ------------------------------------------------------------
        // 2. Change password
        // ------------------------------------------------------------
        } elseif ($action === 'password') {
            $cur     = $_POST['current_password'] ?? '';
            $new     = $_POST['new_password']     ?? '';
            $confirm = $_POST['confirm_password'] ?? '';

            if (!$dbUser || !password_verify($cur, $dbUser['password_hash'])) {
                $errPass = 'Your current password is incorrect.';
            } elseif (($m = validate_password($new, (string)$dbUser['username'], (string)$dbUser['email'])) !== null) {
                $errPass = $m;                       // same rules as sign-up: 8-72 bytes, not common, not username/email
            } elseif ($new !== $confirm) {
                $errPass = 'New passwords do not match.';
            } elseif ($new === $cur) {
                $errPass = 'New password must be different from the current one.';
            } else {
                db()->prepare("UPDATE users SET password_hash = ? WHERE user_id = ?")
                   ->execute([password_hash($new, PASSWORD_BCRYPT), $uid]);
                session_regenerate_id(true);
                log_action($uid, 'PASSWORD_CHANGE', null, null, 'Password updated');
                flash_set('success', 'Password changed.');
                header('Location: profile.php'); exit;
            }
        }
    }
}

// ---------------------------------------------------------------
// Display data (fresh — the forms may have failed validation above)
// ---------------------------------------------------------------
$stmt = db()->prepare(
    "SELECT u.username, u.email, u.phone_num, u.created_at,
            a.last_login, a.email_verified
     FROM users u
     LEFT JOIN authentication a ON a.user_id = u.user_id
     WHERE u.user_id = ?");
$stmt->execute([$uid]);
$p = $stmt->fetch();

// keep rejected input visible so the user can fix it
$vUsername = $_POST['username'] ?? $p['username'];
$vEmail    = $_POST['email']    ?? $p['email'];
$vPhone    = $_POST['phone']    ?? ($p['phone_num'] ?? '');

$pageTitle = 'My profile';
require_once __DIR__ . '/includes/header.php';
?>
<style>
.pf-hero{display:flex;align-items:center;gap:20px;margin-bottom:24px;flex-wrap:wrap}
.pf-avatar{width:72px;height:72px;border-radius:20px;flex:none;
  background:linear-gradient(135deg,var(--violet),var(--cyan));display:grid;
  place-items:center;font-family:'Space Grotesk';font-weight:700;color:#fff;
  font-size:30px;box-shadow:0 10px 30px rgba(39,211,224,.3)}
.pf-name{font-family:'Space Grotesk';font-weight:700;font-size:24px;letter-spacing:-.02em}
.pf-mail{color:var(--txt-dim);font-size:14px;margin-top:2px}
.pf-meta{display:flex;gap:18px;flex-wrap:wrap;margin-top:9px;font-size:12.5px;color:var(--txt-faint)}
.pf-meta b{color:var(--txt-dim);font-weight:600}
.pf-badge{display:inline-flex;align-items:center;gap:6px;padding:4px 11px;border-radius:99px;
  font-size:12px;font-weight:600}
.pf-badge svg{width:13px;height:13px}
.pf-ok{background:rgba(52,224,161,.12);color:var(--green)}
.pf-warn{background:rgba(255,194,75,.14);color:var(--amber)}
.pf-grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}
@media(max-width:1100px){.pf-grid{grid-template-columns:1fr}}
.pf-hint{font-size:12.5px;color:var(--txt-faint);margin-top:6px;transition:color .2s}
.pf-hint.changed{color:var(--amber)}
/* password inputs: show/hide toggle */
.pw-wrap{position:relative}
.pw-wrap .form-control{padding-right:44px}
.pw-toggle{position:absolute;right:8px;top:50%;transform:translateY(-50%);
  width:30px;height:30px;display:grid;place-items:center;background:none;border:none;
  cursor:pointer;color:var(--txt-faint);border-radius:8px;transition:.14s}
.pw-toggle:hover{color:var(--cyan);background:var(--panel-2)}
.pw-toggle svg{width:18px;height:18px}
/* live strength meter + match feedback */
.pw-meter{height:6px;border-radius:99px;background:var(--line-2);overflow:hidden;margin-top:8px}
.pw-meter i{display:block;height:100%;width:0;border-radius:99px;
  transition:width .3s ease,background .3s ease}
.pw-note{font-size:12.5px;margin-top:6px;min-height:17px;color:var(--txt-faint)}
.pw-note.ok{color:var(--green)}
.pw-note.bad{color:var(--red)}
/* dirty-state save button */
.btn[disabled]{opacity:.45;cursor:not-allowed;transform:none;box-shadow:none}
</style>

<h2 class="mb-3">My profile</h2>

<!-- hero -->
<div class="cl-card pf-hero">
  <div class="pf-avatar"><?= e(strtoupper(substr($p['username'], 0, 1))) ?></div>
  <div>
    <div class="pf-name"><?= e($p['username']) ?></div>
    <div class="pf-mail"><?= e($p['email']) ?></div>
    <div class="pf-meta">
      <?php if ((int)$p['email_verified'] === 1): ?>
        <span class="pf-badge pf-ok">
          <svg viewBox="0 0 24 24" fill="none"><path d="M5 13l4 4L19 7" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg>
          Email verified
        </span>
      <?php else: ?>
        <span class="pf-badge pf-warn">
          <svg viewBox="0 0 24 24" fill="none"><path d="M12 3l9 16H3z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M12 9v4m0 3h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
          Verification pending
        </span>
      <?php endif; ?>
      <span>Member since <b><?= e(date('M j, Y', strtotime($p['created_at']))) ?></b></span>
      <?php if (!empty($p['last_login'])): ?>
        <span>Last login <b><?= e(date('M j, Y H:i', strtotime($p['last_login']))) ?></b></span>
      <?php endif; ?>
    </div>
  </div>
</div>

<div class="pf-grid">

  <!-- account details -->
  <div class="cl-card">
    <h3 class="mb-2">Account details</h3>
    <p class="text-muted small mb-3">Update your username, email address or phone number.</p>

    <?php if ($errDetails): ?><div class="alert alert-danger"><?= e($errDetails) ?></div><?php endif; ?>

    <form method="post" autocomplete="off">
      <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
      <input type="hidden" name="action" value="details">

      <div class="mb-3">
        <label for="dUser">Username</label>
        <input type="text" name="username" id="dUser" class="form-control" required
               minlength="3" maxlength="64" value="<?= e($vUsername) ?>"
               data-original="<?= e($p['username']) ?>">
      </div>
      <div class="mb-3">
        <label for="dEmail">Email</label>
        <input type="email" name="email" id="dEmail" class="form-control" required
               value="<?= e($vEmail) ?>" data-original="<?= e($p['email']) ?>">
        <div class="pf-hint" id="emailHint">Changing your email sends a new verification link to the new address.</div>
      </div>
      <div class="mb-3">
        <label for="dPhone">Phone <span style="color:var(--txt-faint);font-weight:400">(optional)</span></label>
        <input type="text" name="phone" id="dPhone" class="form-control"
               value="<?= e($vPhone) ?>" placeholder="012-3456789"
               data-original="<?= e($p['phone_num'] ?? '') ?>">
      </div>
      <div class="mb-3">
        <label for="dPass">Current password</label>
        <div class="pw-wrap">
          <input type="password" name="current_password" id="dPass" class="form-control" required
                 autocomplete="current-password" placeholder="Confirm it's you">
          <button type="button" class="pw-toggle" data-target="dPass" aria-label="Show password">
            <svg viewBox="0 0 24 24" fill="none"><path d="M2 12s3.6-6.5 10-6.5S22 12 22 12s-3.6 6.5-10 6.5S2 12 2 12z" stroke="currentColor" stroke-width="1.6"/><circle cx="12" cy="12" r="2.6" stroke="currentColor" stroke-width="1.6"/></svg>
          </button>
        </div>
      </div>

      <button type="submit" class="btn btn-cloudie w-100" id="dSave">Save changes</button>
    </form>
  </div>

  <!-- change password -->
  <div class="cl-card">
    <h3 class="mb-2">Change password</h3>
    <p class="text-muted small mb-3">Use at least 8 characters. You stay logged in after changing it.</p>

    <?php if ($errPass): ?><div class="alert alert-danger"><?= e($errPass) ?></div><?php endif; ?>

    <form method="post">
      <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
      <input type="hidden" name="action" value="password">

      <div class="mb-3">
        <label for="pwCur">Current password</label>
        <div class="pw-wrap">
          <input type="password" name="current_password" id="pwCur" class="form-control"
                 required autocomplete="current-password">
          <button type="button" class="pw-toggle" data-target="pwCur" aria-label="Show password">
            <svg viewBox="0 0 24 24" fill="none"><path d="M2 12s3.6-6.5 10-6.5S22 12 22 12s-3.6 6.5-10 6.5S2 12 2 12z" stroke="currentColor" stroke-width="1.6"/><circle cx="12" cy="12" r="2.6" stroke="currentColor" stroke-width="1.6"/></svg>
          </button>
        </div>
      </div>
      <div class="mb-3">
        <label for="pwNew">New password</label>
        <div class="pw-wrap">
          <input type="password" name="new_password" id="pwNew" class="form-control"
                 minlength="<?= PASSWORD_MIN ?>" maxlength="<?= PASSWORD_MAX ?>" required autocomplete="new-password"
                 placeholder="8 to 72 characters">
          <button type="button" class="pw-toggle" data-target="pwNew" aria-label="Show password">
            <svg viewBox="0 0 24 24" fill="none"><path d="M2 12s3.6-6.5 10-6.5S22 12 22 12s-3.6 6.5-10 6.5S2 12 2 12z" stroke="currentColor" stroke-width="1.6"/><circle cx="12" cy="12" r="2.6" stroke="currentColor" stroke-width="1.6"/></svg>
          </button>
        </div>
        <div class="pw-meter"><i id="pwBar"></i></div>
        <div class="pw-note" id="pwNote"></div>
      </div>
      <div class="mb-3">
        <label for="pwConf">Confirm new password</label>
        <div class="pw-wrap">
          <input type="password" name="confirm_password" id="pwConf" class="form-control"
                 minlength="8" required autocomplete="new-password" placeholder="Repeat new password">
          <button type="button" class="pw-toggle" data-target="pwConf" aria-label="Show password">
            <svg viewBox="0 0 24 24" fill="none"><path d="M2 12s3.6-6.5 10-6.5S22 12 22 12s-3.6 6.5-10 6.5S2 12 2 12s3.6-6.5 10-6.5" stroke="currentColor" stroke-width="1.6"/><circle cx="12" cy="12" r="2.6" stroke="currentColor" stroke-width="1.6"/></svg>
          </button>
        </div>
        <div class="pw-note" id="pwMatch"></div>
      </div>

      <button type="submit" class="btn btn-cloudie w-100">Change password</button>
    </form>
  </div>

</div>

<script>
(function(){
  // show/hide password toggles
  document.querySelectorAll('.pw-toggle').forEach(function(btn){
    btn.addEventListener('click', function(){
      var input = document.getElementById(btn.dataset.target);
      if (!input) return;
      var show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    });
  });

  // ---- details form: Save enables only when something actually changed ----
  var dSave  = document.getElementById('dSave');
  var fields = ['dUser', 'dEmail', 'dPhone'].map(function(id){ return document.getElementById(id); });
  var emailEl   = document.getElementById('dEmail');
  var emailHint = document.getElementById('emailHint');

  function refreshDirty(){
    var dirty = fields.some(function(f){ return f.value.trim() !== (f.dataset.original || ''); });
    dSave.disabled    = !dirty;
    dSave.textContent = dirty ? 'Save changes' : 'No changes yet';

    var emailChanged = emailEl.value.trim().toLowerCase()
                     !== (emailEl.dataset.original || '').toLowerCase();
    emailHint.classList.toggle('changed', emailChanged);
    emailHint.textContent = emailChanged
      ? '⚠ Email changed — a verification link will be sent to the new address.'
      : 'Changing your email sends a new verification link to the new address.';
  }
  if (dSave){
    fields.forEach(function(f){ f.addEventListener('input', refreshDirty); });
    refreshDirty();
  }

  // warn before leaving the page with unsaved detail changes
  var submitting = false;
  document.querySelectorAll('form').forEach(function(f){
    f.addEventListener('submit', function(){ submitting = true; });
  });
  window.addEventListener('beforeunload', function(e){
    if (!submitting && dSave && !dSave.disabled){ e.preventDefault(); e.returnValue = ''; }
  });

  // ---- new password: live strength meter + match indicator ----
  var pwNew  = document.getElementById('pwNew'),
      pwConf = document.getElementById('pwConf'),
      bar    = document.getElementById('pwBar'),
      note   = document.getElementById('pwNote'),
      match  = document.getElementById('pwMatch');

  function strengthScore(v){
    var s = 0;
    if (v.length >= 8)  s++;
    if (v.length >= 12) s++;
    if (/[a-z]/.test(v) && /[A-Z]/.test(v)) s++;
    if (/\d/.test(v)) s++;
    if (/[^A-Za-z0-9]/.test(v)) s++;
    return s;
  }
  // the same hard rules as the server (includes/validate.php); the server still decides
  var COMMON = <?= json_encode(COMMON_PASSWORDS) ?>;
  var ACCOUNT_USER  = <?= json_encode(strtolower((string)$user['username'])) ?>;
  var ACCOUNT_EMAIL = <?= json_encode(strtolower((string)$user['email'])) ?>;
  function byteLen(v){ try { return new TextEncoder().encode(v).length; } catch (e) { return v.length; } }
  function ruleProblem(v){
    var low = v.toLowerCase();
    if (byteLen(v) > <?= (int)PASSWORD_MAX ?>) return 'Too long — at most <?= (int)PASSWORD_MAX ?> characters.';
    if (COMMON.indexOf(low) !== -1) return 'Weak — this is a very common password.';
    if (/^(.)\1+$/.test(v)) return 'Weak — one character repeated.';
    if (low === ACCOUNT_USER) return 'Weak — same as your username.';
    if (low === ACCOUNT_EMAIL || low === ACCOUNT_EMAIL.split('@')[0]) return 'Weak — same as your email.';
    return null;
  }
  function refreshStrength(){
    var v = pwNew.value, s = strengthScore(v), problem = v ? ruleProblem(v) : null;
    if (!v){
      bar.style.width = '0'; note.textContent = ''; note.className = 'pw-note';
    } else if (problem && byteLen(v) >= 8){
      bar.style.width = '20%'; bar.style.background = 'var(--red)';
      note.textContent = problem; note.className = 'pw-note bad';
    } else if (v.length < 8){
      bar.style.width = '20%'; bar.style.background = 'var(--red)';
      note.textContent = 'Too short — minimum 8 characters.'; note.className = 'pw-note bad';
    } else if (s <= 2){
      bar.style.width = '40%'; bar.style.background = 'var(--red)';
      note.textContent = 'Weak — add capital letters, numbers or symbols.'; note.className = 'pw-note bad';
    } else if (s <= 4){
      bar.style.width = '70%'; bar.style.background = 'var(--amber)';
      note.textContent = 'Okay — longer is even stronger.'; note.className = 'pw-note';
    } else {
      bar.style.width = '100%'; bar.style.background = 'var(--green)';
      note.textContent = 'Strong password.'; note.className = 'pw-note ok';
    }
    refreshMatch();
  }
  function refreshMatch(){
    if (!pwConf.value){ match.textContent = ''; match.className = 'pw-note'; return; }
    if (pwConf.value === pwNew.value){
      match.textContent = '✓ Passwords match'; match.className = 'pw-note ok';
    } else {
      match.textContent = '✗ Passwords do not match'; match.className = 'pw-note bad';
    }
  }
  if (pwNew){
    pwNew.addEventListener('input', refreshStrength);
    pwConf.addEventListener('input', refreshMatch);
  }

  // ---- bring server-side errors into view; fade the success flash ----
  var errAlert = document.querySelector('.cl-card .alert-danger');
  if (errAlert) errAlert.scrollIntoView({ block: 'center', behavior: 'smooth' });

  document.querySelectorAll('.main > .alert-success').forEach(function(al){
    setTimeout(function(){
      al.style.transition = 'opacity .6s';
      al.style.opacity = '0';
      setTimeout(function(){ al.remove(); }, 650);
    }, 4000);
  });
})();
</script>
<?php require_once __DIR__ . '/includes/footer.php'; ?>
