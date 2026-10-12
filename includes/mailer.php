<?php
/**
 * includes/mailer.php
 * -------------------
 * Sends Cloudie emails through Gmail SMTP using PHPMailer.
 *
 * PHPMailer is bundled under includes/PHPMailer/src (no Composer needed),
 * so this works on a stock XAMPP install. SMTP credentials live in config.php.
 *
 * The public entry point is send_key_email(); it never throws — on any
 * failure it logs and returns false so the upload flow is never blocked.
 */

require_once __DIR__ . '/config.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

/**
 * Lazily load the bundled PHPMailer classes. Returns true if available.
 */
function cloudie_load_phpmailer(): bool {
    if (class_exists(PHPMailer::class)) return true;
    $base = __DIR__ . '/PHPMailer/src/';
    foreach (['Exception.php', 'PHPMailer.php', 'SMTP.php'] as $f) {
        $path = $base . $f;
        if (!is_file($path)) {
            error_log('PHPMailer file missing: ' . $path);
            return false;
        }
        require_once $path;
    }
    return class_exists(PHPMailer::class);
}

/**
 * Build a configured PHPMailer instance, or null if email is disabled or
 * the library/credentials aren't ready.
 */
function cloudie_make_mailer(): ?PHPMailer {
    if (!defined('MAIL_ENABLED') || !MAIL_ENABLED) return null;
    if (!cloudie_load_phpmailer()) return null;

    $m = new PHPMailer(true);   // true = throw exceptions, we catch them
    try {
        $m->isSMTP();
        $m->Host       = SMTP_HOST;
        $m->SMTPAuth   = true;
        $m->Username   = SMTP_USER;
        $m->Password   = SMTP_PASS;
        $m->SMTPSecure = SMTP_SECURE;   // 'tls' or 'ssl'
        $m->Port       = SMTP_PORT;
        $m->CharSet    = 'UTF-8';
        $m->setFrom(SMTP_FROM, SMTP_FROM_NAME);
        return $m;
    } catch (Exception $e) {
        error_log('Mailer setup failed: ' . $e->getMessage());
        return null;
    }
}

/**
 * Email a user the AES key for a file they just encrypted.
 *
 * @param string $to_email   recipient (the file owner's email)
 * @param string $to_name    display name (username), may be ''
 * @param string $file_name  original filename
 * @param string $key_hex    64-char hex AES key
 * @param int    $file_id    id for the subject line / reference
 * @return bool              true if the email was accepted by the SMTP server
 */
function send_key_email(string $to_email,
                        string $to_name,
                        string $file_name,
                        string $key_hex,
                        int $file_id): bool {

    if ($to_email === '' || !filter_var($to_email, FILTER_VALIDATE_EMAIL)) {
        return false;
    }

    $mail = cloudie_make_mailer();
    if ($mail === null) return false;   // disabled or not configured — skip quietly

    try {
        $mail->addAddress($to_email, $to_name !== '' ? $to_name : $to_email);
        $mail->Subject = 'Your Cloudie encryption key for "' . $file_name . '"';

        $safeName = htmlspecialchars($file_name, ENT_QUOTES, 'UTF-8');
        $safeKey  = htmlspecialchars($key_hex,   ENT_QUOTES, 'UTF-8');

        $mail->isHTML(true);
        $mail->Body    = cloudie_key_email_html($safeName, $safeKey, $file_id);
        $mail->AltBody = cloudie_key_email_text($file_name, $key_hex, $file_id);

        $mail->send();
        return true;
    } catch (Exception $e) {
        error_log('send_key_email failed: ' . $mail->ErrorInfo);
        return false;
    }
}

/**
 * HTML body for the key email. Inline styles only (email clients ignore
 * <style> blocks and external CSS).
 */
function cloudie_key_email_html(string $safeName, string $safeKey, int $file_id): string {
    return <<<HTML
<div style="font-family:Arial,Helvetica,sans-serif;background:#0b0f2a;padding:28px;color:#e7ecff">
  <div style="max-width:560px;margin:0 auto;background:#11162b;border:1px solid rgba(255,255,255,.08);border-radius:16px;overflow:hidden">
    <div style="padding:22px 26px;border-bottom:1px solid rgba(255,255,255,.08)">
      <span style="font-size:20px;font-weight:700;letter-spacing:1px;color:#19e3ff">Cloud<span style="color:#45a8ff">ie</span></span>
    </div>
    <div style="padding:26px">
      <h2 style="margin:0 0 6px;font-size:18px;color:#ffffff">Your file is encrypted &amp; stored</h2>
      <p style="margin:0 0 18px;font-size:14px;color:#a3aacc;line-height:1.5">
        <strong style="color:#e7ecff">{$safeName}</strong> passed the malware scan, was encrypted
        with AES-256-CBC, and saved to your vault. Here is the key needed to open it.
      </p>

      <div style="font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:#7c83a6;margin-bottom:6px">Your AES-256 key</div>
      <div style="font-family:Consolas,'Courier New',monospace;font-size:14px;word-break:break-all;
                  background:#0b0f2a;border:1px solid rgba(25,227,255,.3);border-radius:10px;
                  padding:14px 16px;color:#19e3ff">{$safeKey}</div>

      <p style="margin:18px 0 0;font-size:13px;color:#a3aacc;line-height:1.5">
        You need this key to view, download, or delete the file. Cloudie does not store it —
        if you lose it, the file cannot be recovered. Keep this email private; anyone with the
        key can decrypt this one file.
      </p>
    </div>
    <div style="padding:14px 26px;border-top:1px solid rgba(255,255,255,.08);font-size:11px;color:#6c7290">
      File reference #{$file_id} &middot; This is an automated message from Cloudie.
    </div>
  </div>
</div>
HTML;
}

/**
 * Plain-text fallback for clients that don't render HTML.
 */
function cloudie_key_email_text(string $file_name, string $key_hex, int $file_id): string {
    return "Cloudie — your file is encrypted & stored\n"
         . "==========================================\n\n"
         . "File: {$file_name}\n"
         . "File reference: #{$file_id}\n\n"
         . "Your AES-256 key:\n{$key_hex}\n\n"
         . "You need this key to view, download, or delete the file. Cloudie does not\n"
         . "store it — if you lose it, the file cannot be recovered. Keep this email\n"
         . "private; anyone with the key can decrypt this one file.\n";
}

/**
 * Email a 6-digit login OTP code. Best-effort: never throws.
 * Returns true only if the SMTP server accepted the message — the caller
 * falls back to showing the code on screen (dev mode) when this fails.
 */
function send_otp_email(string $to_email, string $to_name, string $otp): bool {
    if ($to_email === '' || !filter_var($to_email, FILTER_VALIDATE_EMAIL)) {
        return false;
    }
    $mail = cloudie_make_mailer();
    if ($mail === null) return false;

    try {
        $mail->addAddress($to_email, $to_name !== '' ? $to_name : $to_email);
        $mail->Subject = $otp . ' is your Cloudie login code';

        $safeOtp = htmlspecialchars($otp, ENT_QUOTES, 'UTF-8');
        $ttl     = (int)OTP_TTL_MINUTES;

        $mail->isHTML(true);
        $mail->Body = <<<HTML
<div style="font-family:Arial,Helvetica,sans-serif;background:#0b0f2a;padding:28px;color:#e7ecff">
  <div style="max-width:560px;margin:0 auto;background:#11162b;border:1px solid rgba(255,255,255,.08);border-radius:16px;overflow:hidden">
    <div style="padding:22px 26px;border-bottom:1px solid rgba(255,255,255,.08)">
      <span style="font-size:20px;font-weight:700;letter-spacing:1px;color:#19e3ff">Cloud<span style="color:#45a8ff">ie</span></span>
    </div>
    <div style="padding:26px">
      <h2 style="margin:0 0 6px;font-size:18px;color:#ffffff">Your login code</h2>
      <p style="margin:0 0 18px;font-size:14px;color:#a3aacc;line-height:1.5">
        Enter this code to finish signing in. It expires in {$ttl} minutes.
      </p>
      <div style="font-family:Consolas,'Courier New',monospace;font-size:32px;letter-spacing:.35em;
                  text-align:center;background:#0b0f2a;border:1px solid rgba(25,227,255,.3);
                  border-radius:10px;padding:18px 16px;color:#19e3ff">{$safeOtp}</div>
      <p style="margin:18px 0 0;font-size:13px;color:#a3aacc;line-height:1.5">
        If you did not try to log in to Cloudie, you can ignore this email —
        your password alone is not enough to access your account.
      </p>
    </div>
    <div style="padding:14px 26px;border-top:1px solid rgba(255,255,255,.08);font-size:11px;color:#6c7290">
      This is an automated message from Cloudie.
    </div>
  </div>
</div>
HTML;
        $mail->AltBody = "Your Cloudie login code: {$otp}\n"
                       . "It expires in {$ttl} minutes.\n\n"
                       . "If you did not try to log in, ignore this email.\n";

        $mail->send();
        return true;
    } catch (Exception $e) {
        error_log('send_otp_email failed: ' . $mail->ErrorInfo);
        return false;
    }
}

/**
 * Email the address-verification link after registration. Best-effort:
 * never throws. When this fails (mail disabled locally) the caller marks
 * the account verified so registration is never blocked.
 */
function send_verification_email(string $to_email, string $to_name, string $link): bool {
    if ($to_email === '' || !filter_var($to_email, FILTER_VALIDATE_EMAIL)) {
        return false;
    }
    $mail = cloudie_make_mailer();
    if ($mail === null) return false;

    try {
        $mail->addAddress($to_email, $to_name !== '' ? $to_name : $to_email);
        $mail->Subject = 'Verify your email for Cloudie';

        $safeName = htmlspecialchars($to_name !== '' ? $to_name : 'there', ENT_QUOTES, 'UTF-8');
        $safeLink = htmlspecialchars($link, ENT_QUOTES, 'UTF-8');

        $mail->isHTML(true);
        $mail->Body = <<<HTML
<div style="font-family:Arial,Helvetica,sans-serif;background:#0b0f2a;padding:28px;color:#e7ecff">
  <div style="max-width:560px;margin:0 auto;background:#11162b;border:1px solid rgba(255,255,255,.08);border-radius:16px;overflow:hidden">
    <div style="padding:22px 26px;border-bottom:1px solid rgba(255,255,255,.08)">
      <span style="font-size:20px;font-weight:700;letter-spacing:1px;color:#19e3ff">Cloud<span style="color:#45a8ff">ie</span></span>
    </div>
    <div style="padding:26px">
      <h2 style="margin:0 0 6px;font-size:18px;color:#ffffff">Confirm your email, {$safeName}</h2>
      <p style="margin:0 0 22px;font-size:14px;color:#a3aacc;line-height:1.5">
        One quick step before you can log in: confirm that this address is yours.
      </p>
      <div style="text-align:center;margin-bottom:22px">
        <a href="{$safeLink}"
           style="display:inline-block;background:#19e3ff;color:#0a1230;font-weight:700;
                  padding:13px 30px;border-radius:999px;text-decoration:none;font-size:14px">
          Verify my email</a>
      </div>
      <p style="margin:0;font-size:12px;color:#6c7290;line-height:1.6;word-break:break-all">
        Button not working? Copy this link into your browser:<br>{$safeLink}
      </p>
    </div>
    <div style="padding:14px 26px;border-top:1px solid rgba(255,255,255,.08);font-size:11px;color:#6c7290">
      If you did not create a Cloudie account, you can ignore this email.
    </div>
  </div>
</div>
HTML;
        $mail->AltBody = "Confirm your email for Cloudie\n\n"
                       . "Open this link to verify your address:\n{$link}\n\n"
                       . "If you did not create a Cloudie account, ignore this email.\n";

        $mail->send();
        return true;
    } catch (Exception $e) {
        error_log('send_verification_email failed: ' . $mail->ErrorInfo);
        return false;
    }
}

/**
 * Email a newly-registered user a welcome / onboarding message.
 *
 * Best-effort: never throws. Returns true if the SMTP server accepted the
 * message, false otherwise (disabled, library/credentials missing, or send
 * failure). Registration must NOT be blocked by a mail problem.
 *
 * @param string $to_email  recipient (the new user's email)
 * @param string $to_name   display name (username), may be ''
 * @return bool
 */
function send_welcome_email(string $to_email, string $to_name): bool {

    if ($to_email === '' || !filter_var($to_email, FILTER_VALIDATE_EMAIL)) {
        return false;
    }

    $mail = cloudie_make_mailer();
    if ($mail === null) return false;   // disabled or not configured — skip quietly

    try {
        $mail->addAddress($to_email, $to_name !== '' ? $to_name : $to_email);
        $mail->Subject = 'Welcome to Cloudie';

        $safeName = htmlspecialchars($to_name !== '' ? $to_name : 'there',
                                     ENT_QUOTES, 'UTF-8');

        $mail->isHTML(true);
        $mail->Body    = cloudie_welcome_email_html($safeName);
        $mail->AltBody = cloudie_welcome_email_text($to_name !== '' ? $to_name : 'there');

        $mail->send();
        return true;
    } catch (Exception $e) {
        error_log('send_welcome_email failed: ' . $mail->ErrorInfo);
        return false;
    }
}

/**
 * HTML body for the welcome email. Inline styles only.
 */
function cloudie_welcome_email_html(string $safeName): string {
    return <<<HTML
<div style="font-family:Arial,Helvetica,sans-serif;background:#0b0f2a;padding:28px;color:#e7ecff">
  <div style="max-width:560px;margin:0 auto;background:#11162b;border:1px solid rgba(255,255,255,.08);border-radius:16px;overflow:hidden">
    <div style="padding:22px 26px;border-bottom:1px solid rgba(255,255,255,.08)">
      <span style="font-size:20px;font-weight:700;letter-spacing:1px;color:#19e3ff">Cloud<span style="color:#45a8ff">ie</span></span>
    </div>
    <div style="padding:26px">
      <h2 style="margin:0 0 6px;font-size:18px;color:#ffffff">Welcome to Cloudie, {$safeName}</h2>
      <p style="margin:0 0 18px;font-size:14px;color:#a3aacc;line-height:1.5">
        Thank you for registering. Cloudie is a secure cloud storage platform that
        scans every file for malware using an AI analyzer, then encrypts it with
        AES-256 before storing it. Only you, with your key, can read it back.
      </p>

      <div style="font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:#7c83a6;margin:18px 0 10px">How to use Cloudie</div>
      <ol style="margin:0;padding-left:20px;font-size:14px;color:#cdd3ec;line-height:1.7">
        <li>Log in and click <strong style="color:#e7ecff">Upload &amp; Scan</strong>.</li>
        <li>Select a file. Cloudie's AI analyzer scans it for malware first.</li>
        <li>If the file is clean, it is encrypted with AES-256 and stored securely.</li>
        <li>You receive a unique AES key and a QR code for that file.</li>
        <li>Use the key any time to view, download, or delete the file.</li>
      </ol>

      <div style="margin:22px 0 10px;padding:14px 16px;background:#0b0f2a;border:1px solid rgba(25,227,255,.3);border-radius:10px">
        <div style="font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:#19e3ff;margin-bottom:8px">Important: protect your keys</div>
        <p style="margin:0;font-size:13px;color:#a3aacc;line-height:1.55">
          Each file has its own AES-256 key. <strong style="color:#e7ecff">Cloudie never
          stores your keys</strong> &mdash; if you lose a key, that file cannot be
          recovered by anyone, including us. Save each key somewhere safe and private.
          Anyone who has a key can decrypt that one file, so do not share it.
        </p>
      </div>

      <p style="margin:18px 0 0;font-size:13px;color:#a3aacc;line-height:1.5">
        You can now log in and upload your first file. We hope you enjoy using Cloudie.
      </p>
    </div>
    <div style="padding:14px 26px;border-top:1px solid rgba(255,255,255,.08);font-size:11px;color:#6c7290">
      This is an automated message from Cloudie. Please do not reply to this email.
    </div>
  </div>
</div>
HTML;
}

/**
 * Plain-text fallback for the welcome email.
 */
function cloudie_welcome_email_text(string $name): string {
    return "Welcome to Cloudie, {$name}\n"
         . "================================\n\n"
         . "Thank you for registering. Cloudie is a secure cloud storage platform\n"
         . "that scans every file for malware using an AI analyzer, then encrypts it\n"
         . "with AES-256 before storing it. Only you, with your key, can read it back.\n\n"
         . "HOW TO USE CLOUDIE\n"
         . "  1. Log in and click 'Upload & Scan'.\n"
         . "  2. Select a file. Cloudie's AI analyzer scans it for malware first.\n"
         . "  3. If the file is clean, it is encrypted with AES-256 and stored.\n"
         . "  4. You receive a unique AES key and a QR code for that file.\n"
         . "  5. Use the key any time to view, download, or delete the file.\n\n"
         . "IMPORTANT: PROTECT YOUR KEYS\n"
         . "  Each file has its own AES-256 key. Cloudie never stores your keys —\n"
         . "  if you lose a key, that file cannot be recovered by anyone, including\n"
         . "  us. Save each key somewhere safe and private. Anyone who has a key can\n"
         . "  decrypt that one file, so do not share it.\n\n"
         . "You can now log in and upload your first file. We hope you enjoy Cloudie.\n\n"
         . "This is an automated message from Cloudie. Please do not reply.\n";
}