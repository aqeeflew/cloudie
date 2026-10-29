<?php
/**
 * includes/mailer.php
 * -------------------
 * Sends Cloudie emails through Gmail SMTP using PHPMailer.
 *
 * PHPMailer is bundled under includes/PHPMailer/src (no Composer needed),
 * so this works on a stock XAMPP install. SMTP credentials live in config.php.
 *
 * Every send_*() function is best-effort: it never throws — on any failure it
 * logs and returns false so the calling flow (upload, login, register) is
 * never blocked.
 *
 * All emails share one layout (cloudie_email_layout): a light, table-based
 * design with inline styles only, because email clients ignore <style> blocks
 * and external CSS, Outlook needs tables, and Gmail/Outlook dark modes invert
 * light designs cleanly but often mangle dark ones.
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
        $m->Encoding   = 'base64';      // long key lines are never re-wrapped by quoted-printable
        $m->Timeout    = 10;            // PHPMailer default is 300 s; mail runs inside page requests
        $m->setFrom(SMTP_FROM, SMTP_FROM_NAME);
        // Transactional mail: ask clients and servers not to send out-of-office replies.
        $m->addCustomHeader('Auto-Submitted', 'auto-generated');
        $m->addCustomHeader('X-Auto-Response-Suppress', 'All');
        return $m;
    } catch (Exception $e) {
        error_log('Mailer setup failed: ' . $e->getMessage());
        return null;
    }
}

// ---------------------------------------------------------------------------
// Shared layout and small building blocks (all output is already escaped)
// ---------------------------------------------------------------------------

function cloudie_email_esc(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * Wrap a message body in the Cloudie email frame.
 *
 * @param string $preheader  plain text shown next to the subject in the inbox list
 * @param string $title      heading inside the card (plain text, escaped here)
 * @param string $bodyHtml   inner HTML (already escaped by the caller)
 * @param string $footerText plain text for the small print (escaped here)
 */
function cloudie_email_layout(string $preheader, string $title, string $bodyHtml, string $footerText): string {
    $pre    = cloudie_email_esc($preheader);
    $ttl    = cloudie_email_esc($title);
    $footer = nl2br(cloudie_email_esc($footerText));
    $year   = date('Y');
    return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<title>{$ttl}</title>
</head>
<body style="margin:0;padding:0;background:#f3f5f9;-webkit-text-size-adjust:100%">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;font-size:1px;line-height:1px">{$pre}&#8199;&#65279;&#847;&#8199;&#65279;&#847;&#8199;&#65279;&#847;</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f3f5f9">
  <tr><td align="center" style="padding:32px 16px">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:600px">
      <tr><td style="padding:0 4px 16px;font-family:Arial,Helvetica,sans-serif">
        <span style="font-size:22px;font-weight:700;letter-spacing:.3px;color:#0b1f4d">Cloud<span style="color:#0a8fd8">ie</span></span>
        <span style="font-size:12px;color:#6b7590;padding-left:8px">Secure cloud storage</span>
      </td></tr>
      <tr><td style="background:#ffffff;border:1px solid #e2e6ef;border-radius:12px;overflow:hidden">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
          <tr><td style="height:4px;background:#0a8fd8;line-height:4px;font-size:0">&nbsp;</td></tr>
          <tr><td style="padding:32px 32px 28px;font-family:Arial,Helvetica,sans-serif;color:#1d2433;font-size:15px;line-height:1.6">
            <h1 style="margin:0 0 16px;font-size:21px;line-height:1.3;color:#0b1f4d;font-weight:700">{$ttl}</h1>
            {$bodyHtml}
          </td></tr>
        </table>
      </td></tr>
      <tr><td style="padding:20px 8px 0;font-family:Arial,Helvetica,sans-serif;font-size:12px;line-height:1.6;color:#7a8399;text-align:center">
        {$footer}<br>
        &copy; {$year} Cloudie &middot; This is an automated message; replies are not monitored.
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>
HTML;
}

/** One label/value row for a details table. Both arguments are already-escaped HTML. */
function cloudie_email_row(string $label, string $valueHtml): string {
    return '<tr>'
         . '<td style="padding:9px 0;border-bottom:1px solid #edf0f5;color:#6b7590;font-size:13px;width:38%;vertical-align:top">' . $label . '</td>'
         . '<td style="padding:9px 0;border-bottom:1px solid #edf0f5;color:#1d2433;font-size:14px;vertical-align:top;word-break:break-word">' . $valueHtml . '</td>'
         . '</tr>';
}

/** Coloured notice box. $tone: info | warn. $html is already escaped. */
function cloudie_email_notice(string $tone, string $html): string {
    [$bg, $border, $fg] = $tone === 'warn'
        ? ['#fff7e6', '#f5c26b', '#7a4b00']
        : ['#eef6fd', '#b9dcf5', '#0b3f66'];
    return '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 20px">'
         . '<tr><td style="background:' . $bg . ';border:1px solid ' . $border . ';border-radius:8px;padding:14px 16px;'
         . 'font-size:14px;line-height:1.55;color:' . $fg . '">' . $html . '</td></tr></table>';
}

/** Primary call-to-action button (bulletproof table button). */
function cloudie_email_button(string $href, string $label): string {
    $h = cloudie_email_esc($href);
    $l = cloudie_email_esc($label);
    return '<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:4px 0 24px"><tr>'
         . '<td style="background:#0a8fd8;border-radius:8px">'
         . '<a href="' . $h . '" style="display:inline-block;padding:12px 26px;font-family:Arial,Helvetica,sans-serif;'
         . 'font-size:15px;font-weight:700;color:#ffffff;text-decoration:none;border-radius:8px">' . $l . '</a>'
         . '</td></tr></table>';
}

/** Human-readable size (1.4 MB). */
function cloudie_email_size(int $bytes): string {
    if ($bytes < 1024) return $bytes . ' bytes';
    $units = ['KB', 'MB', 'GB'];
    $v = $bytes / 1024;
    $i = 0;
    while ($v >= 1024 && $i < count($units) - 1) { $v /= 1024; $i++; }
    return number_format($v, $v < 10 ? 1 : 0) . ' ' . $units[$i];
}

/** Local time for the message (the app's users are in Malaysia). */
function cloudie_email_now(): string {
    try {
        $d = new DateTime('now', new DateTimeZone('Asia/Kuala_Lumpur'));
        return $d->format('j M Y, g:i A') . ' (MYT)';
    } catch (Throwable $e) {
        return gmdate('j M Y, H:i') . ' UTC';
    }
}

// ---------------------------------------------------------------------------
// AES key email
// ---------------------------------------------------------------------------

/**
 * Email a user the AES key for a file they just encrypted.
 *
 * @param string $to_email   recipient (the file owner's email)
 * @param string $to_name    display name (username), may be ''
 * @param string $file_name  original filename
 * @param string $key_hex    64-char hex AES key
 * @param int    $file_id    id for the subject line / reference
 * @param array  $info       optional details: size (int bytes), verdict ('clean'|'suspicious'),
 *                           reason (string, why a suspicious file was tagged), scan (string summary),
 *                           qr (data: URI of the key QR, embedded inline), open_url (string)
 * @return bool              true if the email was accepted by the SMTP server
 */
function send_key_email(string $to_email,
                        string $to_name,
                        string $file_name,
                        string $key_hex,
                        int $file_id,
                        array $info = []): bool {

    if ($to_email === '' || !filter_var($to_email, FILTER_VALIDATE_EMAIL)) {
        return false;
    }

    $mail = cloudie_make_mailer();
    if ($mail === null) return false;   // disabled or not configured — skip quietly

    try {
        $mail->addAddress($to_email, $to_name !== '' ? $to_name : $to_email);
        $mail->Subject = cloudie_key_email_subject($file_name, $file_id);

        $hasQr = false;
        $qr    = (string)($info['qr'] ?? '');
        if (preg_match('#^data:image/png;base64,(.+)$#s', $qr, $m)) {
            $png = base64_decode($m[1], true);
            if ($png !== false && $png !== '') {
                $mail->addStringEmbeddedImage($png, 'cloudie-key-qr', 'key-qr.png', 'base64', 'image/png');
                $hasQr = true;
            }
        }

        $mail->isHTML(true);
        $mail->Body    = cloudie_key_email_html($to_name, $file_name, $key_hex, $file_id, $info, $hasQr);
        $mail->AltBody = cloudie_key_email_text($to_name, $file_name, $key_hex, $file_id, $info);

        $mail->send();
        return true;
    } catch (Exception $e) {
        error_log('send_key_email failed: ' . $mail->ErrorInfo);
        return false;
    }
}

function cloudie_key_email_subject(string $file_name, int $file_id): string {
    // Keep the subject short and never put the key in it (subjects show in notifications and logs).
    $name = mb_strlen($file_name, 'UTF-8') > 60 ? mb_substr($file_name, 0, 57, 'UTF-8') . '...' : $file_name;
    return 'Your encryption key for "' . $name . '" (file #' . $file_id . ')';
}

/**
 * HTML body for the key email. All inputs are raw; everything is escaped here.
 */
function cloudie_key_email_html(string $to_name, string $file_name, string $key_hex, int $file_id,
                                array $info = [], bool $hasQr = false): string {
    $name      = cloudie_email_esc($to_name !== '' ? $to_name : 'there');
    $file      = cloudie_email_esc($file_name);
    $key       = cloudie_email_esc($key_hex);
    $suspect   = ($info['verdict'] ?? 'clean') === 'suspicious';
    $resultTxt = $suspect ? 'Stored with a warning (Suspicious)' : 'Clean';
    $resultClr = $suspect ? '#a35d00' : '#137a3f';

    $intro = $suspect
        ? "<p style=\"margin:0 0 16px\">Hi {$name},</p>"
        . "<p style=\"margin:0 0 20px\">Your file <strong>{$file}</strong> has been encrypted and stored in your Cloudie vault. "
        . "Our scan raised a warning, so the file is tagged <strong>Suspicious</strong>. Below is the key you need to open it.</p>"
        : "<p style=\"margin:0 0 16px\">Hi {$name},</p>"
        . "<p style=\"margin:0 0 20px\">Your file <strong>{$file}</strong> passed the security scan and has been encrypted and stored "
        . "in your Cloudie vault. Below is the key you need to open it.</p>";

    $warn = '';
    if ($suspect) {
        $reason = trim((string)($info['reason'] ?? ''));
        $warn = cloudie_email_notice('warn',
            '<strong>Why it was flagged:</strong> '
            . cloudie_email_esc($reason !== '' ? $reason : 'one of the scan checks reported a risk.')
            . '<br>Open it only if you trust where it came from. The full scan report is in your vault.');
    }

    $rows = cloudie_email_row('File', $file);
    if (isset($info['size']) && (int)$info['size'] > 0) {
        $rows .= cloudie_email_row('Size', cloudie_email_esc(cloudie_email_size((int)$info['size'])));
    }
    $rows .= cloudie_email_row('Stored on', cloudie_email_esc(cloudie_email_now()));
    $rows .= cloudie_email_row('Scan result',
        '<span style="color:' . $resultClr . ';font-weight:700">' . cloudie_email_esc($resultTxt) . '</span>'
        . (!empty($info['scan']) ? '<br><span style="color:#6b7590;font-size:13px">' . cloudie_email_esc((string)$info['scan']) . '</span>' : ''));
    $rows .= cloudie_email_row('Encryption', 'AES-256-CBC, unique key for this file');
    $rows .= cloudie_email_row('Reference', 'File #' . (int)$file_id);

    $details = '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 24px">'
             . $rows . '</table>';

    $keyBlock = '<p style="margin:0 0 8px;font-size:12px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#6b7590">Your AES-256 key</p>'
              . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 8px"><tr>'
              . '<td style="background:#f6f8fb;border:1px solid #cfd8e6;border-radius:8px;padding:16px 18px;'
              . 'font-family:Consolas,\'Courier New\',monospace;font-size:16px;line-height:1.7;letter-spacing:.04em;color:#0b1f4d;word-break:break-all">'
              . $key . '</td></tr></table>'
              . '<p style="margin:0 0 24px;font-size:13px;color:#6b7590">64 characters (0-9, a-f). Copy it exactly, as one line.</p>';

    if ($hasQr) {
        $keyBlock .= '<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 24px"><tr>'
                   . '<td style="padding-right:16px;vertical-align:middle"><img src="cid:cloudie-key-qr" width="120" height="120" alt="QR code of your key" '
                   . 'style="display:block;border:1px solid #e2e6ef;border-radius:6px"></td>'
                   . '<td style="vertical-align:middle;font-size:13px;color:#6b7590;line-height:1.5">The same key as a QR code. '
                   . 'Scan it on the Decrypt page instead of typing the key.</td></tr></table>';
    }

    $openUrl = (string)($info['open_url'] ?? '');
    $steps = '<p style="margin:0 0 8px;font-weight:700;color:#0b1f4d">How to open your file</p>'
           . '<ol style="margin:0 0 20px;padding-left:20px;color:#1d2433">'
           . '<li style="margin-bottom:4px">Sign in to Cloudie and open <strong>My files</strong>.</li>'
           . '<li style="margin-bottom:4px">Find <strong>' . $file . '</strong> and choose <strong>View</strong> or <strong>Download</strong>.</li>'
           . ($hasQr ? '<li>Paste the key above, or use <strong>Scan QR</strong> with the QR code.</li>'
                     : '<li>Paste the key above.</li>')
           . '</ol>'
           . ($openUrl !== '' ? cloudie_email_button($openUrl, 'Go to my files') : '');

    $security = cloudie_email_notice('info',
        '<strong>Keep this key safe.</strong> Cloudie stores only a fingerprint (SHA-256 hash) of it, not the key itself, '
        . 'so we cannot recover the file if the key is lost.'
        . '<br>&bull; Save it in a password manager, then delete this email.'
        . '<br>&bull; Anyone with this key can open this one file. Do not forward it.'
        . '<br>&bull; Cloudie will never ask you for your key by email, phone or chat.');

    $body = $intro . $warn . $details . $keyBlock . $steps . $security
          . '<p style="margin:0;color:#1d2433">Regards,<br>The Cloudie team</p>';

    return cloudie_email_layout(
        $suspect ? 'Stored with a warning. Your AES-256 key for ' . $file_name . ' is inside.'
                 : 'Scanned, encrypted and stored. Your AES-256 key for ' . $file_name . ' is inside.',
        $suspect ? 'Your file is stored, with a warning' : 'Your file is encrypted and stored',
        $body,
        "You are receiving this because a file was uploaded to your Cloudie account.\n"
        . "If you did not upload this file, sign in and change your password straight away."
    );
}

/**
 * Plain-text fallback for clients that don't render HTML.
 */
function cloudie_key_email_text(string $to_name, string $file_name, string $key_hex, int $file_id,
                                array $info = []): string {
    $suspect = ($info['verdict'] ?? 'clean') === 'suspicious';
    $t  = 'Hi ' . ($to_name !== '' ? $to_name : 'there') . ",\n\n";
    $t .= $suspect
        ? "Your file has been encrypted and stored in your Cloudie vault, but our scan raised a warning,\n"
        . "so it is tagged SUSPICIOUS. Open it only if you trust where it came from.\n"
        : "Your file passed the security scan and has been encrypted and stored in your Cloudie vault.\n";
    if ($suspect && trim((string)($info['reason'] ?? '')) !== '') {
        $t .= 'Why it was flagged: ' . trim((string)$info['reason']) . "\n";
    }
    $t .= "\nFILE DETAILS\n";
    $t .= "  File:        {$file_name}\n";
    if (isset($info['size']) && (int)$info['size'] > 0) {
        $t .= '  Size:        ' . cloudie_email_size((int)$info['size']) . "\n";
    }
    $t .= '  Stored on:   ' . cloudie_email_now() . "\n";
    $t .= '  Scan result: ' . ($suspect ? 'Stored with a warning (Suspicious)' : 'Clean') . "\n";
    if (!empty($info['scan'])) {
        $t .= '               ' . $info['scan'] . "\n";
    }
    $t .= "  Encryption:  AES-256-CBC, unique key for this file\n";
    $t .= "  Reference:   File #{$file_id}\n\n";
    $t .= "YOUR AES-256 KEY\n  {$key_hex}\n\n";
    $t .= "HOW TO OPEN YOUR FILE\n"
        . "  1. Sign in to Cloudie and open My files.\n"
        . "  2. Find the file and choose View or Download.\n"
        . "  3. Paste the key above to view or download it.\n";
    if (!empty($info['open_url'])) {
        $t .= '  ' . $info['open_url'] . "\n";
    }
    $t .= "\nKEEP THIS KEY SAFE\n"
        . "  Cloudie stores only a fingerprint (SHA-256 hash) of the key, not the key itself, so we\n"
        . "  cannot recover the file if the key is lost.\n"
        . "  - Save it in a password manager, then delete this email.\n"
        . "  - Anyone with this key can open this one file. Do not forward it.\n"
        . "  - Cloudie will never ask you for your key by email, phone or chat.\n\n"
        . "Regards,\nThe Cloudie team\n\n"
        . "If you did not upload this file, sign in and change your password straight away.\n"
        . "This is an automated message; replies are not monitored.\n";
    return $t;
}

// ---------------------------------------------------------------------------
// Login code (OTP)
// ---------------------------------------------------------------------------

/**
 * Email a 6-digit login OTP code. Best-effort: never throws.
 * Returns true only if the SMTP server accepted the message. If mail is on
 * and this fails, login fails closed; the code is shown on screen only when
 * mail is switched off (local development).
 */
function send_otp_email(string $to_email, string $to_name, string $otp): bool {
    if ($to_email === '' || !filter_var($to_email, FILTER_VALIDATE_EMAIL)) {
        return false;
    }
    $mail = cloudie_make_mailer();
    if ($mail === null) return false;

    try {
        $mail->addAddress($to_email, $to_name !== '' ? $to_name : $to_email);
        $mail->Subject = $otp . ' is your Cloudie sign-in code';

        $name    = cloudie_email_esc($to_name !== '' ? $to_name : 'there');
        $safeOtp = cloudie_email_esc($otp);
        $ttl     = (int)OTP_TTL_MINUTES;
        $when    = cloudie_email_esc(cloudie_email_now());

        $body = "<p style=\"margin:0 0 16px\">Hi {$name},</p>"
              . "<p style=\"margin:0 0 20px\">Use this code to finish signing in. It expires in {$ttl} minutes and can be used once.</p>"
              . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 20px"><tr>'
              . '<td align="center" style="background:#f6f8fb;border:1px solid #cfd8e6;border-radius:8px;padding:18px 16px;'
              . 'font-family:Consolas,\'Courier New\',monospace;font-size:32px;font-weight:700;letter-spacing:.3em;color:#0b1f4d">'
              . $safeOtp . '</td></tr></table>'
              . "<p style=\"margin:0 0 20px;font-size:13px;color:#6b7590\">Requested on {$when}.</p>"
              . cloudie_email_notice('info',
                  '<strong>Did not try to sign in?</strong> Someone may know your password. You can ignore this email '
                  . '(the password alone is not enough to get in), but we recommend changing your password.')
              . '<p style="margin:0">Regards,<br>The Cloudie team</p>';

        $mail->isHTML(true);
        $mail->Body = cloudie_email_layout(
            "Your sign-in code is {$otp}. It expires in {$ttl} minutes.",
            'Your sign-in code',
            $body,
            'Never share this code. Cloudie will never ask for it by email, phone or chat.'
        );
        $mail->AltBody = 'Hi ' . ($to_name !== '' ? $to_name : 'there') . ",\n\n"
                       . "Your Cloudie sign-in code: {$otp}\n"
                       . "It expires in {$ttl} minutes and can be used once.\n\n"
                       . "If you did not try to sign in, someone may know your password.\n"
                       . "We recommend changing it.\n\n"
                       . "Never share this code. Cloudie will never ask for it.\n";

        $mail->send();
        return true;
    } catch (Exception $e) {
        error_log('send_otp_email failed: ' . $mail->ErrorInfo);
        return false;
    }
}

// ---------------------------------------------------------------------------
// Email verification
// ---------------------------------------------------------------------------

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
        $mail->Subject = 'Confirm your email address for Cloudie';

        $name     = cloudie_email_esc($to_name !== '' ? $to_name : 'there');
        $safeLink = cloudie_email_esc($link);

        $body = "<p style=\"margin:0 0 16px\">Hi {$name},</p>"
              . '<p style="margin:0 0 20px">Thanks for signing up. Please confirm that this email address belongs to you. '
              . 'You can sign in once it is confirmed.</p>'
              . cloudie_email_button($link, 'Confirm my email')
              . '<p style="margin:0 0 20px;font-size:13px;color:#6b7590;word-break:break-all">'
              . "If the button does not work, copy this link into your browser:<br>"
              . "<a href=\"{$safeLink}\" style=\"color:#0a8fd8\">{$safeLink}</a></p>"
              . '<p style="margin:0">Regards,<br>The Cloudie team</p>';

        $mail->isHTML(true);
        $mail->Body = cloudie_email_layout(
            'Confirm your email address to start using Cloudie.',
            'Confirm your email address',
            $body,
            'If you did not create a Cloudie account, you can ignore this email.'
        );
        $mail->AltBody = 'Hi ' . ($to_name !== '' ? $to_name : 'there') . ",\n\n"
                       . "Thanks for signing up. Open this link to confirm your email address:\n{$link}\n\n"
                       . "If you did not create a Cloudie account, ignore this email.\n";

        $mail->send();
        return true;
    } catch (Exception $e) {
        error_log('send_verification_email failed: ' . $mail->ErrorInfo);
        return false;
    }
}

// ---------------------------------------------------------------------------
// Welcome
// ---------------------------------------------------------------------------

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

        $mail->isHTML(true);
        $mail->Body    = cloudie_welcome_email_html($to_name !== '' ? $to_name : 'there');
        $mail->AltBody = cloudie_welcome_email_text($to_name !== '' ? $to_name : 'there');

        $mail->send();
        return true;
    } catch (Exception $e) {
        error_log('send_welcome_email failed: ' . $mail->ErrorInfo);
        return false;
    }
}

/**
 * HTML body for the welcome email. $name is raw; it is escaped here.
 */
function cloudie_welcome_email_html(string $name): string {
    $n = cloudie_email_esc($name);
    $body = "<p style=\"margin:0 0 16px\">Hi {$n},</p>"
          . '<p style="margin:0 0 20px">Your account is ready. Every file you upload to Cloudie '
          . 'is checked for malware first (VirusTotal plus our own structure checks and AI model for PDFs), then '
          . 'encrypted with AES-256 before it is stored. Only you, with your key, can open it again.</p>'
          . '<p style="margin:0 0 8px;font-weight:700;color:#0b1f4d">How it works</p>'
          . '<ol style="margin:0 0 20px;padding-left:20px">'
          . '<li style="margin-bottom:4px">Sign in and choose <strong>Upload &amp; Scan</strong>.</li>'
          . '<li style="margin-bottom:4px">Cloudie scans the file. A file that is found to be malicious is refused.</li>'
          . '<li style="margin-bottom:4px">Clean files are encrypted and stored; a file with a warning is stored and tagged.</li>'
          . '<li style="margin-bottom:4px">You get a unique key for that file, on screen and by email, with a QR code.</li>'
          . '<li>Use the key any time to view, download or delete the file.</li>'
          . '</ol>'
          . cloudie_email_notice('info',
              '<strong>Protect your keys.</strong> Each file has its own AES-256 key, and Cloudie keeps only a fingerprint of it. '
              . 'If you lose a key, that file cannot be recovered by anyone, including us. Store keys in a password manager '
              . 'and never share them.')
          . '<p style="margin:0">Regards,<br>The Cloudie team</p>';

    return cloudie_email_layout(
        'Your Cloudie account is ready. Here is how it keeps your files safe.',
        'Welcome to Cloudie',
        $body,
        'You are receiving this because you created a Cloudie account.'
    );
}

/**
 * Plain-text fallback for the welcome email.
 */
function cloudie_welcome_email_text(string $name): string {
    return "Hi {$name},\n\n"
         . "Your account is ready. Every file you upload to Cloudie is checked for\n"
         . "malware first (VirusTotal plus our own structure checks and AI model for\n"
         . "PDFs), then encrypted with AES-256 before it is stored.\n"
         . "Only you, with your key, can open it again.\n\n"
         . "HOW IT WORKS\n"
         . "  1. Sign in and choose 'Upload & Scan'.\n"
         . "  2. Cloudie scans the file. A file found to be malicious is refused.\n"
         . "  3. Clean files are encrypted and stored; a file with a warning is stored and tagged.\n"
         . "  4. You get a unique key for that file, on screen and by email, with a QR code.\n"
         . "  5. Use the key any time to view, download or delete the file.\n\n"
         . "PROTECT YOUR KEYS\n"
         . "  Each file has its own AES-256 key, and Cloudie keeps only a fingerprint of it.\n"
         . "  If you lose a key, that file cannot be recovered by anyone, including us.\n"
         . "  Store keys in a password manager and never share them.\n\n"
         . "Regards,\nThe Cloudie team\n\n"
         . "This is an automated message; replies are not monitored.\n";
}
