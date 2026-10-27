<?php
/**
 * includes/validate.php
 * ---------------------
 * Server-side checks for the sign-up form. Each function returns null when the value is fine, or a short
 * message for the user. Limits follow the database columns (users.username 64, email 120, phone_num 20), so
 * a too-long value gives a clear message instead of a generic database error.
 *
 * Pure functions, no database: tested in tests/php/run.php.
 */

const USERNAME_MIN = 3;
const USERNAME_MAX = 32;
const EMAIL_MAX    = 120;
const PASSWORD_MIN = 8;
const PASSWORD_MAX = 72;   // bcrypt only uses the first 72 BYTES: longer passwords would be cut silently

/** The most common passwords (lower case). Not a full list: a cheap guard against the obvious ones. */
const COMMON_PASSWORDS = [
    'password', 'password1', 'password123', '12345678', '123456789', '1234567890', 'qwertyui', 'qwerty123',
    'qwertyuiop', 'iloveyou', 'admin123', 'welcome1', 'welcome123', 'abc12345', 'abcd1234', 'letmein123',
    'changeme', 'passw0rd', 'p@ssw0rd', 'p@ssword', '11111111', '00000000', 'asdfghjk', 'monkey123',
    'football1', 'dragon123', 'cloudie123', 'cloudie1', 'malaysia1', 'malaysia123', 'sayangkamu',
];

function validate_username(string $u): ?string {
    $len = mb_strlen($u, 'UTF-8');
    if ($len < USERNAME_MIN || $len > USERNAME_MAX) {
        return 'Username must be ' . USERNAME_MIN . '-' . USERNAME_MAX . ' characters.';
    }
    if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]*$/', $u)) {
        return 'Username can use letters, numbers, dot, underscore and hyphen, and must start with a letter or number.';
    }
    return null;
}

function validate_email(string $e): ?string {
    if (strlen($e) > EMAIL_MAX) {
        return 'Email address is too long (maximum ' . EMAIL_MAX . ' characters).';
    }
    if (!filter_var($e, FILTER_VALIDATE_EMAIL)) {
        return 'Please enter a valid email address.';
    }
    return null;
}

/** Phone is optional: an empty value is fine. */
function validate_phone(string $p): ?string {
    if ($p === '') return null;
    if (strlen($p) > 20 || !preg_match('/^[0-9+()\-\s]{7,20}$/', $p)) {
        return 'Phone number can use digits, spaces, + ( ) and -, 7 to 20 characters. Leave it empty if you prefer.';
    }
    return null;
}

function validate_password(string $pass, string $username = '', string $email = ''): ?string {
    if (strlen($pass) < PASSWORD_MIN) {
        return 'Password must be at least ' . PASSWORD_MIN . ' characters.';
    }
    if (strlen($pass) > PASSWORD_MAX) {
        return 'Password can be at most ' . PASSWORD_MAX . ' characters.';
    }
    $lower = strtolower($pass);
    if (in_array($lower, COMMON_PASSWORDS, true)) {
        return 'That password is too common. Please choose a less predictable one.';
    }
    if (preg_match('/^(.)\1+$/s', $pass)) {
        return 'Password cannot be one character repeated.';
    }
    if ($username !== '' && $lower === strtolower($username)) {
        return 'Password cannot be the same as your username.';
    }
    if ($email !== '' && ($lower === strtolower($email) || $lower === strtolower((string)strstr($email, '@', true)))) {
        return 'Password cannot be the same as your email.';
    }
    return null;
}
