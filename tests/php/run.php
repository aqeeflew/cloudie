<?php
/**
 * tests/php/run.php — dependency-free PHP tests (no PHPUnit, no database needed).
 *
 *   C:\xampp\php\php.exe C:\xampp\htdocs\cloudie\tests\php\run.php
 *
 * Exit code 0 = all passed, 1 = something failed.
 * Covers: AES round trip and wrong key, key hex helpers, integrity check after
 * decrypt, magic-byte upload check, client IP detection (X-Forwarded-For spoof),
 * rate-limit helpers that need no DB, and a syntax check (php -l) of every PHP file.
 */

$ROOT = dirname(__DIR__, 2);
require_once $ROOT . '/includes/aes.php';
require_once $ROOT . '/includes/upload_check.php';
require_once $ROOT . '/includes/ratelimit.php';   // db.php is loaded but no connection is opened

$passed = 0;
$failed = 0;

function check(string $name, bool $ok): void {
    global $passed, $failed;
    if ($ok) { $passed++; echo "  ok    $name\n"; }
    else     { $failed++; echo "  FAIL  $name\n"; }
}

function tmpfile_with(string $data): string {
    $p = tempnam(sys_get_temp_dir(), 'cl');
    file_put_contents($p, $data);
    return $p;
}

// ---------------------------------------------------------------------------
echo "AES-256-CBC\n";
$plain = str_repeat("Cloudie test line 0123456789\n", 100);
$src   = tmpfile_with($plain);
$key   = generate_aes_key();
$iv    = generate_iv();
check('key is 32 bytes, iv is 16 bytes', strlen($key) === 32 && strlen($iv) === 16);
check('two generated keys differ', generate_aes_key() !== generate_aes_key());

$cipher = aes_encrypt_file_to_string($src, $key, $iv);
check('ciphertext differs from plaintext and is padded to 16 bytes',
      $cipher !== null && $cipher !== $plain && strlen($cipher) % 16 === 0);
check('round trip returns the original bytes', aes_decrypt_string($cipher, $key, $iv) === $plain);

$wrongKey = str_repeat("\x01", 32);   // fixed key: the result is deterministic
$wrong    = aes_decrypt_string($cipher, $wrongKey, $iv);
check('wrong key does not return the plaintext', $wrong !== $plain);

$same = aes_encrypt_file_to_string($src, $key, generate_iv());
check('a different IV gives a different ciphertext', $same !== $cipher);
unlink($src);

// ---------------------------------------------------------------------------
echo "Key helpers\n";
$hex = key_to_hex($key);
check('hex key is 64 characters', strlen($hex) === 64);
check('hex round trip', key_from_hex($hex) === $key);
check('uppercase hex accepted', key_from_hex(strtoupper($hex)) === $key);
check('too short rejected', key_from_hex(substr($hex, 0, 62)) === null);
check('non-hex rejected', key_from_hex(str_repeat('z', 64)) === null);
check('only sha256(key) is stored: 64 hex characters',
      preg_match('/^[0-9a-f]{64}$/', hash_aes_key($key)) === 1 && hash_aes_key($key) !== $hex);

// ---------------------------------------------------------------------------
echo "Integrity check after decrypt\n";
$sha    = hash('sha256', $plain);
$report = json_encode(['file_sha256' => $sha]);
check('sha256 match', verify_plaintext_integrity($plain, md5($plain), $report) === ['ok' => true, 'method' => 'sha256']);
check('sha256 mismatch is rejected', verify_plaintext_integrity($plain . 'x', md5($plain), $report)['ok'] === false);
check('md5 fallback when there is no sha256 (old rows)', verify_plaintext_integrity($plain, md5($plain), null) === ['ok' => true, 'method' => 'md5']);
check('md5 mismatch is rejected', verify_plaintext_integrity($plain, str_repeat('0', 32), null)['ok'] === false);
check('nothing to compare = not blocked', verify_plaintext_integrity($plain, null, null) === ['ok' => true, 'method' => 'none']);
check('malformed scan report falls back to md5', verify_plaintext_integrity($plain, md5($plain), '{not json')['method'] === 'md5');

// ---------------------------------------------------------------------------
echo "Upload magic bytes\n";
$cases = [
    ['pdf',  "%PDF-1.4\n1 0 obj",             true],
    ['pdf',  "MZ\x90\x00 not a pdf",          false],
    ['png',  "\x89PNG\r\n\x1a\nxxxx",         true],
    ['png',  "GIF89a....",                    false],
    ['jpg',  "\xFF\xD8\xFF\xE0xx",            true],
    ['docx', "PK\x03\x04xx",                  true],
    ['docx', "%PDF-1.4",                      false],
    ['doc',  "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1x", true],
    ['txt',  "hello\nworld",                  true],
    ['txt',  "ab\0cd",                        false],
    ['rar',  "Rar!\x1a\x07\x00",              true],
    ['pdf',  "",                              false],
    ['exe',  "MZ",                            false],   // extension not on the allow-list
];
foreach ($cases as [$ext, $bytes, $expected]) {
    $f = tmpfile_with($bytes);
    check(sprintf('.%s %s', $ext, $expected ? 'accepted' : 'rejected') . ' (' . bin2hex(substr($bytes, 0, 4)) . ')',
          upload_magic_ok($f, $ext) === $expected);
    unlink($f);
}

// ---------------------------------------------------------------------------
echo "Client IP (rate limiting)\n";
function with_server(array $vars, callable $fn) {
    $old = $_SERVER;
    foreach (['REMOTE_ADDR', 'HTTP_X_FORWARDED_FOR'] as $k) unset($_SERVER[$k]);
    $_SERVER = array_merge($_SERVER, $vars);
    $r = $fn();
    $_SERVER = $old;
    return $r;
}
check('public REMOTE_ADDR is used as is',
      with_server(['REMOTE_ADDR' => '8.8.8.8'], 'client_ip') === '8.8.8.8');
check('public REMOTE_ADDR ignores a forged X-Forwarded-For',
      with_server(['REMOTE_ADDR' => '8.8.8.8', 'HTTP_X_FORWARDED_FOR' => '1.2.3.4'], 'client_ip') === '8.8.8.8');
check('behind a private proxy the LAST X-Forwarded-For entry is used (earlier ones can be forged)',
      with_server(['REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_FORWARDED_FOR' => '6.6.6.6, 203.0.113.9'], 'client_ip') === '203.0.113.9');
check('invalid X-Forwarded-For falls back to REMOTE_ADDR',
      with_server(['REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_FORWARDED_FOR' => 'not-an-ip'], 'client_ip') === '10.0.0.5');
check('localhost stays 127.0.0.1',
      with_server(['REMOTE_ADDR' => '127.0.0.1'], 'client_ip') === '127.0.0.1');

echo "Rate-limit helpers\n";
check('keys are hashed and case-insensitive', rl_key('Alice') === rl_key(' alice ') && strlen(rl_key('alice')) === 64);
check('keys never contain the raw value', strpos(rl_key('alice'), 'alice') === false);
check('every bucket has a [max, window] policy',
      count(array_filter(RL_POLICY, fn($p) => is_int($p[0]) && $p[0] > 0 && is_int($p[1]) && $p[1] > 0)) === count(RL_POLICY));
check('wait text', rl_wait_text(30) === '30 seconds' && rl_wait_text(1) === '1 second' && rl_wait_text(900) === '15 minutes' && rl_wait_text(100) === '2 minutes');

// ---------------------------------------------------------------------------
echo "Syntax check (php -l) of every PHP file\n";
$skip = ['/vendor/', '/PHPMailer/', '/backup', '/tests/', '/.git/'];
$it   = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($ROOT, FilesystemIterator::SKIP_DOTS));
$bad  = [];
$n    = 0;
foreach ($it as $f) {
    $path = str_replace('\\', '/', $f->getPathname());
    if (substr($path, -4) !== '.php') continue;
    foreach ($skip as $s) if (strpos($path, $s) !== false) continue 2;
    $n++;
    exec('"' . PHP_BINARY . '" -l ' . escapeshellarg($f->getPathname()) . ' 2>&1', $out, $code);
    if ($code !== 0) $bad[] = $path;
}
check("$n PHP files have no syntax errors" . ($bad ? ' (bad: ' . implode(', ', $bad) . ')' : ''), $n > 10 && !$bad);

// ---------------------------------------------------------------------------
echo "\n$passed passed, $failed failed\n";
exit($failed === 0 ? 0 : 1);
