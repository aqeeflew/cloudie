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
require_once $ROOT . '/includes/audit.php';
require_once $ROOT . '/includes/validate.php';

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
echo "Tamper-evident audit chain\n";
function audit_test_chain(int $uid, int $n): array {
    $rows = []; $prev = AUDIT_GENESIS;
    for ($i = 1; $i <= $n; $i++) {
        $time = '2026-10-22 10:00:' . sprintf('%02d', $i);
        $type = $i === 1 ? 'LOGIN' : 'SCAN';
        $fr   = $i % 2 ? null : 100 + $i;
        $det  = 'detail ' . $i;
        $h    = audit_hash($prev, $uid, $type, $fr, null, $det, $time);
        $rows[] = ['act_id' => 1000 + $i, 'act_type' => $type, 'details' => $det, 'act_time' => $time,
                   'file_ref' => $fr, 'key_ref' => null, 'chain_seq' => $i, 'prev_hash' => $prev, 'row_hash' => $h];
        $prev = $h;
    }
    return [$rows, ['seq' => $n, 'head' => $prev, 'mac' => audit_head_mac($uid, $n, $prev)]];
}
function kinds(array $res): array { return array_values(array_unique(array_column($res['problems'], 'kind'))); }

[$rows, $head] = audit_test_chain(7, 6);
$r = audit_verify_rows(7, $rows, $head);
check('an untouched chain verifies (6 sealed)', $r['ok'] && $r['sealed'] === 6 && $r['head'] === $head['head']);
check('hashes are deterministic', audit_hash(AUDIT_GENESIS, 7, 'LOGIN', null, null, 'x', 't') === audit_hash(AUDIT_GENESIS, 7, 'LOGIN', null, null, 'x', 't'));
check('hash depends on the user (an entry cannot be moved to another account)',
      audit_hash(AUDIT_GENESIS, 7, 'LOGIN', null, null, 'x', 't') !== audit_hash(AUDIT_GENESIS, 8, 'LOGIN', null, null, 'x', 't'));
check('a chain of user 7 does not verify as user 8', !audit_verify_rows(8, $rows, $head)['ok']);

$m = $rows; $m[2]['details'] = 'edited by an attacker';
$r = audit_verify_rows(7, $m, $head);
check('editing one entry is detected and pinpointed', !$r['ok'] && kinds($r) === ['edited'] && $r['problems'][0]['act_id'] === 1003);

$m = $rows; $m[2]['act_type'] = 'LOGOUT';
check('changing the event type is detected', !audit_verify_rows(7, $m, $head)['ok']);

$m = $rows; $m[3]['file_ref'] = 999;
check('changing the file reference is detected', !audit_verify_rows(7, $m, $head)['ok']);

$m = $rows; $m[2]['details'] = 'forged';
$m[2]['row_hash'] = hash('sha256', audit_canonical($m[2]['prev_hash'], 7, $m[2]['act_type'], $m[2]['file_ref'], null, 'forged', $m[2]['act_time']));
check('recomputing the hash WITHOUT the secret key does not help the attacker', !audit_verify_rows(7, $m, $head)['ok']);

$m = $rows; array_splice($m, 2, 1);
$r = audit_verify_rows(7, $m, $head);
check('deleting an entry from the middle is detected', !$r['ok'] && in_array('missing', kinds($r), true));

$m = array_slice($rows, 0, 4);
$r = audit_verify_rows(7, $m, $head);
check('deleting the most recent entries is detected (sealed head)', !$r['ok'] && kinds($r) === ['tail']);

$m = array_slice($rows, 0, 4);
$fakeHead = ['seq' => 4, 'head' => $m[3]['row_hash'], 'mac' => str_repeat('a', 64)];
check('rewriting the head without the key is detected', in_array('head', kinds(audit_verify_rows(7, $m, $fakeHead)), true));

$m = $rows; $tmp = $m[2]; $m[2] = $m[3]; $m[3] = $tmp;
check('reordering entries is detected', !audit_verify_rows(7, $m, $head)['ok']);

$m = $rows; array_splice($m, 3, 0, [['act_id' => 1099, 'act_type' => 'DELETE', 'details' => 'fake', 'act_time' => '2026-10-22 10:00:30',
        'file_ref' => null, 'key_ref' => null, 'chain_seq' => null, 'prev_hash' => null, 'row_hash' => null]]);
$r = audit_verify_rows(7, $m, $head);
check('an unsealed entry inserted inside the chain is detected', !$r['ok'] && in_array('unsealed', kinds($r), true));

$legacy = [['act_id' => 5, 'act_type' => 'LOGIN', 'details' => null, 'act_time' => '2026-01-01 00:00:00',
            'file_ref' => null, 'key_ref' => null, 'chain_seq' => null, 'prev_hash' => null, 'row_hash' => null]];
$r = audit_verify_rows(7, array_merge($legacy, $rows), $head);
check('earlier (unsealed) entries before the chain are reported, not flagged', $r['ok'] && $r['legacy'] === 1 && $r['sealed'] === 6);
$r = audit_verify_rows(9, $legacy, null);
check('a user with only earlier entries and no head is fine', $r['ok'] && $r['sealed'] === 0 && $r['legacy'] === 1);
check('an empty log with no head is fine', audit_verify_rows(9, [], null)['ok']);
check('wiping every sealed entry is detected', !audit_verify_rows(7, [], $head)['ok']);
check('labels exist for the event codes', audit_label('LOGIN') === 'Signed in' && audit_label('XYZ') === 'XYZ');

// ---------------------------------------------------------------------------
echo "\nSign-up validation\n";
check('good username accepted', validate_username('aqeef.azhar-01') === null);
check('username too short', validate_username('ab') !== null);
check('username too long', validate_username(str_repeat('a', 33)) !== null);
check('username boundary 3 and 32 accepted', validate_username('abc') === null && validate_username(str_repeat('a', 32)) === null);
check('username with spaces, symbols or markup rejected',
      validate_username('a b c') !== null && validate_username('<b>hi</b>') !== null && validate_username("bob\nx") !== null
      && validate_username('adm!n') !== null);
check('username must start with a letter or number', validate_username('.hidden') !== null && validate_username('-bob') !== null);
check('unicode lookalike / emoji username rejected', validate_username("\u{0430}dmin") !== null && validate_username("bob\u{1F600}") !== null);

check('good email accepted', validate_email('user@example.com') === null);
check('bad email rejected', validate_email('not-an-email') !== null && validate_email('a@b') !== null);
check('email longer than 120 rejected', validate_email(str_repeat('a', 115) . '@x.com') !== null);

check('phone is optional', validate_phone('') === null);
check('normal phone formats accepted', validate_phone('012-3456789') === null && validate_phone('+60 12 345 6789') === null);
check('letters or too long in phone rejected', validate_phone('call me') !== null && validate_phone(str_repeat('1', 21)) !== null);
check('very short phone rejected', validate_phone('12345') !== null);

check('good password accepted', validate_password('Tr1cky-Horse-Battery', 'aqeef', 'a@b.com') === null);
check('password under 8 rejected', validate_password('abc123') !== null);
check('password over 72 bytes rejected (bcrypt would cut it)', validate_password(str_repeat('x1', 37)) !== null
      && validate_password(str_repeat('ab', 36)) === null);
check('common passwords rejected, any case', validate_password('Password123') !== null && validate_password('QWERTY123') !== null);
check('one repeated character rejected', validate_password('aaaaaaaaaa') !== null);
check('password equal to username or email rejected',
      validate_password('aqeefazhar', 'aqeefazhar', 'x@y.com') !== null
      && validate_password('someone@example.com', 'bob', 'someone@example.com') !== null
      && validate_password('someone99', 'bob', 'someone99@example.com') !== null          // the part before the @
      && validate_password('someone99!x', 'bob', 'someone99@example.com') === null);

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
