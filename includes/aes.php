<?php
require_once __DIR__ . '/config.php';

/**
 * Generate a fresh 256-bit AES key.
 * Returns the raw 32-byte key (binary). Convert with bin2hex() / base64_encode()
 * as needed for QR display.
 */
function generate_aes_key(): string {
    return random_bytes(AES_KEY_LEN);
}

function generate_iv(): string {
    return random_bytes(AES_IV_LEN);
}

/**
 * Encrypt the contents of $src_path with $key + $iv using AES-256-CBC and
 * write the ciphertext to $dst_path. Returns true on success.
 */
function aes_encrypt_file(string $src_path,
                          string $dst_path,
                          string $key,
                          string $iv): bool {
    $plaintext = @file_get_contents($src_path);
    if ($plaintext === false) return false;

    $cipher = openssl_encrypt($plaintext, AES_CIPHER, $key,
                              OPENSSL_RAW_DATA, $iv);
    if ($cipher === false) return false;

    return (bool) @file_put_contents($dst_path, $cipher);
}

/**
 * Decrypt $src_path into $dst_path using $key + $iv. Returns true on success.
 */
function aes_decrypt_file(string $src_path,
                          string $dst_path,
                          string $key,
                          string $iv): bool {
    $cipher = @file_get_contents($src_path);
    if ($cipher === false) return false;

    $plain = openssl_decrypt($cipher, AES_CIPHER, $key,
                             OPENSSL_RAW_DATA, $iv);
    if ($plain === false) return false;

    return (bool) @file_put_contents($dst_path, $plain);
}

/**
 * Decrypt $src_path entirely in memory and return the plaintext, or null on
 * failure. Used for view / download flows so we never write the cleartext to
 * disk.
 */
function aes_decrypt_to_string(string $src_path,
                               string $key,
                               string $iv): ?string {
    $cipher = @file_get_contents($src_path);
    if ($cipher === false) return null;
    $plain = openssl_decrypt($cipher, AES_CIPHER, $key,
                             OPENSSL_RAW_DATA, $iv);
    return $plain === false ? null : $plain;
}

/**
 * Encrypt the file at $src_path and RETURN the ciphertext bytes (instead of
 * writing them to a destination path). Used by the Cloud Storage path so the
 * blob can be uploaded directly to GCS without ever touching local disk.
 * Returns null on failure.
 */
function aes_encrypt_file_to_string(string $src_path,
                                    string $key,
                                    string $iv): ?string {
    $plaintext = @file_get_contents($src_path);
    if ($plaintext === false) return null;
    $cipher = openssl_encrypt($plaintext, AES_CIPHER, $key,
                              OPENSSL_RAW_DATA, $iv);
    return $cipher === false ? null : $cipher;
}

/**
 * Decrypt raw ciphertext BYTES (already in memory) and return the plaintext,
 * or null on failure. Used by the Cloud Storage path after downloading the
 * blob from GCS.
 */
function aes_decrypt_string(string $cipher,
                            string $key,
                            string $iv): ?string {
    $plain = openssl_decrypt($cipher, AES_CIPHER, $key,
                             OPENSSL_RAW_DATA, $iv);
    return $plain === false ? null : $plain;
}

/**
 * Hash an AES key for verification storage.
 * We never persist the raw key in the database.
 */
function hash_aes_key(string $key): string {
    return hash('sha256', $key);
}

/**
 * Check a decrypted file against the fingerprint recorded at upload time.
 *
 * AES-CBC has no authentication tag, so a tampered or corrupted ciphertext can
 * still decrypt "successfully" to different bytes. Comparing the plaintext with
 * the original file's hash catches that.
 *
 * Uses SHA-256 from the stored scan report when present (all new uploads),
 * otherwise the stored MD5 (files.file_md5). Returns:
 *   ['ok' => bool, 'method' => 'sha256' | 'md5' | 'none']
 * 'none' (ok = true) only when the row has nothing to compare against.
 */
function verify_plaintext_integrity(string $plain, ?string $md5, ?string $scan_report_json): array {
    $report = $scan_report_json ? json_decode($scan_report_json, true) : null;
    $sha    = is_array($report) ? ($report['file_sha256'] ?? null) : null;

    if (is_string($sha) && preg_match('/^[0-9a-f]{64}$/i', $sha)) {
        return ['ok'     => hash_equals(strtolower($sha), hash('sha256', $plain)),
                'method' => 'sha256'];
    }
    if (is_string($md5) && preg_match('/^[0-9a-f]{32}$/i', $md5)) {
        return ['ok'     => hash_equals(strtolower($md5), md5($plain)),
                'method' => 'md5'];
    }
    return ['ok' => true, 'method' => 'none'];
}

function key_to_hex(string $raw_key): string {
    return bin2hex($raw_key);
}

function key_from_hex(string $hex): ?string {
    if (!ctype_xdigit($hex) || strlen($hex) !== AES_KEY_LEN * 2) return null;
    return hex2bin($hex);
}