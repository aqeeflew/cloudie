<?php
require_once __DIR__ . '/config.php';

/**
 * Auth headers for the Flask scanner.
 *
 * On Cloud Run the Flask service is private (IAM): the caller must present a
 * Google-signed ID token whose audience is the Flask service URL. This PHP
 * service gets one from the metadata server using its own service account.
 * Locally (SCANNER_AUTH=none) no header is sent.
 *
 * Returns ['ok' => bool, 'headers' => string[], 'error' => string|null].
 */
function scanner_auth_headers(string $url): array {
    if (SCANNER_AUTH !== 'iam') {
        return ['ok' => true, 'headers' => [], 'error' => null];
    }

    $p = parse_url($url);
    if (empty($p['scheme']) || empty($p['host'])) {
        return ['ok' => false, 'headers' => [], 'error' => 'Invalid scanner URL.'];
    }
    $audience = $p['scheme'] . '://' . $p['host'];

    static $cache = [];   // audience => ['token' => string, 'exp' => int] (per request)
    if (isset($cache[$audience]) && $cache[$audience]['exp'] > time() + 60) {
        return ['ok' => true, 'headers' => ['Authorization: Bearer ' . $cache[$audience]['token']], 'error' => null];
    }

    $meta = getenv('GCE_METADATA_HOST') ?: 'metadata.google.internal';
    $ch = curl_init('http://' . $meta . '/computeMetadata/v1/instance/service-accounts/default/identity?audience='
                    . rawurlencode($audience));
    curl_setopt_array($ch, [
        CURLOPT_HTTPHEADER     => ['Metadata-Flavor: Google'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 5,
        CURLOPT_CONNECTTIMEOUT => 3,
    ]);
    $token = curl_exec($ch);
    $http  = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    $token = is_string($token) ? trim($token) : '';
    if ($http !== 200 || $token === '' || substr_count($token, '.') !== 2) {
        error_log('scanner_auth_headers: could not get an ID token (HTTP ' . $http . ')');
        return ['ok' => false, 'headers' => [], 'error' => 'Could not authenticate to the AI scanner.'];
    }

    $cache[$audience] = ['token' => $token, 'exp' => time() + 3000];   // tokens last 1 h
    return ['ok' => true, 'headers' => ['Authorization: Bearer ' . $token], 'error' => null];
}

/**
 * Call the Flask /scan endpoint with an uploaded file.
 *
 * Returns an associative array with at least:
 *   ['ok' => bool, 'data' => array|null, 'error' => string|null]
 *
 * On success, $data contains the JSON the Flask API returned, including
 *   verdict, is_clean, probability_malicious, indicators, file_md5, ...
 */
function scan_file_with_ai(string $file_path, string $original_name): array {
    if (!file_exists($file_path)) {
        return ['ok' => false, 'data' => null,
                'error' => 'File not found for scanning.'];
    }

    $auth = scanner_auth_headers(SCANNER_URL);
    if (!$auth['ok']) {
        return ['ok' => false, 'data' => null, 'error' => $auth['error']];
    }

    $ch = curl_init(SCANNER_URL);
    $cfile = new CURLFile($file_path,
                          mime_content_type($file_path) ?: 'application/octet-stream',
                          $original_name);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => ['file' => $cfile],
        CURLOPT_HTTPHEADER     => $auth['headers'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => SCANNER_TIMEOUT,
        CURLOPT_CONNECTTIMEOUT => 10,
    ]);

    $body     = curl_exec($ch);
    $http     = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curl_err = curl_error($ch);
    curl_close($ch);

    if ($body === false) {
        return ['ok' => false, 'data' => null,
                'error' => 'AI scanner unreachable: ' . $curl_err];
    }

    $json = json_decode($body, true);
    if (!is_array($json)) {
        return ['ok' => false, 'data' => null,
                'error' => 'Scanner returned invalid JSON (HTTP ' . $http . ').'];
    }
    if ($http >= 400) {
        return ['ok' => false, 'data' => $json,
                'error' => $json['error'] ?? ('Scanner HTTP ' . $http)];
    }

    return ['ok' => true, 'data' => $json, 'error' => null];
}

function scanner_health(): array {
    $auth = scanner_auth_headers(SCANNER_HEALTH);
    if (!$auth['ok']) return ['ok' => false];
    $ch = curl_init(SCANNER_HEALTH);
    curl_setopt_array($ch, [
        CURLOPT_HTTPHEADER     => $auth['headers'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 5,
    ]);
    $body = curl_exec($ch);
    curl_close($ch);
    if ($body === false) return ['ok' => false];
    $json = json_decode($body, true);
    return ['ok' => is_array($json), 'data' => $json];
}
