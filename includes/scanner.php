<?php
require_once __DIR__ . '/config.php';

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

    $ch = curl_init(SCANNER_URL);
    $cfile = new CURLFile($file_path,
                          mime_content_type($file_path) ?: 'application/octet-stream',
                          $original_name);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => ['file' => $cfile],
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
    $ch = curl_init(SCANNER_HEALTH);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 5,
    ]);
    $body = curl_exec($ch);
    curl_close($ch);
    if ($body === false) return ['ok' => false];
    $json = json_decode($body, true);
    return ['ok' => is_array($json), 'data' => $json];
}
