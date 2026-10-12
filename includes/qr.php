<?php
/**
 * qr.php - Tiny QR helper.
 *
 * The thesis (Sec 3.3.7.6) describes the system showing a QR code containing
 * the AES key so the user can save it on their phone.
 *
 * We avoid pulling in a heavy library by using two strategies:
 *
 *   1. If the `endroid/qr-code` Composer package is installed, use it
 *      (fully offline, recommended for production).
 *   2. Otherwise, fall back to the public Google-Charts-style API at
 *      api.qrserver.com - the AES key never leaves the user's machine in
 *      that case because the URL is rendered client-side by the browser.
 *
 * Both paths return either a data: URI (offline) or an external URL
 * the <img> tag can load directly.
 */

function qr_image_src(string $payload, int $size = 240): string {
    // Path 1: endroid/qr-code if available
    if (class_exists('\\Endroid\\QrCode\\Builder\\Builder')) {
        try {
            $result = \Endroid\QrCode\Builder\Builder::create()
                ->data($payload)
                ->size($size)
                ->margin(10)
                ->build();
            return $result->getDataUri();
        } catch (Throwable $e) {
            // fall through to path 2
        }
    }

    // Path 2: client-side render via public API
    $encoded = urlencode($payload);
    return "https://api.qrserver.com/v1/create-qr-code/"
         . "?size={$size}x{$size}&data={$encoded}";
}
