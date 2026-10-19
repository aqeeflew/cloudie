<?php
/**
 * qr.php - Tiny QR helper.
 *
 * Shows the AES key as a QR code so the user can save it on their phone.
 *
 * The QR is generated SERVER-SIDE with the `endroid/qr-code` Composer package
 * and returned as a data: URI, so the key is never sent to any third party.
 *
 * If the package is not installed (for example local XAMPP before running
 * `composer install`), this returns '' and the page shows the key as text
 * only. There is deliberately NO online fallback: putting the key in a URL
 * for an external QR service would leak it.
 */

function qr_image_src(string $payload, int $size = 240): string {
    $autoload = __DIR__ . '/../vendor/autoload.php';
    if (is_file($autoload)) {
        require_once $autoload;
    }

    if (class_exists('\\Endroid\\QrCode\\Builder\\Builder')) {
        try {
            $result = \Endroid\QrCode\Builder\Builder::create()
                ->data($payload)
                ->size($size)
                ->margin(10)
                ->build();
            return $result->getDataUri();
        } catch (Throwable $e) {
            error_log('qr_image_src failed: ' . $e->getMessage());
        }
    }
    return '';
}
