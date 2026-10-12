<?php
/**
 * includes/storage.php
 * --------------------
 * Storage abstraction for encrypted blobs.
 *
 * Cloudie originally wrote ciphertext to a local directory (ENCRYPTED_DIR).
 * That works under XAMPP, but Cloud Run containers have an EPHEMERAL
 * filesystem: anything written to local disk is lost when the instance
 * restarts, and different instances never share files. Persistent blobs
 * must therefore live in Google Cloud Storage in the cloud.
 *
 * This layer hides that difference behind two functions:
 *
 *     storage_put_encrypted(string $stored_name, string $bytes): bool
 *     storage_get_encrypted(string $stored_name): ?string
 *     storage_delete_encrypted(string $stored_name): bool
 *
 * When USE_CLOUD_STORAGE is false (local dev / XAMPP) it reads & writes
 * ENCRYPTED_DIR exactly as before. When true (Cloud Run) it uses the
 * google-cloud-storage SDK against GCS_BUCKET. The rest of the app does
 * not need to know which backend is active.
 */

require_once __DIR__ . '/config.php';

/**
 * Lazily build and cache a Cloud Storage bucket handle.
 * On Cloud Run, authentication is automatic via the attached service
 * account (Application Default Credentials) — no key file needed.
 */
function gcs_bucket() {
    static $bucket = null;
    if ($bucket === null) {
        // Composer autoloader (vendor/ is created in the Docker build).
        $autoload = __DIR__ . '/../vendor/autoload.php';
        if (is_file($autoload)) {
            require_once $autoload;
        }
        if (!class_exists('\\Google\\Cloud\\Storage\\StorageClient')) {
            throw new RuntimeException(
                'google-cloud-storage SDK not installed (run composer require google/cloud-storage).'
            );
        }
        $client = new \Google\Cloud\Storage\StorageClient([
            'projectId' => GCP_PROJECT_ID,
        ]);
        $bucket = $client->bucket(GCS_BUCKET);
    }
    return $bucket;
}

/**
 * Persist an encrypted blob under $stored_name. Returns true on success.
 */
function storage_put_encrypted(string $stored_name, string $bytes): bool {
    if (!USE_CLOUD_STORAGE) {
        return (bool) @file_put_contents(ENCRYPTED_DIR . $stored_name, $bytes);
    }
    try {
        gcs_bucket()->upload($bytes, ['name' => $stored_name]);
        return true;
    } catch (Throwable $e) {
        error_log('storage_put_encrypted failed: ' . $e->getMessage());
        return false;
    }
}

/**
 * Read an encrypted blob back. Returns the raw ciphertext, or null if
 * it does not exist / could not be read.
 */
function storage_get_encrypted(string $stored_name): ?string {
    if (!USE_CLOUD_STORAGE) {
        $bytes = @file_get_contents(ENCRYPTED_DIR . $stored_name);
        return $bytes === false ? null : $bytes;
    }
    try {
        $object = gcs_bucket()->object($stored_name);
        if (!$object->exists()) {
            return null;
        }
        return $object->downloadAsString();
    } catch (Throwable $e) {
        error_log('storage_get_encrypted failed: ' . $e->getMessage());
        return null;
    }
}

/**
 * Delete an encrypted blob. Best-effort; returns true on success.
 */
function storage_delete_encrypted(string $stored_name): bool {
    if (!USE_CLOUD_STORAGE) {
        return @unlink(ENCRYPTED_DIR . $stored_name);
    }
    try {
        $object = gcs_bucket()->object($stored_name);
        if ($object->exists()) {
            $object->delete();
        }
        return true;
    } catch (Throwable $e) {
        error_log('storage_delete_encrypted failed: ' . $e->getMessage());
        return false;
    }
}
