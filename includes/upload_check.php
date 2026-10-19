<?php
/**
 * includes/upload_check.php
 * -------------------------
 * Magic-byte check: does the file's real content match its extension?
 * (An extension alone is trivial to fake: "virus.exe" renamed to "photo.png".)
 *
 * Returns true when the first bytes are consistent with the claimed type.
 * This is a sanity check, not a malware scan; VirusTotal still judges content.
 */

function upload_magic_ok(string $path, string $ext): bool {
    $fh = @fopen($path, 'rb');
    if ($fh === false) return false;
    $head = (string)fread($fh, 8192);
    fclose($fh);
    if ($head === '') return false;

    $starts = static fn(string $sig): bool => strncmp($head, $sig, strlen($sig)) === 0;

    switch (strtolower($ext)) {
        case 'pdf':   // header may be preceded by a little junk, but within 1 KB
            return strpos(substr($head, 0, 1024), '%PDF-') !== false;
        case 'png':
            return $starts("\x89PNG\r\n\x1a\n");
        case 'jpg':
        case 'jpeg':
            return $starts("\xFF\xD8\xFF");
        case 'zip':
        case 'docx':
        case 'xlsx':
        case 'pptx':  // OOXML files are ZIP containers
            return $starts("PK\x03\x04") || $starts("PK\x05\x06");
        case 'rar':
            return $starts("Rar!\x1a\x07");
        case 'doc':
        case 'xls':
        case 'ppt':   // legacy OLE2 container (a few .doc files are really RTF)
            return $starts("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1") || $starts('{\\rtf');
        case 'txt':
        case 'csv':   // plain text: no NUL bytes
            return strpos($head, "\0") === false;
        default:
            return false;
    }
}
