"""
feature_extractor.py — Cloudie PDF structural feature extraction.

Extracts the 32-feature schema used to train the Random Forest classifier on
CIC-Evasive-PDFMal2022. The schema is FROZEN: do not add/remove features here,
or the model's expected input width (32) will mismatch and predictions fail.

Enhancement in this version: robust extraction. Malformed, encrypted, or
truncated PDFs no longer crash the analyzer. On any parse failure the extractor
returns a complete 32-length vector (zero-filled where a value can't be read)
plus an `extraction_ok` flag and an `error` message the caller can log.
"""

import re
import logging

logger = logging.getLogger("cloudie.features")

# ----------------------------------------------------------------------------
# FROZEN 32-FEATURE SCHEMA. The names AND their order must match the trained
# model exactly (malware_rf.pkl bundle["features"], which comes from the
# Final.csv columns). The model consumes these by name, so both the spelling
# (e.g. "JS", "Javascript", "OpenAction", "isEncrypted") and the position are
# part of the contract. If you retrain with a different schema, change BOTH
# this list and the model together.
# ----------------------------------------------------------------------------
FEATURE_NAMES = [
    "pdf_size",            # 1  total file size in KB
    "metadata_size",       # 2  size of metadata block
    "pages",               # 3  number of pages
    "xref_length",         # 4  length of the cross-reference table
    "title_characters",    # 5  number of characters in the title
    "isEncrypted",         # 6  encryption flag (0/1)
    "embedded_files",      # 7  count of embedded files
    "images",              # 8  count of images
    "contains_text",       # 9  amount of text (proxy count of BT operators)
    "header",              # 10 header marker present / version proxy
    "obj",                 # 11 count of "obj" markers
    "endobj",              # 12 count of "endobj" markers
    "stream",              # 13 count of "stream" markers
    "endstream",           # 14 count of "endstream" markers
    "xref",                # 15 count of "xref" markers
    "trailer",             # 16 count of "trailer" markers
    "startxref",           # 17 count of "startxref" markers
    "pageno",              # 18 /Page count
    "encrypt",             # 19 count of /Encrypt
    "ObjStm",              # 20 count of /ObjStm
    "JS",                  # 21 count of /JS
    "Javascript",          # 22 count of /JavaScript
    "AA",                  # 23 count of /AA (additional actions)
    "OpenAction",          # 24 count of /OpenAction
    "Acroform",            # 25 count of /AcroForm
    "JBIG2Decode",         # 26 count of /JBIG2Decode
    "RichMedia",           # 27 count of /RichMedia
    "launch",              # 28 count of /Launch
    "EmbeddedFile",        # 29 count of /EmbeddedFile
    "XFA",                 # 30 count of /XFA
    "URI",                 # 31 count of /URI (link / launch-URL actions)
    "Colors",              # 32 count of /Colors
]

assert len(FEATURE_NAMES) == 32, "Schema must contain exactly 32 features."

# Keyword markers counted directly from the raw PDF bytes.
# Keys MUST match the trained feature names above.
_KEYWORD_MARKERS = {
    "obj": rb"obj",
    "endobj": rb"endobj",
    "stream": rb"stream",
    "endstream": rb"endstream",
    "xref": rb"xref",
    "trailer": rb"trailer",
    "startxref": rb"startxref",
    "pageno": rb"/Page",
    "encrypt": rb"/Encrypt",
    "ObjStm": rb"/ObjStm",
    "JS": rb"/JS",
    "Javascript": rb"/JavaScript",
    "AA": rb"/AA",
    "OpenAction": rb"/OpenAction",
    "Acroform": rb"/AcroForm",
    "JBIG2Decode": rb"/JBIG2Decode",
    "RichMedia": rb"/RichMedia",
    "launch": rb"/Launch",
    "EmbeddedFile": rb"/EmbeddedFile",
    "XFA": rb"/XFA",
    "URI": rb"/URI",
}


def _safe_count(blob: bytes, needle: bytes) -> int:
    try:
        return blob.count(needle)
    except Exception:  # pragma: no cover - defensive
        return 0


def _zero_vector() -> dict:
    return {name: 0 for name in FEATURE_NAMES}


def extract_features(file_path: str) -> dict:
    """
    Extract the 32 structural features from a PDF on disk.

    Returns a dict:
      {
        "features":      {feature_name: value, ...},   # always 32 keys
        "vector":        [v1, v2, ..., v32],           # model-ready, ordered
        "extraction_ok": True/False,
        "error":         None or "message",
      }

    This function never raises on a bad PDF. A failed parse yields a fully
    zero-filled vector so the model can still produce a prediction (which the
    caller may then down-weight or flag using extraction_ok).
    """
    feats = _zero_vector()
    error = None
    ok = True

    try:
        with open(file_path, "rb") as fh:
            blob = fh.read()

        if not blob:
            raise ValueError("empty file")

        # --- size / structural metrics --------------------------------------
        feats["pdf_size"] = round(len(blob) / 1024.0, 2)  # KB

        # header / version
        header_match = re.search(rb"%PDF-(\d+)\.(\d+)", blob[:1024])
        feats["header"] = 1 if header_match else 0

        # metadata block size (between <x:xmpmeta ...> ... </x:xmpmeta> if present)
        meta_match = re.search(rb"<x:xmpmeta.*?</x:xmpmeta>", blob, re.DOTALL)
        feats["metadata_size"] = len(meta_match.group(0)) if meta_match else 0

        # title characters from /Title (...)
        title_match = re.search(rb"/Title\s*\((.*?)\)", blob, re.DOTALL)
        feats["title_characters"] = len(title_match.group(1)) if title_match else 0

        # encryption (isEncrypted is a 0/1 flag; encrypt is the raw /Encrypt count)
        feats["isEncrypted"] = 1 if b"/Encrypt" in blob else 0

        # pages: count /Type /Page (not /Pages)
        feats["pages"] = len(re.findall(rb"/Type\s*/Page[^s]", blob))

        # xref table length (chars between 'xref' and 'trailer')
        xref_match = re.search(rb"\bxref\b(.*?)\btrailer\b", blob, re.DOTALL)
        feats["xref_length"] = len(xref_match.group(1)) if xref_match else 0

        # embedded files and images (heuristic counts)
        feats["embedded_files"] = _safe_count(blob, b"/EmbeddedFile")
        feats["images"] = len(re.findall(rb"/Subtype\s*/Image", blob))

        # text proxy: count of BT (begin text) operators
        feats["contains_text"] = _safe_count(blob, b"BT")

        # colors heuristic: occurrences of /Colors
        feats["Colors"] = _safe_count(blob, b"/Colors")

        # --- keyword marker counts ------------------------------------------
        for key, needle in _KEYWORD_MARKERS.items():
            feats[key] = _safe_count(blob, needle)

    except Exception as exc:  # noqa: BLE001 - we want to swallow everything
        ok = False
        error = f"{type(exc).__name__}: {exc}"
        logger.warning("Feature extraction failed for %s -> %s", file_path, error)
        feats = _zero_vector()  # guarantee a clean 32-length vector on failure

    vector = [feats[name] for name in FEATURE_NAMES]
    return {
        "features": feats,
        "vector": vector,
        "extraction_ok": ok,
        "error": error,
    }


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) < 2:
        print("usage: python feature_extractor.py <file.pdf>")
        sys.exit(1)
    result = extract_features(sys.argv[1])
    print("extraction_ok:", result["extraction_ok"], "error:", result["error"])
    print("vector length:", len(result["vector"]))
    for n, v in result["features"].items():
        print(f"  {n:18s} = {v}")