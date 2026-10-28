"""
build_benign_set.py
-------------------
Builds the real-world benign PDF set used by benign_fp_benchmark.py.

Source: GovDocs1 (Digital Corpora, https://digitalcorpora.org/corpora/file-corpora/files/), about one million
files collected from US government (.gov) web sites; a standard corpus for testing forensic and security tools.
These files were never part of CIC-Evasive-PDFMal2022, so the test is independent of the training data.

The zip is only READ: members are never extracted with their own paths and nothing is run. A member counts as a
PDF by its magic bytes (the same gate as flask_api/app.py), not by its extension.

Usage (from C:\\xampp\\htdocs\\cloudie):
    flask_api\\.venv\\Scripts\\python.exe ml\\build_benign_set.py <path to 000.zip> [--n 250] [--seed 42] [--max-mb 10]

Output: ml/benign_set/govdocs1/*.pdf and ml/benign_set/manifest.csv (file, sha256, size, source).
"""

import argparse
import csv
import hashlib
import os
import random
import re
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(ROOT, "ml", "benign_set")
PDF_DIR = os.path.join(OUT_DIR, "govdocs1")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("zip_path")
    ap.add_argument("--n", type=int, default=250)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--max-mb", type=float, default=10.0, help="skip PDFs larger than this (keeps the repo small)")
    args = ap.parse_args()
    max_bytes = int(args.max_mb * 1024 * 1024)
    source = os.path.basename(args.zip_path)

    with zipfile.ZipFile(args.zip_path) as zf:
        candidates = []
        for info in zf.infolist():
            if info.is_dir() or info.file_size == 0 or info.file_size > max_bytes:
                continue
            with zf.open(info) as fh:
                if b"%PDF-" in fh.read(1024):
                    candidates.append(info)
        candidates.sort(key=lambda i: i.filename)
        print("PDFs in %s (<= %.0f MB): %d" % (source, args.max_mb, len(candidates)))

        picked = random.Random(args.seed).sample(candidates, min(args.n, len(candidates)))
        picked.sort(key=lambda i: i.filename)

        os.makedirs(PDF_DIR, exist_ok=True)
        rows = []
        for info in picked:
            data = zf.read(info)
            # Flat, safe name: never reuse the member's directory part.
            stem = re.sub(r"[^A-Za-z0-9_-]", "_", os.path.splitext(os.path.basename(info.filename))[0])
            name = stem + ".pdf"
            with open(os.path.join(PDF_DIR, name), "wb") as out:
                out.write(data)
            rows.append({"file": name, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
                         "source": "GovDocs1 %s/%s" % (source, info.filename)})

    with open(os.path.join(OUT_DIR, "manifest.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["file", "sha256", "size", "source"])
        w.writeheader()
        w.writerows(rows)
    total = sum(r["size"] for r in rows)
    print("wrote %d PDFs (%.1f MB) to %s (seed %d)" % (len(rows), total / 1048576, PDF_DIR, args.seed))


if __name__ == "__main__":
    main()
