"""
prediction_log.py — append-only logging of every Cloudie scan.

Writes one CSV row per analysed file: AI probability, AI label, VT hits,
combined verdict, confidence, whether the two engines disagreed, and extraction
status. This is a SEPARATE artifact from the 32-feature training schema — it
adds NO columns to the model input, so it cannot cause the 32/33 mismatch.

The resulting CSV is your Chapter 4 evidence base: you can compute the
disagreement rate, build a confusion matrix against ground truth, and quantify
how often the AI catches structural cases VirusTotal misses.
"""

import os
import csv
import threading
from datetime import datetime, timezone

_LOG_LOCK = threading.Lock()

LOG_FIELDS = [
    "timestamp_utc",
    "filename",
    "ai_proba",
    "ai_label",
    "vt_positives",
    "vt_total",
    "verdict",
    "confidence",
    "disagreement",
    "primary_detector",
    "extraction_ok",
    "extraction_error",
]


def _ensure_header(path: str):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        with open(path, "w", newline="", encoding="utf-8") as fh:
            csv.DictWriter(fh, fieldnames=LOG_FIELDS).writeheader()


def log_prediction(log_path: str, *, filename, ai_proba, ai_label,
                   vt_positives, vt_total, verdict, confidence, disagreement,
                   primary_detector, extraction_ok, extraction_error):
    """Append a single prediction row. Thread-safe; never raises to the caller."""
    row = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "filename": filename,
        "ai_proba": "" if ai_proba is None else round(float(ai_proba), 6),
        "ai_label": "" if ai_label is None else int(bool(ai_label)),
        "vt_positives": "" if vt_positives is None else int(vt_positives),
        "vt_total": "" if vt_total is None else int(vt_total),
        "verdict": verdict,
        "confidence": round(float(confidence), 4),
        "disagreement": int(bool(disagreement)),
        "primary_detector": primary_detector,
        "extraction_ok": int(bool(extraction_ok)),
        "extraction_error": extraction_error or "",
    }
    try:
        with _LOG_LOCK:
            _ensure_header(log_path)
            with open(log_path, "a", newline="", encoding="utf-8") as fh:
                csv.DictWriter(fh, fieldnames=LOG_FIELDS).writerow(row)
    except Exception as exc:  # never let logging break a scan
        print(f"[prediction_log] WARNING: failed to write log row: {exc}")
