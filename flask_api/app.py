"""
app.py — Cloudie Flask malware analysis API (enhanced).

Endpoints
---------
GET  /health         -> liveness + model/schema status
POST /analyze        -> analyse one uploaded PDF, return combined verdict

Enhancements in this version
----------------------------
1. predict_proba confidence scoring (not just a binary label)
2. Explicit VT-primary / AI-supporting verdict logic (verdict_engine.py,
   PRIMARY_DETECTOR = "VT")
3. Robust feature extraction that never crashes on a bad PDF
4. Per-scan prediction logging to CSV for Chapter 4 results

IMPORTANT: replace all four Flask files together —
  app.py, feature_extractor.py, malware_rf.pkl, malware_rf.metrics.json
plus the two new helpers (verdict_engine.py, prediction_log.py). The model
expects exactly 32 features; mixing old and new files causes the 32/33 mismatch.
"""

import os
import json
import tempfile
import logging

import joblib
import numpy as np
import pandas as pd
import requests
from flask import Flask, request, jsonify

from feature_extractor import extract_features, FEATURE_NAMES
from verdict_engine import combine, PRIMARY_DETECTOR
from prediction_log import log_prediction
import vt_client

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "malware_rf.pkl")
METRICS_PATH = os.path.join(BASE_DIR, "malware_rf.metrics.json")
PREDICTION_LOG_PATH = os.environ.get(
    "PREDICTION_LOG_PATH", os.path.join(BASE_DIR, "prediction_log.csv")
)

VT_API_KEY = os.environ.get("VT_API_KEY", "").strip()
VT_FILE_URL = "https://www.virustotal.com/api/v3/files"
VT_TIMEOUT = 30  # seconds

MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # 25 MB guard

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("cloudie.app")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

# ---------------------------------------------------------------------------
# Load model + metrics once at startup
# ---------------------------------------------------------------------------
def _load_model():
    """
    Load the trained model.

    Cloudie saves the model as a BUNDLE dict: {"model": <classifier>,
    "features": [<feature names in training order>]}. We unpack it the same way
    the original working app.py did:  bundle["model"], bundle.get("features").

    Returns (model, model_features) or (None, None) on failure.
    """
    if not os.path.exists(MODEL_PATH):
        logger.error("Model file not found at %s", MODEL_PATH)
        return None, None
    try:
        loaded = joblib.load(MODEL_PATH)

        # Unpack the bundle. Fall back gracefully if a bare model was ever saved.
        if isinstance(loaded, dict):
            model = loaded.get("model")
            model_features = loaded.get("features", FEATURE_NAMES)
        else:
            model = loaded
            model_features = FEATURE_NAMES

        if model is None:
            logger.error("Bundle loaded but contained no 'model' key.")
            return None, None

        # The classifier inside the bundle is the source of truth for width.
        n_expected = getattr(model, "n_features_in_", None)
        if n_expected is None:
            n_expected = len(model_features)  # use the saved feature list

        if n_expected != len(FEATURE_NAMES):
            logger.error(
                "SCHEMA MISMATCH: model expects %s features but extractor "
                "produces %s. Replace all four Flask files together.",
                n_expected, len(FEATURE_NAMES),
            )
        else:
            logger.info("Model loaded from bundle. Expects %s features.", n_expected)

        # Name-level check: the extractor must emit exactly the model's feature
        # names (matched by name at predict time). Flag any divergence loudly —
        # this is the exact class of mismatch that silently corrupts predictions.
        if model_features and set(model_features) != set(FEATURE_NAMES):
            only_model = sorted(set(model_features) - set(FEATURE_NAMES))
            only_extractor = sorted(set(FEATURE_NAMES) - set(model_features))
            logger.error(
                "FEATURE NAME MISMATCH: model-only=%s extractor-only=%s. "
                "Predictions will be unreliable until these match.",
                only_model, only_extractor,
            )

        return model, model_features
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to load model: %s", exc)
        return None, None


def _load_metrics():
    try:
        with open(METRICS_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


MODEL, MODEL_FEATURES = _load_model()
METRICS = _load_metrics()


# ---------------------------------------------------------------------------
# AI prediction with confidence
# ---------------------------------------------------------------------------
def ai_predict(vector):
    """
    Return (malicious_probability, label) using the RF model.
    malicious_probability is the predict_proba for the malicious class.
    Returns (None, None) if the model is unavailable or prediction fails.

    The model was trained on a named pandas DataFrame, so we rebuild a
    single-row DataFrame using the model's OWN saved feature order
    (MODEL_FEATURES, from bundle["features"]). Matching by name guarantees the
    values line up with training regardless of the extractor's internal order,
    and silences sklearn's "X does not have valid feature names" warning.
    """
    if MODEL is None:
        return None, None
    try:
        if len(vector) != len(FEATURE_NAMES):
            logger.error("Vector width %s != schema %s", len(vector), len(FEATURE_NAMES))
            return None, None

        # Align the extractor's values onto the model's expected columns BY NAME.
        # The extractor now emits exactly the model's feature names, so matching
        # by name (not position) guarantees each value lands in the right column
        # and can never silently drift if the ordering ever changes.
        value_by_name = dict(zip(FEATURE_NAMES, vector))
        cols = MODEL_FEATURES if MODEL_FEATURES else FEATURE_NAMES
        row = {col: value_by_name.get(col, 0) for col in cols}
        X = pd.DataFrame([row], columns=cols)

        proba = MODEL.predict_proba(X)[0]
        classes = list(getattr(MODEL, "classes_", [0, 1]))
        if 1 in classes:
            mal_idx = classes.index(1)
        else:
            mal_idx = int(np.argmax(classes))  # fallback: highest class label
        mal_proba = float(proba[mal_idx])
        label = bool(mal_proba >= 0.5)
        return mal_proba, label
    except Exception as exc:  # noqa: BLE001
        logger.warning("AI prediction failed: %s", exc)
        return None, None


# ---------------------------------------------------------------------------
# VirusTotal second opinion
# ---------------------------------------------------------------------------
def vt_scan(file_path, original_name="upload"):
    """
    Ask VirusTotal (PRIMARY detector) and return (positives, total).

    Uses vt_client.scan_file: SHA-256 lookup first (known files are not
    re-uploaded), otherwise upload and POLL until the analysis is completed.
    HTTP 409 (already known) is resolved via the hash report; 429 / timeouts /
    any error give (None, None) = "no result", never "clean". An analysis that
    reports zero engines is also "no result".
    positives = malicious + suspicious engines (same rule as before).
    """
    if not VT_API_KEY:
        logger.info("VT_API_KEY not set; skipping VirusTotal.")
        return None, None
    try:
        rep = vt_client.scan_file(file_path, original_name, api_key=VT_API_KEY)
        if not rep.get("available") or not rep.get("total"):
            logger.warning("VT returned no engine results (total=%s)", rep.get("total"))
            return None, None
        return int(rep["malicious"]) + int(rep["suspicious"]), int(rep["total"])
    except requests.RequestException as exc:
        logger.warning("VT request error: %s", exc)
        return None, None
    except Exception as exc:  # noqa: BLE001 - incl. TimeoutError, VTConfigError
        logger.warning("VT unavailable: %s", exc)
        return None, None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "model_loaded": MODEL is not None,
        "feature_count": len(FEATURE_NAMES),
        "model_expects": getattr(MODEL, "n_features_in_", None) or
                         (len(MODEL_FEATURES) if MODEL_FEATURES else None),
        "primary_detector": PRIMARY_DETECTOR,
        "vt_configured": bool(VT_API_KEY),
        "metrics": METRICS,
    })


@app.route("/scan", methods=["POST"])      # matches the existing Cloudie PHP caller
@app.route("/analyze", methods=["POST"])   # alias, kept for convenience
def analyze():
    if "file" not in request.files:
        return jsonify({"error": "no file uploaded (expected form field 'file')"}), 400

    uploaded = request.files["file"]
    if not uploaded.filename:
        return jsonify({"error": "empty filename"}), 400

    # Save to a temp path for extraction + optional VT upload.
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".pdf")
    os.close(tmp_fd)
    try:
        uploaded.save(tmp_path)

        # Magic-byte gate: the Random Forest only understands PDFs. Any other
        # file type skips structural analysis and is judged by VirusTotal alone.
        with open(tmp_path, "rb") as _fh:
            is_pdf = b"%PDF-" in _fh.read(1024)

        if is_pdf:
            # 1) Robust feature extraction
            ext = extract_features(tmp_path)
            vector = ext["vector"]
            extraction_ok = ext["extraction_ok"]
            extraction_error = ext["error"]

            # 2) Supporting signal: Random Forest probability
            ai_proba, ai_label = ai_predict(vector)
        else:
            ext = {"features": {n: 0 for n in FEATURE_NAMES}, "vector": [],
                   "extraction_ok": True, "error": None}
            extraction_ok, extraction_error = True, None
            ai_proba, ai_label = None, None

        # 3) PRIMARY detector: VirusTotal
        vt_positives, vt_total = vt_scan(tmp_path, uploaded.filename)

        # 4) Combined verdict
        result = combine(
            ai_proba=ai_proba,
            vt_positives=vt_positives,
            vt_total=vt_total,
            extraction_ok=extraction_ok,
        )

        # 5) Log for Chapter 4
        log_prediction(
            PREDICTION_LOG_PATH,
            filename=uploaded.filename,
            ai_proba=ai_proba,
            ai_label=ai_label,
            vt_positives=vt_positives,
            vt_total=vt_total,
            verdict=result["verdict"],
            confidence=result["confidence"],
            disagreement=result["disagreement"],
            primary_detector=result["primary"],
            extraction_ok=extraction_ok,
            extraction_error=extraction_error,
        )

        # ------------------------------------------------------------------
        # Flat, backward-compatible fields for the existing Cloudie PHP
        # (scan_and_encrypt.php reads these exact top-level keys):
        #   is_clean, verdict, probability_malicious, engine, indicators,
        #   file_md5
        # A file is stored ONLY if affirmatively clean. Anything else
        # (malicious, ai_detected_structural, suspicious, error) is blocked —
        # the safe default for a security tool.
        # ------------------------------------------------------------------
        is_clean = (result["verdict"] == "clean")

        # Human-readable engine string describing which detectors ran.
        engine_parts = []
        if ai_proba is not None:
            engine_parts.append("AI (Random Forest, structural)")
        if vt_positives is not None:
            engine_parts.append(f"VirusTotal ({vt_positives} hits)")
        elif VT_API_KEY:
            engine_parts.append("VirusTotal (no result)")
        engine_str = " + ".join(engine_parts) if engine_parts else "unavailable"

        # Indicators: concrete reasons the file was flagged, for the UI list.
        indicators = []
        if ai_proba is not None and ai_proba >= 0.5:
            indicators.append(
                f"AI structural score {round(ai_proba * 100, 1)}% malicious"
            )
        if vt_positives:
            indicators.append(f"VirusTotal: {vt_positives} engine(s) flagged it")
        if result["disagreement"]:
            indicators.append("AI and VirusTotal disagree (logged for review)")
        if not is_pdf:
            indicators.append("Not a PDF: structural AI analysis skipped (VirusTotal only)")
        elif not extraction_ok:
            indicators.append("PDF could not be fully parsed")

        # md5 / sha-256 / size of the uploaded file (PHP falls back to its own
        # md5 if absent; the report page shows sha-256 and size).
        file_md5 = file_sha256 = None
        file_size = None
        try:
            import hashlib
            with open(tmp_path, "rb") as _fh:
                _data = _fh.read()
            file_md5 = hashlib.md5(_data).hexdigest()
            file_sha256 = hashlib.sha256(_data).hexdigest()
            file_size = len(_data)
        except Exception:
            pass

        # AI verdict as a word, for the report card.
        if ai_label is None:
            ai_verdict = "unknown"
        else:
            ai_verdict = "malicious" if ai_label else "clean"

        ai_block = {
            # legacy keys kept for backward compatibility
            "malicious_probability": None if ai_proba is None else round(ai_proba, 4),
            "label": ai_verdict if ai_label is not None else None,
            # keys the report page (scan_report.php) actually reads
            "verdict": ai_verdict,
            "probability_malicious": None if ai_proba is None else round(ai_proba, 4),
            "probability_clean": None if ai_proba is None else round(1 - ai_proba, 4),
            "engine": "Random Forest",
            "n_trees": getattr(MODEL, "n_estimators", None),
        }

        # VirusTotal block. vt_scan() only returns a combined positive count and
        # a total, so we surface those and derive the fields the report expects.
        vt_available = vt_positives is not None and vt_total is not None
        vt_block = {
            "positives": vt_positives,          # legacy key read by scan_and_encrypt.php
            "total": vt_total,
            "configured": bool(VT_API_KEY),
            "available": vt_available,
        }
        if vt_available:
            vt_block["verdict"] = "malicious" if vt_positives else "clean"
            vt_block["malicious"] = int(vt_positives)
            vt_block["suspicious"] = 0
            vt_block["harmless"] = max(0, int(vt_total) - int(vt_positives))
        else:
            vt_block["note"] = ("VirusTotal is not configured for this scan."
                                if not VT_API_KEY else
                                "No VirusTotal result was available for this file.")

        combined_block = {
            "reason": result["rationale"],
            "sources": [s for s in (
                "AI (Random Forest)" if ai_proba is not None else None,
                "VirusTotal" if vt_positives is not None else None,
            ) if s],
            "confidence": result["confidence"],
            "primary": result["primary"],
            "disagreement": result["disagreement"],
        }

        response = {
            # ---- flat keys the existing PHP reads (do not rename) ----------
            "is_clean": is_clean,
            "verdict": result["verdict"],
            "probability_malicious": None if ai_proba is None else round(ai_proba, 4),
            "engine": engine_str,
            "indicators": indicators,
            "file_md5": file_md5,

            # ---- file metadata shown on the report page --------------------
            "filename": uploaded.filename,
            "file_sha256": file_sha256,
            "file_size": file_size,
            "is_pdf": is_pdf,

            # ---- the 32 extracted structural features (the report's
            #      "Key features" table + "Show all 32 features" list) -------
            "features": ext["features"],

            # ---- richer structure the report card renders ------------------
            "ai": ai_block,
            "virustotal": vt_block,
            "combined": combined_block,
            "extraction": {
                "ok": extraction_ok,
                "error": extraction_error,
            },
            "confidence": result["confidence"],
            "disagreement": result["disagreement"],
            "primary_detector": result["primary"],
            "rationale": result["rationale"],
        }
        return jsonify(response), 200

    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


if __name__ == "__main__":
    # Local dev server. For deployment use a WSGI server (gunicorn/waitress)
    # and disable debug.
    app.run(host="0.0.0.0", port=5000, debug=False)