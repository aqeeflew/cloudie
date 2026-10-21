"""
build_feature_reference.py
--------------------------
Builds flask_api/feature_reference.json: for every one of the 32 model features,
the typical value in the training data for benign and for malicious PDFs.

The Flask API uses it to show "your file vs typical benign vs typical malicious"
next to each feature's contribution to the AI score (explainable verdicts).

Encoding matches the model: header "%PDF-1.6" -> 1.6, contains_text Yes/No -> 1/0,
and the identifier column `name` is NOT a feature.

Usage (from C:\\xampp\\htdocs\\cloudie):
    flask_api\\.venv\\Scripts\\python.exe ml\\build_feature_reference.py
"""

import json
import os
import sys

import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV = os.path.join(ROOT, "flask_api", "Final.csv")
OUT = os.path.join(ROOT, "flask_api", "feature_reference.json")


def main():
    df = pd.read_csv(CSV)
    df = df.drop(columns=[c for c in ("name",) if c in df.columns])

    df["contains_text"] = (
        df["contains_text"].astype(str).str.strip().str.lower().map({"yes": 1, "no": 0}).fillna(0)
    )
    df["header"] = pd.to_numeric(
        df["header"].astype(str).str.extract(r"(\d+\.\d+)")[0], errors="coerce"
    ).fillna(0.0)

    label = df["class"].astype(str).str.strip().str.lower()
    feats = [c for c in df.columns if c != "class"]
    if len(feats) != 32:
        sys.exit(f"expected 32 features, found {len(feats)}")
    df[feats] = df[feats].apply(pd.to_numeric, errors="coerce").fillna(0.0)

    ben = df[label == "benign"]
    mal = df[label == "malicious"]
    ref = {}
    for f in feats:
        ref[f] = {
            "benign_median": float(ben[f].median()),
            "malicious_median": float(mal[f].median()),
            "benign_nonzero_pct": round(float((ben[f] != 0).mean() * 100), 1),
            "malicious_nonzero_pct": round(float((mal[f] != 0).mean() * 100), 1),
        }
    payload = {
        "source": "CIC-Evasive-PDFMal2022 (Final.csv)",
        "n_benign": int(len(ben)),
        "n_malicious": int(len(mal)),
        "features": ref,
    }
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    print(f"wrote {OUT}: {len(ref)} features, {len(ben)} benign, {len(mal)} malicious")


if __name__ == "__main__":
    main()
