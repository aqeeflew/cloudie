"""
train_model.py
--------------
Trains a Random Forest classifier on a PDF malware dataset.

The dataset must be a CSV with 33 numeric features extracted from each PDF
plus one label column ('Class' = 1 for malicious, 0 for benign), as described
in the thesis (Chapter 3.3.2).

Typical features (PDFiD style, what the analyzer also extracts at runtime):
    pdfsize, metadata size, pages, xref_length, title_characters,
    isEncrypted, embedded_files, images, text, /Header, /Obj, /Endobj,
    /Stream, /Endstream, /Xref, /Trailer, /StartXref, /Page, /Encrypt,
    /ObjStm, /JS, /JavaScript, /AA, /OpenAction, /AcroForm, /JBIG2Decode,
    /RichMedia, /Launch, /EmbeddedFile, /XFA, /Colors, /URI, /Action

Usage:
    python train_model.py --data ./pdf_dataset.csv --out ./malware_rf.pkl
"""

import argparse
import json
import os
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report,
                              confusion_matrix, f1_score, precision_score,
                              recall_score)
from sklearn.model_selection import train_test_split


# Canonical feature order used at inference time (must match feature_extractor.py)
FEATURE_COLUMNS = [
    "pdfsize", "metadata_size", "pages", "xref_length", "title_characters",
    "isEncrypted", "embedded_files", "images", "text",
    "header", "obj", "endobj", "stream", "endstream", "xref", "trailer",
    "startxref", "page_count", "encrypt", "objstm", "js", "javascript",
    "aa", "openaction", "acroform", "jbig2decode", "richmedia", "launch",
    "embeddedfile", "xfa", "colors", "uri", "action_count",
]


def load_dataset(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    # Strip any whitespace, normalise column names to lowercase
    df.columns = [c.strip().lower() for c in df.columns]
    return df


def prepare_xy(df: pd.DataFrame):
    # Detect the label column
    label_col = None
    for candidate in ("class", "label", "target", "is_malicious"):
        if candidate in df.columns:
            label_col = candidate
            break
    if label_col is None:
        raise ValueError("Dataset must contain a label column "
                         "(class / label / target / is_malicious).")

    # Coerce label to {0,1}; tolerate strings like 'malicious'/'benign'
    y_raw = df[label_col]
    if y_raw.dtype == object:
        y = y_raw.str.strip().str.lower().map(
            {"malicious": 1, "malware": 1, "1": 1,
             "benign": 0, "clean": 0, "0": 0}
        )
    else:
        y = y_raw.astype(int)

    # Use canonical feature columns when present, otherwise fall back to
    # every numeric column except the label
    feature_cols = [c for c in FEATURE_COLUMNS if c in df.columns]
    if len(feature_cols) < 5:
        feature_cols = [c for c in df.columns
                        if c != label_col and pd.api.types.is_numeric_dtype(df[c])]

    X = df[feature_cols].fillna(0).astype(float)
    return X, y, feature_cols


def train(X, y, n_estimators: int = 200, random_state: int = 42):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=random_state
    )

    model = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        n_jobs=-1,
        class_weight="balanced",      # helps with imbalanced sets (Sec 2.8.2)
        random_state=random_state,
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    metrics = {
        "accuracy":  float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall":    float(recall_score(y_test, y_pred, zero_division=0)),
        "f1":        float(f1_score(y_test, y_pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
    }
    return model, metrics, classification_report(y_test, y_pred, zero_division=0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="Path to the CSV dataset.")
    ap.add_argument("--out",  default="malware_rf.pkl",
                    help="Where to save the trained model.")
    ap.add_argument("--trees", type=int, default=200)
    args = ap.parse_args()

    print(f"[*] Loading dataset from {args.data} ...")
    df = load_dataset(args.data)
    print(f"    rows={len(df):,}, cols={len(df.columns)}")

    X, y, feature_cols = prepare_xy(df)
    print(f"[*] Using {len(feature_cols)} features.  "
          f"class balance: {dict(zip(*np.unique(y, return_counts=True)))}")

    print(f"[*] Training Random Forest (n_estimators={args.trees}) ...")
    model, metrics, report = train(X, y, n_estimators=args.trees)

    print("\n[+] Evaluation on hold-out set")
    print("    Accuracy : {:.4f}".format(metrics["accuracy"]))
    print("    Precision: {:.4f}".format(metrics["precision"]))
    print("    Recall   : {:.4f}".format(metrics["recall"]))
    print("    F1-Score : {:.4f}".format(metrics["f1"]))
    print("\n" + report)

    out = Path(args.out)
    joblib.dump({"model": model, "features": feature_cols}, out)
    with out.with_suffix(".metrics.json").open("w") as f:
        json.dump(metrics, f, indent=2)

    print(f"[+] Model saved to {out}")
    print(f"[+] Metrics saved to {out.with_suffix('.metrics.json')}")


if __name__ == "__main__":
    main()
