"""
validate_model.py — honest generalization testing for the Cloudie RF model.

WHY THIS EXISTS
---------------
A near-perfect score (~99.86%) on a random train/test split of a single dataset
usually means the test set is too similar to the training set. An examiner will
ask whether the model GENERALIZES or just memorized one distribution. This
script answers that with two honest evaluations:

  MODE A  "split"  (runs on your existing Final.csv, NO new data needed)
      A distribution-aware hold-out. Instead of a random split, we hold out a
      coherent SLICE of the data (by a chosen column, e.g. file size band, or a
      stratified "hard" subset) so the test set is genuinely unlike training.
      This is the realistic, defensible number to report in Chapter 4.

  MODE B  "cross"  (needs a SECOND csv with the SAME 32 feature columns)
      Train on CIC, test on an independent source. The strongest claim — but
      ONLY valid if the second source is genuinely independent of Contagio,
      which CIC-Evasive-PDFMal2022 is largely built from. Read the note below.

IMPORTANT METHODOLOGY NOTE (put a version of this in your thesis)
-----------------------------------------------------------------
CIC-Evasive-PDFMal2022 was itself constructed largely from Contagio + VirusTotal
samples. So validating on raw Contagio is NOT independent and would be
circular. For a credible cross-dataset claim, the second dataset must come from
a different collection pipeline. If you cannot obtain one, the "split" mode
below is the honest, citable alternative and is sufficient on its own.

USAGE
-----
  # Mode A — distribution hold-out on your existing data:
  python validate_model.py split --data Final.csv --label Class --by pdf_size

  # Mode A — stratified random hold-out (baseline honest split):
  python validate_model.py split --data Final.csv --label Class

  # Mode B — train on CIC, test on an independent csv:
  python validate_model.py cross --train Final.csv --test other.csv --label Class

OUTPUTS
-------
  - Console: accuracy, precision, recall, F1, ROC-AUC, confusion matrix on the
    HELD-OUT data, plus the gap vs. training-set performance.
  - validation_report.json : all metrics, for direct use in Chapter 4.
  - validation_confusion.csv : the confusion matrix as a table.

The script does NOT modify your deployed model or any Flask files.
"""

import os
import sys
import json
import argparse

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _load_csv(path):
    if not os.path.exists(path):
        sys.exit(f"ERROR: file not found: {path}")
    df = pd.read_csv(path)
    # Drop obvious non-feature columns often present in these datasets.
    for junk in ("Filename", "filename", "FileName", "md5", "MD5", "sha256", "hash"):
        if junk in df.columns:
            df = df.drop(columns=[junk])
    return df


def _split_xy(df, label_col):
    if label_col not in df.columns:
        sys.exit(
            f"ERROR: label column '{label_col}' not in CSV. "
            f"Columns are: {list(df.columns)}"
        )
    y = df[label_col]
    X = df.drop(columns=[label_col])

    # Normalize labels to 0/1. Handle numeric, object, AND string-dtype
    # columns (pandas may load text labels as 'str'/StringArray, not 'object').
    if not pd.api.types.is_numeric_dtype(y):
        mapping = {
            "malicious": 1, "malware": 1, "mal": 1, "1": 1, "true": 1, "bad": 1,
            "benign": 0, "clean": 0, "ben": 0, "0": 0, "false": 0, "good": 0,
        }
        normalized = y.astype(str).str.strip().str.lower()
        mapped = normalized.map(mapping)
        if mapped.isna().any():
            bad = sorted(normalized[mapped.isna()].unique())[:10]
            sys.exit("ERROR: could not interpret these label values: "
                     f"{bad}. Edit the 'mapping' dict in validate_model.py "
                     "to cover them (left side lowercase, right side 0 or 1).")
        y = mapped
    y = y.astype(int)

    # Keep only numeric feature columns; coerce and fill any stray NaNs.
    X = X.apply(pd.to_numeric, errors="coerce").fillna(0.0)
    return X, y


def _train_rf(X, y, seed=42):
    # Mirror a typical Cloudie RF configuration. n_jobs=-1 uses all cores.
    clf = RandomForestClassifier(
        n_estimators=200, random_state=seed, n_jobs=-1, class_weight="balanced"
    )
    clf.fit(X, y)
    return clf


def _evaluate(clf, X, y, feature_order):
    # Align columns to the model's training order, matching by name.
    X = X.reindex(columns=feature_order, fill_value=0.0)
    proba = clf.predict_proba(X)
    classes = list(clf.classes_)
    mal_idx = classes.index(1) if 1 in classes else int(np.argmax(classes))
    p_mal = proba[:, mal_idx]
    pred = (p_mal >= 0.5).astype(int)

    cm = confusion_matrix(y, pred, labels=[0, 1])
    metrics = {
        "accuracy": float(accuracy_score(y, pred)),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y, p_mal)) if len(set(y)) > 1 else None,
        "confusion_matrix": cm.tolist(),
        "n_samples": int(len(y)),
        "n_malicious": int((y == 1).sum()),
        "n_benign": int((y == 0).sum()),
    }
    return metrics, cm


def _print_metrics(title, m):
    print(f"\n=== {title} ===")
    print(f"  samples      : {m['n_samples']} "
          f"(malicious={m['n_malicious']}, benign={m['n_benign']})")
    print(f"  accuracy     : {m['accuracy']:.4f}")
    print(f"  precision    : {m['precision']:.4f}")
    print(f"  recall       : {m['recall']:.4f}")
    print(f"  f1           : {m['f1']:.4f}")
    if m["roc_auc"] is not None:
        print(f"  roc_auc      : {m['roc_auc']:.4f}")
    cm = m["confusion_matrix"]
    print(f"  confusion    : TN={cm[0][0]} FP={cm[0][1]} FN={cm[1][0]} TP={cm[1][1]}")


def _save_outputs(report, out_dir="."):
    rpt_path = os.path.join(out_dir, "validation_report.json")
    with open(rpt_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    # Confusion matrix of the held-out eval as a small CSV.
    held = report.get("held_out") or report.get("test")
    if held:
        cm = held["confusion_matrix"]
        pd.DataFrame(
            cm,
            index=["actual_benign", "actual_malicious"],
            columns=["pred_benign", "pred_malicious"],
        ).to_csv(os.path.join(out_dir, "validation_confusion.csv"))
    print(f"\nSaved: {rpt_path}")
    print(f"Saved: {os.path.join(out_dir, 'validation_confusion.csv')}")


# ---------------------------------------------------------------------------
# Mode A: distribution-aware / stratified hold-out on ONE dataset
# ---------------------------------------------------------------------------
def run_split(args):
    df = _load_csv(args.data)
    X, y = _split_xy(df, args.label)

    if args.by and args.by in X.columns:
        # Distribution hold-out: test on the TOP band of `by` (e.g. largest
        # files), train on the rest. The model never sees this region in
        # training, so it is a genuine generalization test, not a random split.
        cutoff = X[args.by].quantile(0.75)
        test_mask = X[args.by] >= cutoff
        X_train, y_train = X[~test_mask], y[~test_mask]
        X_test, y_test = X[test_mask], y[test_mask]
        split_desc = (f"distribution hold-out on '{args.by}' "
                      f">= {cutoff:.3f} (top quartile held out)")
    else:
        # Honest stratified random split (still better than reporting the
        # in-sample number, but weaker than a distribution hold-out).
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.25, random_state=42, stratify=y
        )
        split_desc = "stratified random 75/25 hold-out"

    clf = _train_rf(X_train, y_train)
    feature_order = list(X_train.columns)

    train_m, _ = _evaluate(clf, X_train, y_train, feature_order)
    held_m, _ = _evaluate(clf, X_test, y_test, feature_order)

    print(f"\nValidation design: {split_desc}")
    _print_metrics("TRAINING set (in-sample, expect high)", train_m)
    _print_metrics("HELD-OUT set (the honest number)", held_m)
    gap = train_m["accuracy"] - held_m["accuracy"]
    print(f"\nGeneralization gap (train - held-out accuracy): {gap:.4f}")
    if gap > 0.05:
        print("  -> Notable drop: the held-out region is genuinely harder. "
              "This is the credible result to discuss in Chapter 4.")
    else:
        print("  -> Small drop: the model generalizes well across this split.")

    report = {
        "mode": "split",
        "design": split_desc,
        "feature_count": len(feature_order),
        "feature_order": feature_order,
        "training": train_m,
        "held_out": held_m,
        "generalization_gap_accuracy": gap,
    }
    _save_outputs(report)


# ---------------------------------------------------------------------------
# Mode B: cross-dataset (train on one csv, test on an independent csv)
# ---------------------------------------------------------------------------
def run_cross(args):
    train_df = _load_csv(args.train)
    test_df = _load_csv(args.test)
    Xtr, ytr = _split_xy(train_df, args.label)
    Xte, yte = _split_xy(test_df, args.label)

    # Reconcile feature columns: use the intersection, warn on differences.
    common = [c for c in Xtr.columns if c in Xte.columns]
    missing_in_test = [c for c in Xtr.columns if c not in Xte.columns]
    extra_in_test = [c for c in Xte.columns if c not in Xtr.columns]
    if missing_in_test:
        print(f"WARNING: {len(missing_in_test)} train features absent in test "
              f"(filled 0): {missing_in_test[:8]}{'...' if len(missing_in_test) > 8 else ''}")
    if extra_in_test:
        print(f"NOTE: {len(extra_in_test)} test-only features ignored: "
              f"{extra_in_test[:8]}{'...' if len(extra_in_test) > 8 else ''}")
    if not common:
        sys.exit("ERROR: the two CSVs share NO feature columns. They use "
                 "different schemas and cannot be compared directly.")

    feature_order = list(Xtr.columns)
    clf = _train_rf(Xtr[feature_order], ytr)

    train_m, _ = _evaluate(clf, Xtr, ytr, feature_order)
    test_m, _ = _evaluate(clf, Xte, yte, feature_order)

    print(f"\nCross-dataset validation")
    print(f"  trained on : {os.path.basename(args.train)} ({len(ytr)} samples)")
    print(f"  tested on  : {os.path.basename(args.test)} ({len(yte)} samples)")
    print(f"  shared features: {len(common)} / {len(feature_order)}")
    _print_metrics("TRAINING source (in-sample)", train_m)
    _print_metrics("INDEPENDENT test source (the honest number)", test_m)
    gap = train_m["accuracy"] - test_m["accuracy"]
    print(f"\nCross-dataset accuracy drop: {gap:.4f}")
    print("  -> A real drop here is EXPECTED and strengthens the thesis: it "
          "shows the model's true generalization, not memorization.")

    report = {
        "mode": "cross",
        "train_source": os.path.basename(args.train),
        "test_source": os.path.basename(args.test),
        "shared_features": len(common),
        "feature_count": len(feature_order),
        "training": train_m,
        "test": test_m,
        "cross_dataset_gap_accuracy": gap,
    }
    _save_outputs(report)


# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Cloudie model generalization tests")
    sub = parser.add_subparsers(dest="mode", required=True)

    sp = sub.add_parser("split", help="distribution hold-out on one dataset")
    sp.add_argument("--data", required=True, help="path to the dataset CSV")
    sp.add_argument("--label", default="Class", help="name of the label column")
    sp.add_argument("--by", default=None,
                    help="feature to hold out by (e.g. pdf_size); omit for random split")

    cp = sub.add_parser("cross", help="train on one CSV, test on an independent CSV")
    cp.add_argument("--train", required=True, help="training CSV (e.g. Final.csv)")
    cp.add_argument("--test", required=True, help="independent test CSV")
    cp.add_argument("--label", default="Class", help="name of the label column")

    args = parser.parse_args()
    if args.mode == "split":
        run_split(args)
    elif args.mode == "cross":
        run_cross(args)


if __name__ == "__main__":
    main()