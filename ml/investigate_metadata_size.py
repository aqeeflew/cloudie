"""
investigate_metadata_size.py
----------------------------
Why do real-world PDFs get a middling Random Forest score? `metadata_size` is the model's most important
feature (about 20%), and the extractor sets it to 0 when a PDF has no XMP packet. This script checks, with
measurements only, what the training data's `metadata_size` actually looks like and what happens when it is 0.

It changes nothing: it only reads flask_api/Final.csv, flask_api/malware_rf.pkl and the PDFs under docs/.
Result and interpretation: docs/METADATA_SIZE_INVESTIGATION.md

Usage (from C:\\xampp\\htdocs\\cloudie):
    flask_api\\.venv\\Scripts\\python.exe ml\\investigate_metadata_size.py
"""

import glob
import os
import re
import sys

import joblib
import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "flask_api"))
from feature_extractor import FEATURE_NAMES, extract_features  # noqa: E402


def load_training():
    df = pd.read_csv(os.path.join(ROOT, "flask_api", "Final.csv")).drop(columns=["name"])
    df["contains_text"] = df["contains_text"].astype(str).str.strip().str.lower().map({"yes": 1, "no": 0}).fillna(0)
    df["header"] = pd.to_numeric(df["header"].astype(str).str.extract(r"(\d+\.\d+)")[0], errors="coerce").fillna(0.0)
    y = df["class"].astype(str).str.strip().str.lower().isin(["malicious", "malware", "1"]).astype(int).values
    return df[FEATURE_NAMES].apply(pd.to_numeric, errors="coerce").fillna(0.0), y


def info_dict_size(blob):
    """Length of the document-information (/Info) dictionary: author, producer, dates, title..."""
    m = re.search(rb"/Info\s+(\d+)\s+(\d+)\s+R", blob)
    if not m:
        return 0
    mm = re.search(rb"(?:^|[\r\n\s])" + m.group(1) + rb"\s+\d+\s+obj(.*?)endobj", blob, re.DOTALL)
    return len(mm.group(1).strip()) if mm else 0


def main():
    X, y = load_training()
    bundle = joblib.load(os.path.join(ROOT, "flask_api", "malware_rf.pkl"))
    model, cols = bundle["model"], bundle["features"]
    prob = lambda frame: model.predict_proba(frame[cols])[:, 1]  # noqa: E731

    print("=== 1. metadata_size in the training data ===")
    for lab, name in ((0, "benign"), (1, "malicious")):
        s = X.loc[y == lab, "metadata_size"]
        print("%-9s n=%d zeros=%d min=%.0f p5=%.0f median=%.0f p95=%.0f max=%.0f" % (
            name, len(s), (s == 0).sum(), s.min(), s.quantile(.05), s.median(), s.quantile(.95), s.max()))
    titled = X[X["title_characters"] > 0]
    slope, icpt = np.polyfit(titled["title_characters"], titled["metadata_size"], 1)
    print("correlation with title_characters: %.3f; fit metadata_size = %.2f * title_chars + %.0f" % (
        X["title_characters"].corr(X["metadata_size"]), slope, icpt))
    print("most common values:", {int(k): int(v) for k, v in X["metadata_size"].value_counts().head(6).items()})

    print("\n=== 2. what the model does when metadata_size is 0 ===")
    ben = X[y == 0].copy()
    ben0 = ben.copy()
    ben0["metadata_size"] = 0
    p, p0 = prob(ben), prob(ben0)
    print("benign training PDFs, as in the data   : mean P(malicious)=%.3f, flagged >= 0.5: %.1f%%" % (p.mean(), (p >= .5).mean() * 100))
    print("benign training PDFs, metadata_size = 0: mean P(malicious)=%.3f, flagged >= 0.5: %.1f%%" % (p0.mean(), (p0 >= .5).mean() * 100))
    mal = X[y == 1].copy()
    mal319 = mal.copy()
    mal319["metadata_size"] = 319
    print("malicious training PDFs flagged: as in data %.1f%%, with metadata_size = 319 (a benign-looking value) %.1f%%" % (
        (prob(mal) >= .5).mean() * 100, (prob(mal319) >= .5).mean() * 100))

    print("\n=== 3. real PDFs (project documents): XMP block (current) vs Info-dictionary size ===")
    print("%-40s %6s %8s %8s %10s %10s" % ("file", "KB", "XMP", "Info", "P(XMP)", "P(Info)"))
    for path in sorted(glob.glob(os.path.join(ROOT, "docs", "**", "*.pdf"), recursive=True)):
        blob = open(path, "rb").read()
        feats = dict(extract_features(path)["features"])
        cur = prob(pd.DataFrame([feats]))[0]
        alt = dict(feats)
        alt["metadata_size"] = info_dict_size(blob)
        print("%-40s %6.0f %8d %8d %10.2f %10.2f" % (os.path.basename(path)[:40], len(blob) / 1024,
              feats["metadata_size"], alt["metadata_size"], cur, prob(pd.DataFrame([alt]))[0]))


if __name__ == "__main__":
    main()
