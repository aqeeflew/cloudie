"""
build_ai_familiarity.py
-----------------------
Builds flask_api/ai_familiarity.npz: a compact reference of the training data used to answer
"has the Random Forest ever seen a PDF like this one?" (see flask_api/ai_familiarity.py).

It does not touch malware_rf.pkl or the 32-feature contract. Same encoding as the model:
header "%PDF-1.6" -> 1.6, contains_text Yes/No -> 1/0, `name` and `class` are not features.

What is stored
  q     (32, 101)   per-feature quantiles of the training data (the rank transform)
  ref   (N, 32)     every training PDF in rank space, float16 (about 1 MB)
  loo   (3000,)     leave-one-out nearest-neighbour distances of a random training sample, sorted
                    (the yardstick: how far a training PDF is from the rest of the training set)

Usage (from C:\\xampp\\htdocs\\cloudie):
    flask_api\\.venv\\Scripts\\python.exe ml\\build_ai_familiarity.py
"""

import os
import sys

import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "flask_api"))
from ai_familiarity import rank_transform, knn_distance, K_NEIGHBOURS, N_QUANTILES  # noqa: E402
from feature_extractor import FEATURE_NAMES  # noqa: E402

CSV = os.path.join(ROOT, "flask_api", "Final.csv")
OUT = os.path.join(ROOT, "flask_api", "ai_familiarity.npz")
LOO_SAMPLE = 3000
SEED = 42


def load_training_matrix():
    df = pd.read_csv(CSV)
    df = df.drop(columns=[c for c in ("name",) if c in df.columns])
    df["contains_text"] = (
        df["contains_text"].astype(str).str.strip().str.lower().map({"yes": 1, "no": 0}).fillna(0)
    )
    df["header"] = pd.to_numeric(
        df["header"].astype(str).str.extract(r"(\d+\.\d+)")[0], errors="coerce"
    ).fillna(0.0)
    return df[FEATURE_NAMES].apply(pd.to_numeric, errors="coerce").fillna(0.0).values.astype(float)


def main():
    X = load_training_matrix()
    q = np.quantile(X, np.linspace(0, 1, N_QUANTILES), axis=0).T          # (32, 101)
    ref = rank_transform(X, q)                                             # (N, 32)

    rng = np.random.RandomState(SEED)
    sample = rng.choice(len(ref), LOO_SAMPLE, replace=False)
    ref32 = ref.astype(np.float32)
    loo = np.sort(np.array([knn_distance(ref32, ref32[i], skip_self=True) for i in sample]))

    np.savez_compressed(OUT, q=q.astype(np.float64), ref=ref.astype(np.float16), loo=loo.astype(np.float32),
                        feature_names=np.array(FEATURE_NAMES))
    p50, p90, p99 = np.percentile(loo, [50, 90, 99])
    print("wrote %s (%.2f MB)" % (OUT, os.path.getsize(OUT) / 1e6))
    print("training rows %d, k=%d; leave-one-out distance p50=%.3f p90=%.3f p99=%.3f" % (
        len(X), K_NEIGHBOURS, p50, p90, p99))


if __name__ == "__main__":
    main()
