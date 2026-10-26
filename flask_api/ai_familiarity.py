"""
ai_familiarity.py — "has the Random Forest ever seen a PDF like this one?"

A model gives a number for any input, even one far from everything it learned from. On real-world
PDFs the Random Forest sits close to its 0.5 cut-off (docs/AUDIT_REPORT.md), which is what an
out-of-its-depth model looks like. This module measures that directly:

  1. every one of the 32 features is turned into a RANK among the training PDFs (0 = lowest seen,
     1 = highest seen; a value beyond the training range goes slightly outside [0, 1]);
  2. the distance to the 5 nearest training PDFs (mean) is the file's "strangeness";
  3. it is compared with how far training PDFs are from each other (leave-one-out), giving a
     percentile and a band:  familiar (inside the typical 90%)  <  unusual (90-99%)  <  unfamiliar (beyond 99%).

It never changes the verdict: VirusTotal stays primary and the Random Forest stays secondary. It only
tells the reader how much weight the AI score deserves, and why (which features are unlike the training data).
Reference data: flask_api/ai_familiarity.npz, built by ml/build_ai_familiarity.py. Without that file, or on any
error, assess() returns None and nothing else changes.
"""

import logging
import os

import numpy as np

log = logging.getLogger("cloudie.familiarity")

N_QUANTILES = 101
K_NEIGHBOURS = 5
RANK_LOW, RANK_HIGH = -0.25, 1.25          # how far outside [0, 1] an out-of-range value is placed
REF_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ai_familiarity.npz")

FRIENDLY = {
    "pdf_size": "file size (KB)", "metadata_size": "metadata block size", "pages": "pages",
    "xref_length": "cross-reference size", "images": "image count", "obj": "objects", "endobj": "object ends",
    "stream": "streams", "endstream": "stream ends", "ObjStm": "object streams", "URI": "links",
    "title_characters": "title length", "Colors": "colour entries",
    "AA": "auto-run actions (AA)", "OpenAction": "open-on-load actions", "JS": "JavaScript (JS)",
    "Javascript": "JavaScript", "launch": "launch actions", "EmbeddedFile": "embedded files",
    "RichMedia": "rich media", "XFA": "XFA forms", "Acroform": "form fields", "isEncrypted": "encryption flag",
}


def rank_transform(A, q):
    """Per-feature rank of each value among the training quantiles q (32, 101); out of range is clipped outside [0, 1]."""
    A = np.asarray(A, dtype=float)
    out = np.empty(A.shape, dtype=float)
    steps = np.linspace(0, 1, q.shape[1])
    for j in range(A.shape[1]):
        u, first = np.unique(q[j], return_index=True)
        if len(u) == 1:                                   # constant in training: any other value is novel
            out[:, j] = np.where(A[:, j] == u[0], 0.5, np.where(A[:, j] > u[0], RANK_HIGH, RANK_LOW))
        else:
            out[:, j] = np.interp(A[:, j], u, steps[first], left=RANK_LOW, right=RANK_HIGH)
    return out


def knn_distance(ref, v, k=K_NEIGHBOURS, skip_self=False):
    """Mean Euclidean distance from v to its k nearest rows of ref."""
    d = np.sqrt(((ref - v) ** 2).sum(axis=1))
    s = 1 if skip_self else 0
    part = np.partition(d, s + k - 1)[: s + k]
    part.sort()
    return float(part[s:s + k].mean())


class _Reference:
    def __init__(self, path):
        data = np.load(path, allow_pickle=False)
        self.q = data["q"]
        self.ref = data["ref"].astype(np.float32)
        self.loo = np.sort(data["loo"].astype(np.float64))
        self.names = [str(n) for n in data["feature_names"]]
        self.p50, self.p90, self.p99 = np.percentile(self.loo, [50, 90, 99])


_REF = None
_TRIED = False


def _reference():
    global _REF, _TRIED
    if not _TRIED:
        _TRIED = True
        try:
            if os.path.exists(REF_PATH):
                _REF = _Reference(REF_PATH)
        except Exception as exc:  # noqa: BLE001 - optional layer, must not break a scan
            log.warning("familiarity reference not loaded: %s", exc)
            _REF = None
    return _REF


def assess(features, ref=None):
    """features: {name: value} for the 32 model features. Returns a dict, or None when unavailable."""
    try:
        ref = ref or _reference()
        if ref is None or not features:
            return None
        raw = np.array([[float(features.get(n, 0) or 0) for n in ref.names]])
        v = rank_transform(raw, ref.q)[0].astype(np.float32)
        dist = knn_distance(ref.ref, v)
        pct = float(np.searchsorted(ref.loo, dist) / len(ref.loo) * 100)
        band = "familiar" if dist <= ref.p90 else ("unusual" if dist <= ref.p99 else "unfamiliar")

        unusual = []
        for j, n in enumerate(ref.names):
            lo, med, hi, mx = ref.q[j][1], ref.q[j][50], ref.q[j][99], ref.q[j][100]
            val = raw[0, j]
            if val > hi and val > mx:
                unusual.append((val / max(hi, 1.0), n, val, med, hi, "above everything in the training data"))
            elif val > hi:
                unusual.append((val / max(hi, 1.0) * 0.5, n, val, med, hi, "in the top 1% of the training data"))
        unusual.sort(reverse=True)
        top = [{"feature": n, "meaning": FRIENDLY.get(n, n), "value": round(float(val), 2),
                "typical": round(float(med), 2), "p99": round(float(hi), 2), "why": why}
               for _, n, val, med, hi, why in unusual[:4]]
        # a count the training data never varies (for example images) is reported by name when it is novel
        return {
            "available": True, "band": band, "percentile": round(min(pct, 100.0), 1),
            "distance": round(dist, 3), "p90": round(float(ref.p90), 3), "p99": round(float(ref.p99), 3),
            "unusual_features": top, "message": _message(band, top),
        }
    except Exception as exc:  # noqa: BLE001
        log.warning("familiarity failed: %s", exc)
        return None


def _message(band, top):
    if band == "familiar":
        return ("This PDF looks like the PDFs the AI was trained on, so its score is as reliable as it gets "
                "(still one signal next to VirusTotal).")
    names = ", ".join(t["meaning"] for t in top[:3])
    base = ("This PDF is %s the PDFs the AI learned from%s." % (
        "unlike" if band == "unfamiliar" else "somewhat unlike", (" (" + names + ")") if names else ""))
    return base + " Treat its score as a weak signal; VirusTotal and the structure checks carry more weight here."
