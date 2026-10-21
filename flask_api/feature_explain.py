"""
feature_explain.py — explainable AI verdicts for the Random Forest.

For one file, shows HOW MUCH each feature pushed the model's malicious
probability up or down, using the exact "tree path" decomposition
(the treeinterpreter method; no extra dependency):

  for every tree, walk the file's decision path; each split moves the node's
  malicious fraction from parent to child, and that change is credited to the
  feature that was split on. Averaged over all trees:

      P(malicious) = bias + sum(contribution of every feature)

  bias = the average malicious fraction at the tree roots (the base rate).

This only EXPLAINS the AI score. It never changes a verdict. The explanation is
about the model's reasoning, not proof that a file is malicious.
"""

import json
import logging
import os

import numpy as np

logger = logging.getLogger("cloudie.explain")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REFERENCE_PATH = os.path.join(BASE_DIR, "feature_reference.json")

# Plain-language meaning of each of the 32 features (shown to the user).
MEANINGS = {
    "pdf_size": "File size (KB)",
    "metadata_size": "Size of the document metadata block",
    "pages": "Number of pages",
    "xref_length": "Length of the cross-reference table",
    "title_characters": "Characters in the document title",
    "isEncrypted": "PDF is encrypted",
    "embedded_files": "Number of embedded files",
    "images": "Number of images",
    "contains_text": "Contains readable text",
    "header": "PDF version in the file header",
    "obj": "Count of 'obj' keywords",
    "endobj": "Count of 'endobj' keywords",
    "stream": "Count of 'stream' keywords",
    "endstream": "Count of 'endstream' keywords",
    "xref": "Count of 'xref' keywords",
    "trailer": "Count of 'trailer' keywords",
    "startxref": "Count of 'startxref' keywords",
    "pageno": "Count of /Page objects",
    "encrypt": "Count of /Encrypt entries",
    "ObjStm": "Object streams (can hide objects)",
    "JS": "JavaScript code (/JS)",
    "Javascript": "JavaScript actions (/JavaScript)",
    "AA": "Additional actions triggered by events (/AA)",
    "OpenAction": "Action that runs automatically on open (/OpenAction)",
    "Acroform": "Interactive form (/AcroForm)",
    "JBIG2Decode": "JBIG2 image filter (/JBIG2Decode)",
    "RichMedia": "Embedded rich media (/RichMedia)",
    "launch": "Launches an external program or file (/Launch)",
    "EmbeddedFile": "Embedded file payload (/EmbeddedFile)",
    "XFA": "XFA form, scriptable XML (/XFA)",
    "URI": "Link/URI actions (/URI)",
    "Colors": "Colour decode entries (/Colors)",
}


def _load_reference():
    try:
        with open(REFERENCE_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh).get("features", {})
    except Exception:  # missing file is fine: the explanation just has no reference columns
        return {}


REFERENCE = _load_reference()


def contributions(model, row_values, feature_names, malicious_class=1):
    """
    Return (bias, {feature: contribution}) for one sample.
    row_values must be in the same order as feature_names (the model's order).
    """
    classes = list(model.classes_)
    mal_idx = classes.index(malicious_class)
    x = np.asarray(row_values, dtype=np.float32)   # sklearn compares in float32

    contrib = np.zeros(len(feature_names), dtype=np.float64)
    bias_sum = 0.0
    for est in model.estimators_:
        t = est.tree_
        vals = t.value[:, 0, :]
        frac = vals / vals.sum(axis=1, keepdims=True)
        pm = frac[:, mal_idx]
        node = 0
        bias_sum += pm[0]
        while t.children_left[node] != -1:
            f = t.feature[node]
            child = t.children_left[node] if x[f] <= t.threshold[node] else t.children_right[node]
            contrib[f] += pm[child] - pm[node]
            node = child

    n = len(model.estimators_)
    return bias_sum / n, {name: float(contrib[i] / n) for i, name in enumerate(feature_names)}


def build_explanation(model, feature_names, values_by_name, top_n=6):
    """
    Build the JSON block returned by /scan, or None if anything goes wrong
    (an explanation must never break a scan).
    """
    try:
        row = [values_by_name.get(n, 0) for n in feature_names]
        bias, contrib = contributions(model, row, feature_names)

        ranked = sorted(contrib.items(), key=lambda kv: abs(kv[1]), reverse=True)
        top = []
        for name, c in ranked[:top_n]:
            if abs(c) < 0.005:      # ignore effects under half a percentage point
                continue
            ref = REFERENCE.get(name, {})
            top.append({
                "feature": name,
                "meaning": MEANINGS.get(name, name),
                "value": values_by_name.get(name, 0),
                "effect": round(c, 4),                 # + pushes toward malicious
                "direction": "malicious" if c > 0 else "clean",
                "typical_benign": ref.get("benign_median"),
                "typical_malicious": ref.get("malicious_median"),
            })

        caveats = []
        if values_by_name.get("metadata_size", 0) == 0 and contrib.get("metadata_size", 0) > 0.05:
            caveats.append(
                "No metadata block was found in this PDF. Every PDF in the training data had one, "
                "so the model reads its absence as a malicious sign. This often inflates the AI "
                "score of ordinary documents; it is a known limit of the model, not a finding "
                "about this file."
            )

        return {
            "method": "tree-path contributions (exact decomposition of the Random Forest score)",
            "base_rate": round(float(bias), 4),
            "total": round(float(bias + sum(contrib.values())), 4),
            "top": top,
            "caveats": caveats,
            "note": ("Shows which features pushed the AI score up or down. It explains the "
                     "model; it is not proof that a file is malicious. VirusTotal decides blocking."),
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("explanation failed: %s", exc)
        return None
