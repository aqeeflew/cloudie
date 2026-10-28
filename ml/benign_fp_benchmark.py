"""
benign_fp_benchmark.py
----------------------
False-positive rate of Cloudie on REAL benign PDFs (the set built by build_benign_set.py from GovDocs1).

Two steps:

    label   VirusTotal HASH lookup for every PDF (no upload). Files flagged by 2+ engines (Cloudie's block rule)
            are taken out of the benign set; a lone-engine hit ("weak") and files VirusTotal has never seen are
            kept but reported separately. Resumable: results are
            cached in ml/benign_set/vt_labels.csv. Needs VT_API_KEY; waits 16 s between requests (free quota is
            about 4 per minute).

    run     Sends every kept PDF through the real Flask scan route (flask_api/app.py, test client), with the
            VirusTotal call replaced by its recorded hash-lookup answer. VirusTotal-unknown files are simulated as
            "VT clean", so the other layers decide. Measures, per file:
              - RF alone       : P(malicious) >= 0.5
              - AI tagged      : RF with the risk gate (what the report calls "malicious" for the AI)
              - strong finding : a strong evasion/structure finding
              - final verdict  : what the user would see (clean / suspicious)
            Writes ml/benign_set/results.csv and ml/benign_set/summary.json.

Usage (from C:\\xampp\\htdocs\\cloudie):
    $env:VT_API_KEY = "..."; flask_api\\.venv\\Scripts\\python.exe ml\\benign_fp_benchmark.py label
    flask_api\\.venv\\Scripts\\python.exe ml\\benign_fp_benchmark.py run
"""

import csv
import io
import json
import os
import statistics
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SET_DIR = os.path.join(ROOT, "ml", "benign_set")
PDF_DIR = os.path.join(SET_DIR, "govdocs1")
MANIFEST = os.path.join(SET_DIR, "manifest.csv")
LABELS = os.path.join(SET_DIR, "vt_labels.csv")
RESULTS = os.path.join(SET_DIR, "results.csv")
SUMMARY = os.path.join(SET_DIR, "summary.json")
sys.path.insert(0, os.path.join(ROOT, "flask_api"))

LABEL_FIELDS = ["file", "sha256", "vt_status", "malicious", "suspicious", "total", "checked_at"]
VT_INTERVAL_S = 16


def read_csv(path):
    if not os.path.exists(path):
        return []
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def label():
    import requests
    import vt_client

    key = os.environ.get("VT_API_KEY", "").strip()
    if not key:
        sys.exit("VT_API_KEY is not set")
    done = {r["sha256"] for r in read_csv(LABELS)}
    todo = [r for r in read_csv(MANIFEST) if r["sha256"] not in done]
    print("%d to look up (%d cached)" % (len(todo), len(done)), flush=True)
    new_file = not os.path.exists(LABELS)
    with open(LABELS, "a", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=LABEL_FIELDS)
        if new_file:
            w.writeheader()
        for i, r in enumerate(todo, 1):
            while True:
                try:
                    rep = vt_client._lookup_hash(r["sha256"], key)
                    break
                except requests.HTTPError as exc:
                    code = exc.response.status_code if exc.response is not None else None
                    if code == 429:
                        print("  429 quota, waiting 60 s", flush=True)
                        time.sleep(60)
                        continue
                    raise
                except (requests.ConnectionError, requests.Timeout):
                    print("  network error, retrying in 30 s", flush=True)
                    time.sleep(30)
            if rep is None:
                row = {"vt_status": "unknown", "malicious": "", "suspicious": "", "total": ""}
            else:
                hits = rep["malicious"] + rep["suspicious"]
                row = {"vt_status": "flagged" if hits else "clean", "malicious": rep["malicious"],
                       "suspicious": rep["suspicious"], "total": rep["total"]}
            row.update(file=r["file"], sha256=r["sha256"], checked_at=time.strftime("%Y-%m-%d %H:%M:%S"))
            w.writerow(row)
            fh.flush()
            print("  %d/%d %s %s" % (i, len(todo), r["file"], row["vt_status"]), flush=True)
            time.sleep(VT_INTERVAL_S)


def run():
    # Keep the benchmark out of the real prediction log.
    os.environ["PREDICTION_LOG_PATH"] = os.path.join(tempfile.gettempdir(), "cloudie_benign_fp_log.csv")
    os.environ.pop("VT_API_KEY", None)
    import app as flask_app

    labels = {r["file"]: r for r in read_csv(LABELS)}
    manifest = read_csv(MANIFEST)
    missing = [r["file"] for r in manifest if r["file"] not in labels]
    if missing:
        sys.exit("%d files have no VirusTotal label yet: run 'label' first" % len(missing))

    current = {}
    flask_app.vt_scan = lambda path, name="upload": current["vt"]
    client = flask_app.app.test_client()

    rows = []
    for r in manifest:
        lab = labels[r["file"]]
        hits = (int(lab["malicious"] or 0) + int(lab["suspicious"] or 0)) if lab["vt_status"] == "flagged" else 0
        status = "weak" if 0 < hits < flask_app.MIN_BLOCK_HITS else lab["vt_status"]
        if hits >= flask_app.MIN_BLOCK_HITS:
            # VirusTotal is confident: the file cannot be counted as benign.
            rows.append({"file": r["file"], "vt_status": "flagged", "excluded": 1})
            continue
        total = int(lab["total"]) if lab["vt_status"] != "unknown" else 70   # unknown: simulated "VT clean"
        current["vt"] = (hits, total)
        with open(os.path.join(PDF_DIR, r["file"]), "rb") as fh:
            data = fh.read()
        t0 = time.perf_counter()
        resp = client.post("/scan", data={"file": (io.BytesIO(data), r["file"])},
                           content_type="multipart/form-data")
        ms = (time.perf_counter() - t0) * 1000
        j = resp.get_json()
        ai = j.get("ai") or {}
        fam = ai.get("familiarity") or {}
        p = ai.get("probability_malicious")
        rows.append({
            "file": r["file"], "vt_status": status, "excluded": 0,
            "size": r["size"], "is_pdf": int(bool(j.get("is_pdf"))),
            "rf_proba": "" if p is None else p,
            "rf_alone_flag": int(p is not None and p >= 0.5),
            "ai_tagged": int(ai.get("verdict") == "malicious"),
            "strong_findings": ";".join(j.get("evasion", {}).get("strong") or []),
            "other_findings": ";".join(f["id"] for f in j.get("findings", []) if not f.get("strong")),
            "verdict": j.get("verdict"),
            "familiarity": fam.get("band", ""),
            "extraction_ok": int(bool(j.get("extraction", {}).get("ok"))),
            "ms": round(ms),
        })

    fields = ["file", "vt_status", "excluded", "size", "is_pdf", "rf_proba", "rf_alone_flag", "ai_tagged",
              "strong_findings", "other_findings", "verdict", "familiarity", "extraction_ok", "ms"]
    with open(RESULTS, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    kept = [x for x in rows if not x["excluded"]]

    def block(sub):
        n = len(sub)
        probs = [float(x["rf_proba"]) for x in sub if x["rf_proba"] != ""]
        cnt = lambda k: sum(int(x[k]) for x in sub)                     # noqa: E731
        susp = sum(x["verdict"] != "clean" for x in sub)
        pct = lambda c: round(100.0 * c / n, 2) if n else None          # noqa: E731
        return {
            "n": n,
            "rf_alone_fp": cnt("rf_alone_flag"), "rf_alone_fp_pct": pct(cnt("rf_alone_flag")),
            "ai_tagged": cnt("ai_tagged"), "ai_tagged_pct": pct(cnt("ai_tagged")),
            "strong_finding_files": sum(bool(x["strong_findings"]) for x in sub),
            "final_not_clean": susp, "final_fp_pct": pct(susp),
            "verdicts": {v: sum(x["verdict"] == v for x in sub) for v in sorted({x["verdict"] for x in sub})},
            "rf_proba_median": round(statistics.median(probs), 4) if probs else None,
            "rf_proba_min": round(min(probs), 4) if probs else None,
            "rf_proba_max": round(max(probs), 4) if probs else None,
            "familiarity": {b: sum(x["familiarity"] == b for x in sub)
                            for b in ("familiar", "unusual", "unfamiliar", "")},
            "extraction_failed": sum(not x["extraction_ok"] for x in sub),
            "ms_median": round(statistics.median([x["ms"] for x in sub])) if sub else None,
        }

    summary = {
        "source": "GovDocs1 (Digital Corpora)",
        "files_in_set": len(rows),
        "excluded_vt_flagged": sum(x["excluded"] for x in rows),
        "vt_status": {s: sum(x["vt_status"] == s for x in rows) for s in ("clean", "unknown", "weak", "flagged")},
        "all_kept": block(kept),
        "vt_confirmed_clean": block([x for x in kept if x["vt_status"] == "clean"]),
        "vt_unknown": block([x for x in kept if x["vt_status"] == "unknown"]),
        "vt_weak_hit": block([x for x in kept if x["vt_status"] == "weak"]),
        "kept_without_vt_weak": block([x for x in kept if x["vt_status"] != "weak"]),
        "strong_finding_counts": {},
    }
    for x in kept:
        for f in filter(None, x["strong_findings"].split(";")):
            summary["strong_finding_counts"][f] = summary["strong_finding_counts"].get(f, 0) + 1
    with open(SUMMARY, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    {"label": label, "run": run}.get(sys.argv[1] if len(sys.argv) > 1 else "", lambda: sys.exit(__doc__))()
