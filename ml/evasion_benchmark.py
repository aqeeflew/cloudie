"""
evasion_benchmark.py
--------------------
Measures what the rule-based evasion layer adds on top of the Random Forest, on SYNTHETIC samples.

Every sample is built from harmless text (an alert box); nothing here can exploit a PDF reader.
Keywords are hex-escaped to different degrees to imitate the evasion trick:

    level 0  clear text            /JavaScript
    level 1  first letter escaped  /#4aavaScript
    level 2  half the letters      /J#61vaS#63ript
    level 3  every letter escaped  /#4a#61#76#61#53#63#72#69#70#74

Compared on each sample (VirusTotal assumed clean, so the AI/evasion decide):
    RF alone        : probability >= 0.5
    old logic       : RF with the risk gate (verdict_engine before the evasion layer)
    new logic       : the same plus strong evasion findings (verdict_engine now)

Controls: harmless plain PDFs (false-positive check) and the real benign PDFs found under docs/.

Usage (from C:\\xampp\\htdocs\\cloudie):
    flask_api\\.venv\\Scripts\\python.exe ml\\evasion_benchmark.py
"""

import os
import random
import sys
import tempfile
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "flask_api"))

import joblib                      # noqa: E402
import pandas as pd                # noqa: E402

import evasion_indicators as E     # noqa: E402
from feature_extractor import extract_features        # noqa: E402
from verdict_engine import combine, risk_indicators    # noqa: E402

bundle = joblib.load(os.path.join(ROOT, "flask_api", "malware_rf.pkl"))
MODEL, FEATS = bundle["model"], bundle["features"]


def hexesc(name: str, level: int, rnd: random.Random) -> str:
    if level == 0:
        return name
    out = []
    for i, ch in enumerate(name):
        esc = (i == 0) if level == 1 else (rnd.random() < 0.5 if level == 2 else True)
        out.append("#%02X" % ord(ch) if esc else ch)
    return "".join(out)


def padding(n_bytes: int, rnd: random.Random) -> bytes:
    """A compressed page-content stream, so the file has a realistic size."""
    words = "cloud storage security document report analysis network data file".split()
    text = " ".join(rnd.choice(words) for _ in range(max(10, n_bytes // 6)))
    comp = zlib.compress(("BT /F1 12 Tf (" + text + ") Tj ET").encode())
    return b"6 0 obj\n<< /Filter /FlateDecode /Length %d >>\nstream\n" % len(comp) + comp + b"\nendstream\nendobj\n"


def build(template: str, level: int, pad: int, rnd: random.Random) -> bytes:
    k = lambda n: hexesc(n, level, rnd)       # noqa: E731
    body = b"%PDF-1.4\n"
    if template == "openaction":
        body += ("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /%s 4 0 R >>\nendobj\n"
                 "4 0 obj\n<< /S /%s /%s (app.alert\\('Cloudie test'\\);) >>\nendobj\n"
                 % (k("OpenAction"), k("JavaScript"), k("JS"))).encode()
    elif template == "additional_actions":
        body += ("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
                 "3 0 obj\n<< /Type /Page /Parent 2 0 R /%s << /O 4 0 R >> >>\nendobj\n"
                 "4 0 obj\n<< /S /%s /%s (app.alert\\('Cloudie test'\\);) >>\nendobj\n"
                 % (k("AA"), k("JavaScript"), k("JS"))).encode()
    else:  # script stored in a compressed stream
        js = zlib.compress(b"app.alert('Cloudie test');")
        body += ("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /%s 4 0 R >>\nendobj\n"
                 "4 0 obj\n<< /S /%s /%s 5 0 R >>\nendobj\n" % (k("OpenAction"), k("JavaScript"), k("JS"))).encode()
        body += b"5 0 obj\n<< /Filter /FlateDecode /Length %d >>\nstream\n" % len(js) + js + b"\nendstream\nendobj\n"
    if pad:
        body += padding(pad, rnd)
    return body + b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"


def plain(pad: int, rnd: random.Random) -> bytes:
    body = (b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n")
    if pad:
        body += padding(pad, rnd)
    return body + b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"


def judge(data: bytes):
    fd, path = tempfile.mkstemp(suffix=".pdf")
    os.close(fd)
    try:
        with open(path, "wb") as fh:
            fh.write(data)
        ext = extract_features(path)
        v = ext["features"]
        p = float(MODEL.predict_proba(pd.DataFrame([[v[c] for c in FEATS]], columns=FEATS))[0][1])
        ev = E.analyze(path)["strong_ids"]
    finally:
        os.remove(path)
    feat_risk = risk_indicators(v)
    old = combine(ai_proba=p, vt_positives=0, vt_total=70, ai_risk=feat_risk)["verdict"] == "suspicious"
    new = combine(ai_proba=p, vt_positives=0, vt_total=70,
                  ai_risk=list(dict.fromkeys(feat_risk + ev)), evasion=ev)["verdict"] == "suspicious"
    return p, p >= 0.5, old, new, bool(ev)


def pct(n, d):
    return "%5.1f%%" % (100.0 * n / d) if d else "   n/a"


def main():
    rnd = random.Random(42)
    templates = ["openaction", "additional_actions", "compressed_script"]
    rows = []
    print("Synthetic evasive PDFs (harmless payload), VirusTotal assumed clean\n")
    print("%-34s %4s %9s %9s %9s %9s %8s" % ("keyword obfuscation", "n", "mean P", "RF>=0.5", "old logic", "new logic", "evasion"))
    for level, label in ((0, "level 0: clear text"), (1, "level 1: first letter escaped"),
                         (2, "level 2: half the letters"), (3, "level 3: every letter escaped")):
        n = rf = old = new = evs = 0
        psum = 0.0
        for t in templates:
            for pad in (0, 4000, 40000):
                for _ in range(8):
                    p, rf_flag, o, nw, ev = judge(build(t, level, pad, rnd))
                    n += 1; psum += p; rf += rf_flag; old += o; new += nw; evs += ev
        rows.append((label, n, psum / n, rf, old, new, evs))
        print("%-34s %4d %9.2f %9s %9s %9s %8s" % (label, n, psum / n, pct(rf, n), pct(old, n), pct(new, n), pct(evs, n)))

    print("\nControls (false positives)")
    n = rfa = old = new = evs = 0
    for pad in (0, 2000, 8000, 40000, 120000):
        for _ in range(20):
            p, rf_flag, o, nw, ev = judge(plain(pad, rnd))
            n += 1; rfa += rf_flag; old += o; new += nw; evs += ev
    print("  synthetic plain PDFs (n=%d): RF alone flags %s, old logic flags %s, new logic flags %s, strong evasion findings %s"
          % (n, pct(rfa, n), pct(old, n), pct(new, n), pct(evs, n)))
    docs = os.path.join(ROOT, "docs")
    pdfs = [os.path.join(d, f) for d, _, fs in os.walk(docs) for f in fs if f.lower().endswith(".pdf")]
    strong = 0
    worst_ms = 0
    for pth in pdfs:
        r = E.analyze(pth)
        strong += bool(r["strong_ids"])
        worst_ms = max(worst_ms, r["scanned"]["ms"])
    print("  real benign PDFs under docs/ (n=%d): strong evasion findings in %d; slowest analysis %d ms" % (len(pdfs), strong, worst_ms))


if __name__ == "__main__":
    main()
