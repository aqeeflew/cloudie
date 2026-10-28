# False-positive rate on real benign PDFs (GovDocs1)

Measured on 2026-10-28 with `ml/benign_fp_benchmark.py`. The data and every per-file result are in the repo, so
anyone can check or repeat it.

## Result

| What is measured (200 real benign PDFs) | Flagged | Rate | 95% interval (Wilson) |
|---|---|---|---|
| Random Forest alone (P(malicious) >= 0.5) | 13 | 6.5% | 3.8% – 10.8% |
| AI after the risk gate (what the report tags) | 1 | 0.5% | |
| Strong evasion / structure finding | 0 | 0% | |
| **Final Cloudie verdict not "clean"** | **2** | **1.0%** | 0.3% – 3.6% |
| Blocked (verdict "malicious") | **0** | **0%** | |

Both "not clean" files were stored and tagged **SUSPICIOUS**, never blocked:

- `000570.pdf`: VirusTotal had **1 of 50** engines flag it. Cloudie needs 2 engines to block, so it was only tagged.
  This is the "lone engine" false positive the 2-engine rule was made for.
- `000369.pdf`: RF score 0.53 and the file has an `/OpenAction` entry, so the risk gate passed. Here `/OpenAction`
  is an ordinary "open at this page" action, not a script. Possible refinement: count `/OpenAction` as a risk
  indicator only when it leads to JavaScript or Launch.

What this shows:

- **The risk gate matters.** The RF alone would wrongly tag 13 files (6.5%). They are small (12 of 13 under 60 KB)
  and score 0.50–0.65, the "tiny PDF" weakness noted when the gate was added. After the gate only 1 remains.
- **The evasion and structure layers raised no false alarm** on these 200 files.
- **AI familiarity was right to warn:** 197 of 200 files are "unfamiliar" and 3 "unusual" (none "familiar").
  Real PDFs look different from the training data, which is why VirusTotal stays primary.
- Median scan time without VirusTotal: about 100 ms per file.

## Data

- **Source:** GovDocs1 (Digital Corpora, https://digitalcorpora.org/corpora/file-corpora/files/): about one million
  files collected from US government web sites, a standard corpus for testing forensic and security tools.
  Not part of CIC-Evasive-PDFMal2022, so the test is independent of the training data.
- **Selection:** zip `000.zip`; **all 200** members that are PDFs by magic bytes and at most 10 MB (no sampling was
  needed: the zip holds exactly 200). Files: `ml/benign_set/govdocs1/` (120 MB). List, SHA-256 and origin:
  `ml/benign_set/manifest.csv`.
- **"Benign" check:** VirusTotal hash lookup of every file (no upload), `ml/benign_set/vt_labels.csv`.
  199 clean, 1 flagged by a single engine (kept, see above), 0 flagged by 2 or more, 0 unknown to VirusTotal.

## Method

Every file goes through the **real Flask scan route** (`flask_api/app.py`, Flask test client), so the same code
as production decides: feature extraction, Random Forest, risk gate, evasion and structure checks, familiarity and
`verdict_engine.combine`. Only the VirusTotal call is replaced by its recorded hash-lookup answer (to save quota).
Per-file results: `ml/benign_set/results.csv`; totals: `ml/benign_set/summary.json`.

Repeat it (from `C:\xampp\htdocs\cloudie`):

```powershell
flask_api\.venv\Scripts\python.exe ml\build_benign_set.py <path to GovDocs1 000.zip>
$env:VT_API_KEY = "..."; flask_api\.venv\Scripts\python.exe ml\benign_fp_benchmark.py label
flask_api\.venv\Scripts\python.exe ml\benign_fp_benchmark.py run
```

## Limits (say these out loud)

- 200 files from one source. US government documents, mostly older PDFs (198 of 200 are version 1.1–1.6; only 2 are 1.7). Malaysian, recent,
  scanned or form-heavy PDFs may behave differently.
- PDFs only. There is still **no** false-positive measurement for Office, ZIP, CSV or image files.
- With 200 files the uncertainty is wide: the true final rate could be anywhere from about 0.3% to 3.6%.
- VirusTotal answers can change over time; the lookup date is in `vt_labels.csv`.
