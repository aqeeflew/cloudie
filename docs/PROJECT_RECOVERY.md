# Cloudie: project recovery report (2026-10-12)

## 1. Inventory

| Path | What it is | Verdict |
|---|---|---|
| `C:\xampp\htdocs\cloudie` | PHP app + `flask_api\`; last code change 2026-07-30 | **Canonical.** Now a git repo |
| `Desktop\Cloudie\app` (copy made 2026-10-12 11:18) | Byte-identical copy of htdocs (56/56 files same hash) | Moved to `Desktop\Cloudie\archive\app-copy-20261012` |
| `Desktop\files`, `Desktop\files\cloudie\cloudie` | May 2026 snapshot (no `verdict_engine.py`, old 33-feature extractor) | Old. Copied in `archive\snapshot-2026-05-*` |
| `Desktop\backup`, `Desktop\cloudie_email_feature` | 19 Jun 2026 email-feature experiment | Old. Copied in `archive\cloudie_email_feature` |
| `Desktop\fyp` | Thesis, deck, poster, figures | Copied into `htdocs\cloudie\docs\` |
| `htdocs\clouble`, `htdocs\cloud`, `htdocs\final2025`, `Desktop\fyp\development` | Earlier pre-Cloudie projects (Dec 2025 – Apr 2026) | Not Cloudie |
| `Downloads\rf_pdf_malware.pkl` | Older model (11 May) | Not used |
| `Downloads\cloudie-key-1.txt`, `cloudie-key-7.txt` | AES keys from testing | Can be deleted |
| `Desktop\text folder\cloudieee starttupp.txt` | Deploy + ops commands | Copied to `docs\DEPLOY_NOTES.txt` |
| `start-cloudie.bat` | Doesn't exist | — |

## 2. Code vs. notes checklist

| Item | Status | Where |
|---|---|---|
| VT primary, RF secondary | ✅ code / ⚠️ docstring said AI-primary → fixed | `flask_api/verdict_engine.py:30`, `app.py:12` |
| 3-way verdict in `files.verdict` | ✅ (VARCHAR(20), not 16) | `includes/db.php:69` |
| RF: 200 trees, Gini, 32 features | ✅ (`n_features_in_` = 32, also class_weight=balanced) | `malware_rf.pkl` |
| Extractor emits 32 | ✅ | `feature_extractor.py` |
| Extractor encoding = training encoding | ❌ → fixed (`header` sent 1/0 instead of version; `contains_text` sent a count) | `feature_extractor.py` |
| AES-256-CBC, random key+IV, only sha256(key) stored | ✅ | `includes/aes.php:101`, `decrypt.php:61` |
| Blobs to GCS on Cloud Run | ✅ | `includes/storage.php` |
| Email best-effort (welcome, key, OTP, verify) | ✅ | `includes/mailer.php` |
| Login PDO positional placeholders | ✅ | `login.php` |
| index.php "33 features" | ❌ → fixed (3 places) | `index.php` |
| register.php "33 features" | ✅ already 32 | `register.php:105` |
| Accuracy tile | ✅ was 99.8% → now 99.87% / 99.46% | `index.php` |
| Placeholder GitHub/LinkedIn/email links | ❌ still open (need real URLs) | `index.php` ~L271–279 |
| `database/cloudie_schema.sql` | ❌ outdated → rewritten to match db.php | `database/` |
| Ignore files | ❌ named without dot (inactive) → fixed | `.gcloudignore`, `.dockerignore` |

## 3. Validation re-run

The old reports (`feature_count: 33`) kept `name`. `pd.to_numeric` also silently
zeroed `contains_text` and `header`, so the old runs used about 30 informative
columns. `validate_model.py` now drops `name` and encodes the two text columns
the way the deployed model was trained.

| Design | Old | New (32 features) |
|---|---|---|
| Stratified random 75/25 | 99.80% | **99.87%** (TN 2266, FP 0, FN 6, TP 2260; ROC-AUC 0.9997) |
| Size-based hold-out (top 25% `pdf_size` ≥ 79 KB) | 99.53% | **99.46%** (TN 4170, FP 7, FN 18, TP 448; recall 96.14%, ROC-AUC 0.9984) |

The results are deterministic (random_state 42). Same config as production:
RF 200 trees, Gini, balanced.

**For the defense:** these numbers validate the training *pipeline* (same
features, encoding and hyper-parameters) on held-out data. `malware_rf.pkl`
itself was trained on a separate stratified 80/20 split, and its own test
accuracy is 99.86% (`malware_rf.metrics.json`, 3,626 test files).

**Smoke test** on 3 real benign PDFs (poster, canvas, flow diagram):
- `/scan` returns HTTP 200 with verdict `clean` (VT not configured locally).
- The RF gives P(malicious) between 0.41 and 0.43, which is close to the 0.5 cut-off.
- This shows the model is less certain outside the dataset distribution, which supports using VT as primary.

## 4. Live GCP state

- On 2026-10-12, `cloudie-php` and `cloudie-flask` both returned **HTTP 503 "Service not available yet"** for over a minute.
- Cause still unknown. Run these read-only checks:

```powershell
gcloud run services list --project cloudie-499914 --region asia-southeast1
gcloud run revisions list --service cloudie-flask --project cloudie-499914 --region asia-southeast1 --limit 3
gcloud run services describe cloudie-flask --project cloudie-499914 --region asia-southeast1 --format="yaml(spec.template.spec.containers[0].env)"
gcloud sql instances describe cloudie-db --project cloudie-499914 --format="value(state,settings.activationPolicy)"
gcloud billing projects describe cloudie-499914
gcloud logging read "resource.type=cloud_run_revision AND severity>=ERROR" --project cloudie-499914 --limit 10 --freshness 3d
```

## 5. Changes made (git log in `C:\xampp\htdocs\cloudie`)

1. `5b5a187`: baseline snapshot, before any change.
2. `31fc6a8`: covers these fixes:
   - 33→32 and VT-primary wording in index.php
   - app.py docstring
   - ignore files renamed to dotfiles
   - schema rewritten
   - `.csvexit` → `.csv`
3. `6752404`: covers the model work:
   - honest 32-feature validation
   - extractor encoding aligned with the model
4. `e617ca8`: accuracy tile updated.
5. A final commit adds `CLAUDE.md`.

Backups of every edited file are in `Desktop\Cloudie\archive\backups-20261012-1207\`.

**Consolidation (2026-10-12 12:22):** everything needed now lives in `C:\xampp\htdocs\cloudie`
(code + `docs\` + `ml\` + `database\`). `Desktop\Cloudie` now only holds `archive\`.
To undo everything: `git -C C:\xampp\htdocs\cloudie checkout 5b5a187 -- .`

**Not deployed yet.** The live services still run the old code.
