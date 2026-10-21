# Cloudie — CLAUDE.md

Final Year Project (CSP650), BSc (Hons) Netcentric Computing, UiTM Shah Alam.
Student: Muhammad Aqeef bin Azhar. Supervisor: Dr. Fakariah Hani Binti Mohd Ali.

Cloudie is secure cloud storage. Every upload is scanned (VirusTotal first, a
Random Forest PDF model second), then encrypted with AES-256-CBC before it is
stored. Main goal right now: **competition** (live demo + judges trying the app).
The thesis is no longer a deliverable, but every claim in the UI and in the demo
must still match the code (see `docs\AUDIT_REPORT.md`).

Talk to Aqeef in casual Malay/English. He works in PowerShell on Windows, so
give PowerShell commands with full absolute paths, and full drop-in files
(with a backup first) rather than partial diffs.

## Where things live

Everything is in ONE folder (git repo): `C:\xampp\htdocs\cloudie\`

| What | Path (relative to `C:\xampp\htdocs\cloudie\`) |
|---|---|
| PHP front-end | `*.php`, `includes\`, `assets\` |
| Flask API | `flask_api\` (Windows venv: `flask_api\.venv`, not in git) |
| DB schema | `database\cloudie_schema.sql` |
| Thesis, report, deck, poster | `docs\thesis-and-presentation\` |
| Figures / diagrams / screenshots | `docs\figures\` |
| Deploy + ops command notes | `docs\DEPLOY_NOTES.txt` |
| Recovery report (2026-10-12) | `docs\PROJECT_RECOVERY.md` |
| Old setup notes (May 2026, outdated) | `docs\SETUP-original.md` |
| Old training script (reference only) | `ml\train_model.py` |

- `docs\`, `ml\`, `database\` have `.htaccess` (`Require all denied`) so XAMPP does not serve them,
  and they are in `.gcloudignore` / `.dockerignore` so they never go into the Cloud Run image.
- Old copies and backups (not needed to run anything): `C:\Users\aqeeflew\Desktop\Cloudie\archive\`.
- There is **no** `start-cloudie.bat`.

## Architecture

- **cloudie-php** (Cloud Run, PHP 8.3 + Apache): auth (+ email verification and login OTP),
  upload, AES encryption, folders, dashboard, scan reports, decrypt.
- **cloudie-flask** (Cloud Run, Python 3.12 + gunicorn): `/health`, `/scan` (= `/analyze`).
  `app.py` → PDF magic-byte gate → `feature_extractor.py` → RF in `malware_rf.pkl`;
  `vt_client.py` (hash lookup, upload, polling, 85 s budget); `verdict_engine.py` combines them.
- **Cloud SQL MySQL** `cloudie-db`, public IP 34.143.161.161, DB `cloudie_db`, user `cloudie_user`.
  Cloud Run connects through the socket `/cloudsql/cloudie-499914:asia-southeast1:cloudie-db`.
- **GCS** `cloudie-499914-files`: encrypted blobs when `USE_CLOUD_STORAGE=true`.
- GCP project `cloudie-499914`, region `asia-southeast1`.
- Secret Manager: `cloudie-db-pass` → `DB_PASS`, `cloudie-gmail-pass` → `SMTP_PASS`,
  `cloudie-vt-key` → `VT_API_KEY` (Flask; confirmed attached on 2026-10-20).
- URLs: `https://cloudie-php-800476519477.asia-southeast1.run.app`,
  `https://cloudie-flask-800476519477.asia-southeast1.run.app`
  (the `...-2q6nug2xha-as.a.run.app` URLs also work).
- **Live status (2026-10-21):** deployed from `main` after PR #9
  (php `cloudie-php-00033-4xc`, flask `cloudie-flask-00007-z2z`). The earlier HTTP 503 was
  **billing disabled** (Cloud SQL `SUSPENDED`, reason `BILLING_ISSUE`); billing is active again.
- **Flask is private** (Cloud Run IAM): only the service account
  `800476519477-compute@developer.gserviceaccount.com` has `roles/run.invoker`; `allUsers` was removed.
  PHP has `SCANNER_AUTH=iam` and sends a Google ID token (`includes/scanner.php`). Calling Flask directly
  gives 403/401. Locally `SCANNER_AUTH` defaults to `none`. Rollback: re-add `allUsers` as invoker.

## Facts the code and thesis must agree on

- **VirusTotal is PRIMARY, Random Forest is SECONDARY** (`verdict_engine.py`, `PRIMARY_DETECTOR = "VT"`).
  - **VT no result** (no key, 429, timeout, unfinished analysis) → ERROR, blocked (fail closed).
  - VT malicious → MALICIOUS, blocked.
  - VT clean + AI malicious → SUSPICIOUS, stored but tagged.
  - Both clean → CLEAN.
  - VT HTTP 409 = file already known; `vt_client.py` resolves it through the hash report.
  - Non-PDF files skip the RF (magic-byte gate) and are judged by VirusTotal only.
- The verdict is `clean | suspicious | malicious` in `files.verdict VARCHAR(20)`. The column is added
  by `includes/db.php`. Old notes said VARCHAR(16); the real column is 20.
- **RF model:** RandomForest, 200 trees, Gini, `class_weight="balanced"`, **32 features**.
  - The data is CIC-Evasive-PDFMal2022 (`Final.csv`, 18,126 rows, 9,063 per class).
  - `name` is a file identifier, not a feature. Including it gave the old "33" figure.
- **Feature encoding** must match training:
  - `header` = PDF version (`%PDF-1.6` → 1.6).
  - `contains_text` = 1/0.
- **Validated accuracy** (re-run 2026-10-12, `validate_model.py`, seed 42):
  - Stratified 75/25 hold-out: **99.87%** (FP 0, FN 6).
  - Size-based hold-out (top quartile of `pdf_size`): **99.46%** (FP 7, FN 18, recall 96.14%).
  - Replaces the old 99.80% / 99.53%, which came from a 33-column run with the encoding wrong.
- **AES-256-CBC:** random 32-byte key and 16-byte IV per file (`includes/aes.php`).
  - Only `sha256(key)` is stored, in `file_keys.key_hash`.
  - The real key goes to the user by email/QR.
  - CBC has no built-in integrity. This is mitigated by hash checks. AES-GCM is future work.
- **Storage:** Cloud Run is stateless, so blobs go to GCS via `includes/storage.php`. Local XAMPP uses `encrypted/`.
- **Email:** PHPMailer 6.9.1 (`includes/PHPMailer/src/`) + Gmail SMTP. Best-effort, never blocks.
  - Sends welcome, AES key, OTP, and verification emails.

## Run locally (Windows)

```powershell
# 1. XAMPP: start Apache + MySQL, then import the schema once
& "C:\xampp\mysql\bin\mysql.exe" -u root -e "source C:/xampp/htdocs/cloudie/database/cloudie_schema.sql"

# 2. Flask API
cd C:\xampp\htdocs\cloudie\flask_api
.venv\Scripts\activate
python app.py            # http://127.0.0.1:5000/health

# 3. PHP
# open http://localhost/cloudie/
```

Local defaults live in `includes/config.php` (`getenv()` first, then local fallback).

## Deploy (ASK AQEEF BEFORE RUNNING ANY OF THESE)

```powershell
gcloud config set project cloudie-499914
cd C:\xampp\htdocs\cloudie\flask_api
gcloud run deploy cloudie-flask --source . --region asia-southeast1 --no-allow-unauthenticated
cd C:\xampp\htdocs\cloudie
gcloud run deploy cloudie-php --source . --region asia-southeast1 --allow-unauthenticated
```

The full first-time `cloudie-php` command (env vars + secrets) is in `docs\DEPLOY_NOTES.txt`.
A plain redeploy keeps existing env vars and secrets.
**Flask must be deployed with `--no-allow-unauthenticated`** (it is private; `--allow-unauthenticated` would
re-add `allUsers` as invoker and reopen it). Check afterwards: `gcloud run services get-iam-policy cloudie-flask`
must list only the compute service account.

If Cloud SQL was stopped to save credit:
`gcloud sql instances patch cloudie-db --activation-policy ALWAYS`

## Gotchas (do not relearn these)

- Flask files go together: `app.py`, `feature_extractor.py`, `malware_rf.pkl`, `malware_rf.metrics.json`
  (+ `verdict_engine.py`, `prediction_log.py`). A partial swap gives the 32/33 mismatch.
- The extractor must encode `header`/`contains_text` the same way as training (see above).
  The tree splits on `header` sit at 1.05–1.65.
- PDO: never reuse a named placeholder (`:l` twice) with `ATTR_EMULATE_PREPARES=false`. It gives HTTP 500 on login.
  Use positional `?`.
- Ignore files must start with a dot (`.gcloudignore`, `.dockerignore`). They were named without the dot
  until 2026-10-12, so PHP deploys shipped `flask_api\` (incl. the 396 MB `.venv`).
- `gcloud sql connect` is unreliable without ADC. Use
  `& "C:\xampp\mysql\bin\mysql.exe" -h 34.143.161.161 -u cloudie_user -p cloudie_db`
  after adding your current IP to Cloud SQL Authorized Networks.
- Never commit secrets, `.venv`, `encrypted/`, `uploads/`, `keys/` (see `.gitignore`).
- Windows Defender quarantines EICAR in `C:\xampp\tmp` and `uploads\` on local XAMPP, so the local malicious
  demo needs a temporary Defender exclusion (and `$env:TEMP`/`$env:TMP` set for the Flask window), or use Cloud Run.
- Without `VT_API_KEY` every upload is blocked (fail closed). Set it in the Flask window for local demos.
- Local MySQL (XAMPP) must be running; "MySQL server has gone away" usually means it is stopped.
- `qr.php` has no online fallback by design (a QR service would see the AES key). Without
  `composer install` the key is shown as text only on local XAMPP.
- Keep local backups in `backup/` or `backup-*/` (both are ignored by `.gcloudignore` / `.dockerignore`).
- On real-world PDFs the RF gives P(malicious) ≈ 0.41–0.43 (close to the 0.5 cut-off). The model is less
  certain outside the dataset distribution. This is a good argument for VT being primary.

## Open TODOs

Done: billing/503 fixed and redeployed (2026-10-20); `VT_API_KEY` attached; VT polling, PDF gate,
fail-closed, QR, OTP, header and upload hardening live; Flask made private with IAM (2026-10-21).

1. Post-decrypt integrity check (hash), rate limiting on login/register/upload, CSP, README and basic tests.
2. Replace the placeholder GitHub, LinkedIn and email links in `index.php` (real URLs needed).
3. Clean old IPs in Cloud SQL Authorized Networks; stop Cloud SQL when not demoing (cost).
4. Innovation ideas discussed 2026-10-20: AI (explainable verdicts, calibration + out-of-distribution flag,
   VT-as-teacher feedback loop) and platform (retroactive rescan, hash-chained audit log).
