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
- Secret Manager: `cloudie-db-pass` → `DB_PASS`, `cloudie-gmail-pass` → `SMTP_PASS`, `cloudie-audit-key` → `AUDIT_HMAC_KEY` (PHP; never rotate casually: old entries would no longer verify),
  `cloudie-vt-key` → `VT_API_KEY` (Flask; confirmed attached on 2026-10-20).
- URLs: `https://cloudie-php-800476519477.asia-southeast1.run.app`,
  `https://cloudie-flask-800476519477.asia-southeast1.run.app`
  (the `...-2q6nug2xha-as.a.run.app` URLs also work).
- **Live status (2026-10-27):** deployed from `main` after PR #40 (php `cloudie-php-00053-w4j`, flask `cloudie-flask-00019-zsx`).
  Cloud SQL automated backups ON (daily 19:00 UTC, 7 kept; on-demand backup `1792978507235` taken 2026-10-26).
  **Min instances = 1** on both services for the 2026-11-03 demo (avoids cold starts, small extra cost): set back to 0 after the
  competition with `gcloud run services update <svc> --region asia-southeast1 --min-instances 0`.
  The earlier HTTP 503 was **billing disabled** (Cloud SQL `SUSPENDED`, reason `BILLING_ISSUE`); billing is active again.
- **Flask is private** (Cloud Run IAM): only the service account
  `800476519477-compute@developer.gserviceaccount.com` has `roles/run.invoker`; `allUsers` was removed.
  PHP has `SCANNER_AUTH=iam` and sends a Google ID token (`includes/scanner.php`). Calling Flask directly
  gives 403/401. Locally `SCANNER_AUTH` defaults to `none`. Rollback: re-add `allUsers` as invoker.

## Facts the code and thesis must agree on

- **VirusTotal is PRIMARY, Random Forest is SECONDARY** (`verdict_engine.py`, `PRIMARY_DETECTOR = "VT"`).
  - **VT no result** (no key, 429, timeout, unfinished analysis) → ERROR, blocked (fail closed).
  - VT malicious (**>= 2 engines**, `VT_MALICIOUS_MIN_HITS = 2`) → MALICIOUS, blocked. Exactly 1 engine = weak hit → SUSPICIOUS
    (stored and tagged, report says "only 1 engine"), because a lone engine is the classic false positive. Changed 2026-10-26.
  - VT clean + AI malicious → SUSPICIOUS, stored but tagged, **only if the risk gate passes**:
    RF score >= 0.5 AND (a strong risk indicator is present — `JS`, `Javascript`, `OpenAction`, `AA`,
    `launch`, `EmbeddedFile`, `RichMedia`, `XFA`, `JBIG2Decode` — OR score >= 0.85). Otherwise CLEAN, AI verdict
    shown as UNCERTAIN (`verdict_engine.py`: `AI_HIGH_CONFIDENCE`, `STRONG_RISK_FEATURES`). Held-out cost:
    recall 99.69% → 99.38%, FP 0. Reason: tiny PDFs with no metadata block looked like malware to the RF.
  - **Evasion layer** (`flask_api/evasion_indicators.py`, rule-based, never changes the 32-feature vector): hidden keywords
    (`/J#61vaScript`), exploit techniques in scripts, embedded executables and shell launch are STRONG findings and tag a
    VT-clean PDF as SUSPICIOUS even when the AI score is low (`combine(..., evasion=...)`). Other findings are informational.
    Bounded: 3 s, 1500 streams, 512 KB per stream, 8 MB total. Benchmark (synthetic, with honest limits):
    `docs/EVASION_BENCHMARK.md`, `ml/evasion_benchmark.py`. Demo PDFs: `python tests/make_demo_pdfs.py <folder>`
    (clean / visible script / hidden script).
  - **Structure layer for other types** (`flask_api/file_structure.py`, `office_structure.py`, `archive_structure.py`; see `docs/STRUCTURE_CHECKS.md`):
    Office OOXML and ZIP files get rule-based checks (macro in a macro-free type, DDE, remote template, zip slip, zip bomb,
    disguised/double-extension programs), CSV formula injection, data hidden after PNG/JPEG images and tricks in the uploaded file
    NAME (`content_structure.py`); every upload gets a name-vs-content check. Strong findings tag a VT-clean file
    SUSPICIOUS. The RF stays PDF-only. Not measured on real-world benign Office files (no FP rate claimed).
    Demo files: `python tests/make_demo_files.py <folder>`.
  - **AI familiarity** (flask_api/ai_familiarity.py, reference ai_familiarity.npz built by ml/build_ai_familiarity.py; see docs/AI_FAMILIARITY.md):
    distance of a PDF's 32 features to the nearest training PDFs, compared with how far training PDFs are from each other.
    Bands familiar / unusual / unfamiliar, shown in the report. Information only, never changes the verdict. All 10 project PDFs and the
    3 demo PDFs are "unfamiliar" (real PDFs are larger and have many images; training `images` is always <= 0): evidence that VT must stay primary.
  - The scan report has a "Why this AI score" card (`flask_api/feature_explain.py`, exact tree-path
    contributions + `feature_reference.json` built by `ml/build_feature_reference.py`).
  - Both clean → CLEAN.
  - VT HTTP 409 = file already known; `vt_client.py` resolves it through the hash report.
  - Non-PDF files skip the RF (magic-byte gate) and are judged by VirusTotal plus the structure layer above.
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
  - CBC has no built-in integrity. `decrypt.php` now compares the decrypted bytes with the hash recorded at
    upload (SHA-256 from `files.scan_report`, else `files.file_md5`) via `verify_plaintext_integrity()`; a
    mismatch is not served and is logged as `INTEGRITY_FAIL`. Not applied to delete. AES-GCM is future work.
- **Audit trail** (`includes/audit.php`, page `audit.php`): every `log_action()` call appends a sealed entry to a per-user
  hash chain (`actions.chain_seq/prev_hash/row_hash`, HMAC-SHA256 keyed by `AUDIT_HMAC_KEY`) plus a sealed head in
  `audit_heads` (detects deletion of the latest rows). Detects edited, removed, inserted, reordered entries; does NOT stop
  someone with both DB write access and the secret. Older rows are "earlier" (unsealed). If `audit_append` fails,
  `log_action` falls back to a plain row, shown as an unsealed entry inside the chain. Migration runs automatically
  (`db_ensure_audit`). Concurrency: head row is created outside the transaction + `FOR UPDATE` + deadlock retry
  (a 25-process stress test found a deadlock in the first version; now 80 parallel writes give 80 sealed entries).
  Demo: edit a row (`UPDATE actions SET details='x' WHERE act_id=...`) and reload `audit.php`: "Tampering detected".
- **Storage:** Cloud Run is stateless, so blobs go to GCS via `includes/storage.php`. Local XAMPP uses `encrypted/`.
- **Sign-up validation** (`includes/validate.php`, used by `register.php`, tested in `tests/php/run.php`): username 3-32 chars (letters, numbers, `. _ -`),
  email <= 120, optional phone 7-20, password 8-72 BYTES (bcrypt cuts at 72), no common/one-character/same-as-username-or-email passwords.
  Known and left as is: if the verification email cannot be sent the account is auto-verified (fail-open, protects the demo; limit it to dev mode later),
  verification token has no expiry and is stored in clear, link host comes from the Host header.
- **Email:** PHPMailer 6.9.1 (`includes/PHPMailer/src/`) + Gmail SMTP. Best-effort, never blocks.
  - Sends welcome, AES key, OTP, and verification emails.

## Tests

```powershell
powershell -ExecutionPolicy Bypass -File C:\xampp\htdocs\cloudie\tests\run_all.ps1
```

PHP tests in `tests\php\run.php` (81 checks, no DB), Flask tests in `flask_api\tests\` (175, `unittest`, VT mocked).
Run them before every deploy. `README.md` and `tests\` are in the ignore files (not shipped to Cloud Run).

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
- **Rate limiting** (`includes/ratelimit.php`, table `rate_limits`, keys SHA-256 hashed; policies in `RL_POLICY`):
  login 5 failed/15 min per account and 20 per IP, OTP 10 wrong codes/h and 5 emails/h per account, 5 verification
  emails/h per IP, register 8/h per IP, upload 10/10 min per user. State is in the DB (not the session) because
  Cloud Run instances do not share sessions. Client IP = last `X-Forwarded-For` entry behind Cloud Run.
  To unlock a locked-out test account: `DELETE FROM rate_limits;`.
- **VirusTotal free quota (about 4 requests/min) matters for demos.** A file VT does not know yet needs upload + polling
  (up to 85 s, polls at 15 s then every 10 s); known files need one hash lookup. When the quota is exhausted the scan
  returns ERROR (fail closed) and the user sees "VirusTotal error". Before a demo: scan each demo file ONCE a few minutes
  earlier (so VT knows its hash), and wait about a minute between uploads. Observed on 2026-10-22: three new files in a row,
  only the first got a result.
- Keep local backups in `backup/` or `backup-*/` (both are ignored by `.gcloudignore` / `.dockerignore`).
- On real-world PDFs the RF gives P(malicious) ≈ 0.41–0.43 (close to the 0.5 cut-off). The model is less
  certain outside the dataset distribution. This is a good argument for VT being primary.

## Open TODOs

Done: billing/503 fixed and redeployed (2026-10-20); `VT_API_KEY` attached; VT polling, PDF gate,
fail-closed, QR, OTP, header and upload hardening live; Flask made private with IAM (2026-10-21).

1. CSP. (Done: rate limiting, README, tests.) (Post-decrypt integrity check: done.)
   Also: build a real-world benign PDF set (100-200 files) to measure the false-positive rate.
2. (done) Credit links on `index.php` point to the repo, LinkedIn and email.
3. Clean old IPs in Cloud SQL Authorized Networks; stop Cloud SQL when not demoing (cost).
4. Innovation ideas discussed 2026-10-20: AI (explainable verdicts, calibration + out-of-distribution flag,
   VT-as-teacher feedback loop) and platform (retroactive rescan, hash-chained audit log).
