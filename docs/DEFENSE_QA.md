# Cloudie — Defense Q&A (46 questions)

Companion to `docs\STUDY_GUIDE.md`. Each item has: a short honest English answer, a one-line Malay memory aid, and where to point.
`file:line` = project path (`flask_api\app.py:197` is written `app.py:197`). `Thesis x.y` = section in `FYP_THESIS_formatted`.
Rule for every answer: say what the code does, admit the limit, then say what you would improve.

Numbers to keep in your head: **32 features · 200 trees · Gini · balanced · 18,126 rows (9,063 per class) · 99.86% (pickle's own 80/20 test, n = 3,626) · 99.87% (re-run, stratified 75/25) · 99.46% / recall 96.14% (size hold-out, n = 4,643) · AES-256-CBC · 25 MB upload limit (PHP and scanner agree since 2026-10-27) · OTP 6 digits / 10 min / 5 attempts.**

---

## A. Architecture

### A1. Describe the architecture in one minute.
**Answer:** Two Cloud Run services: `cloudie-php` (PHP 8.3 + Apache) handles auth, upload, encryption, folders and the UI; `cloudie-flask` (Python + gunicorn) does the scan. State lives in Cloud SQL MySQL (users, files metadata, key hashes, audit log) and a Cloud Storage bucket (encrypted blobs). PHP calls Flask `/scan` over HTTPS, then decides what to encrypt and store. The same code also runs on XAMPP, where blobs go to a local folder.
**BM:** Dua servis Cloud Run: PHP urus UI/enkripsi, Flask urus scan; DB di Cloud SQL, fail terenkripsi di GCS.
**Proof:** `config.php:23-43`, `scanner.php:13-52`, `storage.php:56-107`, STUDY_GUIDE 2.1; Thesis 4.2.

### A2. Why split into PHP and Flask?
**Answer:** The ML model needs Python and scikit-learn; the web layer is PHP on the XAMPP stack from the course. A small HTTP boundary (`/scan`) keeps each side simple and lets the scanner be redeployed or replaced without touching the web app. The cost is an extra network hop and a second service to secure.
**BM:** ML perlu Python, web guna PHP; asingkan supaya boleh deploy/tukar sendiri, tapi ada kos network.
**Proof:** `scanner.php`, `flask_api\Dockerfile`; Thesis 3.2.2, 4.2.

### A3. Walk me through what happens when I upload a file.
**Answer:** PHP checks CSRF, size (≤ 25 MB, the scanner limit) and extension, saves a temporary copy, and posts it to Flask. Flask extracts 32 features, gets the Random Forest probability, asks VirusTotal, and `combine()` returns clean, suspicious, malicious or error. Malicious and error are discarded; clean and suspicious are encrypted in memory with a fresh AES-256 key and IV, uploaded to storage, the cleartext temp file is deleted, and the key is shown once.
**BM:** Semak → scan (Flask) → verdict → kalau tak malicious, enkrip & simpan → padam fail asal → tunjuk key sekali.
**Proof:** `scan_and_encrypt.php:32-254`, STUDY_GUIDE 3.3 (sequence diagram); Thesis 3.3.5, 4.3.7.

### A4. Why does the database have a separate `file_keys` table?
**Answer:** It keeps the key-verification material (SHA-256 of the key and the IV) apart from the file metadata, one row per file, with `ON DELETE CASCADE` so deleting a file removes its key row. It mirrors the thesis ERD idea of a KEY entity. Note the thesis ERD has an outdated shape (key_content, key_id on FILE); the real link is `file_keys.file_id`.
**BM:** Pisahkan metadata fail dengan bahan semakan key; satu baris setiap fail.
**Proof:** `database\cloudie_schema.sql:90-101`, `scan_and_encrypt.php:218-226`; Thesis 3.3.6 (mismatch, STUDY_GUIDE 6 rows 2-4).

### A5. How does the same code run on XAMPP and Cloud Run?
**Answer:** `config.php` reads every setting with `getenv()` first and falls back to a local default. `USE_CLOUD_STORAGE` switches the storage backend between a local folder and GCS, and `DB_HOST` starting with `/` switches PDO from TCP to the Cloud SQL Unix socket. Secrets arrive as environment variables from Secret Manager.
**BM:** Config baca env dulu, kalau tiada guna default local; satu kod, dua persekitaran.
**Proof:** `config.php:14-26,38-43`, `db.php:19-28`, `storage.php:56-60`.

### A6. Why are there auto-migrations in `db.php`?
**Answer:** The schema grew during development (folders, verdict, email verification and OTP columns). `db_ensure_folders()` and `db_ensure_auth()` add missing columns idempotently, ignoring MySQL error 1060, so an older database upgrades itself. The downside is a failed `ALTER` attempt on each request; the schema file now matches the final structure for fresh installs.
**BM:** Auto-tambah column yang tiada supaya DB lama terus naik taraf; boleh diulang tanpa rosak.
**Proof:** `db.php:39-105`, `auth.php:20`; STUDY_GUIDE 3.6.

---

## B. AI / model

### B1. Why Random Forest?
**Answer:** The features are tabular counts (JavaScript, OpenAction, object counts), RF handles non-linear interactions and noisy features without scaling, is hard to overfit by majority vote, and gives feature importances that I can explain. It trains in seconds and predicts in milliseconds, which fits an upload path. I did not claim it beats deep learning; it fits this dataset and is explainable.
**BM:** Data jadual, RF kuat untuk interaksi tak linear, laju, dan boleh terangkan feature importance.
**Proof:** `malware_rf.metrics.json` (importances); Thesis 3.3.1.

### B2. What are the model's settings and inputs?
**Answer:** 200 trees, Gini, `class_weight=balanced`, random_state 42, `n_features_in_ = 32`, saved as a bundle with the ordered feature names. Features are PDF structure counts and sizes such as `/JS`, `/JavaScript`, `/OpenAction`, `/EmbeddedFile`, object and stream counts, PDF version and metadata size. I verified these by loading the pickle.
**BM:** 200 pokok, Gini, balanced, 32 feature; sah dengan load pkl.
**Proof:** `app.py:66-123`, STUDY_GUIDE 4.1-4.2; Thesis 3.3.2, 4.4.2.

### B3. Why is `name` not a feature, and where did "33" come from?
**Answer:** `name` in `Final.csv` is just the sample's file identifier, a string you cannot compute for a new upload and which a tree could memorise. The CSV has 34 columns (name, 32 features, class); an earlier validation run kept `name`, which produced the wrong "33 features" report. The deployed model and extractor use 32.
**BM:** `name` cuma ID fail, bukan ciri; versi lama tersilap masukkan, jadi nampak 33.
**Proof:** `Final.csv` header, `validate_model.py:73-79`, `PROJECT_RECOVERY.md` §3; Thesis 3.3.2 ("excluding the filename").

### B4. Why do benign real-world PDFs score around 0.3-0.4?
**Answer:** Because they are outside the training distribution. I measured P(malicious) of 0.28, 0.30 and 0.41 on three of my own documents: they are large (1-4 MB vs a 75 KB benign median), have no XMP block so `metadata_size` is 0 (never 0 in training, and the top-importance feature), and the extractor counts substrings (`obj` also counts `endobj`). The forest's vote share drifts toward the middle when inputs are unfamiliar, but stays below 0.5 so the verdict is still clean. This is exactly why VirusTotal is primary.
**BM:** Fail besar & tiada metadata XMP jauh dari data latihan, jadi undi pokok berpecah ~0.3-0.4; sebab tu VT jadi utama.
**Proof:** STUDY_GUIDE 4.1 (skews) and 4.5; `feature_extractor.py:142-143`; `Final.csv` (metadata_size never 0).

### B5. Is the extractor really the same as the dataset's features?
**Answer:** Names, order and encodings match (`header` as PDF version 1.6, `contains_text` as 1/0), checked by name at model load. It is not a perfect replica of the dataset's tooling: `metadata_size` is defined differently and a few counts use plain substring matching. I measured that fixing the substring counts alone does not change the verdict, but I list it as a limitation and a retraining-on-own-extractor item for future work.
**BM:** Nama/susunan/encoding sama, tapi cara kira beberapa feature tak sama 100% dengan dataset; saya akui dan senaraikan.
**Proof:** `feature_extractor.py:27-60,135-143,165`, `app.py:111-119`; STUDY_GUIDE 4.1.

### B6. What does the AI do with a non-PDF file?
**Answer:** Today it still runs: the Flask API saves any upload as a temporary `.pdf` and extracts features, so a PNG scored 0.84 in my test and would come out "suspicious" if VirusTotal passes it. That is a real gap: the model is only meaningful for PDFs, as the thesis limitations say. The fix is a PDF gate (check `%PDF-` magic) so other types rely on VirusTotal only.
**BM:** Sekarang AI jalan atas semua jenis fail, PNG pun kena 0.84; patut ada gate PDF sahaja.
**Proof:** `app.py:265-277`, `config.php:77-78`; Thesis 5.3; STUDY_GUIDE W6.

---

## C. Validation

### C1. Is 99.87% the accuracy of the deployed model?
**Answer:** No. 99.87% is from `validate_model.py`, which re-trains a fresh model with the same pipeline and settings on a stratified 75/25 split. The deployed pickle's own test result is 99.86% on a different 80/20 split (n = 3,626). Both say the pipeline works on this dataset; neither is evidence about real-world uploads.
**BM:** Bukan; 99.87% dari latih semula pipeline sama, pkl sebenar 99.86% atas split 80/20 lain.
**Proof:** `validate_model.py:201-249`, `malware_rf.metrics.json`; PROJECT_RECOVERY §3; Thesis 4.4.2-4.4.3.

### C2. Why re-train instead of testing the deployed pickle?
**Answer:** The pickle saw a random 80% of all rows. A size-based test set (the largest 25% of files) would overlap its training data, so testing the pickle on it would be leakage. Re-training on the complement is the only valid way to measure that design, so what I validate is the training pipeline and configuration.
**BM:** pkl dah nampak 80% data rawak; kalau uji atasnya hasil bocor, jadi latih semula atas baki.
**Proof:** `validate_model.py:205-224`; STUDY_GUIDE 4.4.

### C3. Why is the size-based hold-out more conservative?
**Answer:** The model never sees any file in the test size band during training, so it must extrapolate to larger PDFs. Accuracy there was 99.46%, but recall dropped to 96.14% (18 missed, 7 false alarms); in this dataset malicious files are small, so the held-out band is mostly benign and accuracy flatters. I quote recall as the honest figure.
**BM:** Fail besar tak pernah dilihat masa latih; accuracy 99.46% tapi recall 96.14% — itu nombor jujur.
**Proof:** `flask_api\validation_report_size_holdout.json:59-78`, `validate_model.py:205-214`; Thesis 4.4.3 (update to 99.46/96.14).

### C4. Isn't the dataset overlapping with Contagio?
**Answer:** Yes, CIC-Evasive-PDFMal2022 is built largely from Contagio and VirusTotal samples, so testing on raw Contagio would be circular, and I did not do that. All my validation is inside this one dataset, which is why I do not claim real-world accuracy and why VirusTotal is primary. Since 2026-10-28 there is one independent check, for false positives only: 200 benign PDFs from GovDocs1 (never in the dataset) gave a final 1.0% tagged and 0 blocked (`docs/BENIGN_FP_BENCHMARK.md`). Detection on independent malware is still not tested.
**BM:** Ya, banyak bertindih; sebab tu saya tak uji atas Contagio & tak dakwa ketepatan dunia sebenar.
**Proof:** `validate_model.py:22-28`; Thesis 5.4 (second recommendation).

### C5. 99.9% accuracy looks too good. Is the model memorising?
**Answer:** The in-sample accuracy is 100% and the held-out accuracy is 99.5-99.9%, so the gap is small, but a small gap inside one dataset is not proof of generalisation: malicious and benign PDFs in this dataset differ strongly in size, metadata and JavaScript use (for example, 96% of benign files have zero `/JavaScript` vs 14% of malicious). Real documents scored 0.3-0.4, which shows the model is uncertain outside the dataset. That is the reason for the layered design.
**BM:** Jurang kecil dalam satu dataset bukan bukti generalisasi; PDF sebenar skor 0.3-0.4 — sebab itu ada VT.
**Proof:** STUDY_GUIDE 4.4-4.5; `Final.csv`; Thesis 4.4.3, 4.5.

### C6. Where is the training script for the deployed model?
**Answer:** The exact script that produced `malware_rf.pkl` is not in the repository; `ml\train_model.py` is an older 33-column design. What I can show is the model's saved configuration, its feature list, its own metrics JSON, and `validate_model.py`, which reproduces the same configuration from `Final.csv`. I should add the training script to the repo before submission.
**BM:** Skrip latih pkl tak ada dalam repo; ada config, metrics dan validate_model sebagai ganti — patut tambah.
**Proof:** `ml\train_model.py:6,37-44` vs `malware_rf.pkl`; STUDY_GUIDE 4.2.

---

## D. VirusTotal

### D1. Why is VT primary if you built an AI model?
**Answer:** VirusTotal aggregates 70+ engines with signatures updated daily, and my model is trained on one dataset and is uncertain outside it (real PDFs score 0.3-0.4). So a VT hit blocks the file; the model can only downgrade a VT-clean file to *suspicious*, which flags a possible zero-day without wrongly blocking users. The supervisor's policy also set VT as primary.
**BM:** VT 70+ enjin & dikemas kini; model saya terhad pada satu dataset, jadi VT putuskan blok, AI cuma beri amaran.
**Proof:** `verdict_engine.py:4-23,30,91-106`; Thesis 4.2, 4.5.

### D2. What happens if VirusTotal is down or the key is missing?
**Answer:** `vt_scan()` returns "no result" and the verdict falls back to the AI: AI below 0.5 gives *clean* (stored), AI at or above 0.5 gives *suspicious* (stored, tagged), and only if both fail is the file blocked as *error*. So an outage degrades to AI-only protection rather than stopping uploads; I should say that plainly. A stricter policy would block when VT is configured but unreachable.
**BM:** VT tiada → guna AI sahaja (clean/suspicious); hanya bila dua-dua gagal baru blok.
**Proof:** `app.py:193-195,229-234`, `verdict_engine.py:80-83,99-125`.

### D3. Is the VirusTotal check reliable as implemented?
**Answer:** I found a weakness: after uploading, `app.py` reads the analysis once without polling, and a new analysis is normally still queued, which could read as zero detections. A richer client with hash lookup and polling (`vt_client.py`) exists but is not wired in. I have not proven the failure live, so I would verify with the EICAR test file and then switch the call to the polling client.
**BM:** Kod baca keputusan VT sekali tanpa poll — boleh nampak "clean" palsu; klien yang betul ada tapi tak disambung.
**Proof:** `app.py:197-228`, `vt_client.py:137-178` (unused); STUDY_GUIDE W1.

### D4. VirusTotal has a free-tier limit. Can this scale?
**Answer:** The free API allows about 4 requests per minute and 500 per day, 32 MB per file, so it supports a prototype, not production. Production would need a paid key, hash-first lookups (which cost no upload), caching of verdicts by SHA-256 and a queue. I describe this as a deployment limitation.
**BM:** Percuma 4 req/min, 500/hari, 32MB; produksi perlu key berbayar, cache hash & queue.
**Proof:** `vt_client.py:14-15,140-143`; Thesis 5.3 (internet dependency), 5.4.

### D5. Isn't uploading user files to VirusTotal a privacy problem?
**Answer:** Yes, it is a trade-off: the file is sent to VirusTotal in cleartext before encryption, and VT can share samples with its partners. It is the price of signature scanning, and it is stated nowhere in the UI today. Mitigations: look up by SHA-256 first and upload only unknown files, add user consent text, or use an on-prem scanner for sensitive tenants.
**BM:** Ya, fail dihantar ke VT sebelum enkripsi; tukar-ganti untuk scan, patut hash-dulu & notis persetujuan.
**Proof:** `app.py:197-203`; STUDY_GUIDE W5.

### D6. What counts as "malicious" from VT?
**Answer:** `vt_positives` is malicious plus suspicious engines, and blocking needs at least two engines (`VT_MALICIOUS_MIN_HITS = 2`); a single engine is a weak hit and gives SUSPICIOUS (stored, tagged), because one engine out of ~70 is the usual false positive. Since 2026-10-26; before that one engine was enough. The three-way VT classification in the thesis text exists only in the unused client; the thesis should describe the two-engine rule.
**BM:** Satu enjin (malicious/suspicious) pun cukup untuk blok; ketat, utamakan keselamatan.
**Proof:** `app.py:226`, `verdict_engine.py:32,47-49`; Thesis 3.3.3 (mismatch row 7).

---

## E. Encryption

### E1. How are the key and IV generated, and what is stored?
**Answer:** A new 32-byte key and 16-byte IV are drawn per file from PHP's CSPRNG `random_bytes()`. The ciphertext goes to storage; the database stores only `sha256(key)` and the base64 IV. The raw key is shown to the user once and emailed, and never saved by the server.
**BM:** Key 32B & IV 16B rawak setiap fail; DB simpan hash key + IV sahaja, key sebenar tak disimpan.
**Proof:** `aes.php:9-15`, `scan_and_encrypt.php:177-226`; Thesis 3.3.3, 4.4.5.

### E2. Why store `sha256(key)` and what does it protect against?
**Answer:** It lets the server check a supplied key without holding it, and a database leak yields only hashes of random 256-bit values, which cannot be reversed or brute-forced. It does not protect against someone who already has the key, and it proves key possession, not that the ciphertext is unmodified.
**BM:** Boleh semak key tanpa simpan key; kalau DB bocor, hash 256-bit rawak tak boleh dipecahkan.
**Proof:** `aes.php:100-102`, `decrypt.php:61`.

### E3. Why CBC and not GCM?
**Answer:** CBC with a random IV gives confidentiality and was a scope decision for this prototype, but it has no authentication tag, so tampering is not detected. GCM (authenticated encryption) is the better choice and is future work: it needs a stored nonce/tag and re-encryption of existing blobs. Until then, integrity relies on storage access controls, and I should add a hash check of the decrypted output.
**BM:** CBC cukup untuk kerahsiaan tapi tiada tag integriti; GCM lebih baik dan jadi kerja akan datang.
**Proof:** `aes.php:28`, `config.php:69`; Thesis 5.3-5.4.

### E4. How do you check integrity then?
**Answer:** Honestly, only partly. The key hash proves the user holds the right key, and `file_md5` is stored at upload, but the app does not recompute it after decrypting; the thesis hash comparison (Table 4.5) was a manual test. Adding `md5/sha256(decrypted) == file_md5` to `decrypt.php`, or moving to GCM, would close this.
**BM:** Sebenarnya separuh sahaja: hash key disemak, md5 fail disimpan tapi tak dibandingkan semula masa decrypt.
**Proof:** `decrypt.php:61-71`, `scan_and_encrypt.php:76,209`; Thesis 4.4.6.

### E5. Can the admin decrypt user files?
**Answer:** Not from the database and bucket alone: they hold ciphertext, IVs and key hashes. But the operator controls the code, the key passes through server memory at upload and decrypt, and it is emailed in plain text, so it is not zero-knowledge. A zero-knowledge design would encrypt in the browser. I should phrase the claim as "keys are not stored at rest".
**BM:** Dari DB+bucket sahaja tak boleh, tapi operator kawal kod & key lalu memori server; bukan zero-knowledge.
**Proof:** `scan_and_encrypt.php:177-194,248-254`, `decrypt.php:56-71`; `index.php:150` (wording).

### E6. What if the user loses the key?
**Answer:** The file cannot be recovered by anyone, including the server, and the user cannot even delete it because deleting also requires the key. That is a deliberate property of not storing keys, shown in the UI and the email. Recovery would need a key-escrow design (for example a key wrapped by a user passphrase), which is future work. Note the thesis mentions a "recovery PIN" that does not exist in the code.
**BM:** Hilang key = fail tak boleh dipulih (dan tak boleh delete); recovery PIN dalam tesis tak wujud dalam kod.
**Proof:** `scan_and_encrypt.php:311-313`, `decrypt.php:56-96`; Thesis 4.2/5.1 (mismatch row 1).

### E7. Is the plaintext ever written to disk?
**Answer:** Briefly, yes: the uploaded cleartext sits in `uploads/` while it is scanned and encrypted, then `unlink()` removes it (also on every error path). Decryption for view/download is done in memory and streamed, never written. A hardening step is a private temp directory outside the web root.
**BM:** Masa scan ada fail asal sekejap dalam uploads/, lepas enkripsi dipadam; decrypt dalam memori sahaja.
**Proof:** `scan_and_encrypt.php:54,65,92,186,195`, `decrypt.php:68-89`; STUDY_GUIDE W10.

---

## F. Security

### F1. How are passwords and the second factor handled?
**Answer:** Passwords are hashed with bcrypt and checked with `password_verify`. After a correct password, a 6-digit code from `random_int` is stored as a bcrypt hash with a 10-minute expiry, limited to 5 attempts and a 60-second resend gap, and emailed; the session is created only after the code verifies, with `session_regenerate_id`. Email must be verified first.
**BM:** Bcrypt untuk password; OTP 6 digit di-hash, tamat 10 min, 5 cubaan; sesi dibuat lepas OTP sah.
**Proof:** `register.php:40`, `login.php:36-47,63-111`, `config.php:83-85`; Thesis 4.3.3-4.3.4.

### F2. Is the 2FA bypassable?
**Answer:** There is one design weakness: if the OTP email cannot be sent (mail disabled or SMTP failure), the code is shown on the page so local XAMPP still works. In production that means an SMTP outage removes the second factor. The fix is to show the code only when a `DEV_MODE` flag is set and otherwise fail closed.
**BM:** Kalau email OTP gagal, kod dipapar atas skrin — patut fail-closed di produksi.
**Proof:** `login.php:206,266-272`; STUDY_GUIDE W3.

### F3. How do you stop SQL injection and XSS?
**Answer:** All queries use PDO prepared statements with native prepares (`ATTR_EMULATE_PREPARES=false`); the only interpolated value is a constant cast to int. Output goes through `htmlspecialchars` via `e()`. Stored files are served from a fixed MIME map with `nosniff`, and HTML/SVG/JS are not in the extension allow-list.
**BM:** PDO prepared statement semua; output di-escape dengan `e()`; jenis fail dihadkan dan nosniff.
**Proof:** `db.php:13-17`, `auth.php:47-49`, `decrypt.php:78-89,325-343`, `config.php:77-78`.

### F4. Is there CSRF protection? Brute-force protection?
**Answer:** Yes for CSRF: a per-session random token is required on every POST handler. Brute-force is weaker: OTP attempts are limited, but stage-1 password attempts have no lockout or throttle, and the OTP resend resets the attempt counter. I would add per-account and per-IP rate limiting.
**BM:** CSRF ada pada semua POST; tapi tiada had cubaan password — patut tambah rate limit.
**Proof:** `auth.php:34-45`, `login.php:171-211`; STUDY_GUIDE W8.

### F5. What are your biggest security weaknesses?
**Answer:** (1) The VirusTotal result is read without polling, so a "clean" may be unverified; (2) the QR fallback sends the key to qrserver.com; (3) 2FA and email verification fail open when mail fails; (4) CBC without integrity check; (5) the public Flask endpoint. I know them, have measured or traced each, and listed fixes.
**BM:** Lima utama: VT tak poll, QR hantar key ke pihak ketiga, 2FA fail-open, CBC tiada integriti, Flask terbuka.
**Proof:** STUDY_GUIDE 5.5 (W1-W3, W7, W11).

### F6. Are users isolated from each other?
**Answer:** Every query that touches files, keys or folders includes `AND user_id = ?` with the session user, so guessing another file ID returns "not found". Decrypting also needs the correct key, so even a bug in ownership would still need the key. File IDs are sequential integers, which is acceptable given those checks.
**BM:** Semua query ada `user_id` sesi; ID fail orang lain = "not found"; ditambah perlu key.
**Proof:** `decrypt.php:32-44`, `view_report.php:30-42`, `folder.php:10-13,24-33`.

---

## G. Cloud / deployment

### G1. Why does a stateless Cloud Run need Cloud Storage?
**Answer:** A Cloud Run container's disk is ephemeral and not shared between instances, so anything written locally disappears on restart. Persistent encrypted blobs therefore go to GCS through `storage.php`, authenticated by the service account, while the container disk holds only the cleartext temp file for one request.
**BM:** Disk Cloud Run sementara; fail kekal mesti dalam GCS.
**Proof:** `storage.php:1-23,56-107`; Thesis 4.4.5.

### G2. How are secrets handled?
**Answer:** The DB password and SMTP app password are stored in Secret Manager and injected as environment variables at deploy time; `config.php` reads them with `getenv()`. `.gitignore` excludes `.env`, key files and runtime folders, and the ignore files keep them out of images. One item is still unconfirmed: that `VT_API_KEY` is attached to the Flask service.
**BM:** Secret Manager → env var; .gitignore/.gcloudignore jaga rahsia; VT_API_KEY perlu disahkan.
**Proof:** `docs\DEPLOY_NOTES.txt` (`--set-secrets`), `config.php:14-26,59`; CLAUDE.md TODO 3.

### G3. How does PHP reach Cloud SQL?
**Answer:** Through the Cloud SQL Unix socket mounted at `/cloudsql/<connection name>`; `DB_HOST` is that path and `db.php` builds a DSN with `unix_socket=` instead of `host=`. Traffic stays on Google's internal path. The instance also has a public IP for admin access, which should be restricted by the authorized-networks list and removed when not needed.
**BM:** Guna socket `/cloudsql/...` dalam DSN; IP awam instance patut dihadkan.
**Proof:** `db.php:19-23`, root `Dockerfile`, `docs\DEPLOY_NOTES.txt`.

### G4. The live site returned 503. Is it deployed?
**Answer:** On 2026-10-12 both Cloud Run services returned 503 and the cause is still being checked (billing, revision state, or Cloud SQL stopped to save credit). The fixes made that day (extractor encoding, text, ignore files) are not deployed yet. For the defense I can run the full system locally and show the Cloud deployment through console screenshots once restored.
**BM:** Dua servis 503, punca belum pasti; pembetulan 12 Okt belum deploy — demo local sebagai pelan B.
**Proof:** `docs\PROJECT_RECOVERY.md` §4-5; CLAUDE.md TODO 1-2.

### G5. Cost and scaling?
**Answer:** Cloud Run scales to zero and bills per request, which suits a prototype; Cloud SQL is the fixed cost (it can be stopped with `--activation-policy`). The Flask worker is one gunicorn worker with 8 threads and the scan can take up to a minute, so concurrent uploads would queue; production would need a job queue and more instances.
**BM:** Cloud Run skala ke sifar; kos tetap di Cloud SQL; scan 1 minit jadi had konkurensi.
**Proof:** `flask_api\Dockerfile`, `docs\DEPLOY_NOTES.txt`; Thesis 5.4.

---

## H. Limitations and future work

### H1. What are the main limitations?
**Answer:** The model is PDF-only and trained on one dataset; real-world detection is unproven (false positives are measured on 200 real PDFs: 1.0% tagged, 0 blocked; not on Office/ZIP); VirusTotal needs internet and has quota limits; CBC lacks authentication; and the key is lost if the user loses it. Non-PDF files skip the model (magic-byte gate) and rely on VirusTotal and the structure checks. Stating these myself is part of the validation.
**BM:** Model PDF sahaja, satu dataset, VT perlu internet & kuota, CBC tiada integriti, key hilang = fail hilang.
**Proof:** Thesis 5.3; STUDY_GUIDE 5.5.

### H2. What would you do next?
**Answer:** In order: (1) poll VirusTotal with hash-first lookup and verify with EICAR; (2) PDF-only gate for the model; (3) AES-GCM or a post-decrypt hash check; (4) retrain with features computed by my own extractor so training and serving match; (5) test on an independent PDF set; (6) rate limiting and fail-closed OTP; (7) an authentication secret between PHP and Flask.
**BM:** Susunan: poll VT, gate PDF, GCM/semak hash, latih semula dengan extractor sendiri, uji dataset bebas, rate-limit, rahsia PHP-Flask.
**Proof:** STUDY_GUIDE 5.5; Thesis 5.4.

### H3. Why did you not use a sandbox / dynamic analysis?
**Answer:** Dynamic analysis is costly, slow per file and evaded by sandbox-aware malware, so for an interactive upload path I chose static analysis (structure) plus VirusTotal's multi-engine signatures. It is a limitation: behaviour-only malware that looks structurally normal and is unknown to VT would pass.
**BM:** Dinamik mahal & lambat, boleh dielak; pilih statik + VT; kelemahan: malware tingkah-laku baru boleh lepas.
**Proof:** Thesis 2.3.2-2.3.3.

### H4. How would you measure the system in the real world?
**Answer:** Use the persisted evidence: `actions` rows (`SCAN` with verdict and probability) and `files.scan_report`, plus a labelled set of fresh PDFs checked against VT, to compute precision/recall and the AI-VT disagreement rate. The scan CSV helps in a local run but is lost on Cloud Run restarts, so the DB is the durable log.
**BM:** Guna log `actions` & `scan_report` dalam DB + set PDF baru berlabel untuk kira precision/recall dan kadar percanggahan AI-VT.
**Proof:** `scan_and_encrypt.php:78-80`, `prediction_log.py`; Thesis 4.4.7 (log field mismatch, STUDY_GUIDE 6 row 21).

---

### Quick "hard-question" cheat card

| If they say… | Land this line |
|---|---|
| "99.87% is amazing" | "That is the pipeline on held-out data inside one dataset; recall on the size-based split is 96.14%, and real PDFs score 0.3-0.4, which is why VT leads." |
| "AI is useless then" | "It can't block alone; it flags structure VT hasn't signed yet. Its value is the *suspicious* tag." |
| "Can't the server read my files?" | "Not at rest. The key is never stored; but I don't claim zero-knowledge — the key passes through server memory and email." |
| "What if VT misses it?" | "Then the AI may tag it suspicious; if both miss, it is stored encrypted — no detector is complete." |
| "Is the thesis consistent with the code?" | "I audited it: the main items (32 features, VT-primary, verdicts) match; I listed the remaining differences and corrected them." *(only say this once you have fixed the table in STUDY_GUIDE 6)* |
