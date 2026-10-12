# Audit Cloudie (read-only) — 2026-10-12

Skop: seluruh repo `C:\xampp\htdocs\cloudie\` pada commit `db980c1`. Tiada fail diubah, tiada deploy, tiada arahan `gcloud`/DB. Tiada secret dipaparkan (grep hardcoded secret: **tiada** jumpa dalam kod aplikasi; `.gitignore` tutup `.env`, `*credentials*.json`, `*service-account*.json`).
Rujukan lanjut: `STUDY_GUIDE.md` (flow penuh) dan `DEFENSE_QA.md`.

Nota: beberapa angka dalam arahan audit sudah lapuk. Kod sebenar: `files.verdict` ialah **VARCHAR(20)** (`includes/db.php:69`), ketepatan yang disahkan ialah **99.87% / 99.46%** (bukan 99.80% / 99.53%).

---

## 1. Ringkasan eksekutif — 5 perkara untuk dibaiki sebelum defense

1. **VirusTotal dibaca sekali tanpa polling** (`flask_api/app.py:197-228`). Analisis baru biasanya masih *queued*, jadi "VT clean" boleh jadi palsu. Test dengan EICAR; kalau gagal, sambung `vt_client.py` (hash lookup + polling).
2. **Tesis menyebut "email recovery PIN" yang tiada dalam kod** (Bab 4.2, 4.5, 5.1, 5.5). Examiner boleh minta demo. Buang dari tesis.
3. **AES key dihantar ke pihak ketiga melalui QR** (`includes/qr.php:35-38`): `api.qrserver.com/...?data=<key>`. Bercanggah dengan dakwaan "key tak keluar". Pasang `endroid/qr-code` atau jana QR di browser.
4. **Flask `/scan` terbuka kepada umum** (`--allow-unauthenticated`, `app.py:254` tiada auth). Sesiapa boleh `curl` fail dan habiskan kuota VT.
5. **Model PDF dijalankan atas semua jenis fail** (`app.py:265`). PNG dapat P = 0.84 (diukur) → upload gambar biasa jadi "suspicious" semasa demo. Tambah gate `%PDF-`.

Selepas itu: betulkan jadual tesis (24 baris dalam `STUDY_GUIDE.md` §6), terutama Table 4.3 dan ERD.

---

## 2. Status known issues 1–5

| # | Isu | Status | Bukti |
|---|---|---|---|
| 1 | Bilangan feature "33" | **Fixed** dalam kod; **Partial** di luar kod | Tiada "33 feature" dalam `*.php`/`*.py`. `register.php:105` dan `index.php:60,126` = 32. Masih ada: `ml/train_model.py:6,37-44` (reka bentuk 33 lajur lama, rujukan sahaja) dan `flask_api/figures/*.png` (larian lama, binari padan "33/99.8" lama) |
| 2 | Tile ketepatan placeholder | **Fixed** | `index.php:171-172` = 99.87% dan "size-based: 99.46%" |
| 3 | Pautan portfolio placeholder | **Still present** | `index.php:271` (`github.com/your-username`), `:275` (`linkedin.com/in/your-handle`), `:279` (`mailto:you@example.com`) |
| 4 | Named placeholder diguna dua kali | **Fixed** | Semua query PDO guna `?`. Tiada pola `:nama` dalam mana-mana `*.php` aplikasi. `login.php:175-182` guna `?` dua kali dengan dua nilai |
| 5 | Konsistensi 32 feature | **Fixed / konsisten** | `feature_extractor.py:62` `assert len == 32`; pkl `n_features_in_ = 32` dan nama sama (diukur); `app.py:99-119` semak masa load. `malware_rf.metrics.json` tidak menyimpan `feature_count` (hanya top-15 importance); `/health` melaporkannya (`app.py:245-247`) |

---

## 3. Jadual findings

Severity ikut konteks FYP: **Critical** = boleh dieksploit/ketara semasa demo atau memusnahkan dakwaan utama; **High** = dakwaan tesis boleh dipatahkan atau eksploit sebenar; **Medium/Low** = elok dibaiki. Effort S/M/L = kecil/sederhana/besar.

| ID | Area | Finding | Evidence | Severity | Effort | Sebelum defense? | Recommended fix |
|---|---|---|---|---|---|---|---|
| F01 | C | VT dibaca sekali, tiada polling/hash lookup; analisis *queued* → `positives=0,total=0` dianggap VT clean. `vt_client.py` (polling) tidak pernah di-import | `app.py:197-228`; `vt_client.py:137-178` | **Critical** | M | **Yes** | Panggil `vt_client.scan_file()` dari `app.py`; test EICAR; anggap `queued`/`total==0` sebagai "tiada keputusan" |
| F02 | G | Tesis mendakwa recovery PIN email (hashed, time-limited, single-use); tiada kod forgot/reset password | Bab 4.2, 4.5, 5.1, 5.5; grep `forgot|reset` kosong | **High** | S | **Yes** | Edit tesis: OTP ialah 2FA login. (Atau bina reset password: L) |
| F03 | A/B | QR fallback hantar key ke `api.qrserver.com` melalui URL; `composer.json` tiada endroid → fallback sentiasa aktif; komen kata key tak keluar | `qr.php:22,35-38`; `composer.json:4-6`; `scan_and_encrypt.php:244,319` | **High** | S | **Yes** | `composer require endroid/qr-code` atau jana QR dengan JS di klien; betulkan komen |
| F04 | C/D | Flask tiada autentikasi; deploy `--allow-unauthenticated` | `app.py:254-258`; `docs/DEPLOY_NOTES.txt:54` | **High** | M | **Yes** (jika masa) | Cloud Run IAM (invoker = SA cloudie-php) atau header shared-secret disemak di Flask |
| F05 | C | RF + extractor dijalankan atas semua 14 jenis fail; fail disimpan sebagai `.pdf` sementara; PNG P=0.84 → "suspicious" | `app.py:265-277`; `config.php:77-78`; `feature_extractor.py:123-165` | **High** | S | **Yes** | Jika bukan `%PDF-` pada 1024 byte pertama → langkau RF, ikut VT sahaja; kemas kini UI/tesis |
| F06 | A | 2FA *fail-open*: jika email OTP gagal, kod dipapar pada skrin | `login.php:137,206,266-272` | **High** | S | **Yes** | Papar hanya jika `MAIL_ENABLED=false` DAN `APP_ENV=dev`; selainnya gagal tertutup |
| F07 | G | Tesis Table 4.3: 99.53% / recall 97.00%; larian semula = 99.46% / 96.14%. Baris 99.86% ialah ujian pkl sendiri (80/20) | `flask_api/validation_report_size_holdout.json:59-78`; `malware_rf.metrics.json` | **High** | S | **Yes** | Kemas kini jadual; label baris dengan jelas; tambah 99.87% |
| F08 | G | ERD tesis tidak sepadan: KEY `key_content`, FILE `key_id`, tiada FOLDER, AUTH kurang 6 lajur, verdict VARCHAR(16)/JSON | `database/cloudie_schema.sql:35-101`; `db.php:45,69` | **High** | M | **Yes** | Lukis semula ERD dan Table 3.4–3.8 |
| F09 | B/G | Tiada semakan integriti pasca-decrypt; `file_md5` disimpan tetapi tidak dibanding; dakwaan "hash checks mitigate CBC" hanya benar untuk key hash | `decrypt.php:61-71`; `scan_and_encrypt.php:76,209` | **Medium** | S | **Yes** | Selepas decrypt: `md5($plain) === file_md5` (S). Jangka panjang: AES-GCM |
| F10 | G | Tesis kata "VT dan AI selari (in parallel)", sebenarnya berurutan; VT-suspicious bukan keadaan berasingan; "hanya fail clean disimpan" (suspicious juga disimpan) | `app.py:271-283,226`; `scan_and_encrypt.php:171-172` | **Medium** | S | **Yes** | Ubah ayat (lihat STUDY_GUIDE §6 baris 6–10) |
| F11 | A | Tiada had percubaan pada login langkah 1, register, upload; resend OTP set semula `otp_attempts` | `login.php:171-211,116-139`; `register.php` | **Medium** | M | Yes jika masa | Throttle berdasarkan IP+akaun (jadual `login_attempts` atau sesi + sleep) |
| F12 | A | Pendaftaran *fail-open*: email pengesahan gagal → akaun auto-verified | `register.php:65-72`; `profile.php:81-87` | **Medium** | S | Future work | Sama pola dev-flag seperti F06 |
| F13 | A/B | Fail disimpan jelas ke VirusTotal sebelum enkripsi; key dihantar email biasa | `app.py:197-203`; `scan_and_encrypt.php:248-254`; `mailer.php:73-103` | **Medium** | M | Disclose dalam tesis | Hash lookup dulu; notis privasi; sebut had "bukan zero-knowledge" |
| F14 | A | Upload hanya semak sambungan; tiada magic-byte/MIME; fail sementara dalam web-root `uploads/` tanpa deny | `scan_and_encrypt.php:47-58`; `config.php:64,77` | **Medium** | S | Yes | `finfo` untuk jenis dibenarkan; `.htaccess Require all denied` dalam `uploads/` atau direktori di luar docroot |
| F15 | A | Cookie sesi tiada `Secure`; tiada CSP/X-Frame-Options/HSTS; logout melalui GET; tiada timeout lekang | `config.php:88-97`; grep header → hanya `nosniff` di `decrypt.php:86` | **Medium** | S | Yes | `secure=>true` bila HTTPS; `header()` X-Frame-Options/CSP asas dalam `config.php`; logout POST |
| F16 | C | Had saiz tidak konsisten: PHP 50 MB, Flask 25 MB, VT free 32 MB → 25–50 MB gagal "scan failed" | `config.php:74`; `app.py:52`; `vt_client.py:140` | **Medium** | S | Yes | Selaraskan kepada 25 MB (kod + UI + tesis) |
| F17 | E | Skrip latih pkl yang di-deploy tiada dalam repo; `ml/train_model.py` ialah reka bentuk lama | `ml/train_model.py:6,37-44`; `malware_rf.pkl` | **Medium** | M | Yes (tambah skrip) | Letak skrip latih sebenar + seed; sebut dalam tesis |
| F18 | C | Skew train/serve: `metadata_size`=0 tanpa XMP (dataset tak pernah 0; feature #1 pada 19.6%); count substring (`obj` kira `endobj`); PDF sebenar skor 0.3–0.4 | `feature_extractor.py:142-143,66-88`; `Final.csv` (diukur) | **Medium** | L | Future work (terangkan) | Latih semula dengan extractor sendiri; dokumenkan |
| F19 | F | `view_report.php` tanda fail `is_clean != 1` sebagai "rejected" → fail suspicious (disimpan) papar "File rejected" | `view_report.php:74`; `scan_report.php:91-93,338` | **Medium** | S | Yes | `$rejected = false` untuk fail tersimpan; guna `verdict` |
| F20 | F | Tiada reset password, tiada halaman sejarah/audit (jadual `actions` ditulis tetapi tidak dipaparkan), tiada admin | grep `FROM actions` kosong | **Medium** | M | Future work | Senarai dalam Bab 5.3/5.4 |
| F21 | E | Tiada ujian automatik, tiada README akar, `requirements.txt` tidak dipin | `git ls-files` (tiada test/README); `flask_api/requirements.txt` | **Medium** | M | Sebahagian | README ringkas + 3 ujian (lihat bawah) + pin versi sklearn yang melatih pkl |
| F22 | D | Log `prediction_log.csv` pada disk Cloud Run (hilang); tesis 4.4.7 kata CSV evidence dengan hash/jenis fail (medan tidak sepadan) | `app.py:44-46`; `prediction_log.py:21-34` | **Low** | S | Yes (tesis) | Rujuk jadual `actions` (SCAN) dan `files.scan_report` sebagai bukti kekal |
| F23 | A | `display_errors` lalai ON; production bergantung pada env `DISPLAY_ERRORS=0` | `config.php:111-112`; `docs/DEPLOY_NOTES.txt:24` | **Low** | S | Yes | Lalai `'0'`; ON hanya bila dev |
| F24 | C | Satu enjin VT (`malicious+suspicious ≥ 1`) sudah blok → risiko false positive; pengecualian 409/rate-limit (429) tidak dikendalikan (semua non-200/201 = "tiada keputusan") | `app.py:204-206,226`; `verdict_engine.py:32` | **Low** | S | Future work | Ambang (cth. ≥ 2) dan layan 429/queued berasingan; CLAUDE.md kata 409 "non-critical" tetapi tiada kod |
| F25 | E | Komen lapuk bercanggah dengan VT-primary ("AI primary", "VT second opinion", "anything else is blocked"); `vt_client.py` docstring | `app.py:184,276,279,311-314`; `vt_client.py:17-19` | **Low** | S | Yes | Betulkan komen; elak ditanya |
| F26 | E | Kod mati/duplikasi: `vt_client.py` tidak digunakan; `figures/` lama; `SETUP-original.md` lapuk | rujuk F01 | **Low** | S | Yes (selepas F01) | Guna atau padam |
| F27 | D | PHP: `memory_limit=256M` dengan fail 50 MB dimuat penuh ke memori (plain + cipher); `pickle` via `joblib.load` | `Dockerfile:` (php.ini), `aes.php:25-30,73-81`; `app.py:80` | **Low** | M | Future work | Sebut sebagai had; had saiz 25 MB (F16) mengurangkan |
| F28 | A | Pendaftaran dedah sama ada username/email wujud | `register.php:76-77` | **Low** | S | Future work | Mesej generik |

### Perlu semak manual (tidak boleh disahkan dari repo)

| Item | Semak apa |
|---|---|
| Cloud SQL IP awam + Authorized Networks | Console → Cloud SQL → Connections; buang IP lama; cadangan Cloud SQL connector/private IP. Cloud Run sudah guna socket (`db.php:19-23`) |
| Bucket `cloudie-499914-files` | Pastikan *Public access prevention* ON, uniform bucket-level access, IAM hanya SA `cloudie-php` (objectAdmin) |
| Service account & least privilege | `gcloud run services describe` (baca sahaja): SA mana, peranan apa |
| `VT_API_KEY` dilampirkan pada `cloudie-flask`? | Env/secret pada revision (TODO 3 dalam CLAUDE.md) |
| Cloud Run: min instances, timeout, memory, ingress | Cold start Flask (muat pkl 3.5 MB + sklearn); timeout ≥ 120 s untuk VT; memory ≥ 512Mi |
| Punca HTTP 503 (12 Okt) | Billing, revision, Cloud SQL stopped (TODO 1) |
| Pemantauan/log | Cloud Logging error alerts; tiada metrik tersuai dalam repo |
| Repo GitHub private? | Settings → Visibility (repo memuat senarai kelemahan dan nama resource) |

### Ujian minimum paling bernilai (cadangan, belum dibina)

1. `feature_extractor`: PDF kecil dengan `/JavaScript` + `/OpenAction` → vektor 32, `header=1.3`, `contains_text` ikut `BT`.
2. `verdict_engine.combine`: 7 baris jadual keputusan (VT hit, AI hit + VT clean, VT tiada, kedua-dua tiada → `error`).
3. AES round-trip: `aes_encrypt_file_to_string` → `aes_decrypt_string` sama dengan asal; kunci salah → `null`.

---

## 4. Soalan examiner (Critical/High)

| Finding | Soalan mungkin | Jawapan defensible |
|---|---|---|
| F01 | "Macam mana awak pastikan keputusan VT benar-benar siap?" | Pelaksanaan semasa membaca analisis sekali; saya kenal pasti had ini dan menyediakan klien polling (`vt_client.py`) untuk disambung. Saya sahkan dengan fail ujian EICAR. Reka bentuk fail-selamat: jika VT tiada keputusan, AI masih boleh menandakan *suspicious*. |
| F02 | "Tesis kata ada recovery PIN, tunjuk." | Ayat itu salah dalam draf; sistem ada OTP email untuk login dan pengesahan email, bukan pemulihan. Dalam reka bentuk kami, kehilangan key = fail tak boleh dipulihkan (sifat tanpa penyimpanan key). Pemulihan ialah kerja akan datang (key wrapping). |
| F03 | "Key anda keluar ke Internet?" | Ya, dalam laluan QR fallback ke qrserver.com. Itu kelemahan yang saya jumpa semasa audit; penyelesaian ialah perpustakaan QR setempat/JS klien. Key tidak disimpan dalam DB. |
| F04 | "Sesiapa boleh panggil API scan?" | Ya pada prototaip; penambahbaikan: IAM Cloud Run invoker atau shared secret. Risiko terhad kepada penggunaan kuota/CPU; tiada data pengguna di Flask. |
| F05 | "Apa jadi bila upload fail bukan PDF?" | Model dilatih untuk PDF sahaja (Bab 5.3). Pada masa ini ia masih dijalankan atas jenis lain; saya akan gate supaya jenis lain bergantung pada VT sahaja. |
| F06 | "Boleh bypass 2FA?" | Hanya jika email OTP gagal dihantar, kod dipapar (untuk XAMPP). Production patut gagal tertutup; ia pilihan konfigurasi. |
| F07/F08 | "Kenapa angka/ERD tak sama dengan sistem?" | Angka dikemas kini selepas larian semula (99.87% / 99.46%, recall 96.14%); ERD diselaraskan dengan skema sebenar (`file_keys`, `folders`, lajur auth). |

---

## 5. Future work (Bab 5)

- AES-256-GCM (atau encrypt-then-HMAC) + semakan hash selepas decrypt; skema perlu nonce/tag dan penyulitan semula blob lama.
- Key wrapping / escrow dengan passphrase pengguna untuk pemulihan; penyulitan di klien (zero-knowledge sebenar).
- Latih semula model dengan extractor sendiri; ujian pada dataset PDF bebas (elak bertindih Contagio); model untuk Office.
- VT: hash-first lookup, cache SHA-256, kunci berbayar, queue untuk scan.
- Rate limiting, lockout, CAPTCHA; header keselamatan; autentikasi PHP→Flask.
- Cloud SQL private IP/connector; audit log dipaparkan; admin view; reset password; CI + ujian automatik.
