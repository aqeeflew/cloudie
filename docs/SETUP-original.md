# Cloudie — Setup Guide

This walks through getting the whole system running locally on Windows
(XAMPP) or Linux/macOS. Tested with PHP 8.1+, Python 3.10+, MySQL 8.

---

## 1. Prerequisites

- **MySQL 8** (or MariaDB 10.6+)
- **PHP 8.1+** with the `pdo_mysql`, `openssl`, and `curl` extensions
  enabled (these are bundled with XAMPP's default install).
- **Python 3.10+** with `pip`.
- A web server. Any of these is fine:
  - XAMPP / WAMP / Laragon (Windows)
  - Apache + PHP-FPM (Linux)
  - The built-in PHP development server (`php -S`)

---

## 2. Create the database

```bash
# Linux / macOS
mysql -u root -p < database/cloudie_schema.sql
```

On XAMPP, you can also import `database/cloudie_schema.sql` from
phpMyAdmin (Import tab).

If your MySQL credentials are not `root` / empty, edit
`php_app/includes/config.php` and update `DB_USER` / `DB_PASS`.

---

## 3. Train the AI model

The Flask scanner can run in *heuristic* mode without a trained model
(useful for the very first demo), but the thesis target is the
Random Forest classifier described in Section 3.3.1.

You need a labelled CSV with the same column names listed in
`flask_api/feature_extractor.py::FEATURE_COLUMNS`, plus a `Class`
column where `1 = malicious`, `0 = benign`.

The Contagio PDF dataset (referenced in Sec 2.8.2) and the
`Evasive-PDFMal2022` Kaggle dataset both work after a tiny rename pass.

```bash
cd flask_api
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cd ../ml_model
python train_model.py --data /path/to/pdf_dataset.csv \
                      --out  ../flask_api/malware_rf.pkl
```

Expected output (numbers will vary):

```
[+] Evaluation on hold-out set
    Accuracy : 0.9912
    Precision: 0.9893
    Recall   : 0.9876
    F1-Score : 0.9884
[+] Model saved to ../flask_api/malware_rf.pkl
```

The corresponding metrics JSON is written next to the model file —
you can paste those numbers straight into Chapter 4.

---

## 4. Start the Flask scanner

```bash
cd flask_api
python app.py
# -> Running on http://127.0.0.1:5000
```

Smoke test:

```bash
curl http://127.0.0.1:5000/health
# {"status":"ok","engine":"random_forest","features":33,"max_upload_bytes":52428800}
```

To scan a PDF directly:

```bash
curl -F "file=@sample.pdf" http://127.0.0.1:5000/scan
```

---

## 5. Start the PHP front-end

### Option A — built-in PHP server

```bash
cd php_app
php -S 127.0.0.1:8080
```

Open <http://127.0.0.1:8080/> in your browser.

### Option B — XAMPP / Apache

Copy or symlink the `php_app/` folder into your `htdocs`, e.g.
`htdocs/cloudie`, and visit <http://localhost/cloudie/>.

> **Permissions:** make sure the web server user can write to
> `php_app/uploads`, `php_app/encrypted`, and `php_app/keys`.

---

## 6. End-to-end smoke test

1. Register a new user.
2. Upload a benign PDF — you should get the green "Success!" screen and
   a QR code containing your AES key.
3. Save the key (copy it or download the .txt).
4. Go to **My files** → click **View** → paste the key → the PDF opens.
5. Try uploading `eicar.com` or a known-malicious test PDF — the
   scanner should reject it before encryption.
6. Click **Delete** on a file → paste the key → the encrypted blob is
   removed from disk and from the database.

---

## 7. Common issues

| Symptom                              | Likely cause                                     |
|--------------------------------------|--------------------------------------------------|
| `Malware scan failed: ... Could not connect` | Flask API not running, or `SCANNER_URL` wrong.  |
| All uploads marked malicious         | No model file → falling back to heuristics. Train and place `malware_rf.pkl` in `flask_api/`. |
| `SQLSTATE[HY000] [1045]`             | Wrong DB user/password in `config.php`.          |
| QR image doesn't render              | Browser blocked the external QR API; install `endroid/qr-code` via Composer for an offline data-URI. |
| `decrypt.php` says "wrong key"       | The user pasted the wrong key, or used a key from another file. (Each file has its own key.) |

---

## 8. Hardening checklist for production

- [ ] Move `php_app/encrypted/` outside the web root.
- [ ] Force HTTPS and set `session.cookie_secure=1`.
- [ ] Run the Flask API behind gunicorn/uvicorn + reverse proxy.
- [ ] Limit `MAX_UPLOAD_BYTES` and add per-user upload quotas.
- [ ] Rotate the model file weekly; track its hash in `actions`.
- [ ] Ship a Composer install of `endroid/qr-code` so QR codes never
      involve a third-party service.
