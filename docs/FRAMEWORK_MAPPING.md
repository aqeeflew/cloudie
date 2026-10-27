# Cloudie: mapping to security frameworks

Cloudie is **mapped to** these frameworks. It is **not certified or audited** against any of them.
ISO/IEC 27001 certifies an organisation's management system (ISMS), not an application, so only
the technical Annex A controls are mapped here. Every row names the code that implements it, so a
reviewer can check it.

Say it like this: *"Cloudie's controls are mapped to MITRE ATT&CK, NIST CSF 2.0, OWASP and
ISO/IEC 27001:2022 Annex A."* Do not say "compliant" or "certified".

## 1. MITRE ATT&CK: what the structure layer detects

Finding ids are the `out.add("...")` ids in `flask_api/`.

| Technique | Cloudie finding(s) | Where |
|---|---|---|
| T1566.001 Phishing: Spearphishing Attachment | whole upload pipeline (malicious attachments are the entry point) | `app.py` |
| T1204.002 User Execution: Malicious File | VirusTotal verdict + structure layer | `vt_client.py`, `verdict_engine.py` |
| T1027 Obfuscated Files or Information | `obfuscated_keywords` (`/J#61vaScript`), `obfuscated_filters`, `filter_chain` | `evasion_indicators.py` |
| T1027.003 Steganography | `image_hidden_payload`, `image_script_payload`, `image_trailing_data` | `content_structure.py` |
| T1059.005 Command and Scripting Interpreter: Visual Basic | `macro_in_macrofree_type`, `office_macro`, `macro_autoexec`, `macro_risky_calls` | `office_structure.py` |
| T1059.007 Command and Scripting Interpreter: JavaScript | `js_exploit_techniques`, `js_risky_api` (PDF scripts) | `evasion_indicators.py` |
| T1221 Template Injection | `remote_template` | `office_structure.py` |
| T1559.002 Inter-Process Communication: DDE | `dde_field`, `dde_formula`, `csv_dde_formula` | `office_structure.py`, `content_structure.py` |
| T1036.007 Masquerading: Double File Extension | `double_extension`, `filename_double_extension` | `archive_structure.py`, `content_structure.py` |
| T1036.002 Masquerading: Right-to-Left Override | `rtlo_name`, `filename_rtlo` | `archive_structure.py`, `content_structure.py` |
| T1036.008 Masquerading: Masquerade File Type | `type_mismatch`, `type_mismatch_executable`, `disguised_executable` | `file_structure.py`, `archive_structure.py` |
| T1027.009 Obfuscated Files: Embedded Payloads | `embedded_executable`, `executable_in_archive`, `polyglot_executable_archive` | `evasion_indicators.py`, `archive_structure.py` |

Weaknesses without an ATT&CK technique, mapped to CWE instead:

| Weakness | Finding | Where |
|---|---|---|
| CWE-22 Path Traversal (zip slip) | `path_traversal` | `archive_structure.py` |
| CWE-409 Highly Compressed Data (zip bomb) | `zip_bomb`, `archive_too_large` | `archive_structure.py` |
| CWE-1236 CSV/Formula Injection | `csv_dde_formula`, `csv_exfil_formula` | `content_structure.py` |

Demo files for most rows: `python tests/make_demo_files.py <folder>` and `python tests/make_demo_pdfs.py <folder>`.

## 2. NIST Cybersecurity Framework 2.0

| Function / category | Cloudie control | Where |
|---|---|---|
| ID.RA Risk Assessment | Written threat model | `docs/THREAT_MODEL.md` |
| PR.AA Identity, Authentication, Access Control | bcrypt passwords, login OTP, rate limits, per-owner file access, private scanner (Cloud Run IAM) | `login.php`, `includes/ratelimit.php`, `includes/scanner.php` |
| PR.DS-01 Data at rest | AES-256-CBC, random key + IV per file, only `sha256(key)` stored | `includes/aes.php` |
| PR.DS-02 Data in transit | HTTPS on Cloud Run, HSTS, ID token to the scanner | `includes/config.php` |
| PR.DS-11 Backups | Cloud SQL automated backups (daily, 7 kept) | GCP config, `docs/DEPLOY_NOTES.txt` |
| PR.PS-04 Log records | HMAC-sealed per-user audit chain | `includes/audit.php`, `audit.php` |
| DE.CM-09 Monitoring of software/data | Every upload scanned before storage | `flask_api/app.py` |
| DE.AE-02 Adverse events analysed | Verdict engine + explained report ("Why this AI score", structure findings) | `verdict_engine.py`, `includes/scan_report.php` |
| RS.MI Incident Mitigation | Malicious files blocked, fail closed when VirusTotal gives no answer, suspicious files tagged | `verdict_engine.py` |
| RC.RP Recovery Plan Execution | Restore from Cloud SQL backup | `docs/DEPLOY_NOTES.txt` |

**GV (Govern)** is out of scope: there is no organisation, policy or ISMS behind a student project.

## 3. OWASP

| OWASP item | Cloudie control | Where |
|---|---|---|
| A01 Broken Access Control | Every file query is filtered by the session user; CSRF tokens on state-changing forms | `includes/auth.php`, `verify_csrf()` |
| A02 Cryptographic Failures | AES-256 at rest, bcrypt, HTTPS + HSTS, key never stored | `includes/aes.php` |
| A03 Injection | PDO prepared statements (positional `?`), output escaping `e()` | `includes/db.php` |
| A04 Insecure Design | Threat model, fail-closed scanning | `docs/THREAT_MODEL.md` |
| A05 Security Misconfiguration | Security headers (X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy). **Gap: no CSP yet** | `includes/config.php` |
| A07 Identification and Authentication Failures | Rate limits, OTP, generic login error, session id regenerated, idle timeout, HttpOnly/SameSite cookie | `login.php`, `includes/config.php` |
| A08 Software and Data Integrity Failures | Plaintext hash checked after decrypt; tamper-evident audit chain | `decrypt.php`, `includes/audit.php` |
| A09 Logging and Monitoring Failures | Audit trail with verification page | `audit.php` |
| File Upload Cheat Sheet | Extension allowlist, content (magic-byte) check, 25 MB limit, malware scan, stored encrypted outside the web root, generated storage names (never the user's file name) | `upload.php`, `scan_and_encrypt.php`, `flask_api/file_structure.py` |

## 4. ISO/IEC 27001:2022 Annex A (technical controls only)

| Control | Cloudie | Where |
|---|---|---|
| 5.17 Authentication information | Password rules, bcrypt | `includes/validate.php` |
| 8.3 Information access restriction | Owner-only file access, private scanner | `includes/scanner.php` |
| 8.5 Secure authentication | OTP, rate limits | `login.php` |
| 8.7 Protection against malware | VirusTotal + structure layer + RF | `flask_api/` |
| 8.13 Information backup | Cloud SQL backups | GCP |
| 8.15 Logging | Sealed audit chain | `includes/audit.php` |
| 8.24 Use of cryptography | AES-256-CBC, SHA-256, HMAC-SHA256 | `includes/aes.php`, `includes/audit.php` |
| 8.26 Application security requirements | Threat model | `docs/THREAT_MODEL.md` |
| 8.28 Secure coding | Prepared statements, input validation, escaping | `includes/validate.php` |
| 8.29 Security testing | 81 PHP checks + 175 Flask tests | `tests/run_all.ps1` |

Clauses 4-10 (the management system itself) are out of scope.

## 5. NIST SP 800-63B (passwords and login)

| Requirement | Cloudie |
|---|---|
| At least 8 characters | Yes (`PASSWORD_MIN = 8`) |
| Allow at least 64 characters | Yes, 72 (bcrypt's byte limit, `PASSWORD_MAX = 72`) |
| Check against common / context-specific passwords | Yes: common list, repeated character, same as username or email |
| No forced composition rules | Yes, none |
| Offer a strength meter | Yes, on sign-up and profile |
| Limit failed attempts | Yes, 5 per account per 15 min, 20 per IP |
| Out-of-band authenticator | **No.** 800-63B does not accept email as an out-of-band authenticator, so the email OTP is not AAL2 |

## Honest gaps (say these before a judge does)

1. **Email OTP is not an 800-63B authenticator.** Stronger than a password alone, not AAL2. Future: TOTP or passkeys.
2. **AES-CBC has no built-in integrity.** Cloudie checks the plaintext hash after decrypting; AES-GCM is future work (ISO 8.24).
3. **No Content-Security-Policy yet** (OWASP A05).
4. **No ISMS:** NIST CSF *Govern* and ISO 27001 clauses 4-10 do not apply.
5. **Structure checks are not measured on a real benign Office set**, so no false-positive rate is claimed.
