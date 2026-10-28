# Cloudie threat model

What Cloudie protects, from whom, how, and what it does **not** protect. Every mitigation below names the code
that does it, so a claim can be checked. Limits are stated on purpose: a threat model that lists no gaps is not
believable.

## 1. What is being protected

| Asset | Why it matters |
|---|---|
| File contents | the user's documents (confidentiality) |
| Integrity of stored files | a file must come back exactly as it went in |
| Account access | login, OTP, session |
| The AES key of each file | whoever holds it can read that file |
| The activity history (audit trail) | evidence of what happened to an account |
| Other users' safety | a malicious upload must not reach them or the service |
| Availability of the service | demo and daily use |

## 2. Who might attack

| Actor | Can do | Cannot do (assumed) |
|---|---|---|
| Malicious uploader | upload crafted files: malware, disguised programs, zip bombs, evasive PDFs | reach other users' files |
| Account attacker | guess or stuff passwords, replay OTP, hit endpoints from many IPs | bypass rate limits cheaply, read other accounts' data |
| Curious or compromised other user | try ids of other users' files (IDOR) | decrypt without the key |
| Storage reader (leak of the GCS bucket or a DB dump) | read encrypted blobs, key hashes, metadata | recover keys from `sha256(key)` |
| Mailbox attacker | read the user's email, which carries the AES key | (this is a real gap, see 5) |
| Insider with database write access | edit rows | do so without being noticed, unless they also hold the audit key |

Out of scope: a compromised Cloud Run service or Google account, nation-state attackers, physical access to
the user's device, denial of service at network level (left to Google's edge).

## 3. How a file flows (trust boundaries)

```
Browser ──HTTPS──> cloudie-php (Cloud Run) ──Google ID token──> cloudie-flask (private Cloud Run)
                        │                                              │
                        │                                              ├── VirusTotal (hash lookup, then upload if unknown)
                        │                                              ├── structure checks (PDF / Office / ZIP / name vs content)
                        │                                              └── Random Forest (PDFs only)
                        ├── AES-256-CBC encrypt in memory ──> GCS bucket (ciphertext only)
                        └── Cloud SQL (users, key HASHES, scan reports, audit chain)
```

Boundaries that matter: browser to PHP; PHP to Flask (private, authenticated); Flask to VirusTotal (a third party);
PHP to GCS and Cloud SQL; PHP to the user's mailbox (Gmail SMTP).

## 4. Threats and what stops them

| # | Threat | Mitigation (where) | Residual risk |
|---|---|---|---|
| T1 | Known malware uploaded | VirusTotal is the primary detector; blocked at >= 2 engines (`verdict_engine.py`). VT gives no answer: upload is refused (fail closed) | a brand-new sample no engine knows yet |
| T2 | Unknown or modified file (no signature) | structure layer: PDF evasion rules, Office macro/DDE/remote template, zip slip/bomb, disguised programs (`evasion_indicators.py`, `file_structure.py`, `docs/STRUCTURE_CHECKS.md`); Random Forest on PDFs. Strong findings tag the file SUSPICIOUS | rules are known tricks; a careful attacker can avoid them. False-positive rate not measured on real Office files |
| T3 | Program disguised as a document | content type from the first bytes, compared with the extension; magic-byte gate on upload (`upload_check.php`, `file_structure.py`) | none for the checked types |
| T4 | Zip bomb or parser abuse against the scanner | sizes read from the zip index and never expanded, 3 s budget, bounded reads, regex instead of XML parsing, analyzers never raise | files over 25 MB are rejected by the scanner (fail closed), not scanned |
| T5 | Password guessing, credential stuffing | bcrypt hashes, rate limits per account and per IP kept in the database (`ratelimit.php`), email verification, one-time code at login | a distributed attack from many IPs against many accounts stays slow but not impossible |
| T6 | Session theft or fixation | cookie HttpOnly, SameSite=Lax, Secure on HTTPS, 30 min idle timeout, session id regenerated, CSRF token on forms (`config.php`, `auth.php`) | no CSP yet; sessions are not shared between Cloud Run instances |
| T7 | Reading another user's file (IDOR) | every lookup is filtered by the logged-in `user_id` (`decrypt.php`, `view_report.php`) | none known |
| T8 | Reading stored files (bucket leak, DB dump) | only ciphertext is stored; a random 32-byte key and 16-byte IV per file; only `sha256(key)` is kept (`aes.php`) | none for confidentiality, assuming the key stays secret |
| T9 | Tampered ciphertext in storage | after decrypting, the SHA-256 recorded at upload is compared; a mismatch is not served and is logged `INTEGRITY_FAIL` (`decrypt.php`) | CBC itself has no integrity; AES-GCM is future work. Detection happens after decryption, not before |
| T10 | Wrong key or brute force of the key | key checked by comparing hashes with `hash_equals`; failed attempts are logged and rate limited | a 256-bit key is not brute-forceable |
| T11 | Quiet editing of the history | per-user hash chain sealed with HMAC-SHA256 and a sealed head; edits, deletes, inserts and reorders show as "Tampering detected" (`includes/audit.php`) | someone with database write access AND the secret `AUDIT_HMAC_KEY` can rewrite it |
| T12 | Scanner exposed to the internet | Flask is private (Cloud Run IAM); only the service account may invoke it, PHP sends a Google ID token (`scanner.php`) | a compromised PHP service can call it |
| T13 | Secrets in the repository | DB password, SMTP password, VT key and audit key live in Secret Manager; `.gitignore` excludes keys and uploads | a leaked developer machine |
| T14 | Cleartext left on the server | uploads are deleted right after encryption (`scan_and_encrypt.php`); Cloud Run disk is ephemeral | memory of a running instance holds the plaintext briefly |

## 5. Known gaps (said plainly)

1. **Not end-to-end encrypted.** The server receives the plaintext, scans it, encrypts it, and holds the key in
   memory for that moment. Cloudie protects data **at rest** and against storage leaks, not against a compromised
   running server.
2. **The AES key travels by email and is shown once.** Anyone with the mailbox can read the files. A lost key means
   the file cannot be recovered (by design: the server keeps only the hash).
3. **Unknown files are uploaded to VirusTotal.** Known hashes are only looked up (no content sent), but a file VT has
   never seen is uploaded, and VT may share it with security vendors. Sensitive files should not be scanned this
   way; a private scanner (own AV, sandbox) is future work.
4. **Single detector dependence.** If VirusTotal is down or over quota the upload is refused. This is safe but it is
   also an availability cost (free quota is about 4 requests per minute).
5. **No Content-Security-Policy**, and Cloud SQL has a public IP protected by an allow-list and a password.
6. **The Random Forest is trained on one PDF dataset.** On real-world PDFs it is close to its 0.5 cut-off, which is
   why it is secondary and why a risk gate and the rule-based layer sit next to it.
7. **Measured accuracy applies to the dataset**, not to all PDFs (see `docs/AUDIT_REPORT.md`). The false-positive rate
   on real files is measured for PDFs only (200 GovDocs1 PDFs: 1.0% tagged, 0 blocked, `docs/BENIGN_FP_BENCHMARK.md`);
   there is no real-world rate yet for Office, ZIP, CSV or image files.

## 6. Design choices that follow from the threats

* VirusTotal primary, AI secondary: signatures are reliable on known samples, the AI and structure layer look at what
  signatures cannot (new or modified files). Disagreement is expected and logged.
* Fail closed: no VirusTotal result means no storage. A false block is cheaper than a stored infection.
* Block only at >= 2 engines: one engine out of about 70 is the typical false positive, so a single hit is stored and
  tagged SUSPICIOUS instead of blocking a harmless file.
* Keep the verdict explainable: every tag names its reason (engine count, risk indicators, structure findings).

## 7. Future work

AES-GCM with the key bound to the file; client-side encryption so the server never sees the plaintext; a private
sandbox for unknown files; Content-Security-Policy; shared sessions; measuring false positives on a real benign Office/ZIP set (PDFs: done);
retroactive rescan of stored files when new signatures appear.
