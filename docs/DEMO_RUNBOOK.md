# Cloudie demo runbook (competition 2026-11-03)

One page to follow before and during the demo. Results marked **TO VERIFY** have not been confirmed on the live
site yet: do a full rehearsal and write the real result in the table in section 3.

Live site: https://cloudie-php-800476519477.asia-southeast1.run.app

## 1. The story (60 seconds)

> "VirusTotal knows what has been seen before: that is signature detection. Cloudie also checks **how a file is
> built**. So a new or modified file, which has no signature yet, can still be flagged. Every file is scanned, then
> encrypted with AES-256 before it is stored, and every action goes into a tamper-evident log."

Three things to show, in this order: (1) a clean file goes through, (2) a file VirusTotal calls clean but its
**structure** gives away, (3) a log that proves someone edited it. Keep it under 8 minutes; leave time for questions.

## 2. Preparation

### Three days before (30 Oct, code freeze)
- [ ] `powershell -ExecutionPolicy Bypass -File C:\xampp\htdocs\cloudie\tests\run_all.ps1` passes.
- [ ] Billing is active, Cloud SQL is `RUNNABLE`:
  `gcloud sql instances describe cloudie-db --format="value(state,settings.activationPolicy)"`
- [ ] Both services have min instances 1 (already set 2026-10-26):
  `gcloud run services describe cloudie-php --region asia-southeast1 --format="value(spec.template.metadata.annotations.'autoscaling.knative.dev/minScale')"`
- [ ] Flask is still private: `gcloud run services get-iam-policy cloudie-flask --region asia-southeast1` lists only the compute service account.
- [ ] Generate the demo files:
  ```powershell
  python C:\xampp\htdocs\cloudie\tests\make_demo_pdfs.py C:\Users\aqeeflew\Desktop\cloudie-demo
  python C:\xampp\htdocs\cloudie\tests\make_demo_files.py C:\Users\aqeeflew\Desktop\cloudie-demo
  ```
- [ ] EICAR (optional "known malware" example): download `eicar.com.txt` from eicar.org into a folder that Windows
  Defender excludes, otherwise Defender deletes it. Never put it in the demo folder above.

### Two days before: pre-scan every demo file once
VirusTotal's free quota is about **4 requests per minute**. A file VT has not seen needs an upload plus polling (up to
85 s); a file it already knows needs one hash lookup. So upload each demo file **once, a few minutes apart**, on a
test account, and write down the verdict. Then the live demo only does fast hash lookups.

### The day before
- [ ] Log in with the demo account on the laptop you will present with, check the OTP email arrives (Gmail).
  If the account is locked after wrong codes: `DELETE FROM rate_limits;` (needs your IP in Cloud SQL Authorized Networks).
- [ ] Delete old test files from the demo account so the dashboard looks clean.
- [ ] For the tamper demo (section 4, step 6): add your current IP to Cloud SQL Authorized Networks and confirm the
  mysql command in section 4 connects. Remove the IP afterwards.
- [ ] Charge the laptop, close other tabs, set the browser zoom so the report is readable on the projector.

### 30 minutes before
- [ ] Open the site once (warm), log in, stay logged in (session idles out after 30 minutes without a request).
- [ ] Have `C:\Users\aqeeflew\Desktop\cloudie-demo` open in a file window.
- [ ] Keep a notes file with the AES key of each file you upload (the key is shown once).
- [ ] Phone hotspot ready as a network backup.

## 3. Demo files and expected results

VirusTotal is the primary detector, so the final verdict always depends on what it says that day. Fill in the last
column during the rehearsal.

| File | What it is | Expected | Seen on |
|---|---|---|---|
| `1_clean.pdf` | plain one-page PDF | CLEAN, AI shows "uncertain", no findings | TO VERIFY |
| `2_visible_script.pdf` | clear-text OpenAction + JavaScript | on 2026-10-22: 1 VT engine, so now SUSPICIOUS | TO VERIFY |
| `3_hidden_script.pdf` | same script with hex-escaped names (`/J#61vaScript`) | on 2026-10-22: 12 VT engines, so MALICIOUS (blocked) | TO VERIFY |
| `1_normal_report.docx` | ordinary Word file | CLEAN, no findings | TO VERIFY |
| `2_macro_in_docx.docx` | macro project inside .docx | SUSPICIOUS, "Macro project inside a macro-free file type" | TO VERIFY |
| `3_remote_template.docx` | template loaded from a remote address | SUSPICIOUS, "Document loads a template from a remote address" | TO VERIFY |
| `4_zip_slip.zip` | entry named `../../...` | SUSPICIOUS, "Entry names escape the extraction folder" | TO VERIFY |
| `5_double_extension.zip` | `invoice.pdf.exe` (a text file) | SUSPICIOUS, "Program disguised with a document extension" | TO VERIFY |
| EICAR test file | standard antivirus test string | MALICIOUS (many engines), blocked, never stored | confirmed 2026-10-20 |

The **best demo files are the structure ones** (`2_macro_in_docx.docx`, `4_zip_slip.zip`): they have no malicious
code, VirusTotal should call them clean, and Cloudie still flags them with a named reason. If a PDF demo file is
blocked by VirusTotal instead, say so: it shows VirusTotal is the primary detector.

## 4. Demo script (about 8 minutes)

1. **Log in** (30 s). Mention: password, then a one-time code by email, rate limits on both.
2. **Upload `1_normal_report.docx`** (1 min). Show the progress: scanned, encrypted, stored. Point to the AES key
   screen: "shown once, only its hash is stored; lose it and the file cannot be opened, by design". Save the key.
3. **Upload `2_macro_in_docx.docx`** (2 min). Result: stored but tagged SUSPICIOUS. Open the report: VirusTotal
   0 flagged, structure finding named in red. Say: "this is the point: no signature, the structure gave it away."
4. **Upload `4_zip_slip.zip` or `5_double_extension.zip`** (1 min), same idea with a different file family.
5. **Show a malicious file** (1 min): upload EICAR (or a demo PDF VirusTotal blocks). Result: blocked, never stored.
   Mention the rule: blocked at 2 or more VirusTotal engines; a single engine is a weak hit, so the file is kept but
   tagged. If VirusTotal gives no answer the upload is refused (fail closed).
6. **Audit trail** (1.5 min). Open "Audit trail": all entries sealed. Then edit one row from a second window:
   ```powershell
   & "C:\xampp\mysql\bin\mysql.exe" -h 34.143.161.161 -u cloudie_user -p cloudie_db -e "UPDATE actions SET details='edited' WHERE act_id=<id from the table>"
   ```
   Reload the page: "Tampering detected" and the changed row is pinpointed. Say honestly: it detects edits; someone
   with both database access and the secret key could rewrite it (see THREAT_MODEL).
7. **Download or decrypt a file** (30 s): enter the key, the file comes back; mention the integrity hash check.

If time is short, drop step 4 and step 7.

## 5. When something goes wrong

| Symptom | Cause | What to do / say |
|---|---|---|
| "VirusTotal error" or `error` verdict | free quota used up, or analysis not finished | Say: "this is fail-closed: with no answer from the primary detector, nothing is stored." Wait one minute and retry a file you pre-scanned. |
| HTTP 503 | billing disabled or Cloud SQL stopped (happened before) | `gcloud sql instances describe cloudie-db` and check billing; `gcloud sql instances patch cloudie-db --activation-policy ALWAYS`. Switch to the recorded backup video/screenshots. |
| OTP email does not arrive | Gmail delay | wait 30 s, use "Resend code" once; limit is 5 emails per hour per account |
| Login says locked | too many wrong attempts | `DELETE FROM rate_limits;` or use a second prepared account |
| Logged out suddenly | 30 min idle, or the service moved to another instance (sessions are not shared) | log in again; keep the demo account ready |
| Upload slow (up to ~85 s) | VirusTotal analysing a new file | narrate the pipeline while waiting; this is why files are pre-scanned |
| File over 25 MB | scanner limit | not a demo case; use small files |
| Projector shows nothing | network | phone hotspot |

Always prepare a **fallback**: a screen recording of the full flow, and screenshots of each result, stored on the
laptop (not only online).

## 6. Questions you will probably get

Short answers are in `docs/DEFENSE_QA.md`; the security reasoning is in `docs/THREAT_MODEL.md`. The honest limits to
volunteer rather than hide: not end-to-end encrypted (the server sees the file while it scans and encrypts it),
unknown files are uploaded to VirusTotal, the false-positive rate on real-world files is not measured, and the
Random Forest is trained on a single PDF dataset.

## 7. After the demo

```powershell
gcloud run services update cloudie-php --region asia-southeast1 --min-instances 0
gcloud run services update cloudie-flask --region asia-southeast1 --min-instances 0
```

Remove your IP from Cloud SQL Authorized Networks; stop Cloud SQL if it will not be used
(`gcloud sql instances patch cloudie-db --activation-policy NEVER`, start again with `ALWAYS`).
