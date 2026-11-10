# Cloudie: 10-minute pitch script

Pitch: 17 Nov 2026. Speaking pace about 130 words a minute. **Bold** = stress it. `[ ]` = what to do or show.
Every number here matches the code and `CLAUDE.md`. Do not round them up.

| Part | Time | Clock at end |
|---|---|---|
| 1. Hook | 0:45 | 0:45 |
| 2. Problem | 1:00 | 1:45 |
| 3. Solution | 1:30 | 3:15 |
| 4. Live demo | 3:30 | 6:45 |
| 5. Results and honesty | 1:00 | 7:45 |
| 6. Business and impact | 1:30 | 9:15 |
| 7. Close | 0:45 | 10:00 |

If you are running late, cut demo step 4c (audit trail) first, then shorten part 6 to pricing only.

---

## 1. Hook (0:45)

`[Title slide / poster header. Look at the judges, not the screen.]`

> Good morning, judges. My name is Muhammad Aqeef bin Azhar, from UiTM Shah Alam, supervised by
> Dr. Fakariah Hani binti Mohd Ali.
>
> Let me start with a question. When you upload a file to the cloud and your antivirus says it is clean,
> **how long does "clean" last?**
>
> The honest answer is: only until someone discovers it is not. New malware usually passes every scanner on
> day one, and is recognised days or weeks later. By then, it is already sitting in your storage, marked "safe".
>
> That is the problem Cloudie solves. Cloudie is **secure cloud storage that checks every file before it keeps
> it, encrypts it, and keeps checking it after upload.**

## 2. Problem (1:00)

`[Problem statement: the three numbered points.]`

> There are three problems.
>
> **One: new and disguised malware slips past signature scanners.** Antivirus signatures only know files that
> someone has already reported. Attackers hide a macro inside a Word file, or name a program `invoice.pdf.exe`.
>
> **Two: files are scanned once.** Most storage scans a file at upload and never again. If that file is found to
> be malware next week, nobody tells you.
>
> **Three: stored files and logs can be read or quietly changed after a breach.** If files are kept unencrypted,
> one leak exposes everything. And if the activity log can be edited, you cannot even prove what happened.
>
> In Malaysia this matters more now. The PDPA Amendment Act 2024 brings breach notification, and the Cyber
> Security Act 2024 brings new duties for critical sectors. Organisations need storage that can **prove** it is
> safe.

## 3. Solution (1:30)

`[Our Solutions section.]`

> Cloudie answers each problem with a layer.
>
> **First, a layered malware analyzer.** Every upload goes to **VirusTotal, which checks it with about seventy
> antivirus engines.** That is our primary detector. On top of that, Cloudie reads **how the file is built**:
> rule-based structure checks for Office, ZIP, CSV and image files, which catch macros in macro-free documents,
> remote templates, zip-slip paths and fake extensions. For PDFs, a **Random Forest AI model reads 32 structural
> features.** Two or more engines means the file is blocked and never stored. A structure or AI finding means the
> file is stored but clearly tagged suspicious, with the reason in plain words.
>
> **Second, encryption.** Every file gets its **own AES-256 key**. Cloudie stores only a SHA-256 fingerprint of
> that key, never the key itself. The user receives the key as text, a QR code and a key file, and by email.
> After decryption, Cloudie checks the file's fingerprint again, so a tampered file is never served.
>
> **Third, and this is our main innovation: retroactive re-check.** After upload, Cloudie asks VirusTotal again,
> using only the file's fingerprint. **It does not need the key, and it never decrypts the file.** If VirusTotal
> now recognises the file as malware, Cloudie quarantines it and warns the owner.
>
> And finally, every sign-in, scan, download and deletion goes into a **tamper-evident audit trail**: each entry
> is sealed with HMAC-SHA256 and linked to the one before it, so any edit breaks the chain.

## 4. Live demo (3:30)

`[Switch to the browser. Already logged in to the demo account, site already warm.]`
`[If the network fails, say "let me show you the recording" and play the backup video. Do not troubleshoot live.]`

### 4a. Upload a clean file (1:00)

`[Upload 1_normal_report.docx (pre-scanned).]`

> This is Cloudie. I will upload an ordinary Word report.
>
> `[While it scans:]` It is going to VirusTotal first, then the structure checks.
>
> `[Result screen:]` Clean. It was encrypted with AES-256 and stored. Here is the key, shown **once**, as text
> and as a QR code. I can copy it, download it as a key file, or save the QR. Cloudie keeps only its
> fingerprint, so **even if our database leaks, this file cannot be opened.** I tick "I have saved my key"
> before I can leave.

### 4b. A file that antivirus misses (1:15)

`[Upload 2_macro_in_docx.docx (pre-scanned).]`

> Now a file that looks like a normal Word document but carries a macro project inside, which a `.docx`
> should never have.
>
> `[Result:]` VirusTotal: **zero engines** flagged it. But Cloudie tagged it **suspicious**, and the report names
> the reason: "macro project inside a macro-free file type". This is the point of reading the structure: there
> is no signature yet, but the way the file is built gives it away.

### 4c. Retroactive re-check and audit (1:15)

`[Open the throwaway file's report, prepared before the pitch with the SQL in docs/RETROACTIVE_RESCAN.md.]`

> This file was clean when I uploaded it. To show you what happens when VirusTotal later learns about a file, I
> have pointed its fingerprint at a known test file. **The answer you are about to see is VirusTotal's real
> answer.**
>
> `[Click "Re-check now".]`
>
> Flagged after upload, and **quarantined**. On "My files" it is red, the View button is gone, and downloading it
> needs an explicit warning. Notice: Cloudie never needed the key.
>
> `[Open Audit trail.]` And every one of these actions is sealed in the audit trail. Chain intact. If anyone
> edits a row in the database, this page shows "Tampering detected".

`[Back to slides.]`

## 5. Results and honesty (1:00)

`[Results strip on the poster or results slide.]`

> How do we know it works?
>
> The AI model was validated on a public research dataset of **18,126 PDFs**: **99.87% accuracy** on a held-out
> test set, and 99.46% on a harder test where it had to judge the largest files it had never seen.
>
> But lab accuracy is not enough, so we also tested **200 real-world PDFs** from a public government document
> collection. Only **2 were tagged, that is 1.0%, and none were blocked.**
>
> The whole system is covered by **280 automated tests.**
>
> And we are open about the limits. Cloudie is not end-to-end encrypted: the server sees the file while it scans
> and encrypts it. The AI is for PDFs only. And we have not yet measured false alarms for Office files. We would
> rather tell you this than have you find it.

## 6. Business and impact (1:30)

`[Business poster: marketing strategy, then pricing table.]`

> Who is it for? **Individuals and students, small businesses like clinics, law and accounting firms,
> universities, NGOs and government offices**: organisations that handle sensitive files but have no security
> team.
>
> The model is **freemium**. The free plan gives 1 GB of encrypted storage. A personal plan is RM 59 a year. Our
> main target is the **team plan at RM 19 per user per month** for small businesses, and institutions get a
> quote. These prices are proposed, and we will test them in the pilot.
>
> To reach customers, we start with a **campus pilot at one UiTM faculty**, then go to small businesses through
> SME associations and IT resellers, plus short demo videos online. Our year-one goals are one campus pilot, 500
> free users and 20 paying teams.
>
> It runs on open-source tools and Google Cloud services that scale to zero when idle, so the cost stays low.
> And it supports **UN SDG 9**, industry, innovation and infrastructure, and **SDG 16**, strong institutions, by
> giving small organisations security that used to be only for large ones.

## 7. Close (0:45)

`[Back to the title, or the QR code "Try it live".]`

> To sum up: most storage scans a file once and trusts it forever. **Cloudie checks before it keeps, encrypts
> with a key only you hold, and keeps watching after upload.**
>
> Cloudie is live on Google Cloud today. You can scan this QR code and try it yourself.
>
> Thank you. I am happy to take your questions.

---

## Likely questions: 30-second answers

**Why is VirusTotal primary and not your AI?**
> VirusTotal combines about seventy engines and is the industry reference. Our AI was trained on one research
> dataset, and on real-world PDFs it is less certain, so it supports VirusTotal and never overrules it. If
> VirusTotal cannot answer, the upload is refused: we fail closed.

**What if VirusTotal is down or the quota runs out?**
> The upload is refused, nothing is stored. We chose safety over availability. Re-checks are capped so they
> never use the quota that uploads need.

**Can you, the admin, read users' files?**
> Not from the database or storage: they only hold encrypted files and key fingerprints. But it is not
> end-to-end: the server sees the file during the scan. Browser-side encryption is future work.

**What if the user loses the key?**
> The file cannot be recovered by anyone, including us. That is the price of not storing keys, so we make losing
> it hard: text, QR, key file, email, and the page will not let you leave until you confirm you saved it. A
> recovery key that does not give us access is on the roadmap.

**What is new compared to Google Drive or an antivirus?**
> Three things together: scanning before storing with a reason you can read, a per-file key the owner holds, and
> re-checking stored files later without the key. Typical storage does not combine these.

**Why AES-CBC and not AES-GCM?**
> CBC has no built-in integrity, so we added a fingerprint check after decryption. Moving to GCM is the next
> step on the roadmap.

**Is it certified, ISO 27001 or NIST compliant?**
> No. Our controls are **mapped** to MITRE ATT&CK, NIST CSF 2.0, ISO 27001 Annex A and OWASP, but we do not claim
> certification.

**How often do stored files get flagged later?**
> We have not measured that yet, so we make no claim. The feature exists so that when it happens, the owner is
> told.

---

## Before you go on

- [ ] Rehearse with a timer at least twice, out loud.
- [ ] Day before: set both Cloud Run services to min instances 1; pre-scan every demo file once, a few minutes apart.
- [ ] Morning of: prepare the throwaway file for 4c (SQL in `docs/RETROACTIVE_RESCAN.md`), then remove your IP from Cloud SQL.
- [ ] 30 minutes before: open the site, log in, stay logged in.
- [ ] Backup video of the whole demo on the laptop, not only online. Phone hotspot ready.
