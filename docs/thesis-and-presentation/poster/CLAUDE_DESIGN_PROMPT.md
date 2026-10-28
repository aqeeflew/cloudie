Design two A1 competition posters for my cybersecurity final-year project, **Cloudie**. They will be printed and hung on a board at a university innovation competition (judged on cybersecurity innovation). Judges walk past, read from 1–2 metres away, then scan a QR code to try the live app.

## Format (both posters)
- A1 portrait, 594 × 841 mm, print-ready PDF, 3 mm bleed, no crop marks needed.
- Readable from 1.5 m: body text at least 24 pt, headings 60 pt+, title 120 pt+.
- One clear reading path, top to bottom. Plenty of white space. **Less text than you think**: if something doesn't fit, cut words, never shrink type below 24 pt.
- The two posters must look like a set (same grid, header, colours, type), but each has its own hero visual.

## Creative direction
I don't want the generic "dark navy dashboard with glowing cards and pill badges" look; I already tried that and it looked like a web page, not a poster. Please make it feel **editorial and bold, like a science/design-festival poster**:
- One big visual idea per poster that explains the concept at a glance, not a grid of equal-sized cards.
- Poster 1 hero idea: a file being **x-rayed**: the outside looks like a normal "invoice.docx", the inside (cut-away / x-ray view) reveals its structure, with a hidden macro highlighted. Caption: "Signatures know the past. Structure reads the file."
- Poster 2 hero idea: a clean, large Business Model Canvas as the centrepiece, with pricing beneath it.
- Strong typography (a geometric/grotesk display face + a clean sans for body + a monospace for technical IDs like T1221).
- Colour: you choose, but it must print well (avoid huge solid black areas that print muddy). Suggested starting point to adapt freely: deep ink blue #0B1020, cyan #27D3E0, violet #9B7BFF, amber #FFC24B for warnings, red #FF6B7D for blocked, green #34D399 for clean. A light background with dark ink is welcome if it looks better in print.
- Icons: simple line icons, consistent stroke. No stock photos, no clip-art people, no 3D cartoon illustrations.

## Assets I will upload
- UiTM + MDTI logo strip (place top-right of each poster, on a white or light area).
- Two QR codes: `qr-live.svg` (live app) and `qr-repo.svg` (source code). Each QR at least 5 × 5 cm, with a label under it.

## Accuracy rules (important: judges will check)
- Use the facts below exactly. Do not invent statistics, percentages, customer numbers, logos of other companies or testimonials.
- Never write "compliant" or "certified". The frameworks are "mapped".
- Anything labelled "proposed" or "goal" must keep that label.

---

# POSTER 1: Project poster

**Header**
- Project name: **Cloudie**
- Title: **Secure cloud storage that reads how a file is built**
- Tag: CSP650 · Cybersecurity
- Byline: Muhammad Aqeef bin Azhar | Supervisor: Dr. Fakariah Hani binti Mohd Ali | BSc (Hons) Netcentric Computing, Universiti Teknologi MARA (UiTM) Shah Alam

**The idea (hero)**
"Signatures know the past. Structure reads the file."
Antivirus signatures only catch files someone has already reported. Cloudie also checks how a file is put together, so a disguised file is caught even when no engine has a signature for it yet. Every file is then encrypted before it is stored.

**The problem (3 short points)**
1. New malware has no signature yet.
2. Attackers disguise files: a macro inside a .docx, `invoice.pdf.exe`, a ZIP hidden inside a picture.
3. Files stored unencrypted are exposed if storage is breached.

**How it works (one horizontal flow, 6 steps)**
1. Upload: file-type allow-list, 25 MB limit, rate limit
2. VirusTotal: 70+ antivirus engines give the primary verdict. **Fail closed**: no answer means the upload is blocked.
3. Structure checks: PDF, Office, ZIP, CSV, images and the file name. **No signature needed.**
4. AI for PDFs: Random Forest, 32 structural features, explained score
5. AES-256 encryption: a new key and IV for every file, the key goes to the owner
6. Cloud storage: only ciphertext is stored, on Google Cloud

**Innovation: the structure layer (table: file type → what it catches → MITRE ATT&CK)**
- PDF: hidden keywords (`/J#61vaScript`), exploit code in scripts, embedded programs → T1027, T1059.007
- Office: macro inside a macro-free .docx, DDE, remote template → T1059.005, T1221, T1559.002
- ZIP: zip slip (`../`), zip bomb, programs disguised as documents → T1036.007, CWE-22
- CSV: cells that run commands (`=cmd|…`) or leak data → T1559.002, CWE-1236
- Images: a ZIP, program or script hidden after the picture ends → T1027.003
- Every file: real type vs. its name, double extension, right-to-left-override trick → T1036.008, T1036.002
Footnote: Bytes are only read, never run or extracted, with a 3-second limit per file.

**Verdict engine: "VirusTotal decides first"**
- 2 or more engines flag it → BLOCKED
- No answer from VirusTotal → BLOCKED
- Only 1 engine (the classic false positive) → SUSPICIOUS
- VirusTotal clean, but a strong structure finding → SUSPICIOUS
- VirusTotal clean, but the AI flags a risky PDF → SUSPICIOUS
- Everything clean → CLEAN
Suspicious files are stored encrypted and tagged, and the scan report says why.

**Explainable AI**
- "Why this AI score": every feature's exact contribution to the score, computed from the decision trees.
- Familiarity check: how close the PDF is to the PDFs the model was trained on. Bands: Familiar / Unusual / Unfamiliar. It tells the user when the AI is outside what it knows. (If you draw example bars, label them "example".)

**Evidence: "Measured, not assumed"**
- 99.87%: hold-out accuracy on 18,126 PDFs (CIC-Evasive-PDFMal2022), 0 false positives
- 99.46%: harder test, trained on smaller PDFs and tested on the largest
- 1.0%: real benign PDFs tagged suspicious (2 of 200, GovDocs1), 0 blocked
- 256 automated tests (81 PHP + 175 Python)

**Protecting what is stored: "Only the owner holds the key"**
- Key not stored: only a SHA-256 hash of each file's key is kept
- Integrity check: decrypted bytes must match the hash taken at upload
- Sealed audit log: HMAC hash chain, so edited or deleted entries are detected
- 2-step login: password + one-time code, rate limited
- Private scanner: only the web service can call it (Google Cloud IAM)
- QR key: the key is delivered by email and QR, generated on our own server

**Standards: "Mapped to recognised frameworks" (mapped, not certified)**
MITRE ATT&CK (12 techniques) · NIST CSF 2.0 (Identify, Protect, Detect, Respond, Recover) · ISO/IEC 27001:2022 Annex A (8.5, 8.7, 8.13, 8.15, 8.24) · OWASP (File Upload Cheat Sheet, Top 10) · NIST SP 800-63B (passwords and login)

**Call to action (bottom)**
"Live now. Scan, sign up, upload a file."
QR: Live app · QR: Source code
Built on Google Cloud Run, Cloud SQL and Cloud Storage. For individuals, SMEs, schools, NGOs and government offices.
UN SDG 9 (Industry, Innovation & Infrastructure) · UN SDG 16 (Peace, Justice & Strong Institutions)

---

# POSTER 2: Business model poster

**Header** (same as poster 1). Tag: Business Model. Title: **From campus project to secure storage for Malaysian teams**

**Value proposition**
"Storage that checks before it keeps."
- Catches disguised files: structure checks find what has no signature yet.
- Encrypts every file: a new AES-256 key per file; only the owner holds it.
- Shows the evidence: readable scan reports and a tamper-evident audit log.

**Why now in Malaysia**
1. PDPA (Amendment) Act 2024: data breach notification and data protection officers are now required.
2. Cyber Security Act 2024 (Act 854): new duties for national critical information infrastructure (NCII) sectors.
3. Files are the way in: invoices, CVs and forms arrive as attachments every day.

**Business Model Canvas (centrepiece, classic 9-block layout)**
- Key partners: Google Cloud; VirusTotal or another scanning engine (commercial licence); UiTM as pilot site and research partner; IT resellers and SME associations
- Key activities: scanning, encrypting and storing files; writing new structure rules for new attacks; retraining and measuring the AI
- Key resources: structure-check engine and RF model; cloud platform with 256 automated tests; security know-how
- Value proposition: every upload scanned before it is stored; disguised files caught without a signature; per-file AES-256 key held by the owner; verdicts explained in plain words; tamper-evident audit log for accountability
- Customer relationships: self-service sign-up with a free plan; onboarding help for teams; security tips and alerts
- Channels: web app (live on Google Cloud); campus pilot, competitions and talks; LinkedIn demo videos
- Customer segments: SMEs and professional firms (law, accounting, clinics); schools and universities; NGOs; government offices; individuals (free plan)
- Cost structure: cloud hosting (compute, database, storage; grows with use); scanning licence (the free VirusTotal API is for non-commercial use only); development, support, marketing
- Revenue streams: monthly or yearly subscriptions (freemium); per-seat team plans; institution licences with setup, training and support

**Pricing (label clearly: "Proposed, to be tested with the pilot")**
- Free, RM0 (students and individuals): 1 GB encrypted storage, 30 scans a month, full scan reports, 2-step login
- Personal, RM59 / year (freelancers): 25 GB, 300 scans a month, audit log, email support
- Team, RM19 / user / month (SMEs and firms), highlight as most popular: 100 GB per user, unlimited fair-use scans, audit log export, admin console and shared folders (planned)
- Institution, by quote (universities, agencies): volume pricing, training and support, single sign-on (planned), dedicated scanner (planned)
Show "available now" vs "planned" with two distinct icons.

**Positioning (compare categories, not brands)**
Rows × columns: Typical cloud storage | Typical antivirus | Cloudie
- Scans before storing: Some | — | ✓
- Catches disguised files without a signature: — | Some | ✓
- Explains the verdict: — | Some | ✓
- Per-file key held by the owner: Varies | — | ✓
- Tamper-evident activity log: Varies | — | ✓

**Go to market (3 steps)**
1. Campus pilot: one UiTM faculty uses Cloudie for assignment and document uploads.
2. SMEs and firms: through SME associations, IT resellers and demo videos of files that signature scanners missed.
3. Institutions: universities and agencies, with single sign-on and a dedicated scanner.

**Year-1 targets (label: "goals, not results")**
1 campus pilot · 500 free users · 20 paying teams · 3 reseller partners

**Roadmap (timeline)**
- Now: live on Google Cloud (scanning, encryption, reports, audit log)
- 6 months: pilot; AES-GCM; authenticator-app or passkey login; false-positive test on real Office and ZIP files
- 12 months: team plan with admin console, shared folders, Malay-language interface
- 24 months: institution plan with single sign-on and a dedicated scanner

**Social impact**
UN SDG 9 · UN SDG 16 · Affordable security for small organisations
QR: Try it live

---

## Deliverables
1. Both posters as print-ready A1 PDFs.
2. A small PNG preview of each.
3. Keep all text editable, so I can fix wording later.

Before finalising, check every number and claim against the content above, check that no text is under 24 pt, and check that the QR codes are at least 5 cm wide with clear space around them.
