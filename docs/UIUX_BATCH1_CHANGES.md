# UI/UX Batch 1 — change log

Branch `fix/uiux-batch1` (from `docs/audit-cloudie`). Source: `docs/UIUX_STUDY.md` §11. One commit per U-ID. Not pushed, not merged.
Backups of every touched file: `backup/2026-10-12/<path>` (git-ignored).
Not changed: verdict logic, Flask, DB schema, AES/key-hash flow, 32-feature contract, the 50 MB upload limit.
Lint: `php -l` passed on every changed file (index, login, register, profile, decrypt, dashboard, folder, upload, view_report, scan_and_encrypt, includes/auth, includes/header).
Live check (guest only, via curl; no forms submitted): `index.php`, `login.php`, `register.php` return 200; `?theme=light` keeps the query string (`index.php?x=1&theme=light` → `Location: index.php?x=1`, cookie set; `folder.php?id=3&theme=dark` → `Location: folder.php?id=3`); no "your-username", "Bootstrap" or "client-side" left in the landing HTML; `for=` ids present on login and register. **Logged-in screens (key screen, report, dashboard, folder, decrypt, profile) were NOT opened**, so the manual checks below are still to do.

## 1. Changes

| U-ID | Files:lines | Before → after (UI strings verbatim) | How to verify manually |
|---|---|---|---|
| U-01 | `view_report.php:74` | `$rejected = ((int)$rec['is_clean'] !== 1);` → `$rejected = false;`. A stored suspicious file's report no longer shows "File rejected — SUSPICIOUS" or "This file was deleted from the server and was not encrypted or stored."; it shows the amber "SUSPICIOUS" banner and no red alert. | Open Report on any file tagged Suspicious. Banner reads `SUSPICIOUS`, bottom has no red "deleted from the server" alert. A blocked (malicious) upload still shows the red page (that path is in `scan_and_encrypt.php`, unchanged). |
| U-02 | `scan_and_encrypt.php:270,346-354,386-408` (+ CSS `.key-saved`), `includes/header.php:662-672` | Key screen: theme toggle hidden; "Go to my files" starts disabled (greyed, not clickable) and a checkbox "I have saved my key (copied it, downloaded it, or stored the QR)." enables it; a `beforeunload` prompt fires on leaving until the box is ticked. Key is not stored anywhere new (no DB/session/cookie). | Upload a clean PDF. Check: no moon/sun icon in the topbar; "Go to my files" can't be clicked; try a sidebar link or F5 → browser "Leave site?" prompt; tick the box → button works and no prompt. |
| U-03 | `includes/auth.php:10-23` (new `cl_apply_theme_param()`), `includes/header.php:14-36` | Toggle link was `…/folder.php?theme=light` (query dropped) and handled after page logic → "Invalid request" → dashboard. Now `folder.php?id=3&theme=light`, handled at the top of `auth.php`, redirects back to `folder.php?id=3`. Redirect is by relative script name only. | Log in, open a folder, press the theme icon: stays on the same folder, theme flips. Repeat on `view_report.php?id=…` and `decrypt.php?action=view&id=…`. |
| U-04 | `index.php:22-26,58-62,138-139,151,265-268`; `register.php:99-101,105,109`; `login.php:227-228,233,238,241` | Removed: "Only you, with your key, can read it back."; "Without it, nobody can decrypt your data — not even us."; "strong client-side encryption"; "End-to-end AES-256-CBC"; "your key never leaves your hands"; "keys held by you". New e.g.: "…encrypts the file on the server with AES-256-CBC before it is stored. Only a SHA-256 hash of your key is kept, so you need your key to read the file back."; "AES-256-CBC encryption"; "Files are scanned (VirusTotal first, then an AI analyzer for PDFs) and encrypted with AES-256. You receive the key; only its hash is stored."; "VirusTotal first" card; "AES-256-CBC, only a key hash stored". | Read `/cloudie/`, `register.php`, `login.php` (aside panel). Search the page text for "client-side", "end-to-end", "not even us": none. |
| U-05 | `upload.php:12-20` | "Files are scanned with the AI malware analyzer first. Only files verified as clean are encrypted with AES-256 and stored." → "VirusTotal checks the file first, then Cloudie's AI analyzer (PDF files only). Malicious files are blocked. Clean and suspicious files are encrypted with AES-256-CBC on the server and stored." + new small line "The file is sent to VirusTotal for scanning. Do not upload anything you are not willing to share with them." (the "max 50 MB" text is unchanged on purpose: Batch 2) | Open `upload.php`. |
| U-07 | `scan_and_encrypt.php:66-69` | "Malware scan failed: {raw scanner error}" → "The malware scan could not be completed, so your file was not stored. Please try again in a minute. If it keeps happening, try a smaller file." (raw detail goes to `error_log`). | Stop Flask locally, upload any file: red flash on `upload.php` with the new text, nothing in the vault. |
| U-10 | `scan_and_encrypt.php:257-266,309` | Chip "Clean · 98% safe" → "Clean · VirusTotal 0/70 flagged · AI 2.3% malicious" (VT shown as "VirusTotal: no result" when unavailable; the AI part is shown only for PDFs). | Upload a clean PDF; read the chip row. |
| U-13 (copy) | `scan_and_encrypt.php:328-330` | "Save this key. You'll need it to view, download, or delete this file. We never store it — lose it and the file can't be recovered." → "Save this key. You need it to view, download, and also to delete this file. Cloudie stores only a SHA-256 hash of it, so if you lose it the file can't be recovered or deleted." Delete logic untouched. | Key screen text. |
| U-15 | `login.php` (`loginId`, `pw`, `otpCode`), `register.php` (`regUser`, `regEmail`, `regPhone`, `pw`, `pw2`), `profile.php:233-299`, `decrypt.php:126`, `includes/header.php:581,589,658,663,675` | `<label>` had no `for`; now every label points at its input id. Added `aria-label`: vault search "Search your encrypted vault", theme toggle "Toggle light/dark theme", avatar "Account menu", folder add "New folder", folder name "Folder name". | Click a label: the input focuses. Screen reader / DevTools accessibility tree shows names. |
| U-18 | `dashboard.php:94,159`, `folder.php:211` | Added legend under the title: "Suspicious = VirusTotal found nothing, but the AI flagged structural features of the file. It is stored and encrypted; open it with caution. Malicious files are blocked and never stored." and a `title` tooltip on the Suspicious pill: "VirusTotal found nothing, but the AI flagged structural features. Stored; open with caution." | Hover a Suspicious pill; read the legend line. |
| U-19 | `includes/header.php:572-577` | Removed sidebar "Upload" nav item and the "Security → Scan reports" block (it pointed at `dashboard.php` and highlighted together with "My files"). "Upload & Scan" button and "My files" remain. | Dashboard: only "My files" is highlighted. |
| U-20 | `index.php` credits card | Removed the GitHub, LinkedIn and `you@example.com` buttons. No URLs invented. | Landing page, "About the developer". |
| U-21 | `index.php:221` | Thesis check: `FYP_THESIS_formatted.docx` never mentions Bootstrap (it lists PHP, HTML, CSS, Python), and the site uses custom CSS → badge "Bootstrap" → "HTML/CSS". | Landing page, "Technology stack → Frontend". |
| U-33 | `scan_and_encrypt.php:284,297,317` | "was cleared by VirusTotal, but the AI…" → same when VT returned a result, else "got no result from VirusTotal, and the AI…"; "was scanned, verified clean, encrypted…" → "was scanned (VirusTotal: clean; AI analysis: no flag), encrypted…" or "(VirusTotal: no result; AI analysis: no flag)"; "Why is this flagged?" box says "VirusTotal returned no result for this file" when VT was unavailable. Verdict policy unchanged. | Normal run: "VirusTotal: clean". To see the no-result text, run Flask without `VT_API_KEY` locally. |

## 2. Thesis sentences that now contradict the UI wording

Line numbers refer to the paragraph index in my text extraction of the DOCX (use Find in Word with the quoted words). The UI now says: VT first, AI for PDFs only, malicious blocked, clean **and** suspicious stored, server-side AES-256-CBC, only a key hash stored, file sent to VirusTotal.

| Where | Sentence (shortened) | Conflict | Suggested edit |
|---|---|---|---|
| 3.3.2 Physical design (para ~626) | "runs two checks **in parallel**: a VirusTotal signature-based scan and an AI-based structural analysis" | Sequential in code | "runs two checks: VirusTotal first, then the AI structural analysis" |
| Use-case table, test step (para ~670) | "File is scanned by AI model and Virus total **in parallel**" | same | same |
| 3.3.5 flow text (para ~799) | "submits it **in parallel** to VirusTotal … and to the AI model" | same | same |
| 4.3.7 (para ~1185) | "submits the file to VirusTotal and, **in parallel**, extracts its structural features" | same | same |
| 4.3.7 (paras ~1180, 1182) | "users **select a PDF file**" | Upload accepts 14 types; AI applies to PDFs only | "select a file (PDF files receive the additional AI analysis)" |
| 4.3.7 (para ~1193) | "A flagged file cannot proceed to encryption or be stored" | OK for malicious; suspicious files are stored and tagged | add: "AI-only flags (suspicious) are stored with a warning tag" |
| 4.3.8 (para ~1197) | "After a file has been confirmed clean, the user can **proceed to encrypt** it" | Encryption is automatic; no button; suspicious files are encrypted too | "Clean and suspicious files are encrypted automatically…" |
| 4.3.8 (para ~1198) | "The **encryption key is stored** separately in the file_keys table" | Only `sha256(key)` + IV are stored | "Only a SHA-256 hash of the key and the IV are stored in file_keys" |
| 4.4.5 (para ~1324) | "…the encryption key is recorded separately…" | same | same |
| 4.5 Discussion (para ~1373) | "**no harmful content** … can penetrate the storage system" | Not guaranteed (AUDIT A-01/A-04/A-15) | "reduces the risk of harmful content being stored" |
| 5.1 (para ~1385) | "Uploaded files are analysed and **only clean files are stored**" | Suspicious files are stored | "malicious files are blocked; clean and suspicious files are stored" |
| 4.2, 4.5, 5.1, 5.2, 5.5 | "email-based **recovery PIN**" | No such feature (A-06; not a Batch 1 UI change) | remove |
| 3.3.7.5/3.3.7.6 and Table 3.9 (paras ~685, 1094, 1097) | "**Generate Key**" button | No such step | remove / reword |

Searched for and **not found** in the thesis: "client-side", "never leaves", "not even us", "AI first". "end-to-end" appears only in the literature sections (paras ~238) describing deployable systems in general, not Cloudie's encryption. No sentence says Bootstrap.

## 3. Skipped / not done, and why

- **U-06, U-08, U-09, U-11, U-14:** not touched (backend-dependent, per brief).
- **Dashboard card label** `dashboard.php:99` "Clean (VirusTotal + AI)": left as is. It cannot know per file whether VT returned a result; it is covered by A-15 (Batch 2).
- **Key email** (`mailer.php:119`, "passed the malware scan" also for suspicious files): outside the listed IDs (U-32).
- **`scan_and_encrypt.php` "Why is this flagged?" example text** ("often seen in malicious PDFs") still appears for a non-PDF: that is U-09 (needs the Flask PDF gate).
- **Upload size text** "max 50 MB": unchanged on purpose (Batch 2).
- **U-02 limits:** the `beforeunload` prompt is a browser feature; it cannot stop a hard tab close from running. The checkbox gates only the "Go to my files" button; the "View report" button is covered by the prompt, not disabled.
- **U-19:** I removed the duplicate "Upload" nav item (kept the "Upload & Scan" button), so the Upload page itself no longer has a highlighted nav entry.
- Commits do not carry the `Co-Authored-By` trailer from the session reminder (added after the fact is not possible without rewriting history); tell me if you want it amended.
- Not verified live: everything behind login (no forms were submitted by rule).
