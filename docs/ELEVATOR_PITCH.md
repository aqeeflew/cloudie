# Cloudie elevator pitch

Say it in your own words; these are the facts and the order. Every number here matches the code and the docs
(`docs/THREAT_MODEL.md`, `docs/STRUCTURE_CHECKS.md`). Do not add claims that are not on this page.

## 30 seconds (English)

> Cloudie is cloud storage that scans every file **before** it encrypts it. Most scanners only recognise what they
> have already seen. Cloudie keeps VirusTotal as the main detector, then adds a second question: **how is this file
> built?** A macro inside a Word file that cannot hold macros, a script hidden in a PDF, a program named like a
> document: none of these needs a signature. Clean files are encrypted with AES-256, and every action goes into a
> log that shows if anyone edits it.

## 60 seconds (English)

> Antivirus tools are good at known threats, but a new or slightly modified file has no signature yet, and
> documents can attack through features like macros and hidden scripts. Cloudie is secure cloud storage built around
> that gap. Every upload is checked in order: first what the file really is, from its bytes and not its name; then
> VirusTotal, our primary detector; then a structure layer that reads how the file is built, for PDF, Office and
> ZIP files, plus a Random Forest model for PDFs that explains its score. If VirusTotal cannot answer, the upload is
> refused. Two engines block a file, one engine only warns. Only then is the file encrypted with a random AES-256
> key, and only a hash of that key is stored. Every action goes into a tamper-evident chain, so an edited history
> shows up as "tampering detected". And we are open about the limits: the server sees a file while scanning, and
> we have not yet measured false positives on real-world files.

## 2 minutes: add these three points

1. **Evidence.** Show the demo: a Word file with a macro project and a zip with an entry that escapes its folder.
   VirusTotal flags nothing; Cloudie names the structural reason.
2. **Why it is trustworthy.** Every verdict names its reason. The AI is secondary and gated (score of 50% plus a
   risk indicator, or 85% or more). Accuracy 99.87% is on a held-out part of one public dataset (18,126 PDFs), and
   on real-world PDFs the model is less certain, which is why it supports VirusTotal and does not replace it.
3. **What is next.** Client-side encryption so the server never sees the file, a private sandbox so unknown files
   are not uploaded to a third party, and learning from VirusTotal labels with human review.

## Versi Bahasa Melayu (30 saat)

> Cloudie ialah storan awan yang mengimbas setiap fail **sebelum** menyulitkannya. Kebanyakan pengimbas hanya
> mengenal apa yang pernah mereka lihat. Cloudie mengekalkan VirusTotal sebagai pengesan utama, kemudian bertanya
> soalan kedua: **bagaimana fail ini dibina?** Makro dalam fail Word yang tak boleh ada makro, skrip tersembunyi
> dalam PDF, atau program yang dinamakan seperti dokumen: semua ini boleh dikesan tanpa signature. Fail yang bersih
> disulitkan dengan AES-256, dan setiap tindakan direkod dalam log yang menunjukkan jika ada yang mengubahnya.

## Versi Bahasa Melayu (60 saat)

> Alat antivirus bagus untuk ancaman yang dikenali, tetapi fail baharu atau yang diubah sedikit belum ada signature,
> dan dokumen boleh menyerang melalui ciri seperti makro dan skrip tersembunyi. Cloudie dibina untuk jurang itu.
> Setiap muat naik disemak mengikut urutan: jenis sebenar fail dari bait-baitnya, bukan namanya; kemudian
> VirusTotal sebagai pengesan utama; kemudian lapisan struktur yang membaca bagaimana fail dibina (PDF, Office, ZIP),
> serta model Random Forest untuk PDF yang menerangkan skornya. Jika VirusTotal tidak memberi jawapan, muat naik
> ditolak. Dua enjin menyekat fail, satu enjin hanya memberi amaran. Barulah fail disulitkan dengan kunci AES-256
> rawak, dan hanya hash kunci disimpan. Setiap tindakan masuk ke dalam rantaian yang menunjukkan jika diusik. Kami
> juga terbuka tentang had: pelayan nampak fail semasa mengimbas, dan kadar false positive pada fail sebenar belum
> diukur.

## One-line takeaways (pick one for the close)

* "Signatures know the past; structure reads the file."
* "Scan first, encrypt second, store last, and prove the history was not edited."
* "A system that tells you why it flagged a file, and what it cannot do."

## Questions to expect (short answers; the long ones are in `docs/DEFENSE_QA.md`)

| Question | Short answer |
|---|---|
| What is new compared with VirusTotal? | We do not replace it. We add structural checks for files it has no signature for, and keep every verdict explainable. |
| Why not only the AI? | One dataset, and on real-world PDFs it sits near 50%. That is why VirusTotal is primary and the AI is gated. |
| Is it end-to-end encrypted? | No. The server sees a file while it scans and encrypts it; client-side encryption is the first roadmap item. |
| What if VirusTotal is down? | The upload is refused (fail closed). We chose safety over availability. |
| False-positive rate? | Not yet measured on real-world files. We say so, and a single VirusTotal engine only warns instead of blocking. |
