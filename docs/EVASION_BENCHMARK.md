# Evasion-aware indicators: what they add (measured, synthetic)

Script: `ml\evasion_benchmark.py` (seed 42, reproducible). Module: `flask_api\evasion_indicators.py`.
Date of the numbers below: 2026-10-22.

## Why this exists

The Random Forest looks at 32 counts, among them `/JavaScript`, `/JS`, `/OpenAction`. A PDF can write the same
names with hex escapes (`/J#61vaScript` is the same name as `/JavaScript`), so the counts read 0 while a reader
still runs the script. The risk gate added on 2026-10-21 (a score of 0.5 or more needs a visible risk keyword, or a
score of 0.85) removes false positives on small PDFs, but it also cannot be confirmed by keywords that are hidden.
The evasion layer reads the file the way a PDF reader does and reports the trick itself.

## Method

- 72 synthetic samples per obfuscation level: 3 templates (OpenAction script, additional-actions script, script in
  a compressed stream) x 3 sizes (about 1 KB, 5 KB, 45 KB) x 8 random escapes.
- The payload is always `app.alert('Cloudie test')`. Nothing here can exploit a reader.
- VirusTotal is assumed clean, so only the AI and the evasion layer decide.
- Controls: 100 synthetic plain PDFs of 5 sizes, and the 10 real, benign PDFs under `docs\`.

## Results

| Keyword obfuscation | n | mean P(malicious) | RF alone (>= 0.5) | old logic (RF + risk gate) | new logic (+ evasion) | strong evasion finding |
|---|---|---|---|---|---|---|
| level 0: clear text | 72 | 0.96 | 100% | 100% | 100% | 0% |
| level 1: first letter escaped | 72 | 0.74 | 100% | **0%** | **100%** | 100% |
| level 2: half the letters escaped | 72 | 0.75 | 100% | **31.9%** | **100%** | 100% |
| level 3: every letter escaped | 72 | 0.74 | 100% | **0%** | **100%** | 100% |

| Control (should NOT be flagged) | n | RF alone | old logic | new logic | strong evasion finding |
|---|---|---|---|---|---|
| synthetic plain PDFs | 100 | **100%** | 0% | 0% | 0% |
| real benign PDFs under `docs\` | 10 | not measured | not measured | not measured | 0 (slowest analysis 133 ms) |

## How to read it honestly

1. **"RF alone" is not a good detector here.** It flags every tiny synthetic PDF, evasive or plain (100% and 100%),
   because in the training data small files are mostly malware. That is the false-positive problem the risk gate
   fixed, so RF alone is not the baseline to beat; the "old logic" column is.
2. **The old logic loses the evasive samples** (0% at levels 1 and 3) because the evidence it needs, a visible
   keyword, was hidden. The evasion layer supplies that evidence and restores 100%, with 0% on the plain controls.
3. **These samples are synthetic and share one trick** (hex-escaped keyword names). Real evasive malware uses many
   more. 100% here means "this layer understands this trick", not "it detects evasive malware".
4. The layer is rule-based and was designed together with the benchmark; the real-world check is only 10 benign
   PDFs. A larger benign set is still the main open measurement (the false-positive rate on real documents).
5. VirusTotal stays the primary detector. This layer only adds a suspicious tag; it never blocks and never
   overrides a VirusTotal result.

## What the layer checks (all rule-based, bounded in time and memory)

| Finding | Severity | Tags the file? |
|---|---|---|
| Hidden keywords (hex-escaped `/JavaScript`, `/OpenAction`, `/Launch`, ...) | high | yes |
| Exploit/shellcode techniques in a script (`eval(unescape(`, NOP sled, `Collab.*`, `media.newPlayer`), only if a script action exists | high | yes |
| Embedded executable (MZ/PE or ELF header, in raw or compressed streams) | high | yes |
| `/Launch` that starts `cmd.exe`, `powershell`, `wscript`, ... | high | yes |
| Risky script functions (`util.printf`, `getAnnots`, ...) | medium | no |
| Hidden filter names, filter chains of 3 or more, unfiltered random-looking stream | medium | no |
| Appended data after `%%EOF` (over 1 KB), remote actions, links to raw IP addresses, executable-looking file names | medium | no |
| URL shorteners, bytes before the header, exploit text with no script action | low | no |

Limits: streams are decoded only if they use Flate; at most 1500 streams, 512 KB per stream, 8 MB total and 3
seconds are analysed (a decompression bomb is capped); page-content streams are skipped for script patterns so a
document that merely quotes "eval(unescape(" is not flagged.
