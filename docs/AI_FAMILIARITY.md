# AI familiarity: does the model know this kind of PDF?

A model gives a number for any input, even one far from everything it learned from. The Random Forest
(`malware_rf.pkl`) was trained on one public dataset. This layer measures **how close a PDF is to the training
data**, so the report can say how much weight the AI score deserves. It is information only: it never changes
the verdict (VirusTotal stays primary, the AI stays secondary).

## How it works

Code: `flask_api/ai_familiarity.py`; reference data `flask_api/ai_familiarity.npz` (0.2 MB), built from the
training CSV by `ml/build_ai_familiarity.py`. It does not touch `malware_rf.pkl` or the 32-feature contract.

1. Each of the 32 features becomes a **rank** among the training PDFs (0 = lowest seen, 1 = highest seen; a value
   beyond the training range is placed outside [0, 1]).
2. The file's **strangeness** = mean distance to its 5 nearest training PDFs in that rank space.
3. The yardstick is how far training PDFs are from *each other* (leave-one-out): p50 0.106, p90 0.460, p99 1.034.
4. Bands: **familiar** (inside the typical 90%), **unusual** (90-99%), **unfamiliar** (beyond 99%).
5. The report also names the features that are in the top 1%, above the training range, or **below** it (for example
   `metadata_size` = 0 when no training PDF goes below 180), with the typical value or the lowest value seen.

## Does the yardstick work? (check on held-out training data)

Reference built from a random 75% of the dataset; the other 25% scored against it (seed 42):

| Band edge | Expected if the measure is fair | Measured on held-out 25% |
|---|---|---|
| beyond p90 | about 10% | 9.5% |
| beyond p99 | about 1% | 0.9% |

So for PDFs that look like the training data, the measure behaves as designed.

## What it says about real PDFs

Scored with the final reference. RF = the model's malicious probability.

| File (project documents and demo PDFs) | RF | Band | Percentile | Most unusual features |
|---|---|---|---|---|
| flow wite.pdf | 0.28 | unfamiliar | 100 | 18 images, metadata size 0, 3 AA actions |
| flow.pdf | 0.41 | unfamiliar | 100 | 16 images, metadata size 0, 1,356 KB |
| real flow.pdf | 0.41 | unfamiliar | 100 | 16 images, metadata size 0, 3 AA actions |
| Strength and Weakness.pdf | 0.31 | unfamiliar | 99.9 | metadata size 0 |
| thesis / report PDFs (4 files) | 0.14-0.30 | unfamiliar | 99.9-100 | 51 images, 4.1-4.6 MB, 1,774 objects |
| presentation deck and poster | 0.27-0.28 | unfamiliar | 100 | 24-64 images, 602-1,144 streams |
| demo 1_clean.pdf | 0.61 | unfamiliar | 99.9 | cross-reference size 0, metadata size 0 |
| demo 2_visible_script.pdf | 0.92 | unfamiliar | 99.0 | cross-reference size 0, metadata size 0 |
| demo 3_hidden_script.pdf | 0.60 | unfamiliar | 99.9 | cross-reference size 0, metadata size 0 |

**All 13 files are beyond the 99th percentile.** Two reasons are visible in the data:

* The training data's `images` feature is always -1 or 0, but real documents carry 16-64 images; and real PDFs are
  far larger (median training PDF is 20 KB, these are 1-4.6 MB).
* Seven of the ten project PDFs and the tiny demo PDFs have **no XMP metadata block**, so `metadata_size` is 0, a value
  below every training PDF (minimum 180). The report now says so. `docs/METADATA_SIZE_INVESTIGATION.md` shows why it matters:
  with 0, 15% of benign training PDFs would be flagged. The demo PDFs also have no cross-reference table (size 0).

This matches what was already seen: on real-world PDFs the Random Forest sits near its 0.5 cut-off (0.14-0.41
here, 0.60-0.61 on tiny PDFs). It is the quantitative answer to "why is VirusTotal primary and the AI secondary".

## How to present it

> "Our AI tells you when it is out of its depth. On every real document we tried, it reports that the PDF is
> unlike what it was trained on, and then says its score is a weak signal. The structure checks and VirusTotal
> carry the weight. The fix is more real-world training data, which is the first AI item on our roadmap."

## Honest limits

* 13 files, all from this project plus the demo files. This is not a benign benchmark and does not measure a
  false-positive rate. The separate benchmark on 200 real GovDocs1 PDFs (`docs/BENIGN_FP_BENCHMARK.md`) agrees:
  197 unfamiliar, 3 unusual, none familiar.
* A nearest-neighbour distance is a **measure of similarity, not of danger**: an unfamiliar PDF is not a malicious
  one, which is why the label is amber/cyan, never red.
* Because the training set is dense (many near-duplicates), the yardstick is tight, so almost any real document
  lands beyond p99. A broader reference (real benign PDFs) would spread the bands; that needs data we do not have.
* The reference is a snapshot of the training CSV. Re-run `ml/build_ai_familiarity.py` if the dataset changes.

## Tests

`flask_api/tests/test_familiarity.py` (14 tests: typical file familiar, far-away file unfamiliar and explained,
monotone distance, rank clipping, constant feature, garbage input, missing reference) plus two API tests. Mutation
checks (band logic, rank clipping, "above everything" label) each make a test fail.
