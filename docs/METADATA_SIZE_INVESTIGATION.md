# Investigation: `metadata_size` and the middling AI score on real PDFs

**Question.** On real documents the Random Forest gives 0.28 to 0.41, close to its 0.5 cut-off. `metadata_size` is
its most important feature (about 20%). Is that feature measured the same way in training and in production?

**Answer in one paragraph.** Probably not. The training data's `metadata_size` behaves like the size of the PDF's
document-information (`/Info`) block: never 0, always at least 180 bytes, and growing byte for byte with the title
length. The extractor instead measures the XMP packet, which most PDFs do not have, and reports **0**, a value that
never occurs in the training data. In the model, that single zero turns benign-looking files towards "malicious".
Reproduce with `ml/investigate_metadata_size.py` (read-only).

## What the training data says (18,126 PDFs)

| | benign | malicious |
|---|---|---|
| rows | 9,063 | 9,063 |
| `metadata_size` equal to 0 | **0** | **0** |
| minimum | 180 | 180 |
| median | 319 | 180 |
| 5th to 95th percentile | 260 to 459 | 180 to 288 |

* 36% of all rows have exactly **180** (6,616 rows), then 224, 262, 298, 283, 256: a small set of fixed values, which
  is what a metadata block built from a few fixed-length fields looks like.
* A fit on rows with a title gives `metadata_size = 1.00 x title_characters + 340`: **one extra byte per title
  character**, and a correlation of 0.805 with `title_characters`. The title text is part of what is measured.

## What the extractor does

`feature_extractor.py` takes the length of the XMP packet (`<x:xmpmeta ... </x:xmpmeta>`) and returns **0 if there is
none**. Of the 10 project PDFs tested, 7 have no XMP packet, so they get 0.

## What 0 does to the model

| Test | Result |
|---|---|
| Benign training PDFs, as in the data | mean P(malicious) 0.003, **0.0% flagged** |
| The same PDFs with `metadata_size` set to 0 | mean P(malicious) **0.311**, **15.4% flagged** |
| Malicious training PDFs, as in the data | 100% flagged |
| The same with a benign-looking 319 | 97.7% still flagged |

So the zero alone moves a benign population from "never flagged" to "15% flagged", while a malicious population stays
almost fully detected when it looks benign in this feature (the model does not rely on this feature alone).

## What happens if the extractor measured the Info block instead

For the 10 real PDFs, replacing the XMP length by the length of the `/Info` dictionary (248 to 274 bytes, inside the
training range) and leaving everything else as is:

| File | KB | XMP size (now) | Info size | P(malicious) now | P if Info size |
|---|---|---|---|---|---|
| flow wite.pdf | 1,083 | 0 | 268 | 0.28 | 0.05 |
| flow.pdf | 1,356 | 0 | 268 | 0.41 | 0.07 |
| real flow.pdf | 954 | 0 | 268 | 0.41 | 0.07 |
| Strength and Weakness.pdf | 65 | 0 | 248 | 0.31 | 0.04 |
| Cloudie deck presentation.pdf | 2,127 | 0 | 274 | 0.27 | 0.04 |
| FYP_THESIS_formatted.pdf | 4,599 | 0 | 264 | 0.30 | 0.09 |
| Project presentation poster.pdf | 1,060 | 0 | 268 | 0.28 | 0.05 |
| thesis / report PDFs (3 files, XMP present) | about 4,100 | 3,028 | 270 | 0.14 | 0.15 |

The 7 files without XMP drop from 0.27 to 0.41 down to 0.04 to 0.09. The three with an XMP packet barely change,
because their XMP length (3,028) was already above the training range and the score was already low.

## What this means

* **It explains the middling scores.** Real PDFs are not "mysteriously uncertain": one feature is measured differently
  from the training data, and it is the model's most important one. This is a measured train/serve mismatch, not
  a vague generalisation problem.
* **The risk gate was the right patch.** Tiny PDFs without a metadata block looked like malware (0.60 and 0.61 for the
  demo PDFs); the gate (score of 50% plus a risk indicator, or 85%) already stops those from being tagged.
* **It supports VirusTotal-first**: a single feature mismatch can move the score by 0.2 to 0.4.

## What we did not do, and why

We did **not** change the extractor before the competition:

1. The finding is an inference. The slope of 1.00 and the fixed floor strongly suggest an Info-like block, but the
   dataset's exact definition is not documented, and the raw PDFs are not available to verify.
2. Changing a model input without a real benign **and** real malicious test set could silently reduce detection.
   We cannot measure recall on real malware here.
3. An attacker could add a plausible `/Info` block to look benign (the same applies to XMP today). The structure
   layer and VirusTotal do not depend on this feature.

## Recommended next steps (after the competition)

1. Build a real-world benign PDF set (100 to 200 files) and measure the false-positive rate with both definitions.
2. Retrain on the training data **plus** real benign PDFs, with the extractor written to match, and validate on a
   frozen hold-out, a size-based hold-out, and the real set. Promote only if nothing gets worse.
3. Replace `images` too: in training it is always 0 or -1, so it carries no signal (see `docs/AI_FAMILIARITY.md`).
4. Small, safe improvement to the familiarity card: also report features **below** the training range (here,
   `metadata_size` = 0 against a minimum of 180). Today only values above the range are listed.

## How to say it to the judges

> "We found why the model is unsure on real documents: one feature is measured differently in production from
> in the training data, and it is the model's most important one. With a zero there, 15% of benign training PDFs would
> be flagged. We measured it, we did not hide it, and the fix is a retrain with real data and a matching extractor.
> That is also why VirusTotal is primary and the model is a supporting signal."

## Limits of this investigation

* 10 PDFs, all from this project, plus the training data; not a benchmark of real-world files.
* The dataset's definition of `metadata_size` is inferred from its distribution, not confirmed.
* The "P if Info size" column is what the model would say under that assumption; it is not a validated improvement.
