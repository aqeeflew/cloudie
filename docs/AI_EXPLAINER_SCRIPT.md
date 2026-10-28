# How to explain the AI part to the judges

Use this with slide 8 ("A second opinion from a Random Forest"). Every number matches the code and
`docs/DEFENSE_QA.md`. Say it in your own words; keep the order.

## The idea in one sentence

> "The AI does not read the file's text. It counts structural facts about a PDF, such as how many scripts, auto-run
> actions and embedded files it has, and 200 small decision trees vote on whether that structure looks like malware."

## 90-second script (English)

**1. What goes in (15 s)**
"When a PDF is uploaded, we turn it into 32 numbers. They describe how the file is built: its size, its number of
pages, whether it has a metadata block, and how many times it uses features like JavaScript, OpenAction, launch
actions or embedded files. We never read the content of the document."

**2. What the model is (20 s)**
"The model is a Random Forest: 200 decision trees. Each tree asks a chain of simple questions, for example 'does this
file contain JavaScript, and is there an auto-run action?', and gives a vote. The forest averages the votes into one
probability that the file is malicious."

**3. Why we trust it only so far (25 s)**
"It was trained once, offline, on a public dataset of 18,126 PDFs, half malicious and half clean, and on a held-out
quarter of that data it reaches about 99.9%. After that the model is fixed: it does not learn from VirusTotal or from
users' files while running, so nobody can poison it. But it is one dataset, so VirusTotal stays our primary detector
and the AI is a second opinion, not the judge."

**4. How we keep it honest (30 s)**
"First, a score above 50% is not enough to tag a file. It also needs a specific risk indicator, such as JavaScript or
an auto-run action, or a very high score of 85% or more. We added this gate because tiny harmless PDFs without a
metadata block were being mistaken for malware. Second, the model explains itself: the report lists which features
pushed the score up or down, calculated exactly from the path through the trees. Third, it tells you when it is out of
its depth: we measure how close each PDF is to the training data, and on every real document we tried the answer is
'unlike what I learned from', and the report names why, for example a metadata size that never went below 180 in
training. So the score is shown as a weak signal."

## 3-minute version: add these

**How a tree votes (plain words).** "Imagine one inspector with a checklist: 'Is there JavaScript? Yes. Is there an
auto-run action? Yes. Then suspicious.' Another inspector looks at different questions. 200 inspectors, each trained
on a different random slice of the data, so they make different mistakes and the mistakes cancel out. That is a
Random Forest."

**What the model learned.** "The strongest signals are the size of the metadata block and the JavaScript counts.
Malicious PDFs in this dataset very often carry scripts and very often lack normal metadata."

**The weak point, said by us first.** "A Random Forest only knows the 32 numbers. If an attacker hides the keyword,
for example by writing `/J#61vaScript` instead of `/JavaScript`, the count is zero and the model sees nothing. That is
why we added a separate rule-based layer: it decodes those hidden names and reads inside compressed streams. The model
and the rules cover each other."

**Does it learn from VirusTotal?** "No, not while running. The model is trained once, offline, and then fixed. Results
from VirusTotal are combined with the AI score to make a verdict, but they are not fed back into the model. We chose that
on purpose: a model that learns from uploads can be poisoned by an attacker who uploads crafted files. VirusTotal's
knowledge reached the model only indirectly, because the public dataset was built from sources such as Contagio and
VirusTotal. Learning from VirusTotal labels, with human review and a frozen test set, is on our roadmap."

**How it knows it is out of its depth.** "Each of the 32 features is turned into a rank among the training PDFs. We take
the average distance to the five closest training PDFs and compare it with how far the training PDFs are from each
other. On a held-out 25% of the data this behaves as designed: 9.5% fall beyond the 90th percentile and 0.9% beyond the
99th. All thirteen real or demo PDFs we tried, our own thesis and posters plus three generated demo files, fall beyond
the 99th percentile. Real documents are larger and carry many images, while in the training data the image feature
is always zero or below. That is the evidence for why VirusTotal is primary."

**The cause we found.** "When we asked why the model is unsure on real documents, we traced it to one feature, the
metadata size, which is the model's most important one. In the training data it is never zero: at least 180, and it grows
one byte for each character of the title, so it looks like the document-information block. Our extractor measures
a different thing, the XMP packet, and returns zero when there is none, which is true for most PDFs. We tested the effect:
with a zero there, 15% of benign training PDFs would be flagged, against none as they are. Using the information-block
size instead, our real documents would score 0.04 to 0.09 instead of 0.27 to 0.41. We documented it and did not hide it.
It is not fixed yet: changing a model input needs real benign and malicious test files, so the fix is a retrain with real
data and a matching extractor after the competition. This is also why VirusTotal is primary."

**What the numbers mean.** "On the standard split the model made 0 false alarms and missed 6 malicious files out of
about 3,600 test files. On a harder split by file size, where the largest PDFs are held out, accuracy is 99.46% and
recall drops to 96%. We report both, because the harder number is the honest one."

## Live walkthrough (45 s, on the scan report)

1. Open the report of a PDF with a script. Point to the **AI card**: "score 91%, verdict malicious".
2. Scroll to **Why this AI score**: "these are the features that moved it: JavaScript present, auto-run action present."
3. Point to the **gate note**: "tagged because the score is at least 50% and it has risk indicators."
4. Point to the **AI familiarity** box under the table: "this tells us how well the AI knows this kind of PDF; here it
   says unfamiliar, so the score counts as a weak signal." Name one of the listed features (for example image count).
5. Point at the line **"metadata block (XMP) size: 0, never below 180 in training"**: "this is the measured mismatch;
   most real PDFs have no XMP block, so the extractor says zero, a value the model never saw."
6. Open a clean PDF: "score near 50% but not tagged: the gate says no risk indicator, so it is treated as a weak
   signal." (Check the real values during the rehearsal.)

## Questions you may get, with short answers

| Question | Answer |
|---|---|
| Why not trust the 99.9%? | It is accuracy on a held-out part of one public dataset. On other PDFs the model is less certain, so it never decides alone. |
| Why a Random Forest and not deep learning? | Small tabular data, fast, and we can explain every score exactly. A neural network would be harder to justify to a user. |
| Can an attacker fool it? | Yes, a model that counts keywords can be evaded. That is why the rule layer exists and why VirusTotal is primary. We test our own evasions in `docs/EVASION_BENCHMARK.md` and say what fails. |
| Why is the AI unsure on real documents? | One feature, the metadata size, is measured differently in production from in training. Training never has zero; most real PDFs get zero. We measured it (15% of benign training PDFs would be flagged with a zero), documented it, and the fix is a retrain after the competition. |
| Why not fix it before the demo? | We cannot verify a model change without real benign and real malicious test files, and a silent drop in detection would be worse than an honest limitation. VirusTotal and the structure checks do not depend on this feature. |
| Does it learn from users' files or from VirusTotal? | No. It is trained once, offline, then fixed. Results from VirusTotal are used in the verdict, not fed back into the model, so nobody can poison it. Learning from VirusTotal labels, with human review, is on the roadmap. |
| So is the AI useless on real files? | It is a supporting signal. Our own check shows real PDFs are unlike its training data, and it says so. VirusTotal and the structure checks carry the weight; broader real-world training data is the first AI item on the roadmap. |
| Does the familiarity score change the verdict? | No. It is information for the reader. It says how much weight the AI score deserves; the verdict still comes from VirusTotal first. |
| What happens to non-PDF files? | The model is PDF-only. Office files and ZIPs go through structure rules and VirusTotal. We say so on the report page. |
| What is the false-positive rate on real files? | On 200 real PDFs from GovDocs1: the AI alone would tag 13 (6.5%), after the risk gate 1 (0.5%); the final verdict tagged 2 (1.0%) and blocked none. On the dataset it was 0 on the standard split. Office and ZIP files are not measured yet. See `docs/BENIGN_FP_BENCHMARK.md`. |

## Do not say

* "99.9% accurate" without "on a held-out part of a public dataset".
* "The AI detects all malware" or "zero false positives" in general.
* "It reads the document" (it does not read the content).
* "The AI learns from VirusTotal" or "it gets smarter with every file". It is fixed after training.
* "We fixed the metadata problem". It is measured and documented; the fix is planned, not done.
* "Unfamiliar means malicious". It only means unlike the training data.
* Anything about the AI on Office or ZIP files: those use rules, not the model.
