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
"It was trained on a public dataset of 18,126 PDFs, half malicious and half clean, and on a held-out quarter of that
data it reaches about 99.9%. But that is one dataset. On real-world PDFs its score sits closer to 50%, which is why
VirusTotal stays our primary detector and the AI is a second opinion, not the judge."

**4. How we keep it honest (30 s)**
"First, a score above 50% is not enough to tag a file. It also needs a specific risk indicator, such as JavaScript or
an auto-run action, or a very high score of 85% or more. We added this gate because tiny harmless PDFs without a
metadata block were being mistaken for malware. Second, the model explains itself: the report lists which features
pushed the score up or down, calculated exactly from the path through the trees. Nothing is a black box."

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

**What the numbers mean.** "On the standard split the model made 0 false alarms and missed 6 malicious files out of
about 3,600 test files. On a harder split by file size, where the largest PDFs are held out, accuracy is 99.46% and
recall drops to 96%. We report both, because the harder number is the honest one."

## Live walkthrough (45 s, on the scan report)

1. Open the report of a PDF with a script. Point to the **AI card**: "score 91%, verdict malicious".
2. Scroll to **Why this AI score**: "these are the features that moved it: JavaScript present, auto-run action present."
3. Point to the **gate note**: "tagged because the score is at least 50% and it has risk indicators."
4. Open a clean PDF: "score near 50% but not tagged: the gate says no risk indicator, so it is treated as a weak
   signal." (Check the real values during the rehearsal.)

## Questions you may get, with short answers

| Question | Answer |
|---|---|
| Why not trust the 99.9%? | It is accuracy on a held-out part of one public dataset. On other PDFs the model is less certain, so it never decides alone. |
| Why a Random Forest and not deep learning? | Small tabular data, fast, and we can explain every score exactly. A neural network would be harder to justify to a user. |
| Can an attacker fool it? | Yes, a model that counts keywords can be evaded. That is why the rule layer exists and why VirusTotal is primary. We test our own evasions in `docs/EVASION_BENCHMARK.md` and say what fails. |
| Does it learn from users' files? | Not yet. We keep the model fixed so nobody can poison it. Learning from VirusTotal labels, with human review, is on the roadmap. |
| What happens to non-PDF files? | The model is PDF-only. Office files and ZIPs go through structure rules and VirusTotal. We say so on the report page. |
| What is the false-positive rate on real files? | Not measured yet on a real-world set. On the dataset it was 0 on the standard split. |

## Do not say

* "99.9% accurate" without "on a held-out part of a public dataset".
* "The AI detects all malware" or "zero false positives" in general.
* "It reads the document" (it does not read the content).
* Anything about the AI on Office or ZIP files: those use rules, not the model.
