# Retroactive re-check

**The problem.** A scan only knows what was known on upload day. New malware usually scores 0 on VirusTotal at first and
gets detected days later. Most storage services scan once, so a file that passed stays "clean" forever.

**What Cloudie does.** It asks VirusTotal again later, using only the SHA-256 recorded at upload. The AES key is not
needed and the file is never decrypted, so re-checking does not weaken the "keys are not stored at rest" design.

## How it works

```
My files opens / "Re-check now"  ->  rescan.php  ->  Flask POST /vt_lookup {hash}  ->  VirusTotal GET /files/{hash}
                                         |
                                         v
                                 files.recheck_* (files.verdict and scan_report are never overwritten)
```

| VirusTotal answers | Stored | User sees |
|---|---|---|
| 2 or more engines | `malicious` | **Malicious, found after upload.** Quarantined (below), banner on My files |
| 1 engine | `suspicious` | **Suspicious, found after upload** |
| 0 engines | `clean` | No new flag. An earlier later-flag is lifted. An AI or structure tag from upload stays |
| Does not know the hash | only the time | No change |
| Error or 429 | nothing | No change. No answer is never read as clean |

The thresholds are the same as at upload (`VT_MALICIOUS_MIN_HITS`, `verdict_engine.recheck_label`). The shown verdict is
the worse of the upload verdict and the latest re-check (`rescan_effective`), so a false alarm can be undone.

**Quarantine** (enforced on the server in `decrypt.php`): no opening in the browser, download only after ticking a warning
(logged in the audit trail), delete still allowed. The file is never deleted automatically, because a false positive
must not destroy someone's data and Cloudie cannot judge that for them.

**Audit trail.** `RESCAN_FLAGGED` and `RESCAN_CLEARED` are sealed entries with the engine count and old and new verdict.
Manual re-checks log `RESCAN`. Automatic checks with no change log nothing.

## When it runs

- **Automatically:** when the owner opens My files, the one most overdue file (not checked for 24 h) is checked in the
  background. It is skipped if any re-check ran in the last minute or this user uploaded in the last 2 minutes.
- **Manually:** "Re-check now" on the scan report (10 per user per 10 min).
- **Quota:** at most 2 re-checks per minute for the whole app, because uploads need the rest of VirusTotal's free quota
  (about 4 requests/min) and an upload without an answer is refused.

## Honest limits

1. **It depends on VirusTotal analysing again.** VT reports its last analysis and does not re-scan by itself. If the last
   analysis is older than 7 days, Cloudie asks for a new one (one extra request); a later re-check reads the result.
2. **No background job.** Files are only checked when their owner opens My files or clicks the button, so nothing is
   checked for a user who stays away. A scheduled sweep (Cloud Scheduler) would fix this but is not built.
3. **Slow for a large vault.** One file per visit, per 24 h at best. Fine for a demo account, not for thousands of files.
   A paid VT quota would be needed at scale.
4. **Only VirusTotal is re-run.** The Random Forest and structure checks need the plaintext, so they stay as at upload.
5. **Not measured.** There is no figure for how often stored files get flagged later. Do not claim a detection rate.
6. **Exact file only.** A hash match finds the same bytes, not a variant of the malware.
7. **Fingerprint stored.** The plaintext SHA-256 is kept in the database (it already was, for the integrity check).
   Someone who reads the database can confirm that a user holds a specific known file, without being able to read it.

## Demo

A real file cannot be made to turn malicious on stage, so point one throwaway file's fingerprint at EICAR and say so:
"I am simulating the moment VirusTotal learns about this file. The answer you will see is VirusTotal's real answer."

```powershell
& "C:\xampp\mysql\bin\mysql.exe" -h 34.143.161.161 -u cloudie_user -p cloudie_db -e "UPDATE files SET scan_report=JSON_SET(scan_report,'$.file_sha256','275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f') WHERE file_id=<id>"
```

Then open that file's report and click **Re-check now**. It needs your IP in Cloud SQL Authorized Networks (remove it
afterwards). The swapped fingerprint also makes the integrity check fail for that file, so delete it after the demo and
use a file you do not need.

## Tests

`flask_api/tests/test_vt_lookup.py` (thresholds, unknown, 429, bad hash, reanalysis, VT mocked) and the "Retroactive
re-check" group in `tests/php/run.php`. On 2026-11-02 the whole flow also ran in a browser against a temporary MariaDB
and the real Flask route with VirusTotal faked: flagged, quarantine (including a forged view POST), lowered, lifted, 429,
unknown, app-wide limit, automatic check, audit chain intact, and the migration on a database without the new columns.
A real VirusTotal response through `/vt_lookup` still has to be confirmed after deploy.
