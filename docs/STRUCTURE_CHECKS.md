# Structure checks for Office files and archives

Cloudie's idea: **VirusTotal knows what has been seen before (signatures). Cloudie also looks at how a file is
built (structure), so a new or modified file with no signature can still be tagged.** The PDF layer
(`evasion_indicators.py` + Random Forest) already did this. Since this change the same idea covers Office
Open XML files (`.docx .xlsx .pptx`) and ZIP archives, and every upload gets an extension-vs-content check.

## What runs for each type

| Real type (from the first bytes) | Checks | AI model |
|---|---|---|
| PDF | evasion layer (unchanged) | Random Forest, 32 features |
| Office OOXML (`[Content_Types].xml` + `word/ xl/ ppt/`) | `office_structure.py` + zip checks (strict) | no |
| ZIP | `archive_structure.py` | no |
| Anything else (PNG, JPEG, RAR, OLE, RTF, text) | only "name vs content" (`file_structure.py`) | no |

The Random Forest is trained on PDFs only, so it is never used for the other types. For them the verdict is
VirusTotal plus these rule-based findings. VirusTotal stays PRIMARY and fail-closed: structure findings can
only add a SUSPICIOUS tag to a file VirusTotal cleared, they never turn "no VirusTotal result" into a pass.

## Findings

STRONG = tags a VT-clean file SUSPICIOUS (stored, tagged, report shows the evidence). Others are shown only.

| id | strong | meaning |
|---|---|---|
| `macro_in_macrofree_type` | yes | VBA project inside .docx/.xlsx/.pptx (Office does not run macros from those; the file was renamed) |
| `macro_autoexec` | yes | the macro project names an auto-run entry point (`AutoOpen`, `Workbook_Open`...), best effort |
| `xlm_macro_sheet` | yes | Excel 4.0 macro sheet in an .xlsx |
| `dde_field` / `dde_formula` | yes | DDE/DDEAUTO field in Word, `cmd\|...` formula in Excel |
| `remote_template` | yes | `attachedTemplate` pulled from http(s)/ftp/UNC (template injection) |
| `remote_object` | yes | OLE object / frame / sub-document pulled from a remote address |
| `embedded_executable` | yes | program inside an Office file |
| `path_traversal` | yes | zip entry named `../x`, `/x`, `C:/x` (zip slip) |
| `zip_bomb` | yes | tiny archive that expands to gigabytes (declared sizes, never expanded) |
| `double_extension` | yes | `invoice.pdf.exe` |
| `rtlo_name` | yes | right-to-left override character in an entry name |
| `disguised_executable` | yes | entry starts like a program (MZ/PE, ELF) but is not named like one |
| `type_mismatch_executable` | yes | the upload is a program but named `.pdf`, `.png`, `.docx`... |
| `polyglot_executable_archive` | yes | file is a program and a valid ZIP |
| `office_macro`, `very_hidden_sheet`, `activex_controls`, `unc_reference`, `executable_in_archive`, `encrypted_entries`, `duplicate_entries`, `type_mismatch`, `malformed_archive`, `nested_archive`, `embedded_objects`, `ooxml_type_mismatch` | no | informational |

## Safety of the analyzers

Nothing is executed or extracted to disk. Archive sizes come from the central directory; entries are only read
through a bounded 1 KB read; Office parts are read with a hard limit (4 MB, 256 KB for relationship files) and
matched with plain regular expressions (no XML parser, so XML bombs and external entities are not an issue).
Time budget 3 s per file, at most 2000 entries inspected. Every analyzer returns an empty result with `error`
set instead of raising.

## Honest limits

* **Macro source is compressed** (MS-OVBA inside an OLE container) and there is no OLE parser here, so
  `macro_autoexec` and the risky-call list are best effort: they find names stored literally and can miss others.
  The decisive signal is the macro project in a macro-free file type, which does not depend on that.
* **Legacy Office (.doc .xls .ppt), RTF, images and RAR** are only type-checked (name vs content). No macro scan
  for OLE yet; that is the next step.
* **False-positive rate is not measured.** The unit tests contain clean documents, hyperlinks, images, a large
  honest archive and the project's own Office/zip files (none flagged), but there is no real-world benign Office
  set yet, so no rate is claimed. `executable_in_archive` is deliberately non-strong because installers exist.
* A determined attacker can avoid every rule here (these are known tricks). The value is detecting the common,
  cheap ones without needing a signature, on top of VirusTotal.

## Demo files

```powershell
python C:\xampp\htdocs\cloudie\tests\make_demo_files.py C:\Users\<you>\Desktop\cloudie-demo
```

Writes five harmless files (normal docx, macro-in-docx, remote template, zip slip, double extension). Expected:
CLEAN for the first, SUSPICIOUS with a named finding for the other four, provided VirusTotal does not flag
them. Upload each once a few minutes before the demo (VirusTotal quota).

## Tests

`flask_api\tests\test_file_structure.py` (48 tests: each finding, clean files, bomb timing, robustness) and five
API-level tests in `test_scan_api.py`. Mutation-checked: disabling traversal, disguised-program, external-relationship,
DDE and mismatch checks each makes tests fail.
