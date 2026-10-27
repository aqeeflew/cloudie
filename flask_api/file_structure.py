"""
file_structure.py — one entry point for the structure checks of every file type Cloudie accepts.

  detect_type(path)           what the file REALLY is, from its first bytes (never from its name)
  analyze(path, filename)     {'file_type', 'file_type_label', 'findings', 'strong_ids', 'scanned', 'error'}

PDFs go to evasion_indicators.py (unchanged). Office Open XML files and ZIP archives go to
office_structure.py / archive_structure.py. Every file also gets the "name says one thing, content says
another" check. The Random Forest stays PDF-only: for the other types the verdict is VirusTotal plus these
rule-based structure findings.

Like the PDF layer: never raises, bounded in time and memory, reads bytes only (nothing is executed),
and a "strong" finding can tag a VT-clean file as suspicious (see verdict_engine.py).
"""

import os
import zipfile

import evasion_indicators
from structure_common import Collector, Budget, is_pe, printable
import archive_structure
import office_structure
import content_structure

LABELS = {
    "pdf": "PDF document", "ooxml": "Office document (OOXML)", "zip": "ZIP archive",
    "ole": "Legacy Office document (OLE)", "rtf": "RTF document", "png": "PNG image", "jpg": "JPEG image",
    "gif": "GIF image", "rar": "RAR archive", "7z": "7-Zip archive", "pe": "Windows/Linux program",
    "elf": "Windows/Linux program", "text": "Plain text", "unknown": "Unknown type",
}

# claimed extension -> the real types that are acceptable for it
EXPECTED = {
    "pdf": {"pdf"},
    "docx": {"ooxml"}, "xlsx": {"ooxml"}, "pptx": {"ooxml"},
    "doc": {"ole", "rtf", "ooxml"}, "xls": {"ole", "rtf", "ooxml"}, "ppt": {"ole", "ooxml"},
    "zip": {"zip", "ooxml"}, "rar": {"rar"}, "7z": {"7z"},
    "png": {"png"}, "jpg": {"jpg"}, "jpeg": {"jpg"}, "gif": {"gif"},
    "txt": {"text"}, "csv": {"text"},
}

MAX_BYTES = 30 * 1024 * 1024


def detect_type(path: str) -> str:
    try:
        with open(path, "rb") as fh:
            head = fh.read(8192)
    except OSError:
        return "unknown"
    if b"%PDF-" in head[:1024]:
        return "pdf"
    if head[:2] == b"MZ":
        return "pe"
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        try:
            with zipfile.ZipFile(path) as zf:
                if office_structure.is_ooxml(zf.namelist()):
                    return "ooxml"
        except Exception:  # noqa: BLE001 - malformed archive still counts as a zip by its magic
            pass
        return "zip"
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"
    if head[:5] == b"{\\rtf":
        return "rtf"
    if head[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if head[:3] == b"\xff\xd8\xff":
        return "jpg"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if head[:6] == b"Rar!\x1a\x07":
        return "rar"
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if head and b"\x00" not in head:
        return "text"
    return "unknown"


def _extension(filename: str) -> str:
    base = os.path.basename((filename or "").replace("\\", "/"))
    return base.rsplit(".", 1)[1].lower() if "." in base else ""


def _check_extension(ftype: str, ext: str, out: Collector):
    if ftype in ("pe", "elf") and ext:
        out.add("type_mismatch_executable", "A program disguised as a %s file" % ext, "high", True,
                "The name says .%s but the content is a Windows/Linux program (MZ/PE or ELF header). "
                "This is how an executable is passed off as a document or image." % ext,
                ["name: .%s" % ext, "content: program header"])
        return
    expected = EXPECTED.get(ext)
    if expected is None or ftype in expected:
        return
    out.add("type_mismatch", "File content does not match its extension", "medium", False,
            "The name says .%s but the content looks like a %s." % (ext, LABELS.get(ftype, ftype)),
            ["name: .%s" % ext, "content: %s" % LABELS.get(ftype, ftype)])


def analyze(path: str, filename: str = "") -> dict:
    budget = Budget()
    try:
        return _analyze(path, filename, budget)
    except Exception as exc:  # noqa: BLE001 - this layer must never break a scan
        r = Collector().result({"ms": budget.ms()}, error="%s: %s" % (type(exc).__name__, exc))
        r.update(file_type="unknown", file_type_label=LABELS["unknown"])
        return r


def _analyze(path: str, filename: str, budget: Budget) -> dict:
    if not os.path.isfile(path):
        r = Collector().result({"ms": budget.ms()}, error="file not found")
        r.update(file_type="unknown", file_type_label=LABELS["unknown"])
        return r
    ftype = detect_type(path)
    ext = _extension(filename)

    if ftype == "pdf":
        r = evasion_indicators.analyze(path)
        c = Collector()
        c.items = {f["id"]: f for f in r["findings"]}
        if ext and ext != "pdf":
            _check_extension(ftype, ext, c)
        content_structure.analyze_filename(filename, c)
        r = c.result(r["scanned"], r["error"])
        r.update(file_type="pdf", file_type_label=LABELS["pdf"])
        return r

    out = Collector()
    _check_extension(ftype, ext, out)
    content_structure.analyze_filename(filename, out)
    scanned, error = {}, None

    if ftype == "text" and ext == "csv":
        try:
            scanned.update(content_structure.analyze_csv(path, out, budget))
        except Exception as exc:  # noqa: BLE001
            error = "%s: %s" % (type(exc).__name__, exc)
    if ftype in ("png", "jpg"):
        try:
            scanned.update(content_structure.analyze_image(path, ftype, out, budget))
        except Exception as exc:  # noqa: BLE001
            error = "%s: %s" % (type(exc).__name__, exc)

    # a program that is also a valid zip (polyglot) hides its payload from archive-aware scanners
    if ftype in ("pe", "elf"):
        try:
            if zipfile.is_zipfile(path):
                out.add("polyglot_executable_archive", "Program that is also a ZIP archive", "high", True,
                        "The file starts as a program but also contains a valid ZIP structure. Such "
                        "polyglots are built to be read differently by different tools.", [])
        except Exception:  # noqa: BLE001
            pass

    if ftype in ("zip", "ooxml"):
        try:
            if os.path.getsize(path) > MAX_BYTES * 4:
                out.add("archive_too_large", "Archive too large to inspect", "low", False,
                        "Only the file type was checked.", [])
            else:
                with zipfile.ZipFile(path) as zf:
                    if ftype == "ooxml":
                        scanned.update(office_structure.analyze_ooxml(zf, ext, out, budget))
                    else:
                        scanned.update(archive_structure.analyze_zip(zf, out, budget))
        except zipfile.BadZipFile as exc:
            out.add("malformed_archive", "Damaged or deliberately malformed ZIP structure", "medium", False,
                    "The archive's index cannot be read. Broken structures are used to make parsers and scanners "
                    "disagree.", [printable(str(exc), 80)])
        except Exception as exc:  # noqa: BLE001
            error = "%s: %s" % (type(exc).__name__, exc)

    scanned["ms"] = budget.ms()
    r = out.result(scanned, error)
    r.update(file_type=ftype, file_type_label=LABELS.get(ftype, LABELS["unknown"]))
    return r
