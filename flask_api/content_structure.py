"""
content_structure.py — three more structure checks that need no signature:

  analyze_csv(path, out, budget)         spreadsheet formula injection in a .csv (DDE commands, data-leaking formulas)
  analyze_image(path, ftype, out, budget)  data hidden after the end of a PNG/JPEG, or scripts inside it (polyglots)
  analyze_filename(filename, out)        tricks in the NAME of the uploaded file (double extension, RTLO, padding)

Same rules as the other analyzers: bytes only (nothing is executed), bounded reads and time, never raises
(file_structure.analyze() catches everything), and "strong" is reserved for things legitimate files almost never do.
See docs/STRUCTURE_CHECKS.md.
"""

import os
import re

from structure_common import Collector, Budget, EXEC_EXT, DOC_EXT, is_pe, printable

MAX_TEXT_BYTES = 4 * 1024 * 1024
MAX_IMAGE_BYTES = 60 * 1024 * 1024
TRAILING_IGNORED = 16                  # a few stray bytes after the end marker are not worth reporting

# ---- CSV -----------------------------------------------------------------------------------------------------------
_CELL_START = r"""(?:^|[,;\t"'])\s*[=+\-@]\s*"""
_ARITH_PREFIX = r"""(?:[\w\s.()+\-*/]{0,40}[+\-*/]\s*)?"""      # classic form: =1+cmd|'/C calc'!A0
_CSV_DDE = re.compile(
    _CELL_START + _ARITH_PREFIX + r"""(?:cmd|powershell|pwsh|mshta|msiexec|cscript|wscript|rundll32|regsvr32|calc|notepad|bash|sh|curl|wget|certutil)"""
    r"""\s*\|[^!\r\n]{0,200}!""", re.I | re.M)
_CSV_EXFIL = re.compile(
    _CELL_START + r"""(?:HYPERLINK|WEBSERVICE|IMPORTXML|IMPORTDATA|IMPORTHTML|IMPORTFEED|IMAGE)\s*\([^)\r\n]{0,300}https?://""",
    re.I | re.M)

# ---- images --------------------------------------------------------------------------------------------------------
_TRAILING_SIGNATURES = (
    (b"PK\x03\x04", "a ZIP archive"), (b"Rar!\x1a\x07", "a RAR archive"), (b"%PDF-", "a PDF document"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "an Office (OLE) document"), (b"<?php", "PHP code"),
    (b"<script", "a script"), (b"<SCRIPT", "a script"), (b"#!/bin/", "a shell script"), (b"#!/usr/bin/", "a shell script"),
)

# ---- file names ------------------------------------------------------------------------------------------------------
_BIDI = re.compile("[‪-‮⁦-⁩]")
_CTRL = re.compile("[\x00-\x1f\x7f]")


def analyze_csv(path: str, out: Collector, budget: Budget) -> dict:
    with open(path, "rb") as fh:
        text = fh.read(MAX_TEXT_BYTES).decode("utf-8", "replace")
    m = _CSV_DDE.search(text)
    if m:
        out.add("csv_dde_formula", "Spreadsheet cell that starts a program", "high", True,
                "A cell begins with = + - or @ and calls a command interpreter through DDE (for example "
                "=cmd|'/c ...'!A1). Excel can run it when the file is opened, the 'CSV injection' attack.",
                [printable(m.group(0).strip(",;\t\"' "), 80)])
    if not budget.over():
        m = _CSV_EXFIL.search(text)
        if m:
            out.add("csv_exfil_formula", "Spreadsheet cell that contacts a web address", "medium", False,
                    "A cell uses HYPERLINK, WEBSERVICE, IMPORTXML or similar with a web address. Such formulas "
                    "can send the contents of other cells to an outside server.",
                    [printable(m.group(0).strip(",;\t\"' "), 80)])
    return {"text_bytes": len(text)}


def _png_end(blob: bytes):
    """Offset just after the IEND chunk, walking the chunk list; None if the structure is broken."""
    pos, n = 8, 0
    while pos + 12 <= len(blob) and n < 200000:
        length = int.from_bytes(blob[pos:pos + 4], "big")
        ctype = blob[pos + 4:pos + 8]
        pos += 12 + length
        n += 1
        if pos > len(blob):
            return None
        if ctype == b"IEND":
            return pos
    return None


def analyze_image(path: str, ftype: str, out: Collector, budget: Budget) -> dict:
    with open(path, "rb") as fh:
        blob = fh.read(MAX_IMAGE_BYTES)
    end = None
    if ftype == "png":
        end = _png_end(blob)
        if end is None:
            out.add("image_malformed", "Image structure is damaged", "medium", False,
                    "The PNG chunk list cannot be followed to its end marker (IEND). Broken structures make image "
                    "parsers and scanners disagree.", [])
    elif ftype == "jpg":
        i = blob.rfind(b"\xff\xd9")
        end = i + 2 if i >= 0 else None

    tail = blob[end:] if end is not None else b""
    if len(tail.strip(b"\x00\r\n\t ")) > TRAILING_IGNORED:
        found = [label for sig, label in _TRAILING_SIGNATURES if sig in tail]
        # a program keeps its header: MZ/PE at the start of the extra data, or the DOS stub text, or an ELF header
        if is_pe(tail[:1024]) or b"This program cannot be run" in tail:
            found.insert(0, "a Windows program")
        if b"\x7fELF\x02\x01\x01" in tail or b"\x7fELF\x01\x01\x01" in tail:
            found.insert(0, "a Linux program")
        if found:
            out.add("image_hidden_payload", "Hidden file after the end of the image", "high", True,
                    "Bytes after the image's end marker hold %s. Viewers ignore them, but this is how an image "
                    "is used to smuggle another file past filters." % found[0],
                    ["%d bytes after the end of the %s" % (len(tail), ftype.upper()), "contains " + found[0]])
        else:
            out.add("image_trailing_data", "Extra data after the end of the image", "medium", False,
                    "%d bytes follow the image's end marker. Some cameras and editors append data, but it is also "
                    "a place to hide content." % len(tail), ["%d bytes" % len(tail)])
    if not budget.over():
        for sig in (b"<?php", b"<script", b"<SCRIPT"):
            if sig in blob:
                out.add("image_script_payload", "Script code inside an image", "high", True,
                        "The image contains %s. Pictures never need it; this is the 'web shell in a picture' trick."
                        % ("PHP code" if sig == b"<?php" else "a <script> tag"), [printable(sig)])
                break
    return {"image_bytes": len(blob)}


def analyze_filename(filename: str, out: Collector) -> None:
    name = os.path.basename((filename or "").replace("\\", "/"))
    if not name:
        return
    if _BIDI.search(name):
        out.add("filename_rtlo", "File name uses a right-to-left override character", "high", True,
                "Invisible direction-control characters can make 'exe.pdf' display as 'fdp.exe' or the reverse. "
                "Real file names do not need them.", [printable(name, 60)])
    if _CTRL.search(name):
        out.add("filename_control_chars", "File name contains control characters", "medium", False,
                "Control characters in a name are used to confuse file handling.", [printable(name, 60)])
    parts = name.split(".")
    last = "." + parts[-1].strip().lower() if len(parts) > 1 else ""
    prev = "." + parts[-2].strip().lower() if len(parts) > 2 else ""
    if last in EXEC_EXT and prev in DOC_EXT:
        out.add("filename_double_extension", "Program disguised with a document extension", "high", True,
                "The name ends like a document and then like a program (for example invoice.pdf.exe), a "
                "common phishing trick.", [printable(name, 60)])
    elif last in EXEC_EXT:
        out.add("filename_executable_extension", "Name ends with a program extension", "medium", False,
                "The extension is one that runs code (%s)." % last, [printable(name, 60)])
    if name.endswith((" ", ".")):
        out.add("filename_trailing_chars", "File name ends with a dot or a space", "medium", False,
                "Windows hides trailing dots and spaces, so 'name.exe.' is treated as 'name.exe'.", [printable(name, 60)])
