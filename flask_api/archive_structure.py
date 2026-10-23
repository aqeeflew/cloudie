"""
archive_structure.py — structure checks for ZIP containers (plain .zip and the zip inside Office files).

Looks at HOW the archive is built, not at signatures:
  * zip bombs (tiny file that expands to gigabytes)
  * path traversal ("zip slip": ../ or absolute paths in entry names)
  * programs inside (by name AND by content, so a renamed .exe is still seen)
  * double extensions (invoice.pdf.exe) and right-to-left-override names
  * duplicate entry names and password-protected entries (both hide content from scanners)

Nothing is extracted. Entries are only read through a small bounded read (first 1 KB), the sizes come
from the central directory, and the number of entries and the time are capped.
"""

import re
import zipfile

from structure_common import Collector, Budget, EXEC_EXT, DOC_EXT, is_pe, printable

MAX_ENTRIES_INSPECTED = 2000
HEAD_BYTES = 1024
BOMB_TOTAL_BYTES = 2 * 1024 ** 3                  # 2 GB when expanded
BOMB_RATIO_TOTAL_MIN = 200 * 1024 ** 2            # 200 MB expanded and ...
BOMB_RATIO = 100                                  # ... more than 100x the archive size
BOMB_ENTRY_BYTES = 50 * 1024 ** 2                 # one entry above 50 MB with a ratio above 1000
BOMB_ENTRY_RATIO = 1000
MAX_ENTRY_COUNT_BOMB = 50000
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".gz", ".tgz", ".cab", ".iso"}
_RTLO = re.compile("[‪-‮⁦-⁩]")
_DRIVE = re.compile(r"^[A-Za-z]:")


def _ext(name: str) -> str:
    base = name.rstrip("/").rsplit("/", 1)[-1]
    return ("." + base.rsplit(".", 1)[1].lower()) if "." in base else ""


def analyze_zip(zf: "zipfile.ZipFile", out: Collector, budget: Budget, strict: bool = False) -> dict:
    """
    Add findings for an opened ZipFile to `out`.
    strict=True is used for Office files: a program inside a .docx/.xlsx/.pptx is never legitimate,
    so it is a STRONG finding there, while in a plain .zip it is only a medium (installers exist).
    """
    infos = zf.infolist()
    n = len(infos)
    info = {"entries": n}

    total_unc = sum(i.file_size for i in infos)
    total_cmp = sum(i.compress_size for i in infos) or 1
    worst = max(infos, key=lambda i: i.file_size / max(i.compress_size, 1), default=None)
    worst_ratio = (worst.file_size / max(worst.compress_size, 1)) if worst else 0
    if (total_unc > BOMB_TOTAL_BYTES
            or (total_unc > BOMB_RATIO_TOTAL_MIN and total_unc / total_cmp > BOMB_RATIO)
            or (worst and worst.file_size > BOMB_ENTRY_BYTES and worst_ratio > BOMB_ENTRY_RATIO)
            or n > MAX_ENTRY_COUNT_BOMB):
        out.add("zip_bomb", "Possible decompression bomb", "high", True,
                "The archive is small but declares an enormous expanded size or entry count. Opening it can "
                "exhaust memory or disk (denial of service) and it also stops scanners from looking inside.",
                ["%d entries" % n, "declares %.1f MB expanded from %.1f MB (x%d)" % (
                    total_unc / 1048576, total_cmp / 1048576, total_unc / total_cmp)])

    seen, dup = set(), []
    traversal, rtlo, dbl, execs, disguised, encrypted, nested = [], [], [], [], [], [], []
    for idx, zi in enumerate(infos):
        name = zi.filename
        low = name.lower()
        if low in seen:
            dup.append(name)
        seen.add(low)
        if name.endswith("/"):
            continue
        parts = re.split(r"[\\/]", name)
        if ".." in parts or name.startswith(("/", "\\")) or _DRIVE.match(name):
            traversal.append(name)
        if _RTLO.search(name):
            rtlo.append(name)
        ext = _ext(name)
        stem_ext = _ext(name.rsplit(".", 1)[0]) if ext else ""
        if ext in EXEC_EXT and stem_ext in DOC_EXT:
            dbl.append(name)
        if zi.flag_bits & 0x1:
            encrypted.append(name)
        if ext in ARCHIVE_EXT:
            nested.append(name)
        if ext in EXEC_EXT:
            execs.append(name)
        # look at the real bytes of the first entries: a program keeps its MZ/ELF header whatever it is named
        if idx < MAX_ENTRIES_INSPECTED and not (zi.flag_bits & 0x1) and zi.file_size >= 64 and not budget.over():
            try:
                with zf.open(zi) as fh:
                    head = fh.read(HEAD_BYTES)
                if is_pe(head) and ext not in EXEC_EXT:
                    disguised.append(name)
                elif is_pe(head) and name not in execs:
                    execs.append(name)
            except Exception:  # noqa: BLE001 - unreadable entry: skip, never fail the scan
                continue

    if traversal:
        out.add("path_traversal", "Entry names escape the extraction folder", "high", True,
                "An entry is named with ../ or an absolute path. Extracting it can overwrite files outside "
                "the chosen folder (the 'zip slip' attack).", [printable(x) for x in traversal[:4]])
    if rtlo:
        out.add("rtlo_name", "File name uses a right-to-left override character", "high", True,
                "Invisible direction-control characters make 'exe.pdf' look like 'fdp.exe' or the reverse. "
                "Legitimate files do not need them.", [printable(x) for x in rtlo[:4]])
    if dbl:
        out.add("double_extension", "Program disguised with a document extension", "high", True,
                "A program is named like a document (for example invoice.pdf.exe), a common phishing trick.",
                [printable(x) for x in dbl[:4]])
    if disguised:
        out.add("disguised_executable", "Program hidden under a non-program name", "high", True,
                "The content of an entry starts like a Windows/Linux program (MZ/PE or ELF) although its "
                "name does not say so.", [printable(x) for x in disguised[:4]])
    if execs:
        if strict:
            out.add("embedded_executable", "Embedded executable file", "high", True,
                    "A program or script is stored inside an Office document. Office files never need one.",
                    [printable(x) for x in execs[:4]])
        else:
            out.add("executable_in_archive", "Archive contains programs or scripts", "medium", False,
                    "The archive holds executable or script files. This is normal for installers and "
                    "software bundles, and also how malware is delivered, so open it with care.",
                    [printable(x) for x in execs[:4]])
    if encrypted:
        out.add("encrypted_entries", "Password-protected entries", "medium", False,
                "Some entries are encrypted, so no scanner (including VirusTotal) can look inside them.",
                [printable(x) for x in encrypted[:4]])
    if dup:
        out.add("duplicate_entries", "Duplicate entry names", "medium", False,
                "Two entries share one name. Different tools may read different ones, which is used to show a "
                "harmless file to a scanner and a harmful one to the user.", [printable(x) for x in dup[:4]])
    if nested:
        out.add("nested_archive", "Archive inside the archive", "low", False,
                "Nested archives make files harder to scan.", [printable(x) for x in nested[:4]])
    info["inspected"] = min(n, MAX_ENTRIES_INSPECTED)
    return info
