"""
office_structure.py — structure checks for Office Open XML files (.docx / .xlsx / .pptx).

An OOXML file is a ZIP of XML parts. Malware hides in a few well-known places, none of which needs a
signature to spot:
  * a VBA macro project in a file type that cannot legitimately hold one (macros are only allowed in
    .docm/.xlsm/.pptm, so a "docx" with vbaProject.bin was renamed to avoid scrutiny)
  * Excel 4.0 macro sheets (xl/macrosheets) and "very hidden" sheets
  * DDE fields / formulas that start a program when the document is opened
  * remote template injection and remote OLE objects (the document fetches code from a URL)
  * embedded programs, OLE objects and ActiveX controls
The parts are read with small bounded reads and matched with plain regular expressions (no XML parser,
so XML bombs and external entities cannot hurt); nothing is executed or extracted to disk.
"""

import re
import zipfile

from structure_common import Collector, Budget, EXEC_EXT, is_pe, printable
from archive_structure import analyze_zip

PART_LIMIT = 4 * 1024 * 1024          # a part is never read beyond 4 MB
RELS_LIMIT = 256 * 1024
MAX_RELS = 80
MAX_SHEETS = 8

MACRO_EXT = {"docm", "dotm", "xlsm", "xltm", "xlsb", "xlam", "pptm", "potm", "ppam", "ppsm"}
AUTOEXEC = ("AutoOpen", "Auto_Open", "AutoExec", "AutoNew", "Document_Open", "Document_New",
            "Workbook_Open", "Workbook_Activate", "Auto_Close", "Presentation_Open")
RISKY_CALLS = ("CreateObject", "WScript.Shell", "Wscript.Shell", "Shell(", "URLDownloadToFile", "powershell",
               "cmd.exe", "MSXML2.XMLHTTP", "ADODB.Stream", "Environ(")

_REL = re.compile(rb"<Relationship\b([^>]*)>", re.I)
_ATTR = re.compile(rb'(\w+)\s*=\s*"([^"]*)"')
_INSTR = re.compile(rb"<w:instrText[^>]*>([^<]*)</w:instrText>|w:instr=\"([^\"]*)\"", re.I)
_DDE_FIELD = re.compile(r"(?i)\bDDE(?:AUTO)?\b\s+\S")
_DDE_FORMULA = re.compile(rb"<f[^>]*>\s*(?:cmd|powershell|mshta|msiexec|cscript|wscript|rundll32|regsvr32)\s*\|", re.I)
_VERYHIDDEN = re.compile(rb'<sheet\b[^>]*state="veryHidden"', re.I)


def _read(zf, name, limit=PART_LIMIT):
    try:
        with zf.open(name) as fh:
            return fh.read(limit)
    except Exception:  # noqa: BLE001 - missing/corrupt/encrypted part
        return b""


def _kind(names):
    for prefix, label in (("word/", "word"), ("xl/", "excel"), ("ppt/", "powerpoint")):
        if any(n.startswith(prefix) for n in names):
            return label
    return None


def is_ooxml(names) -> bool:
    return "[Content_Types].xml" in names and _kind(names) is not None


def _rels(blob: bytes):
    for m in _REL.finditer(blob):
        attrs = {k.lower().decode("latin-1"): v.decode("utf-8", "replace") for k, v in _ATTR.findall(m.group(1))}
        yield attrs


def analyze_ooxml(zf: "zipfile.ZipFile", ext: str, out: Collector, budget: Budget) -> dict:
    names = [i.filename for i in zf.infolist()]
    lower = [n.lower() for n in names]
    kind = _kind(names)
    info = {"office_kind": kind}

    # ---- the generic zip checks, in strict mode (a program inside an Office file is never normal) ----
    info.update(analyze_zip(zf, out, budget, strict=True))

    ctypes = _read(zf, "[Content_Types].xml", 256 * 1024)
    macro_ext = ext.lstrip(".").lower() in MACRO_EXT

    # ---- 1) VBA macros ------------------------------------------------------------------------------
    vba = [n for n in names if re.search(r"(^|/)vbaProject\.bin$", n, re.I)]
    macro_ct = b"macroEnabled" in ctypes or b"vbaProject" in ctypes
    if vba or macro_ct:
        if macro_ext:
            out.add("office_macro", "Contains VBA macros", "medium", False,
                    "The document carries a macro project. Macros are how most Office malware runs, so only "
                    "enable them if you trust the sender.", [printable(x) for x in vba[:3]])
        else:
            out.add("macro_in_macrofree_type", "Macro project inside a macro-free file type", "high", True,
                    "Word, Excel and PowerPoint do not run macros from .%s files, so a VBA project here means the "
                    "file was renamed to look harmless and slip past filters."
                    % (ext.lstrip(".") or "docx"), [printable(x) for x in vba[:3]] or ["macro content type declared"])
        for n in vba[:2]:
            blob = _read(zf, n, 2 * 1024 * 1024)
            auto = [a for a in AUTOEXEC if a.encode() in blob]
            calls = [c for c in RISKY_CALLS if c.lower().encode() in blob.lower()]
            if auto:
                out.add("macro_autoexec", "Macro runs automatically on open", "high", True,
                        "The macro project names an auto-run entry point (%s), so it starts without the user "
                        "clicking anything." % ", ".join(auto[:3]), auto[:4])
            if calls:
                out.add("macro_risky_calls", "Macro uses system or network calls", "medium", False,
                        "The macro project mentions calls used to start programs or download files "
                        "(best-effort: VBA source is stored compressed, so this can miss some).", calls[:5])

    # ---- 2) Excel 4.0 macro sheets and very hidden sheets -------------------------------------------
    if any(n.startswith("xl/macrosheets/") for n in lower):
        out.add("xlm_macro_sheet", "Excel 4.0 (XLM) macro sheet", "high", True,
                "An old-style macro sheet is present. It is not allowed in .xlsx and is a favourite of "
                "malware because many scanners do not read it.", [n for n in names if n.lower().startswith("xl/macrosheets/")][:3])
    wb = _read(zf, "xl/workbook.xml", 512 * 1024) if kind == "excel" else b""
    if wb and _VERYHIDDEN.search(wb):
        out.add("very_hidden_sheet", "Very hidden worksheet", "medium", False,
                "A sheet is hidden so that it cannot be unhidden from the Excel menu. Used to store macros or "
                "payload data out of sight.", ["state=veryHidden"])

    # ---- 3) DDE: a field/formula that starts a program -----------------------------------------------
    if kind == "word" and not budget.over():
        parts = [n for n in names if re.match(r"word/(document|header\d*|footer\d*|footnotes|endnotes)\.xml$", n)][:8]
        for n in parts:
            xml = _read(zf, n)
            text = " ".join((a or b).decode("utf-8", "replace") for a, b in _INSTR.findall(xml))[:200000]
            m = _DDE_FIELD.search(text)
            if m:
                s = max(0, m.start() - 5)
                out.add("dde_field", "DDE field that starts a program", "high", True,
                        "The document contains a DDE/DDEAUTO field. It can launch a command when the file is "
                        "opened, without any macro.", [printable(text[s:s + 70])])
                break
    if kind == "excel" and not budget.over():
        for n in [x for x in names if re.match(r"xl/worksheets/sheet\d+\.xml$", x)][:MAX_SHEETS]:
            m = _DDE_FORMULA.search(_read(zf, n))
            if m:
                out.add("dde_formula", "Spreadsheet formula that starts a program", "high", True,
                        "A cell formula calls a command interpreter through DDE (for example cmd|'/c ...').",
                        [printable(m.group(0))])
                break

    # ---- 4) relationships that pull things from outside ----------------------------------------------
    rel_parts = [n for n in names if n.endswith(".rels")][:MAX_RELS]
    for n in rel_parts:
        if budget.over():
            break
        for a in _rels(_read(zf, n, RELS_LIMIT)):
            if (a.get("targetmode") or "").lower() != "external":
                continue
            rtype = (a.get("type") or "").rsplit("/", 1)[-1].lower()
            target = a.get("target") or ""
            remote = bool(re.match(r"(?i)(https?|ftp)://|\\\\", target))
            if rtype == "attachedtemplate" and remote:
                out.add("remote_template", "Document loads a template from a remote address", "high", True,
                        "The document is set to download its template from another server. This is the "
                        "'template injection' technique: the file looks clean and the harmful part arrives later.",
                        [printable(target)])
            elif rtype in ("oleobject", "frame", "subdocument", "package") and remote:
                out.add("remote_object", "Document embeds an object from a remote address", "high", True,
                        "An OLE object, frame or sub-document is fetched from a remote server when the file "
                        "opens (the pattern behind well-known Office exploits).", [printable(target)])
            elif re.match(r"(?i)\\\\|file:", target) and rtype != "hyperlink":
                out.add("unc_reference", "Reference to a network share or local file", "medium", False,
                        "Opening the file makes Office reach out to a share (\\\\host\\...) which can leak the "
                        "user's Windows credentials.", [printable(target)])

    # ---- 5) embedded objects and ActiveX --------------------------------------------------------------
    emb = [n for n in names if re.search(r"(^|/)embeddings/[^/]+$", n, re.I)]
    for n in emb[:20]:
        head = _read(zf, n, 1024)
        if is_pe(head) or re.search(r"\.[A-Za-z0-9]{2,4}$", n) and ("." + n.rsplit(".", 1)[1].lower()) in EXEC_EXT:
            out.add("embedded_executable", "Embedded executable file", "high", True,
                    "A program is embedded as an object in the document.", [printable(n)])
    if emb:
        out.add("embedded_objects", "Embedded OLE objects", "low", False,
                "The document carries embedded objects (%d)." % len(emb), [printable(x) for x in emb[:3]])
    if any(n.lower().startswith(("word/activex/", "xl/activex/", "ppt/activex/")) for n in names):
        out.add("activex_controls", "ActiveX controls", "medium", False,
                "ActiveX controls can run code and are rarely needed in ordinary documents.", ["activeX/"])

    # ---- 6) the file says one thing and contains another --------------------------------------------
    want = {"docx": "word", "dotx": "word", "xlsx": "excel", "xltx": "excel", "pptx": "powerpoint", "potx": "powerpoint"}.get(ext.lstrip(".").lower())
    if want and kind and want != kind:
        out.add("ooxml_type_mismatch", "Extension does not match the document type", "medium", False,
                "The name says .%s but the parts inside belong to a %s document." % (ext.lstrip("."), kind),
                ["inside: %s parts" % kind])
    return info
