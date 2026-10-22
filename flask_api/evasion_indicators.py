"""
evasion_indicators.py — deterministic, explainable PDF evasion findings.

The Random Forest counts keywords such as /JavaScript and /OpenAction. Malware that hides those
keywords (hex-escaped names like /J#61vaScript, scripts inside compressed streams, payloads appended
after %%EOF) looks harmless to it. This module looks for exactly those tricks with plain, readable
rules. It does NOT change the 32-feature vector the model sees; its output is a list of findings
shown in the report, and the "strong" ones can tag a file as suspicious (see verdict_engine.py).

Design rules
  * never raises: any error gives an empty result with `error` set
  * bounded: file size, number of streams, decompressed bytes and wall-clock time are capped
    (a decompression bomb or a huge file cannot stall the scanner)
  * conservative: "strong" findings are rare in legitimate PDFs; the others are informational
  * the file is only READ as bytes; nothing in it is ever executed
"""

import math
import re
import time
import zlib

MAX_BYTES = 30 * 1024 * 1024            # larger files are analysed on their first 30 MB only
TIME_BUDGET_S = 3.0
MAX_STREAMS = 1500
MAX_INFLATE_PER_STREAM = 512 * 1024      # scripts and object streams are small; big streams are images/fonts
MAX_INFLATE_TOTAL = 8 * 1024 * 1024

# Names whose letters are almost never hex-escaped in legitimate files
RISKY_NAMES = {
    "JavaScript", "JS", "OpenAction", "AA", "Launch", "EmbeddedFile", "RichMedia", "XFA",
    "AcroForm", "SubmitForm", "GoToR", "GoToE", "ImportData", "URI",
}
FILTER_NAMES = {
    "FlateDecode", "ASCIIHexDecode", "ASCII85Decode", "LZWDecode", "RunLengthDecode",
    "DCTDecode", "JBIG2Decode", "JPXDecode", "CCITTFaxDecode", "Crypt",
}

_NAME_WITH_HASH = re.compile(rb"/([^\s\x00()<>\[\]{}/%]*#[0-9A-Fa-f]{2}[^\s\x00()<>\[\]{}/%]*)")
_HEXESC = re.compile(rb"#([0-9A-Fa-f]{2})")
_STREAM = re.compile(rb"(?<!end)stream(?:\r\n|\n|\r)")
_JS_ACTION = re.compile(rb"/(?:JS|JavaScript)(?![A-Za-z])")
# streams that can only hold pictures, fonts, colour profiles or bookkeeping: never worth decoding
_SKIP_DICT = re.compile(rb"/Subtype\s*/(?:Image|Type1C|CIDFontType0C|OpenType)|/Length[123]|"
                        rb"/Type\s*/(?:XRef|Metadata)|/FontFile|/ColorSpace|/BitsPerComponent")
# cheap pre-filter: only run the 13 script regexes when one of these tokens is present at all
_JS_HINT = re.compile(rb"eval|unescape|Collab|newPlayer|spell\.|printf|getAnnots|exportDataObject|"
                      rb"launchURL|fromCharCode|%u[0-9a-fA-F]{4}|x90|u9090")
_URI = re.compile(rb"/URI\s*\(([^)]{1,300})\)")
_URI_HOST = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://([^/:?#\s]+)")
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_FILTER_ARRAY = re.compile(rb"/Filter\s*\[([^\]]{1,240})\]")
_SHELL = re.compile(rb"(?i)(cmd\.exe|powershell|wscript|cscript|mshta|rundll32|regsvr32|/bin/(?:ba)?sh)")
_EXEC_NAME = re.compile(rb"(?i)\(([^()\\]{1,80}\.(?:exe|scr|bat|cmd|vbs|js|jse|wsf|ps1|jar|lnk|hta|msi|dll))\)")

SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly"}

# (regex, label, level) level: "high" = classic exploit/shellcode technique, "medium", "low"
_JS_PATTERNS = [
    (re.compile(rb"eval\s*\(\s*unescape\s*\("), "eval(unescape(...))", "high"),
    (re.compile(rb"(?:%u[0-9a-fA-F]{4}){40,}"), "long %u-encoded string (shellcode style)", "high"),
    (re.compile(rb"(?:%u9090){2,}|(?:\\x90){8,}|(?:\\u9090){2,}"), "NOP sled", "high"),
    (re.compile(rb"Collab\.(?:collectEmailInfo|getIcon)\s*\("), "Collab.* exploit API", "high"),
    (re.compile(rb"media\.newPlayer\s*\("), "media.newPlayer exploit API", "high"),
    (re.compile(rb"spell\.customDictionaryOpen\s*\("), "spell.customDictionaryOpen exploit API", "high"),
    (re.compile(rb"util\.printf\s*\("), "util.printf", "medium"),
    (re.compile(rb"getAnnots\s*\("), "getAnnots", "medium"),
    (re.compile(rb"this\.exportDataObject\s*\("), "exportDataObject", "medium"),
    (re.compile(rb"app\.launchURL\s*\("), "app.launchURL", "medium"),
    (re.compile(rb"String\.fromCharCode\s*\("), "String.fromCharCode", "low"),
    (re.compile(rb"\beval\s*\("), "eval()", "low"),
    (re.compile(rb"\bunescape\s*\("), "unescape()", "low"),
]


def _decode_name(raw: bytes) -> str:
    return _HEXESC.sub(lambda m: bytes([int(m.group(1), 16)]), raw).decode("latin-1")


def _printable(b: bytes, limit: int = 60) -> str:
    s = b[:limit].decode("latin-1", "replace")
    return "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in s)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def _empty(error=None, ms=0):
    return {"findings": [], "strong_ids": [], "error": error,
            "scanned": {"streams": 0, "inflated_bytes": 0, "truncated": False, "ms": ms}}


class _Collector:
    def __init__(self):
        self.items = {}

    def add(self, fid, title, severity, strong, detail, evidence=None):
        cur = self.items.get(fid)
        if cur:
            # merge evidence of the same finding found in several places
            for e in evidence or []:
                if e not in cur["evidence"] and len(cur["evidence"]) < 6:
                    cur["evidence"].append(e)
            cur["strong"] = cur["strong"] or strong
            return
        self.items[fid] = {"id": fid, "title": title, "severity": severity, "strong": bool(strong),
                           "detail": detail, "evidence": list((evidence or [])[:6])}


def analyze(path: str) -> dict:
    """Analyse a PDF on disk. Returns {'findings': [...], 'strong_ids': [...], 'scanned': {...}, 'error': ...}."""
    t0 = time.time()
    try:
        with open(path, "rb") as fh:
            blob = fh.read(MAX_BYTES + 1)
        return analyze_bytes(blob, t0=t0)
    except Exception as exc:  # noqa: BLE001 - this layer must never break a scan
        return _empty(f"{type(exc).__name__}: {exc}", int((time.time() - t0) * 1000))


def analyze_bytes(blob: bytes, t0=None) -> dict:
    t0 = t0 or time.time()
    try:
        return _analyze(blob, t0)
    except Exception as exc:  # noqa: BLE001
        return _empty(f"{type(exc).__name__}: {exc}", int((time.time() - t0) * 1000))


def _analyze(blob: bytes, t0: float) -> dict:
    truncated = len(blob) > MAX_BYTES
    if truncated:
        blob = blob[:MAX_BYTES]
    out = _Collector()
    over_budget = lambda: (time.time() - t0) > TIME_BUDGET_S  # noqa: E731

    # ---- 1) walk the streams once: inflate what we may, keep pieces for the pattern scans ----------
    pieces = [("file", blob)]          # (kind, bytes): the raw file plus decoded streams
    stream_count = 0
    inflated_total = 0
    encrypted = b"/Encrypt" in blob
    for m in _STREAM.finditer(blob):
        if stream_count >= MAX_STREAMS or over_budget():
            truncated = True
            break
        start = m.end()
        end = blob.find(b"endstream", start)
        if end < 0:
            end = min(len(blob), start + MAX_INFLATE_PER_STREAM)
        data = blob[start:end].rstrip(b"\r\n")
        stream_count += 1
        head = blob[max(0, m.start() - 400):m.start()]
        dict_seg = head[head.rfind(b"obj") + 3:] if b"obj" in head else head
        has_filter = b"/Filter" in dict_seg or b"/F#" in dict_seg

        # executable magic in the raw stream (embedded file payloads)
        if data[:2] == b"MZ" and b"PE\x00\x00" in data[:4096] or data[:4] == b"\x7fELF":
            out.add("embedded_executable", "Embedded executable file", "high", True,
                    "A stream inside the PDF starts like a Windows or Linux program (MZ/PE or ELF).",
                    ["stream header: " + _printable(data[:4])])

        # unfiltered but random-looking content (packed or encrypted payload)
        if (not encrypted and not has_filter and len(data) > 512 and b"/Image" not in dict_seg
                and _entropy(data[:16384]) > 7.3):
            out.add("random_stream", "Unfiltered stream with random-looking content", "medium", False,
                    "A stream declares no compression yet its bytes look random, which can hide a packed "
                    "or encrypted payload.", ["%d bytes, entropy > 7.3" % len(data)])

        if (b"FlateDecode" in dict_seg or b"/Fl" in dict_seg) and not _SKIP_DICT.search(dict_seg):
            if inflated_total >= MAX_INFLATE_TOTAL:
                truncated = True
                continue
            try:
                d = zlib.decompressobj()
                dec = d.decompress(data, MAX_INFLATE_PER_STREAM)
                if d.unconsumed_tail:
                    truncated = True
                inflated_total += len(dec)
                if dec:
                    pieces.append(("stream", dec))
                    if (dec[:2] == b"MZ" and b"PE\x00\x00" in dec[:4096]) or dec[:4] == b"\x7fELF":
                        out.add("embedded_executable", "Embedded executable file", "high", True,
                                "A decompressed stream starts like a Windows or Linux program.",
                                ["decoded header: " + _printable(dec[:4])])
            except Exception:  # corrupt or non-zlib data: skip it
                continue

    # ---- 2) hex-escaped names (the classic evasion) ------------------------------------------------
    hidden_js = False
    for kind, data in pieces:
        if over_budget():
            truncated = True
            break
        hidden, filt = [], []
        if b"#" not in data:
            continue                       # a hex-escaped name needs a '#'
        for m in _NAME_WITH_HASH.finditer(data):
            raw = m.group(1)
            dec = _decode_name(raw)
            if dec in RISKY_NAMES:
                hidden.append(("/" + _printable(raw, 40), dec))
            elif dec in FILTER_NAMES:
                filt.append("/" + _printable(raw, 40))
            if len(hidden) >= 6 and len(filt) >= 6:
                break
        if hidden:
            out.add("obfuscated_keywords", "Hidden keywords (hex-escaped names)", "high", True,
                    "Names such as /J#61vaScript are the same as /JavaScript but evade keyword counters. "
                    "Legitimate files do not hex-escape these letters.",
                    ["%s means /%s" % (r, d) for r, d in hidden])
            if any(d in ("JavaScript", "JS", "OpenAction", "AA", "Launch") for _, d in hidden):
                hidden_js = True
        if filt:
            out.add("obfuscated_filters", "Hidden stream filter names", "medium", False,
                    "A compression/encoding filter name is hex-escaped, a known trick to confuse scanners.",
                    filt[:6])

    # ---- 3) is there a JavaScript action at all? (clear text, decoded streams, or hidden) ---------
    js_action = hidden_js or any(_JS_ACTION.search(d) for _, d in pieces)

    # ---- 4) script techniques inside the file and its decoded streams -----------------------------
    found = {}
    for kind, data in pieces:
        if over_budget():
            truncated = True
            break
        # skip page-content streams (text drawn on the page), they can quote any words
        if kind == "stream" and b"BT" in data and (b"Tj" in data or b"TJ" in data):
            continue
        if not _JS_HINT.search(data):
            continue
        for rx, label, level in _JS_PATTERNS:
            if label in found and found[label][1] == level:
                continue
            if rx.search(data):
                found[label] = (label, level)
    high = [l for l, lv in found.values() if lv == "high"]
    medium = [l for l, lv in found.values() if lv == "medium"]
    low = [l for l, lv in found.values() if lv == "low"]
    combo = ("eval()" in low or "eval(unescape(...))" in high) and (
        "unescape()" in low or "String.fromCharCode" in low or "eval(unescape(...))" in high)
    if high and js_action:
        out.add("js_exploit_techniques", "Exploit or shellcode techniques in script", "high", True,
                "The script uses techniques typical of PDF exploits.", high[:6])
    elif high:
        out.add("js_pattern_no_action", "Script-like exploit text without a script action", "low", False,
                "Exploit-style text was found but no JavaScript action refers to it.", high[:6])
    if js_action and (medium or combo) and not high:
        out.add("js_risky_api", "Risky script functions", "medium", False,
                "The script calls functions that are common in exploits but also appear in some forms.",
                (medium + (["eval + string decoding"] if combo else []))[:6])

    # ---- 5) launch / shell, remote actions, links, filter chains ----------------------------------
    for m in re.finditer(rb"/Launch", blob):
        window = blob[m.start():m.start() + 600]
        s = _SHELL.search(window)
        if s:
            out.add("launch_shell", "Launch action that starts a shell or script host", "high", True,
                    "A /Launch action refers to a command interpreter or script host.",
                    ["/Launch ... " + _printable(s.group(1), 30)])
            break
    remote = [n.decode() for n in (b"/SubmitForm", b"/GoToR", b"/GoToE", b"/ImportData") if n in blob]
    if remote:
        out.add("remote_actions", "Actions that contact or open external resources", "medium", False,
                "These actions can send data out or open remote files.", remote)
    ips, shorts = [], []
    for m in _URI.finditer(blob):
        hm = _URI_HOST.match(m.group(1).decode("latin-1"))
        if not hm:
            continue
        host = hm.group(1).lower()
        if _IPV4.match(host):
            ips.append(host)
        elif host in SHORTENERS:
            shorts.append(host)
        if len(ips) >= 5 and len(shorts) >= 5:
            break
    if ips:
        out.add("uri_ip", "Link to a raw IP address", "medium", False,
                "Links that point to an IP address instead of a domain are common in malicious documents.",
                sorted(set(ips))[:6])
    if shorts:
        out.add("uri_shortener", "Link through a URL shortener", "low", False,
                "Shortened links hide the real destination.", sorted(set(shorts))[:6])
    for m in _FILTER_ARRAY.finditer(blob):
        if len(re.findall(rb"/[A-Za-z0-9#]+", m.group(1))) >= 3:
            out.add("filter_chain", "Stream with three or more chained filters", "medium", False,
                    "Chaining several encodings is a way to hide content from scanners.",
                    [_printable(m.group(0), 70)])
            break
    en = [_printable(m.group(1), 50) for m in _EXEC_NAME.finditer(blob)][:4]
    if en and b"/EmbeddedFile" in blob:
        out.add("executable_filename", "Embedded file with an executable-looking name", "medium", False,
                "A file attachment is named like a program or script.", en)

    # ---- 6) structure tricks ----------------------------------------------------------------------
    eof = blob.rfind(b"%%EOF")
    if eof >= 0:
        tail = blob[eof + 5:].strip()
        if len(tail) > 1024:
            out.add("appended_data", "Data appended after the end of the PDF", "medium", False,
                    "%d bytes follow the final %%EOF marker, a place where payloads are hidden." % len(tail),
                    ["%d bytes after %%EOF" % len(tail)])
    hdr = blob.find(b"%PDF-", 0, 1024)
    if hdr > 0:
        out.add("bytes_before_header", "Bytes before the PDF header", "low", False,
                "%d bytes precede the %%PDF- header; readers tolerate this and some malware relies on it." % hdr,
                ["%d bytes" % hdr])
    if b"This program cannot be run in DOS mode" in blob or any(
            b"This program cannot be run in DOS mode" in d for k, d in pieces[1:]):
        out.add("embedded_executable", "Embedded executable file", "high", True,
                "The text of a Windows program header was found inside the PDF.",
                ["'This program cannot be run in DOS mode'"])

    findings = sorted(out.items.values(), key=lambda f: ({"high": 0, "medium": 1, "low": 2}[f["severity"]], f["id"]))
    return {
        "findings": findings,
        "strong_ids": [f["id"] for f in findings if f["strong"]],
        "error": None,
        "scanned": {"streams": stream_count, "inflated_bytes": inflated_total, "truncated": truncated,
                    "ms": int((time.time() - t0) * 1000)},
    }
