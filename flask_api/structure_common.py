"""
structure_common.py — shared pieces of the structure analyzers (office_structure, archive_structure,
file_structure). Same finding shape as evasion_indicators.py, so the verdict engine and the report page
treat PDFs, Office files and archives the same way.
"""

import time

TIME_BUDGET_S = 3.0

EXEC_EXT = {".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".ps1", ".jar",
            ".lnk", ".hta", ".msi", ".dll", ".com", ".cpl", ".reg", ".pif"}
# extensions people trust, which attackers put in front of a real one: invoice.pdf.exe
DOC_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv", ".jpg", ".jpeg",
           ".png", ".gif", ".rtf", ".zip", ".mp3", ".mp4"}


def printable(b, limit=80):
    if isinstance(b, bytes):
        b = b[:limit].decode("latin-1", "replace")
    else:
        b = str(b)[:limit]
    return "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in b)


def is_pe(head: bytes) -> bool:
    """Windows program (MZ header with a PE signature near the start) or Linux ELF."""
    return (head[:2] == b"MZ" and b"PE\x00\x00" in head[:1024]) or head[:4] == b"\x7fELF"


class Collector:
    def __init__(self):
        self.items = {}

    def add(self, fid, title, severity, strong, detail, evidence=None):
        cur = self.items.get(fid)
        if cur:
            for e in evidence or []:
                if e not in cur["evidence"] and len(cur["evidence"]) < 6:
                    cur["evidence"].append(e)
            cur["strong"] = cur["strong"] or strong
            return
        self.items[fid] = {"id": fid, "title": title, "severity": severity, "strong": bool(strong),
                           "detail": detail, "evidence": list((evidence or [])[:6])}

    def result(self, scanned=None, error=None):
        items = list(self.items.values())
        order = {"high": 0, "medium": 1, "low": 2}
        items.sort(key=lambda f: (not f["strong"], order.get(f["severity"], 3)))
        base = {"streams": 0, "inflated_bytes": 0, "truncated": False, "ms": 0}
        base.update(scanned or {})
        return {"findings": items, "strong_ids": [f["id"] for f in items if f["strong"]],
                "error": error, "scanned": base}


class Budget:
    def __init__(self, seconds=TIME_BUDGET_S):
        self.t0 = time.time()
        self.seconds = seconds

    def over(self):
        return (time.time() - self.t0) > self.seconds

    def ms(self):
        return int((time.time() - self.t0) * 1000)
