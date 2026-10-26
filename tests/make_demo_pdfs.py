"""
make_demo_pdfs.py - writes harmless PDFs for the live demo (standard library only).

    python C:\\xampp\\htdocs\\cloudie\\tests\\make_demo_pdfs.py C:\\Users\\<you>\\Desktop\\cloudie-demo

Files written
  1_clean.pdf                  plain one-page PDF                        -> CLEAN (AI shows "uncertain", no risk keyword)
  2_visible_script.pdf         clear-text /OpenAction + /JavaScript      -> AI + risk keywords; the final verdict depends on VirusTotal
  3_hidden_script.pdf          the same script with hex-escaped names    -> evasion layer finds the hidden keywords;
                               (/J#61vaScr#69pt ...), which the AI cannot see     the final verdict depends on VirusTotal

Live results on 2026-10-22: file 2 was flagged by 1 VirusTotal engine (now SUSPICIOUS: blocking needs 2 engines),
file 3 by 12 engines (MALICIOUS, blocked). VirusTotal engines react to these test scripts differently over time, so
check the result of every file a day before the demo and write down what you see (docs/DEMO_RUNBOOK.md).

The only script is app.alert('Cloudie demo'): it shows a message box and does nothing else.
With VirusTotal configured the results above assume VirusTotal does not flag these tiny files; try them once
before the demo. (EICAR, the standard antivirus test file, is deliberately not generated here: your antivirus
will quarantine it. Download it from eicar.org into a folder excluded from scanning.)
"""

import os
import sys

HEAD = b"%PDF-1.3\n"
TAIL = b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"

PAGES = (b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
         b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] /Contents 6 0 R >>\nendobj\n"
         b"6 0 obj\n<< /Length 44 >>\nstream\nBT /F1 14 Tf 20 100 Td (Cloudie demo) Tj ET\nendstream\nendobj\n")


def clean() -> bytes:
    return HEAD + b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" + PAGES + TAIL


def script(open_action: str, js_type: str, js_key: str) -> bytes:
    return (HEAD
            + ("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /%s 4 0 R >>\nendobj\n" % open_action).encode()
            + PAGES
            + ("4 0 obj\n<< /S /%s /%s (app.alert\\('Cloudie demo'\\);) >>\nendobj\n" % (js_type, js_key)).encode()
            + TAIL)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "cloudie-demo"
    os.makedirs(out, exist_ok=True)
    files = {
        "1_clean.pdf": clean(),
        "2_visible_script.pdf": script("OpenAction", "JavaScript", "JS"),
        "3_hidden_script.pdf": script("Open#41ction", "J#61vaScr#69pt", "J#53"),
    }
    for name, data in files.items():
        with open(os.path.join(out, name), "wb") as fh:
            fh.write(data)
        print("wrote", os.path.join(out, name), len(data), "bytes")


if __name__ == "__main__":
    main()
