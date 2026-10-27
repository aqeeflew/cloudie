"""
make_demo_files.py - writes harmless Office/ZIP files for the live demo (standard library only).

    python C:\\xampp\\htdocs\\cloudie\\tests\\make_demo_files.py C:\\Users\\<you>\\Desktop\\cloudie-demo

Files written                                          expected in Cloudie (when VirusTotal does not flag them)
  1_normal_report.docx       an ordinary Word document   -> CLEAN
  2_macro_in_docx.docx       a macro project inside .docx  -> SUSPICIOUS  "Macro project inside a macro-free file type"
  3_remote_template.docx     template fetched from a URL   -> SUSPICIOUS  "Document loads a template from a remote address"
  4_zip_slip.zip             entry named ../../...         -> SUSPICIOUS  "Entry names escape the extraction folder"
  5_double_extension.zip     invoice.pdf.exe inside        -> SUSPICIOUS  "Program disguised with a document extension"
  6_csv_formula.csv          a cell that calls a command   -> SUSPICIOUS  "Spreadsheet cell that starts a program"
  7_png_with_zip.png         a ZIP after the image's end   -> SUSPICIOUS  "Hidden file after the end of the image"

Everything is harmless: the CSV command only echoes text (do NOT open that file in Excel, it is for the scanner), the PNG is a
1x1 picture with a tiny text-only ZIP after it, the "macro project" is text, the template address uses the reserved .invalid domain
(it never resolves), the zip-slip entry is a text note, and the "exe" is a text file. These files are built
only to trigger Cloudie's structure checks; there is no malicious code in them. VirusTotal should not flag them,
which is the point of the demo: structure finds what a signature scan cannot. Upload each file once a few
minutes before the demo so VirusTotal knows its hash (free quota: about 4 requests per minute).
"""

import io
import os
import sys
import zipfile

CT = ('<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
      '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
      '<Default Extension="xml" ContentType="application/xml"/>'
      '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
      '%s</Types>')
ROOT_RELS = ('<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
             '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
             '</Relationships>')
DOC = ('<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
       '<w:body><w:p><w:r><w:t>Cloudie demo document</w:t></w:r></w:p></w:body></w:document>')
MACRO_CT = '<Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>'
SETTINGS_RELS = ('<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                 '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
                 'Target="http://template.example.invalid/demo.dotm" TargetMode="External"/></Relationships>')


def build(entries) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


def png_with_zip() -> bytes:
    import struct
    import zlib

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(b"\x00\x27\xd3\xe0")) + chunk(b"IEND", b""))
    return png + build([("note.txt", "Cloudie demo: a text file hidden after the end of the image")])


def docx(extra_ct="", extra=()):
    return build([("[Content_Types].xml", CT % extra_ct), ("_rels/.rels", ROOT_RELS), ("word/document.xml", DOC)] + list(extra))


FILES = {
    "1_normal_report.docx": lambda: docx(),
    # the "macro project" is plain text with an auto-run name: it cannot run anything
    "2_macro_in_docx.docx": lambda: docx(MACRO_CT, [("word/vbaProject.bin",
                                                       b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1 Cloudie demo text only. Sub AutoOpen()")]),
    "3_remote_template.docx": lambda: docx("", [("word/_rels/settings.xml.rels", SETTINGS_RELS),
                                                ("word/settings.xml", "<w:settings xmlns:w='http://schemas.openxmlformats.org/wordprocessingml/2006/main'/>")]),
    "4_zip_slip.zip": lambda: build([("readme.txt", "Cloudie demo"), ("../../cloudie-demo-note.txt", "harmless text")]),
    "5_double_extension.zip": lambda: build([("invoice.pdf.exe", "Cloudie demo: this is a text file, not a program")]),
    "6_csv_formula.csv": lambda: b"name,amount\nAnna,10\n=cmd|'/c echo Cloudie demo'!A1,5\n",
    "7_png_with_zip.png": png_with_zip,
}


def main(argv):
    out = argv[1] if len(argv) > 1 else os.path.join(os.getcwd(), "cloudie-demo")
    os.makedirs(out, exist_ok=True)
    for name, make in FILES.items():
        with open(os.path.join(out, name), "wb") as fh:
            fh.write(make())
        print("wrote", os.path.join(out, name))


if __name__ == "__main__":
    main(sys.argv)
