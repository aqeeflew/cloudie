"""/scan end to end with VirusTotal mocked (no network, no API key needed)."""

import io
import os
import unittest

import helpers
import requests

import app as A
import vt_client


def vt_report(malicious=0, suspicious=0, total=70):
    return {"available": True, "total": total, "malicious": malicious, "suspicious": suspicious}


class ScanApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._key, cls._scan = A.VT_API_KEY, vt_client.scan_file
        A.VT_API_KEY = "test-key"           # makes vt_scan() call the (mocked) client
        cls.client = A.app.test_client()

    @classmethod
    def tearDownClass(cls):
        A.VT_API_KEY, vt_client.scan_file = cls._key, cls._scan

    def scan(self, data, name, vt=None, vt_error=None):
        def fake(path, orig, api_key=None):
            if vt_error:
                raise vt_error
            return vt
        vt_client.scan_file = fake
        r = self.client.post("/scan", data={"file": (io.BytesIO(data), name)},
                             content_type="multipart/form-data")
        self.assertEqual(r.status_code, 200)
        return r.get_json()

    def test_plain_pdf_with_vt_clean_is_clean(self):
        j = self.scan(helpers.PDF_PLAIN + b"\n" * 5, "a.pdf", vt_report())
        self.assertEqual(j["verdict"], "clean")
        self.assertTrue(j["is_pdf"])
        self.assertEqual(len(j["features"]), 32)
        self.assertEqual(j["primary_detector"], "VT")

    def test_js_pdf_with_vt_clean_is_suspicious_and_explained(self):
        j = self.scan(helpers.PDF_JS, "js.pdf", vt_report())
        self.assertEqual(j["verdict"], "suspicious")
        self.assertEqual(j["ai"]["verdict"], "malicious")
        self.assertTrue(j["explanation"]["gate"]["tagged"])
        self.assertIn("JS", j["explanation"]["gate"]["risk_indicators"])

    HIDDEN_JS = (b"%PDF-1.3\n1 0 obj\n<< /Type /Catalog /Open#41ction 4 0 R >>\nendobj\n"
                 b"4 0 obj\n<< /S /J#61vaScr#69pt /J#53 (app.alert\\('Cloudie test'\\);) >>\nendobj\n"
                 b"trailer\n<< /Root 1 0 R >>\n%%EOF\n")

    def test_hidden_script_is_tagged_suspicious_by_the_evasion_layer(self):
        j = self.scan(self.HIDDEN_JS, "hidden.pdf", vt_report())
        self.assertEqual(j["verdict"], "suspicious")
        self.assertIn("obfuscated_keywords", j["evasion"]["strong"])
        self.assertEqual([f["id"] for f in j["findings"] if f["strong"]], ["obfuscated_keywords"])
        self.assertTrue(any("Evasion indicator" in i for i in j["indicators"]))
        # the 32-feature view of the model is untouched: the keywords are invisible to it
        self.assertEqual(j["features"]["Javascript"], 0)
        self.assertEqual(j["features"]["OpenAction"], 0)

    def test_hidden_script_is_still_blocked_when_virustotal_flags_it(self):
        self.assertEqual(self.scan(self.HIDDEN_JS, "hidden.pdf", vt_report(malicious=5))["verdict"], "malicious")

    def test_plain_pdf_has_empty_findings(self):
        j = self.scan(helpers.PDF_PLAIN, "a.pdf", vt_report())
        self.assertEqual(j["findings"], [])
        self.assertEqual(j["evasion"]["strong"], [])

    def test_non_pdf_runs_no_evasion_checks(self):
        j = self.scan(helpers.PNG_BYTES, "a.png", vt_report())
        self.assertEqual(j["findings"], [])

    @unittest.skipUnless(os.path.isdir(os.path.join(helpers.ROOT, "..", "docs")), "project docs folder not present")
    def test_real_world_pdfs_produce_no_strong_findings(self):
        docs = os.path.join(helpers.ROOT, "..", "docs")
        pdfs = [os.path.join(d, f) for d, _, fs in os.walk(docs) for f in fs if f.lower().endswith(".pdf")]
        if not pdfs:
            self.skipTest("no PDFs under docs/")
        import evasion_indicators as E
        for p in pdfs:
            r = E.analyze(p)
            self.assertEqual(r["strong_ids"], [], os.path.basename(p))

    def test_vt_hit_blocks_even_a_plain_pdf(self):
        j = self.scan(helpers.PDF_PLAIN, "a.pdf", vt_report(malicious=12, suspicious=1))
        self.assertEqual(j["verdict"], "malicious")
        self.assertFalse(j["is_clean"])

    def test_pdf_scan_reports_familiarity_without_changing_the_verdict(self):
        j = self.scan(helpers.PDF_PLAIN + b"\n" * 5, "a.pdf", vt_report())
        fam = j["ai"]["familiarity"]
        self.assertIn(fam["band"], ("familiar", "unusual", "unfamiliar"))
        self.assertEqual(j["explanation"]["familiarity"], fam)
        self.assertEqual(j["verdict"], "clean")                       # unchanged by familiarity
        js = self.scan(helpers.PDF_JS, "js.pdf", vt_report())
        self.assertEqual(js["verdict"], "suspicious")

    def test_non_pdf_has_no_familiarity(self):
        j = self.scan(helpers.PNG_BYTES, "a.png", vt_report())
        self.assertIsNone(j["ai"]["familiarity"])

    def test_a_single_vt_engine_is_suspicious_not_blocked(self):
        j = self.scan(helpers.PDF_PLAIN, "a.pdf", vt_report(malicious=1))
        self.assertEqual(j["verdict"], "suspicious")
        self.assertFalse(j["is_clean"])
        self.assertEqual(j["virustotal"]["verdict"], "suspicious")
        self.assertTrue(any("weak hit" in i for i in j["indicators"]))
        self.assertEqual(self.scan(helpers.PDF_PLAIN, "a.pdf", vt_report(malicious=2))["verdict"], "malicious")

    def test_vt_no_result_is_error_not_clean(self):
        for kind in (TimeoutError("slow"), requests.HTTPError("429 rate limit")):
            j = self.scan(helpers.PDF_PLAIN, "a.pdf", vt_error=kind)
            self.assertEqual(j["verdict"], "error")
            self.assertFalse(j["is_clean"])

    def test_vt_with_zero_engines_is_error_not_clean(self):
        j = self.scan(helpers.PDF_PLAIN, "a.pdf", vt_report(total=0))
        self.assertEqual(j["verdict"], "error")

    def test_non_pdf_skips_the_model_and_uses_virustotal_only(self):
        j = self.scan(helpers.PNG_BYTES, "a.png", vt_report())
        self.assertFalse(j["is_pdf"])
        self.assertEqual(j["verdict"], "clean")
        self.assertIsNone(j["ai"]["probability_malicious"])
        self.assertIsNone(j["explanation"])

    # ---- structure checks for Office files and archives (VT clean, structure decides) ----------------
    @staticmethod
    def _zip(entries):
        import zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for n, d in entries:
                zf.writestr(n, d)
        return buf.getvalue()

    def test_docx_with_a_hidden_macro_is_suspicious_when_vt_is_clean(self):
        ct = b"<Types><Override PartName='/word/vbaProject.bin' ContentType='application/vnd.ms-office.vbaProject'/></Types>"
        data = self._zip([("[Content_Types].xml", ct), ("word/document.xml", b"<w:document/>"),
                          ("word/vbaProject.bin", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1 Sub AutoOpen()")])
        j = self.scan(data, "invoice.docx", vt_report())
        self.assertEqual(j["verdict"], "suspicious")
        self.assertFalse(j["is_pdf"])
        self.assertEqual(j["file_type"], "ooxml")
        self.assertIn("macro_in_macrofree_type", j["evasion"]["strong"])
        self.assertTrue(any("Structure indicator" in i for i in j["indicators"]))
        self.assertIsNone(j["ai"]["probability_malicious"])          # the model stays PDF-only

    def test_the_same_docx_is_blocked_when_virustotal_flags_it(self):
        data = self._zip([("[Content_Types].xml", b"<Types>vbaProject</Types>"), ("word/document.xml", b"<w/>")])
        self.assertEqual(self.scan(data, "a.docx", vt_report(malicious=7))["verdict"], "malicious")

    def test_a_plain_zip_and_a_plain_docx_are_clean(self):
        z = self._zip([("notes.txt", b"hello"), ("a.pdf", helpers.PDF_PLAIN)])
        self.assertEqual(self.scan(z, "bundle.zip", vt_report())["verdict"], "clean")
        d = self._zip([("[Content_Types].xml", b"<Types/>"), ("word/document.xml", b"<w:document/>")])
        j = self.scan(d, "report.docx", vt_report())
        self.assertEqual(j["verdict"], "clean")
        self.assertEqual(j["findings"], [])

    def test_a_program_renamed_to_pdf_is_suspicious_even_though_virustotal_is_clean(self):
        pe = b"MZ" + b"\x90" * 62 + b"PE\x00\x00" + b"\x00" * 100
        j = self.scan(pe, "cv.pdf", vt_report())
        self.assertEqual(j["verdict"], "suspicious")
        self.assertIn("type_mismatch_executable", j["evasion"]["strong"])
        self.assertEqual(j["file_type"], "pe")

    def test_structure_findings_never_override_a_missing_virustotal_result(self):
        z = self._zip([("../evil.txt", b"x")])
        self.assertEqual(self.scan(z, "a.zip", vt_error=TimeoutError("x"))["verdict"], "error")

    def test_non_pdf_with_vt_no_result_is_error(self):
        j = self.scan(helpers.PNG_BYTES, "a.png", vt_error=TimeoutError("x"))
        self.assertEqual(j["verdict"], "error")

    def test_missing_file_field_is_a_400(self):
        r = self.client.post("/scan", data={}, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 400)

    def test_health_reports_the_model_contract(self):
        j = self.client.get("/health").get_json()
        self.assertTrue(j["model_loaded"])
        self.assertEqual(j["feature_count"], 32)
        self.assertEqual(j["model_expects"], 32)
        self.assertEqual(j["primary_detector"], "VT")


if __name__ == "__main__":
    unittest.main()
