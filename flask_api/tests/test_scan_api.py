"""/scan end to end with VirusTotal mocked (no network, no API key needed)."""

import io
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

    def test_vt_hit_blocks_even_a_plain_pdf(self):
        j = self.scan(helpers.PDF_PLAIN, "a.pdf", vt_report(malicious=12, suspicious=1))
        self.assertEqual(j["verdict"], "malicious")
        self.assertFalse(j["is_clean"])

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
