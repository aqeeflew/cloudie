"""/vt_lookup: hash-only re-check of a stored file (VirusTotal mocked, no network)."""

import time
import unittest

import helpers  # noqa: F401
import requests

import app as A
import vt_client
from verdict_engine import recheck_label

SHA = "a" * 64


def http_error(status):
    resp = requests.Response()
    resp.status_code = status
    return requests.HTTPError(str(status), response=resp)


class VtLookup(unittest.TestCase):
    def setUp(self):
        self._saved = (A.VT_API_KEY, vt_client.lookup_hash, vt_client.request_reanalysis)
        A.VT_API_KEY = "test-key"
        self.reanalysed = []

        def fake_reanalysis(file_hash, api_key=None):
            self.reanalysed.append(file_hash)
            return True
        vt_client.request_reanalysis = fake_reanalysis
        self.client = A.app.test_client()

    def tearDown(self):
        A.VT_API_KEY, vt_client.lookup_hash, vt_client.request_reanalysis = self._saved

    def ask(self, rep=None, error=None, file_hash=SHA):
        def fake(h, api_key=None):
            if error:
                raise error
            return rep
        vt_client.lookup_hash = fake
        return self.client.post("/vt_lookup", json={"hash": file_hash})

    def report(self, malicious=0, suspicious=0, total=70, age_days=0):
        return {"malicious": malicious, "suspicious": suspicious, "total": total,
                "last_seen": int(time.time() - age_days * 86400), "permalink": "https://vt/x"}

    def test_labels_match_upload_thresholds(self):
        self.assertEqual(recheck_label(0), "clean")
        self.assertEqual(recheck_label(1), "suspicious")
        self.assertEqual(recheck_label(2), "malicious")

    def test_two_engines_is_malicious(self):
        r = self.ask(self.report(malicious=2))
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual((body["status"], body["verdict"], body["positives"], body["total"]),
                         ("ok", "malicious", 2, 70))

    def test_one_engine_is_suspicious(self):
        self.assertEqual(self.ask(self.report(suspicious=1)).get_json()["verdict"], "suspicious")

    def test_clean(self):
        self.assertEqual(self.ask(self.report()).get_json()["verdict"], "clean")

    def test_hash_vt_does_not_know_is_unknown_not_clean(self):
        body = self.ask(None).get_json()
        self.assertEqual(body["status"], "unknown")
        self.assertNotIn("verdict", body)

    def test_zero_engines_is_unknown_not_clean(self):
        self.assertEqual(self.ask(self.report(total=0)).get_json()["status"], "unknown")

    def test_rate_limit_is_an_error_not_clean(self):
        r = self.ask(error=http_error(429))
        self.assertEqual(r.status_code, 503)
        self.assertEqual(r.get_json(), {"status": "error", "reason": "rate_limited"})

    def test_other_vt_failure_is_an_error(self):
        r = self.ask(error=requests.ConnectionError("down"))
        self.assertEqual(r.status_code, 503)
        self.assertEqual(r.get_json()["reason"], "unavailable")

    def test_no_api_key_is_an_error(self):
        A.VT_API_KEY = ""
        r = self.ask(self.report())
        self.assertEqual(r.status_code, 503)
        self.assertEqual(r.get_json()["reason"], "not_configured")

    def test_bad_hash_is_rejected_before_vt(self):
        for bad in ("", "xyz", "a" * 40, "a" * 63, "../../etc/passwd", SHA + "\n"):
            r = self.ask(self.report(), file_hash=bad)
            self.assertEqual(r.status_code, 400, repr(bad))

    def test_md5_of_older_rows_is_accepted(self):
        self.assertEqual(self.ask(self.report(), file_hash="b" * 32).status_code, 200)

    def test_old_analysis_requests_a_new_one(self):
        body = self.ask(self.report(age_days=8)).get_json()
        self.assertTrue(body["reanalysis_requested"])
        self.assertEqual(self.reanalysed, [SHA])

    def test_recent_analysis_spends_no_extra_quota(self):
        body = self.ask(self.report(age_days=2)).get_json()
        self.assertFalse(body["reanalysis_requested"])
        self.assertEqual(self.reanalysed, [])


if __name__ == "__main__":
    unittest.main()
