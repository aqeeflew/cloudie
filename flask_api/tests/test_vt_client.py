"""vt_client polling: quota-friendly, bounded, and 409/429 handled (no network, fake clock)."""

import unittest
from unittest import mock

import helpers  # noqa: F401
import vt_client as V


class FakeResp:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self._body = body or {}

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(str(self.status_code))


class Clock:
    """Replaces time.time / time.sleep so the tests run instantly."""
    def __init__(self):
        self.now = 1000.0
        self.sleeps = []

    def time(self):
        return self.now

    def sleep(self, s):
        self.sleeps.append(s)
        self.now += s


def analysis(status):
    return FakeResp(200, {"data": {"attributes": {"status": status, "stats": {
        "malicious": 0, "suspicious": 0, "harmless": 60, "undetected": 3}}},
        "meta": {"file_info": {"sha256": "ab" * 32}}})


FILE_REPORT = FakeResp(200, {"data": {"attributes": {
    "sha256": "ab" * 32, "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 60, "undetected": 3},
    "last_analysis_results": {}}}})


class Polling(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.f = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False)
        self.f.write(b"%PDF-1.4 test")
        self.f.close()
        self.clock = Clock()

    def tearDown(self):
        import os
        os.remove(self.f.name)

    def run_upload(self, get_side_effect, post_resp=None):
        post_resp = post_resp or FakeResp(200, {"data": {"id": "analysis-1"}})
        with mock.patch.object(V.time, "time", self.clock.time), \
             mock.patch.object(V.time, "sleep", self.clock.sleep), \
             mock.patch.object(V.requests, "post", return_value=post_resp), \
             mock.patch.object(V.requests, "get", side_effect=get_side_effect) as get:
            deadline = self.clock.now + V.VT_BUDGET
            try:
                return V._upload_and_wait(self.f.name, "a.pdf", "key", "ab" * 32, deadline), get
            except Exception as exc:  # noqa: BLE001
                return exc, get

    def test_the_schedule_fits_the_budget_and_is_gentler_than_every_5_seconds(self):
        self.assertLessEqual(sum(V.VT_POLL_SCHEDULE), V.VT_BUDGET)
        self.assertLessEqual(len(V.VT_POLL_SCHEDULE), 8)          # at most 8 polls (was 12)
        self.assertGreaterEqual(min(V.VT_POLL_SCHEDULE), 10)      # never faster than every 10 s

    def test_finishes_on_the_third_poll(self):
        calls = [analysis("queued"), analysis("queued"), analysis("completed"), FILE_REPORT]
        res, get = self.run_upload(calls)
        self.assertIsInstance(res, dict)
        self.assertTrue(res["available"])
        self.assertEqual(res["total"], 63)
        self.assertEqual(get.call_count, 4)                        # 3 polls + 1 report fetch
        self.assertEqual(self.clock.sleeps[:3], [15, 10, 10])

    def test_gives_up_with_a_timeout_after_the_budget_and_never_over_polls(self):
        res, get = self.run_upload(lambda *a, **k: analysis("queued"))
        self.assertIsInstance(res, TimeoutError)
        self.assertLessEqual(get.call_count, len(V.VT_POLL_SCHEDULE))
        self.assertLessEqual(self.clock.now - 1000.0, V.VT_BUDGET + 1)   # stays inside the budget

    def test_rate_limit_429_backs_off_instead_of_hammering(self):
        res, get = self.run_upload(lambda *a, **k: FakeResp(429))
        self.assertIsInstance(res, TimeoutError)
        self.assertLessEqual(get.call_count, len(V.VT_POLL_SCHEDULE))
        # extra back-off sleeps after each 429 (more sleeps than polls)
        self.assertGreater(len(self.clock.sleeps), get.call_count)

    def test_409_on_upload_is_resolved_through_the_hash_report(self):
        res, get = self.run_upload([FILE_REPORT], post_resp=FakeResp(409))
        self.assertIsInstance(res, dict)
        self.assertTrue(res["available"])
        self.assertEqual(get.call_count, 1)                        # one hash lookup, no polling
        self.assertEqual(self.clock.sleeps, [])

    def test_other_upload_errors_raise_so_the_scan_fails_closed(self):
        res, _ = self.run_upload([], post_resp=FakeResp(500))
        self.assertIsInstance(res, Exception)

    def test_a_429_on_the_upload_itself_raises(self):
        res, _ = self.run_upload([], post_resp=FakeResp(429))
        self.assertIsInstance(res, Exception)


if __name__ == "__main__":
    unittest.main()
