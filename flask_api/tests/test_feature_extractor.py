"""feature_extractor: fixed 32-feature schema, robust on bad input."""

import os
import unittest

import helpers
from feature_extractor import extract_features, FEATURE_NAMES


class Schema(unittest.TestCase):
    def test_schema_has_exactly_32_features_and_no_name_column(self):
        self.assertEqual(len(FEATURE_NAMES), 32)
        self.assertEqual(len(set(FEATURE_NAMES)), 32)
        self.assertNotIn("name", FEATURE_NAMES)   # file identifier, not a feature

    def test_schema_matches_the_trained_model(self):
        import joblib
        bundle = joblib.load(os.path.join(helpers.ROOT, "malware_rf.pkl"))
        self.assertEqual(list(bundle["features"]), FEATURE_NAMES)
        self.assertEqual(bundle["model"].n_features_in_, 32)


class Extraction(unittest.TestCase):
    def setUp(self):
        self.paths = []

    def tearDown(self):
        for p in self.paths:
            os.remove(p)

    def make(self, data):
        p = helpers.write_temp(data)
        self.paths.append(p)
        return p

    def test_plain_pdf_vector(self):
        r = extract_features(self.make(helpers.PDF_PLAIN))
        self.assertTrue(r["extraction_ok"])
        self.assertEqual(len(r["vector"]), 32)
        f = r["features"]
        self.assertEqual(f["header"], 1.4)            # version number, not a 1/0 flag
        self.assertEqual(f["JS"], 0)
        self.assertEqual(f["Javascript"], 0)
        self.assertEqual(f["OpenAction"], 0)
        self.assertEqual(f["contains_text"], 0)       # 1/0, no BT operator

    def test_js_pdf_is_detected(self):
        f = extract_features(self.make(helpers.PDF_JS))["features"]
        self.assertEqual(f["header"], 1.3)
        self.assertGreaterEqual(f["JS"], 1)
        self.assertGreaterEqual(f["Javascript"], 1)
        self.assertGreaterEqual(f["OpenAction"], 1)

    def test_vector_order_follows_the_schema(self):
        r = extract_features(self.make(helpers.PDF_JS))
        self.assertEqual(r["vector"], [r["features"][n] for n in FEATURE_NAMES])

    def test_empty_file_never_raises_and_returns_a_zero_vector(self):
        r = extract_features(self.make(b""))
        self.assertFalse(r["extraction_ok"])
        self.assertEqual(r["vector"], [0] * 32)

    def test_missing_file_never_raises(self):
        r = extract_features(os.path.join(helpers.ROOT, "does-not-exist.pdf"))
        self.assertFalse(r["extraction_ok"])
        self.assertEqual(len(r["vector"]), 32)

    def test_garbage_bytes_never_raise(self):
        r = extract_features(self.make(os.urandom(4096)))
        self.assertEqual(len(r["vector"]), 32)


if __name__ == "__main__":
    unittest.main()
