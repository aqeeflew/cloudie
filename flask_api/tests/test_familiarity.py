"""AI familiarity: 'has the model ever seen a PDF like this one?' (information only, never changes a verdict)."""

import unittest

import numpy as np

import helpers  # noqa: F401
import ai_familiarity as F
from feature_extractor import FEATURE_NAMES, extract_features


def vector_from(ref, q_index):
    """A synthetic file whose every feature sits at one training quantile (50 = the typical PDF)."""
    return {n: float(ref.q[j][q_index]) for j, n in enumerate(ref.names)}


class Reference(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ref = F._reference()

    def test_the_reference_is_present_and_matches_the_32_feature_contract(self):
        self.assertIsNotNone(self.ref, "run ml/build_ai_familiarity.py")
        self.assertEqual(self.ref.names, FEATURE_NAMES)
        self.assertEqual(self.ref.ref.shape[1], 32)
        self.assertGreater(self.ref.ref.shape[0], 10000)
        self.assertLess(self.ref.p50, self.ref.p90)
        self.assertLess(self.ref.p90, self.ref.p99)

    def test_a_typical_pdf_is_familiar(self):
        r = F.assess(vector_from(self.ref, 50), self.ref)
        self.assertEqual(r["band"], "familiar")
        self.assertLess(r["percentile"], 90)
        self.assertEqual(r["unusual_features"], [])

    def test_a_pdf_far_outside_the_training_range_is_unfamiliar_and_says_why(self):
        v = vector_from(self.ref, 50)
        v.update(pdf_size=5e6, obj=400000, stream=90000, endobj=400000, endstream=90000, pages=5000)
        r = F.assess(v, self.ref)
        self.assertEqual(r["band"], "unfamiliar")
        self.assertGreaterEqual(r["percentile"], 99.0)
        names = [u["feature"] for u in r["unusual_features"]]
        self.assertTrue({"pdf_size", "obj"} & set(names), names)
        self.assertIn("weak signal", r["message"])
        size = next(u for u in r["unusual_features"] if u["feature"] == "pdf_size")
        self.assertEqual(size["why"], "above everything in the training data")

    def test_a_value_in_the_top_percent_but_inside_the_range_is_labelled_as_such(self):
        j = self.ref.names.index("pdf_size")
        hi, mx = self.ref.q[j][99], self.ref.q[j][100]
        self.assertLess(hi, mx)
        v = vector_from(self.ref, 50)
        v["pdf_size"] = (hi + mx) / 2
        r = F.assess(v, self.ref)
        size = next(u for u in r["unusual_features"] if u["feature"] == "pdf_size")
        self.assertEqual(size["why"], "in the top 1% of the training data")

    def test_a_value_below_everything_in_training_is_reported_as_below(self):
        v = vector_from(self.ref, 50)
        v["metadata_size"] = 0                      # training never goes below 180
        r = F.assess(v, self.ref)
        meta = next(u for u in r["unusual_features"] if u["feature"] == "metadata_size")
        self.assertEqual(meta["direction"], "below")
        self.assertEqual(meta["why"], "below everything in the training data")
        self.assertEqual(meta["value"], 0)
        self.assertGreaterEqual(meta["lowest"], 180)
        self.assertIn("XMP", meta["meaning"])

    def test_zero_is_not_unusual_for_a_feature_that_is_often_zero(self):
        v = vector_from(self.ref, 50)
        for name in ("JS", "Javascript", "OpenAction", "launch", "EmbeddedFile"):
            v[name] = 0                             # most training PDFs have none of these
        r = F.assess(v, self.ref)
        self.assertEqual(r["unusual_features"], [])

    def test_above_range_items_say_above_and_a_typical_value_is_not_listed(self):
        v = vector_from(self.ref, 50)
        v["pdf_size"] = 5e6
        r = F.assess(v, self.ref)
        self.assertEqual({u["direction"] for u in r["unusual_features"]}, {"above"})

    def test_the_distance_grows_as_a_file_moves_away_from_the_training_data(self):
        base = vector_from(self.ref, 50)
        dists = []
        for size in (20, 400, 4000, 40000):
            v = dict(base, pdf_size=size)
            dists.append(F.assess(v, self.ref)["distance"])
        self.assertEqual(dists, sorted(dists))
        self.assertLess(dists[0], dists[-1])

    def test_a_real_looking_pdf_gets_a_valid_result(self):
        p = helpers.write_temp(helpers.PDF_PLAIN)
        r = F.assess(extract_features(p)["features"], self.ref)
        self.assertIn(r["band"], ("familiar", "unusual", "unfamiliar"))
        self.assertTrue(0 <= r["percentile"] <= 100)
        for key in ("distance", "p90", "p99", "message", "unusual_features", "available"):
            self.assertIn(key, r)

    def test_the_score_is_deterministic(self):
        v = vector_from(self.ref, 80)
        self.assertEqual(F.assess(v, self.ref), F.assess(dict(v), self.ref))


class Transform(unittest.TestCase):
    def test_rank_is_monotone_and_clipped_outside_the_range(self):
        q = np.tile(np.linspace(0, 100, F.N_QUANTILES), (2, 1))
        out = F.rank_transform(np.array([[-5, 0], [50, 50], [100, 100], [500, 100]]), q)
        self.assertEqual(list(out[:, 0]), [F.RANK_LOW, 0.5, 1.0, F.RANK_HIGH])

    def test_a_feature_that_never_varies_in_training_marks_a_new_value_as_novel(self):
        q = np.vstack([np.zeros(F.N_QUANTILES), np.linspace(0, 1, F.N_QUANTILES)])
        out = F.rank_transform(np.array([[0, 0.5], [7, 0.5]]), q)
        self.assertEqual(out[0, 0], 0.5)
        self.assertEqual(out[1, 0], F.RANK_HIGH)


class Robustness(unittest.TestCase):
    def test_garbage_features_never_raise(self):
        ref = F._reference()
        for bad in ({}, None, {"pdf_size": "abc"}, {"pdf_size": None}, {n: float("nan") for n in FEATURE_NAMES}):
            try:
                F.assess(bad, ref)
            except Exception as exc:  # noqa: BLE001
                self.fail("assess raised %r for %r" % (exc, bad))

    def test_missing_reference_gives_none_and_nothing_else_breaks(self):
        saved = (F.REF_PATH, F._REF, F._TRIED)
        try:
            F.REF_PATH, F._REF, F._TRIED = "no-such-file.npz", None, False
            self.assertIsNone(F.assess({n: 1 for n in FEATURE_NAMES}))
        finally:
            F.REF_PATH, F._REF, F._TRIED = saved


if __name__ == "__main__":
    unittest.main()
