"""feature_explain: contributions must add up exactly to the model's own score."""

import os
import unittest

import helpers
import joblib
import pandas as pd

from feature_extractor import extract_features
import feature_explain as fx


class Explain(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        bundle = joblib.load(os.path.join(helpers.ROOT, "malware_rf.pkl"))
        cls.model, cls.feats = bundle["model"], bundle["features"]

    def vals(self, data):
        p = helpers.write_temp(data)
        try:
            return extract_features(p)["features"]
        finally:
            os.remove(p)

    def test_base_plus_contributions_equals_predict_proba(self):
        for data in (helpers.PDF_PLAIN, helpers.PDF_JS):
            v = self.vals(data)
            row = [v[n] for n in self.feats]
            bias, contrib = fx.contributions(self.model, row, self.feats)
            p = self.model.predict_proba(pd.DataFrame([row], columns=self.feats))[0][1]
            self.assertAlmostEqual(bias + sum(contrib.values()), p, places=9)

    def test_js_pdf_is_pushed_toward_malicious_by_javascript_features(self):
        v = self.vals(helpers.PDF_JS)
        ex = fx.build_explanation(self.model, self.feats, v)
        self.assertIsNotNone(ex)
        effects = {t["feature"]: t["effect"] for t in ex["top"]}
        self.assertTrue(any(effects.get(k, 0) > 0 for k in ("Javascript", "JS")))
        self.assertAlmostEqual(ex["total"],
                               self.model.predict_proba(pd.DataFrame([[v[n] for n in self.feats]],
                                                                     columns=self.feats))[0][1], places=3)

    def test_every_feature_has_a_plain_language_meaning(self):
        self.assertEqual(set(fx.MEANINGS), set(self.feats))

    def test_explanation_failure_returns_none_instead_of_raising(self):
        self.assertIsNone(fx.build_explanation(object(), self.feats, {}))


if __name__ == "__main__":
    unittest.main()
