"""Decision table of verdict_engine.combine(): VirusTotal primary, RF supporting."""

import unittest

import helpers  # noqa: F401  (sets up sys.path)
from verdict_engine import (combine, risk_indicators, AI_HIGH_CONFIDENCE,
                            STRONG_RISK_FEATURES)


def verdict(**kw):
    kw.setdefault("vt_total", 70)
    kw.setdefault("extraction_ok", True)
    return combine(**kw)["verdict"]


class VtPrimary(unittest.TestCase):
    def test_vt_hit_blocks_regardless_of_ai(self):
        for p in (0.01, 0.5, 0.99):
            self.assertEqual(verdict(ai_proba=p, vt_positives=2, ai_risk=[]), "malicious")

    def test_a_single_engine_is_a_weak_hit_not_a_block(self):
        for p in (0.01, 0.5, 0.99):
            r = combine(ai_proba=p, vt_positives=1, vt_total=70, ai_risk=[])
            self.assertEqual(r["verdict"], "suspicious")
            self.assertIn("1 VirusTotal engine", r["rationale"])
        self.assertEqual(verdict(ai_proba=None, vt_positives=1, ai_risk=None), "suspicious")

    def test_the_block_threshold_is_exactly_two_engines(self):
        import verdict_engine
        self.assertEqual(verdict_engine.VT_MALICIOUS_MIN_HITS, 2)
        self.assertEqual(verdict(ai_proba=0.1, vt_positives=0, ai_risk=[]), "clean")
        self.assertEqual(verdict(ai_proba=0.1, vt_positives=2, ai_risk=[]), "malicious")

    def test_vt_no_result_is_error_fail_closed(self):
        for p in (0.01, 0.99, None):
            self.assertEqual(verdict(ai_proba=p, vt_positives=None, ai_risk=["JS"]), "error")

    def test_vt_clean_ai_clean_is_clean(self):
        self.assertEqual(verdict(ai_proba=0.2, vt_positives=0, ai_risk=[]), "clean")

    def test_vt_clean_and_ai_unavailable_is_clean(self):
        # e.g. non-PDF files: judged by VirusTotal only
        self.assertEqual(verdict(ai_proba=None, vt_positives=0, ai_risk=None), "clean")


class RiskGate(unittest.TestCase):
    def test_high_score_with_risk_indicator_is_suspicious(self):
        self.assertEqual(verdict(ai_proba=0.60, vt_positives=0, ai_risk=["JS"]), "suspicious")

    def test_score_at_threshold_without_indicator_is_clean(self):
        self.assertEqual(verdict(ai_proba=0.69, vt_positives=0, ai_risk=[]), "clean")

    def test_very_high_score_without_indicator_is_suspicious(self):
        self.assertEqual(verdict(ai_proba=AI_HIGH_CONFIDENCE, vt_positives=0, ai_risk=[]), "suspicious")
        self.assertEqual(verdict(ai_proba=0.84, vt_positives=0, ai_risk=[]), "clean")

    def test_low_score_with_indicator_stays_clean(self):
        self.assertEqual(verdict(ai_proba=0.40, vt_positives=0, ai_risk=["JS", "OpenAction"]), "clean")

    def test_gate_off_keeps_legacy_behaviour(self):
        self.assertEqual(verdict(ai_proba=0.69, vt_positives=0, ai_risk=None), "suspicious")


class EvasionRule(unittest.TestCase):
    """Rule-based evasion findings can tag a file suspicious on their own, but never override VirusTotal."""

    def test_strong_evasion_makes_a_low_scoring_file_suspicious(self):
        r = combine(ai_proba=0.20, vt_positives=0, vt_total=70, ai_risk=["obfuscated_keywords"],
                    evasion=["obfuscated_keywords"])
        self.assertEqual(r["verdict"], "suspicious")
        self.assertIn("obfuscated_keywords", r["rationale"])

    def test_strong_evasion_works_even_when_the_score_is_below_the_gate(self):
        self.assertEqual(verdict(ai_proba=0.69, vt_positives=0, ai_risk=[], evasion=["embedded_executable"]), "suspicious")

    def test_without_evasion_nothing_changes(self):
        self.assertEqual(verdict(ai_proba=0.20, vt_positives=0, ai_risk=[], evasion=[]), "clean")
        self.assertEqual(verdict(ai_proba=0.20, vt_positives=0, ai_risk=[], evasion=None), "clean")

    def test_virustotal_still_decides_first(self):
        self.assertEqual(verdict(ai_proba=0.1, vt_positives=2, ai_risk=[], evasion=["launch_shell"]), "malicious")
        self.assertEqual(verdict(ai_proba=0.1, vt_positives=None, ai_risk=[], evasion=["launch_shell"]), "error")

    def test_high_score_with_evasion_is_still_one_suspicious_verdict(self):
        r = combine(ai_proba=0.95, vt_positives=0, vt_total=70, ai_risk=["JS"], evasion=["obfuscated_keywords"])
        self.assertEqual(r["verdict"], "suspicious")
        self.assertIn("Evasion indicators were found as well", r["rationale"])


class Helpers(unittest.TestCase):
    def test_risk_indicators_picks_only_strong_features_that_are_present(self):
        feats = {n: 0 for n in STRONG_RISK_FEATURES}
        feats.update({"JS": 1, "OpenAction": 2, "URI": 5, "Acroform": 1})
        self.assertEqual(sorted(risk_indicators(feats)), ["JS", "OpenAction"])
        self.assertEqual(risk_indicators({}), [])

    def test_confidence_is_distance_from_the_fence(self):
        self.assertEqual(combine(ai_proba=0.5, vt_positives=0, ai_risk=[])["verdict"], "clean")
        r = combine(ai_proba=0.99, vt_positives=0, vt_total=70, ai_risk=["JS"])
        self.assertGreaterEqual(r["confidence"], 0.9)


if __name__ == "__main__":
    unittest.main()
