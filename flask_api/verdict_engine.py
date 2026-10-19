r"""
verdict_engine.py — Cloudie combined verdict logic.

POLICY (set by supervisor): VirusTotal is the PRIMARY detector; the AI
(Random Forest) structural model is a SUPPORTING signal.

Decision matrix
---------------
    AI \ VT      VT clean            VT malicious
    -----------  ------------------  ------------------
    AI clean     CLEAN  (store)      MALICIOUS (block)
    AI malicious SUSPICIOUS (store,  MALICIOUS (block)
                 tag suspicious)

Rules in words:
  * VT no result (any AI)   -> ERROR, blocked (fail closed; VT is primary).
  * Both clean              -> CLEAN, stored normally.
  * AI malicious, VT clean  -> SUSPICIOUS, stored but tagged.
  * VT malicious (any AI)   -> MALICIOUS, blocked (VT is primary authority).

The two engines measure different things (VT = signatures, AI = structure),
so disagreement is EXPECTED and is logged for Chapter 4. Flip PRIMARY_DETECTOR
back to "AI" to restore the old thesis-default policy.
"""

from enum import Enum

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
PRIMARY_DETECTOR = "VT"          # "VT" (current policy) or "AI" (old default)
AI_MALICIOUS_THRESHOLD = 0.50    # RF predict_proba cutoff for "malicious"
VT_MALICIOUS_MIN_HITS = 1        # VT engines flagging it to count as malicious


class Verdict(str, Enum):
    MALICIOUS = "malicious"     # blocked, never stored
    CLEAN = "clean"            # stored normally
    SUSPICIOUS = "suspicious"  # stored, but tagged for the user
    ERROR = "error"            # could not evaluate -> blocked (safe default)


def _ai_label(ai_proba):
    """True if AI considers the file malicious at the configured threshold."""
    return ai_proba is not None and ai_proba >= AI_MALICIOUS_THRESHOLD


def _vt_label(vt_positives):
    """True if VirusTotal considers the file malicious."""
    return vt_positives is not None and vt_positives >= VT_MALICIOUS_MIN_HITS


def combine(ai_proba, vt_positives, vt_total=None, extraction_ok=True):
    """
    Produce the combined Cloudie verdict under the VT-primary policy.

    Parameters
    ----------
    ai_proba : float | None      RF malicious probability (0..1), None if AI failed.
    vt_positives : int | None    VT engines flagging the file, None if VT unavailable.
    vt_total : int | None        Total VT engines (reporting only).
    extraction_ok : bool         Whether feature extraction succeeded.

    Returns
    -------
    dict: verdict, confidence, ai_label, vt_label, disagreement, primary, rationale
    """
    ai_says_mal = _ai_label(ai_proba) if ai_proba is not None else None
    vt_says_mal = _vt_label(vt_positives) if vt_positives is not None else None

    disagreement = (
        ai_says_mal is not None
        and vt_says_mal is not None
        and ai_says_mal != vt_says_mal
    )

    # AI confidence = distance of the probability from the 0.5 fence.
    ai_conf = abs(ai_proba - 0.5) * 2 if ai_proba is not None else 0.0

    # -- Both signals missing -> cannot evaluate -> block. -------------------
    if ai_proba is None and vt_positives is None:
        return _result(Verdict.ERROR, 0.0, ai_says_mal, vt_says_mal, False,
                       "Both AI and VirusTotal results unavailable; "
                       "blocked as a safe default.")

    # ======================================================================
    # VT-PRIMARY POLICY (current)
    # ======================================================================
    if PRIMARY_DETECTOR == "VT":
        # 0) FAIL CLOSED: VirusTotal is the primary detector. If it gave no
        #    result (key missing, rate limit, timeout, analysis not finished),
        #    the file is NOT stored, whatever the AI says.
        if vt_positives is None:
            return _result(
                Verdict.ERROR, 0.0, ai_says_mal, None, False,
                "VirusTotal (primary) returned no result. Upload blocked "
                "until VirusTotal can verify the file.")

        # 1) VirusTotal is the authority: if it flags the file, block it,
        #    regardless of what the AI thinks.
        if vt_says_mal:
            return _result(
                Verdict.MALICIOUS, 0.95, ai_says_mal, vt_says_mal, disagreement,
                "VirusTotal (primary) flagged the file. Upload blocked.")

        # From here on, VirusTotal answered and did not flag the file.

        # 2) VT clean but AI flags structural features -> store, tag suspicious.
        if ai_says_mal:
            return _result(Verdict.SUSPICIOUS, max(ai_conf, 0.5),
                           ai_says_mal, vt_says_mal, disagreement,
                           "AI structural analysis flagged the file while "
                           "VirusTotal did not. Stored but tagged SUSPICIOUS "
                           "for the user.")

        # 3) AI clean (or AI failed) and VT did not flag it.
        if extraction_ok and ai_proba is not None:
            return _result(Verdict.CLEAN, max(ai_conf, 0.6),
                           ai_says_mal, vt_says_mal, disagreement,
                           "Neither VirusTotal nor AI flagged the file.")

        # VT explicitly clean, AI unavailable/unreliable (or not a PDF) -> trust VT.
        return _result(Verdict.CLEAN, 0.6, ai_says_mal, vt_says_mal,
                       disagreement,
                       "VirusTotal (primary) reports clean; AI signal was "
                       "unreliable but VirusTotal did not flag the file.")

    # ======================================================================
    # AI-PRIMARY POLICY (legacy; kept for reference / easy rollback)
    # ======================================================================
    if not extraction_ok:
        if vt_says_mal:
            return _result(Verdict.MALICIOUS, 0.6, ai_says_mal, vt_says_mal,
                           disagreement,
                           "Feature extraction failed; relying on VirusTotal, "
                           "which flagged the file.")
        return _result(Verdict.SUSPICIOUS, 0.4, ai_says_mal, vt_says_mal,
                       disagreement,
                       "Feature extraction failed; AI unreliable and VT did not "
                       "flag the file. Manual review advised.")
    if ai_says_mal and vt_says_mal:
        return _result(Verdict.MALICIOUS, max(ai_conf, 0.9), ai_says_mal,
                       vt_says_mal, disagreement,
                       "AI and VirusTotal both flag the file.")
    if ai_says_mal and not vt_says_mal:
        return _result(Verdict.SUSPICIOUS, ai_conf, ai_says_mal, vt_says_mal,
                       disagreement,
                       "AI detected structural features VirusTotal missed.")
    if not ai_says_mal and vt_says_mal:
        return _result(Verdict.SUSPICIOUS, 0.5, ai_says_mal, vt_says_mal,
                       disagreement,
                       "VirusTotal flagged the file but AI did not.")
    return _result(Verdict.CLEAN, max(ai_conf, 0.6), ai_says_mal, vt_says_mal,
                   disagreement, "Neither AI nor VirusTotal flagged the file.")


def _result(verdict, confidence, ai_label, vt_label, disagreement, rationale):
    return {
        "verdict": verdict.value if isinstance(verdict, Verdict) else verdict,
        "confidence": round(float(confidence), 4),
        "ai_label": ai_label,
        "vt_label": vt_label,
        "disagreement": disagreement,
        "primary": PRIMARY_DETECTOR,
        "rationale": rationale,
    }