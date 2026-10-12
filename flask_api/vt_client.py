"""
vt_client.py
------------
Lightweight VirusTotal API v3 client.

Three modes are exposed:

    scan_file(path, original_name)
        1. computes SHA-256 of the file
        2. asks VT if it already knows that hash (free, no quota)
        3. if not, uploads the file and polls for the analysis
        4. returns a normalised dict

Free-tier limits:
    4 requests / minute, 500 / day, 32MB max upload.

Notes for the thesis:
    VirusTotal is used here as a SECOND opinion, alongside our Random Forest.
    The AI verdict remains the primary detector — VT corroborates or
    contradicts it.
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from typing import Any, Dict, Optional

import requests


VT_BASE     = "https://www.virustotal.com/api/v3"
VT_TIMEOUT  = 30
VT_MAX_POLL = 12          # try up to 12 * 5s = 60s for the analysis to finish
VT_POLL_GAP = 5

log = logging.getLogger("cloudie.vt")


class VTConfigError(RuntimeError):
    """Raised when no API key is configured."""


def _sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _headers(api_key: str) -> Dict[str, str]:
    return {"x-apikey": api_key, "Accept": "application/json"}


def _summarise_stats(stats: Dict[str, int]) -> Dict[str, Any]:
    """Turn VT's per-category counts into a single verdict."""
    malicious  = int(stats.get("malicious",  0))
    suspicious = int(stats.get("suspicious", 0))
    harmless   = int(stats.get("harmless",   0))
    undetected = int(stats.get("undetected", 0))
    total      = malicious + suspicious + harmless + undetected
    detected   = malicious + suspicious

    if total == 0:
        verdict, score = "unknown", 0.0
    elif malicious >= 3 or (malicious >= 1 and detected >= 5):
        verdict = "malicious"
        score = round(detected / total, 4)
    elif detected >= 1:
        verdict = "suspicious"
        score = round(detected / total, 4)
    else:
        verdict = "clean"
        score = round(detected / total, 4)

    return {
        "verdict":    verdict,
        "score":      score,                     # 0..1 - share of engines flagging it
        "malicious":  malicious,
        "suspicious": suspicious,
        "harmless":   harmless,
        "undetected": undetected,
        "total":      total,
        "detected":   detected,
    }


def _parse_file_report(data: Dict[str, Any]) -> Dict[str, Any]:
    """Convert the /files/{hash} response into Cloudie's report shape."""
    attrs = (data.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats", {}) or {}
    summary = _summarise_stats(stats)

    # Top engines that flagged the file (limit to 8 for the report card)
    flagged = []
    for engine, result in (attrs.get("last_analysis_results") or {}).items():
        if result.get("category") in ("malicious", "suspicious"):
            flagged.append({
                "engine":   engine,
                "category": result.get("category"),
                "result":   result.get("result") or "",
                "method":   result.get("method") or "",
            })
        if len(flagged) >= 8:
            break

    return {
        **summary,
        "available":   summary["total"] > 0,
        "sha256":      attrs.get("sha256")  or "",
        "md5":         attrs.get("md5")     or "",
        "file_type":   attrs.get("type_description") or attrs.get("type_tag") or "",
        "size":        attrs.get("size")    or 0,
        "first_seen":  attrs.get("first_submission_date") or 0,
        "last_seen":   attrs.get("last_analysis_date")    or 0,
        "reputation":  attrs.get("reputation") or 0,
        "flagged":     flagged,
        "permalink":   f"https://www.virustotal.com/gui/file/{attrs.get('sha256') or ''}",
    }


def _lookup_hash(sha256: str, api_key: str) -> Optional[Dict[str, Any]]:
    """GET /files/{hash} - returns None if VT has never seen this hash."""
    url = f"{VT_BASE}/files/{sha256}"
    r = requests.get(url, headers=_headers(api_key), timeout=VT_TIMEOUT)
    if r.status_code == 200:
        return _parse_file_report(r.json())
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return None


def _upload_and_wait(path: str, name: str, api_key: str) -> Dict[str, Any]:
    """POST /files, then poll /analyses/{id} until it completes."""
    size = os.path.getsize(path)
    if size > 32 * 1024 * 1024:
        # VT requires a special upload URL above 32 MB. We don't bother
        # implementing that for the free tier - just refuse.
        raise RuntimeError("File is too large for VirusTotal free tier (>32MB).")

    with open(path, "rb") as f:
        r = requests.post(
            f"{VT_BASE}/files",
            headers=_headers(api_key),
            files={"file": (name, f)},
            timeout=VT_TIMEOUT,
        )
    r.raise_for_status()
    analysis_id = r.json()["data"]["id"]
    log.info("VT upload accepted, analysis_id=%s", analysis_id)

    for attempt in range(VT_MAX_POLL):
        time.sleep(VT_POLL_GAP)
        r = requests.get(f"{VT_BASE}/analyses/{analysis_id}",
                         headers=_headers(api_key),
                         timeout=VT_TIMEOUT)
        if r.status_code != 200:
            continue
        body = r.json()
        status = (body.get("data") or {}).get("attributes", {}).get("status")
        if status == "completed":
            # Once complete, re-fetch the file report (richer than the analysis)
            sha256 = (body.get("meta") or {}).get("file_info", {}).get("sha256")
            if sha256:
                report = _lookup_hash(sha256, api_key)
                if report is not None:
                    return report
            # Fallback: build a minimal report from the analysis itself
            stats = (body.get("data") or {}).get("attributes", {}).get("stats", {})
            summary = _summarise_stats(stats)
            return {**summary, "available": summary["total"] > 0,
                    "sha256": sha256 or "", "flagged": [], "permalink": ""}

    raise TimeoutError("VirusTotal analysis did not complete in time.")


def scan_file(path: str, original_name: str,
              api_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Main entry point. Returns a normalised dict:

        {
          "available":  True/False,        # was VT able to answer?
          "verdict":    clean | suspicious | malicious | unknown,
          "score":      0..1,              # share of engines that flagged
          "malicious":  int, "suspicious": int, "harmless": int,
          "undetected": int, "total": int, "detected": int,
          "sha256":     "...",
          "flagged":    [ {engine, category, result, method}, ... ],
          "permalink":  "https://www.virustotal.com/gui/file/<sha256>",
          ...
        }

    Raises VTConfigError when no API key is configured.
    """
    api_key = api_key or os.environ.get("VT_API_KEY") or ""
    if not api_key:
        raise VTConfigError("VT_API_KEY environment variable is not set.")

    sha = _sha256_of(path)
    log.info("VT lookup sha256=%s", sha)

    cached = _lookup_hash(sha, api_key)
    if cached is not None:
        log.info("VT cache hit: verdict=%s detected=%d/%d",
                 cached["verdict"], cached["detected"], cached["total"])
        return cached

    log.info("VT cache miss - uploading file")
    return _upload_and_wait(path, original_name, api_key)
