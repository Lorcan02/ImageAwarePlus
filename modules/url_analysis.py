from __future__ import annotations

import base64
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import requests
from dotenv import load_dotenv

load_dotenv()

# FIX 1: API key is fetched lazily inside _vt_headers() rather than at module
# import time. Loading at import time means if .env hasn't been loaded yet when
# the module is first imported (e.g. during testing or in certain Flask startup
# orders), VT_API_KEY is silently None for the entire process lifetime even if
# .env is present. Fetching lazily calls os.getenv() at request time, so it
# always picks up the current environment.
VT_BASE = "https://www.virustotal.com/api/v3"

# FIX 2: Retry constants for rate limiting and transient failures.
# VT free tier returns 429 frequently — without retry the entire URL check
# fails on quota hits rather than waiting briefly and trying again.
MAX_RETRIES = 3
RETRY_BACKOFF_SECONDS = 3.0

# FIX 3: How long to wait after submitting a new URL before polling for results.
# VT free tier is slow — 2 seconds was often not enough, causing a second 404.
VT_SUBMIT_POLL_WAIT = 5.0
VT_SUBMIT_POLL_RETRIES = 3


@dataclass
class URLReputation:
    url: str
    vt_malicious: int
    vt_suspicious: int
    vt_harmless: int
    vt_undetected: int
    vt_timeout: int
    verdict: str
    # FIX 4: Replaced `raw: dict` (entire VT response) with a trimmed summary.
    # The full VT response includes results from 70+ scanning engines and can
    # be several KB per URL. Storing this in the JSON report for every URL
    # makes reports very large. Now stores only the stats summary.
    stats_summary: Dict[str, Any] = field(default_factory=dict)


def _vt_headers() -> Dict[str, str]:
    # FIX 1 (applied): lazy key fetch
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        raise RuntimeError(
            "VT_API_KEY not set. Add it to your .env file or environment."
        )
    return {"x-apikey": api_key}


def vt_url_id(url: str) -> str:
    """
    VirusTotal requires the URL to be base64url-encoded without padding.
    """
    b = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8")
    return b.strip("=")


def _get_vt_result(url_id: str, url: str) -> Dict[str, Any]:
    """
    GET the VT analysis result for a URL ID.
    FIX 5: Extracted into a helper so it can be retried independently of the
    submission step. The original inlined the GET after the POST with no retry,
    meaning any transient failure after submission lost the result entirely.
    """
    endpoint = f"{VT_BASE}/urls/{url_id}"

    for attempt in range(1, MAX_RETRIES + 1):
        r = requests.get(endpoint, headers=_vt_headers(), timeout=30)

        if r.status_code == 429:
            wait = RETRY_BACKOFF_SECONDS * attempt
            if attempt < MAX_RETRIES:
                time.sleep(wait)
            continue

        if r.status_code == 404:
            return {}  # Caller handles 404

        r.raise_for_status()
        return r.json()

    raise RuntimeError(f"VirusTotal rate limit exceeded after {MAX_RETRIES} retries for: {url}")


def _submit_url(url: str) -> bool:
    """
    Submit a URL to VirusTotal for scanning.
    FIX 6: The original never checked whether the submission succeeded.
    If the POST failed (network error, quota, bad request), the code
    silently continued to the GET which would 404 again. Now returns False
    on failure so the caller can skip the poll rather than 404-crashing.
    """
    try:
        r = requests.post(
            f"{VT_BASE}/urls",
            headers=_vt_headers(),
            data={"url": url},
            timeout=30,
        )
        return r.ok
    except Exception:
        return False


def query_virustotal_url(url: str) -> URLReputation:
    """
    Query VirusTotal for a URL reputation.
    Handles 404 (URL not yet in VT) by submitting and polling.
    Handles 429 (rate limit) with exponential backoff retry.
    """
    url_id = vt_url_id(url)
    data = _get_vt_result(url_id, url)

    if not data:
        # URL not in VT database — submit it then poll
        # FIX 6 (applied): check submission result before polling
        submitted = _submit_url(url)

        if not submitted:
            # Submission failed — return a neutral result rather than crashing
            return URLReputation(
                url=url,
                vt_malicious=0,
                vt_suspicious=0,
                vt_harmless=0,
                vt_undetected=0,
                vt_timeout=0,
                verdict="unsubmitted",
                stats_summary={"note": "URL submission to VT failed"},
            )

        # FIX 3 (applied): poll with retries instead of a single sleep+GET.
        # VT free tier can take 10-30 seconds to process a new URL submission.
        data = {}
        for poll_attempt in range(VT_SUBMIT_POLL_RETRIES):
            time.sleep(VT_SUBMIT_POLL_WAIT)
            data = _get_vt_result(url_id, url)
            if data:
                break

        if not data:
            # VT still hasn't finished scanning — return pending result
            return URLReputation(
                url=url,
                vt_malicious=0,
                vt_suspicious=0,
                vt_harmless=0,
                vt_undetected=0,
                vt_timeout=0,
                verdict="pending",
                stats_summary={"note": "URL submitted to VT but scan not yet complete"},
            )

    # FIX 7: Guard against missing keys in the VT response structure.
    # The original accessed data["data"]["attributes"]["last_analysis_stats"]
    # with no error handling — a malformed or unexpected response would raise
    # a KeyError and crash the entire analysis for this URL.
    try:
        stats = data["data"]["attributes"]["last_analysis_stats"]
    except (KeyError, TypeError):
        return URLReputation(
            url=url,
            vt_malicious=0,
            vt_suspicious=0,
            vt_harmless=0,
            vt_undetected=0,
            vt_timeout=0,
            verdict="error",
            stats_summary={"note": "Unexpected VT response structure"},
        )

    malicious   = int(stats.get("malicious",   0))
    suspicious  = int(stats.get("suspicious",  0))
    harmless    = int(stats.get("harmless",    0))
    undetected  = int(stats.get("undetected",  0))
    vt_timeout  = int(stats.get("timeout",     0))

    # FIX 8: Changed verdict "clean" to "harmless" to match the field name
    # used consistently throughout scoring.py, vt_cache.py, and the rest of
    # the codebase. "clean" was only used here, creating an inconsistency
    # where scoring.py checked `verdict in ["malicious", "suspicious"]` and
    # would correctly exclude "clean" — but any code checking for "harmless"
    # would never match these results.
    if malicious > 0:
        verdict = "malicious"
    elif suspicious > 0:
        verdict = "suspicious"
    else:
        verdict = "harmless"

    return URLReputation(
        url=url,
        vt_malicious=malicious,
        vt_suspicious=suspicious,
        vt_harmless=harmless,
        vt_undetected=undetected,
        vt_timeout=vt_timeout,
        verdict=verdict,
        # FIX 4 (applied): store only the stats summary, not the entire response
        stats_summary=stats,
    )