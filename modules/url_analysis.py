from __future__ import annotations

import base64
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import requests



VT_BASE = "https://www.virustotal.com/api/v3"


MAX_RETRIES = 3
RETRY_BACKOFF_SECONDS = 3.0


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
 
    stats_summary: Dict[str, Any] = field(default_factory=dict)


def _vt_headers() -> Dict[str, str]:
    
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
        
        stats_summary=stats,
    )