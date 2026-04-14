from __future__ import annotations

import os
import time

from urllib.parse import urlencode
from typing import Any, Dict, Optional

import requests

PHISHTANK_CHECK_ENDPOINT = "https://checkurl.phishtank.com/checkurl/"

MAX_RETRIES = 3
RETRY_BACKOFF_SECONDS = 2.0


def phishtank_check(
    url: str,
    timeout: int = 15,
) -> Optional[Dict[str, Any]]:
    """
    Check a URL against PhishTank.

    PhishTank expects an HTTP POST to /checkurl/ with:
        url=<encoded_url>&format=json[&app_key=<key>]

    Returns a dict with provider, checked, in_database, and (if found)
    phishing detail fields. Returns None only if all retries are exhausted.
    """
    app_key = os.getenv("PHISHTANK_API_KEY")

    
    payload: Dict[str, str] = {
        "url": url,
        "format": "json",
    }
    if app_key:
        payload["app_key"] = app_key

    last_error: Optional[str] = None

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = requests.post(
                PHISHTANK_CHECK_ENDPOINT,
                data=payload,
                timeout=timeout,
                
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            
            if r.status_code in (429, 509):
                wait = RETRY_BACKOFF_SECONDS * attempt * 2
                last_error = f"Rate limited (HTTP {r.status_code}), waiting {wait}s"
                if attempt < MAX_RETRIES:
                    time.sleep(wait)
                continue

            
            if not r.ok:
                raise requests.HTTPError(
                    f"PhishTank returned HTTP {r.status_code} for URL: {url}",
                    response=r,
                )

            
            try:
                data = r.json()
            except Exception as e:
                raise ValueError(
                    f"PhishTank returned non-JSON response for URL: {url}"
                ) from e

            if not isinstance(data, dict):
                raise ValueError(
                    f"PhishTank response was not a JSON object for URL: {url}"
                )

            results = data.get("results") or {}

            if not isinstance(results, dict):
                raise ValueError(
                    f"PhishTank 'results' field was not a dict for URL: {url}"
                )

            in_db = bool(results.get("in_database", False))

            out: Dict[str, Any] = {
                "provider": "phishtank",
                "checked": True,
                "in_database": in_db,
            }

            if in_db:
                out.update({
                    "valid":             results.get("valid"),
                    "verified":          results.get("verified"),
                    "phish_id":          results.get("phish_id"),
                    "phish_detail_page": results.get("phish_detail_page"),
                })

            return out

        except (requests.Timeout, requests.ConnectionError) as e:
            last_error = str(e)
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_BACKOFF_SECONDS * attempt)
            continue

        except (requests.HTTPError, ValueError):
            # Non-retryable errors — bad status or malformed response
            raise

    
    return {
        "provider": "phishtank",
        "checked": False,
        "in_database": False,
        "error": last_error or "Max retries exhausted",
    }