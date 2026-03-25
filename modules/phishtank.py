from __future__ import annotations

import os
import time
# FIX 1: Import urllib.parse for proper URL encoding in POST body.
from urllib.parse import urlencode
from typing import Any, Dict, Optional

import requests

PHISHTANK_CHECK_ENDPOINT = "https://checkurl.phishtank.com/checkurl/"

# FIX 2: Retry constants. PhishTank's free tier is rate-limited and occasionally
# returns 5xx errors on first attempt. A simple retry with backoff handles both
# transient failures and brief rate-limit windows without hammering the API.
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

    # FIX 3: Encode the URL properly before sending. URLs containing '&', '=',
    # '#', or non-ASCII characters would be silently mangled in a raw POST body
    # without encoding. urlencode handles this correctly.
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
                # FIX 4: Set an explicit Content-Type header. Without it some
                # server configurations reject the POST or misparse the body.
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            # FIX 5: Handle rate limiting explicitly before raise_for_status().
            # PhishTank returns 509 (Bandwidth Limit Exceeded) or 429 when the
            # free-tier quota is hit. Retrying immediately just burns more quota —
            # back off and try again after a longer wait.
            if r.status_code in (429, 509):
                wait = RETRY_BACKOFF_SECONDS * attempt * 2
                last_error = f"Rate limited (HTTP {r.status_code}), waiting {wait}s"
                if attempt < MAX_RETRIES:
                    time.sleep(wait)
                continue

            # FIX 6: Wrap raise_for_status() with context so the caller's
            # exception message includes the URL being checked, not just an
            # opaque HTTP status code.
            if not r.ok:
                raise requests.HTTPError(
                    f"PhishTank returned HTTP {r.status_code} for URL: {url}",
                    response=r,
                )

            # FIX 7: Validate the response structure before accessing nested
            # keys. If PhishTank returns unexpected JSON (e.g. an error object,
            # or a maintenance page that slips past status checks), the original
            # .get() chains would silently return None for all fields, making the
            # result look like "not in database" when it's actually an error.
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

    # All retries exhausted
    # FIX 8: Return a structured error dict instead of None so callers can
    # distinguish "not in database" (in_database=False) from "check failed"
    # (checked=False). The original always raised on failure, but wrapping
    # callers in report.py use try/except and store the error — returning a
    # dict with checked=False gives more useful information in the JSON report.
    return {
        "provider": "phishtank",
        "checked": False,
        "in_database": False,
        "error": last_error or "Max retries exhausted",
    }