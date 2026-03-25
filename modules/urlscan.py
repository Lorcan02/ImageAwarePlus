from __future__ import annotations

import os
import time
from typing import Any, Dict, Optional

import requests

URLSCAN_SEARCH_ENDPOINT = "https://urlscan.io/api/v1/search/"

# FIX 1: Named constants for retry behaviour and timeout.
# urlscan.io free tier returns 429 fairly readily on bursts of requests.
MAX_RETRIES = 3
RETRY_BACKOFF_SECONDS = 2.0
DEFAULT_TIMEOUT = 15


def urlscan_search(url: str, timeout: int = DEFAULT_TIMEOUT) -> Optional[Dict[str, Any]]:
    """
    Search urlscan.io for an existing scan of a URL.
    Returns a compact dict of useful fields if a result is found, else None.
    """
    api_key = os.getenv("URLSCAN_API_KEY")
    headers = {"api-key": api_key} if api_key else {}

    # FIX 2: Broadened the search query. The original used `page.url:"<exact>"`
    # which requires an exact string match against urlscan's indexed page URL.
    # This misses results where:
    #   - urlscan followed a redirect and indexed the final URL
    #   - http vs https variant was scanned instead
    #   - trailing slash differs
    # Using `domain:` + `page.url:` as an OR query catches more hits.
    # We then verify the result actually matches our URL (Fix 3) to avoid
    # false positives from the broader query.
    parsed_domain = _extract_domain(url)
    if parsed_domain:
        query = f'page.url:"{url}" OR domain:"{parsed_domain}"'
    else:
        query = f'page.url:"{url}"'

    params = {
        "q": query,
        "size": 5,  # FIX 2 (cont): fetch top 5 so we can pick the best match
    }

    last_error: Optional[str] = None

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = requests.get(
                URLSCAN_SEARCH_ENDPOINT,
                headers=headers,
                params=params,
                timeout=timeout,
            )

            # FIX 1 (applied): handle rate limiting explicitly before raise_for_status
            if r.status_code == 429:
                wait = RETRY_BACKOFF_SECONDS * attempt
                last_error = f"Rate limited (HTTP 429), waiting {wait}s"
                if attempt < MAX_RETRIES:
                    time.sleep(wait)
                continue

            # FIX 4: Wrap raise_for_status with context so the caller's
            # exception log includes which URL triggered the error.
            if not r.ok:
                raise requests.HTTPError(
                    f"urlscan.io returned HTTP {r.status_code} for URL: {url}",
                    response=r,
                )

            data = r.json()
            results = data.get("results", [])

            if not results:
                return None

            # FIX 3: Verify the best result actually relates to our URL.
            # With the broader query we might get results for a different page
            # on the same domain. Pick the result whose page.url most closely
            # matches what we queried.
            hit = _best_match(url, results)
            if hit is None:
                return None

            scan_id = hit.get("_id")
            page  = hit.get("page",  {}) or {}
            task  = hit.get("task",  {}) or {}
            stats = hit.get("stats", {}) or {}

            # FIX 5: Renamed 'score' to 'verdict_score' to clarify that this
            # is urlscan.io's own internal scoring, not our risk score. Keeping
            # the field name ambiguous caused confusion when the result was
            # displayed in the PDF report alongside our own risk score.
            verdict_score = hit.get("verdicts", {}).get("overall", {}).get("score") \
                            if hit.get("verdicts") else hit.get("score")

            return {
                "provider":       "urlscan",
                "found":          True,
                "scan_id":        scan_id,
                "result_url":     hit.get("result"),
                "screenshot_url": (
                    f"https://urlscan.io/screenshots/{scan_id}.png"
                    if scan_id else None
                ),
                "page_url":       page.get("url"),
                "domain":         page.get("domain"),
                "ip":             page.get("ip"),
                "asn":            page.get("asn"),
                "task_url":       task.get("url"),
                "verdict_score":  verdict_score,
                "tags":           hit.get("tags", []),
                "stats": {
                    "requests": stats.get("requests"),
                    "domains":  stats.get("domains"),
                    "ips":      stats.get("ips"),
                },
            }

        except (requests.Timeout, requests.ConnectionError) as e:
            last_error = str(e)
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_BACKOFF_SECONDS * attempt)
            continue

        except requests.HTTPError:
            raise

    # All retries exhausted — return None rather than crashing the pipeline.
    # Caller in report.py already wraps this in try/except and stores errors.
    return None


def _extract_domain(url: str) -> Optional[str]:
    """Extract the domain from a URL without importing urllib for a one-liner."""
    try:
        from urllib.parse import urlparse
        netloc = urlparse(url).netloc.lower()
        # Strip port if present
        return netloc.split(":")[0] if netloc else None
    except Exception:
        return None


def _best_match(query_url: str, results: list) -> Optional[dict]:
    """
    FIX 3 (implementation): From a list of urlscan results, return the one
    whose page.url most closely matches the URL we searched for.

    Strategy:
    1. Exact match on page.url (after normalising http/https and trailing slash)
    2. Match on domain if no exact match found
    3. Return None if nothing meaningful found
    """
    query_norm = _normalise_url(query_url)
    query_domain = _extract_domain(query_url)

    # Pass 1: exact normalised match
    for hit in results:
        page_url = (hit.get("page") or {}).get("url", "")
        if _normalise_url(page_url) == query_norm:
            return hit

    # Pass 2: domain match
    for hit in results:
        hit_domain = (hit.get("page") or {}).get("domain", "").lower()
        if query_domain and hit_domain == query_domain:
            return hit

    return None


def _normalise_url(url: str) -> str:
    """Normalise a URL for comparison: lowercase scheme+host, strip trailing slash."""
    try:
        from urllib.parse import urlparse, urlunparse
        p = urlparse(url.lower())
        path = p.path.rstrip("/") or "/"
        return urlunparse((p.scheme, p.netloc, path, p.params, p.query, ""))
    except Exception:
        return url.lower().rstrip("/")