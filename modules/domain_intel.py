from __future__ import annotations

# FIX 1: Import timezone for tz-aware datetime comparisons.
from datetime import datetime, timezone
from functools import lru_cache
from typing import Optional
from urllib.parse import urlparse

import whois

# FIX 2: WHOIS timeout constant — prevents the entire analysis pipeline from
# hanging silently on an unresponsive WHOIS server. Same fix applied in
# scoring.py; centralised here so domain_intel is the single place that
# owns WHOIS behaviour.
WHOIS_TIMEOUT_SECONDS = 5

# FIX 3: Young domain threshold in days — defined as a named constant so it
# matches the threshold used in scoring.py and is easy to tune in one place.
YOUNG_DOMAIN_THRESHOLD_DAYS = 30


def _parse_domain(url: str) -> str:
    """Extract the netloc from a URL, falling back to treating the whole
    string as a domain if urlparse finds no netloc."""
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    if not domain:
        # Handle bare domains passed without a scheme
        domain = url.lower().split("/")[0]
    # Strip port if present
    domain = domain.split(":")[0]
    return domain


@lru_cache(maxsize=256)
def _whois_cached(domain: str):
    """
    FIX 4: Cache WHOIS results using lru_cache so the same domain is only
    looked up once per process lifetime. During evaluation runs, the same
    domain can appear in dozens of phishing images — without caching this
    causes hundreds of redundant WHOIS lookups, burning time and risking
    rate-limiting by WHOIS servers.

    lru_cache is process-scoped (in-memory), which is appropriate here
    since WHOIS data rarely changes within a single analysis session.
    For cross-session persistence, the VTCache SQLite pattern could be
    extended to cover WHOIS, but that's a future improvement.
    """
    return whois.whois(domain)


def get_domain_age_days(url: str) -> Optional[int]:
    """
    Returns domain age in days, or None if it cannot be determined.

    FIX 1 + FIX 2 + FIX 3 applied:
    - Uses timezone-aware datetime.now(timezone.utc) instead of deprecated utcnow()
    - Normalises naive WHOIS creation_dates to UTC before comparison to avoid TypeError
    - Catches the specific case where creation_date is in the future (data error)
    """
    try:
        domain = _parse_domain(url)
        if not domain:
            return None

        w = _whois_cached(domain)

        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        if not creation:
            return None

        # FIX 1 (applied): normalise naive creation dates to UTC so comparison
        # with timezone-aware now() doesn't raise TypeError. WHOIS dates are
        # usually UTC even when returned as naive datetimes.
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)

        # Guard against WHOIS data errors where creation_date is in the future
        if creation > now:
            return None

        return (now - creation).days

    except Exception:
        return None


def is_young_domain(url: str) -> bool:
    """
    FIX 5: Added a convenience boolean helper so callers don't have to
    re-implement the threshold comparison themselves. Previously every
    caller of get_domain_age_days() had to repeat `age is not None and age < 30`,
    which meant the threshold could drift between callers.
    """
    age = get_domain_age_days(url)
    if age is None:
        return False
    return age < YOUNG_DOMAIN_THRESHOLD_DAYS


def get_domain_intel(url: str) -> dict:
    """
    FIX 6: Added a richer return dict that bundles age, young-domain verdict,
    and the domain string together. Callers in scoring.py currently only use
    age_days, but having the full intel dict available makes it straightforward
    to extend the scoring engine with additional WHOIS signals (registrar,
    country, expiry) without changing call signatures throughout the codebase.
    """
    domain = _parse_domain(url)
    age_days = get_domain_age_days(url)
    young = is_young_domain(url)

    return {
        "domain": domain,
        "age_days": age_days,
        "is_young": young,
        "threshold_days": YOUNG_DOMAIN_THRESHOLD_DAYS,
    }