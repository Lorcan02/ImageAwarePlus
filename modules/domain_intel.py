from __future__ import annotations

from datetime import datetime, timezone
from functools import lru_cache
from typing import Optional
from urllib.parse import urlparse

import whois


WHOIS_TIMEOUT_SECONDS = 5


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
   
    return whois.whois(domain)


def get_domain_age_days(url: str) -> Optional[int]:
    
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
    
    age = get_domain_age_days(url)
    if age is None:
        return False
    return age < YOUNG_DOMAIN_THRESHOLD_DAYS


def get_domain_intel(url: str) -> dict:
    
    domain = _parse_domain(url)
    age_days = get_domain_age_days(url)
    young = is_young_domain(url)

    return {
        "domain": domain,
        "age_days": age_days,
        "is_young": young,
        "threshold_days": YOUNG_DOMAIN_THRESHOLD_DAYS,
    }