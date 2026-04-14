from __future__ import annotations

import re
from typing import List
from urllib.parse import urlparse

# Extensions that are not meaningful phishing URLs
BLOCKED_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".css", ".js", ".ico", ".woff", ".woff2",
)


TRACKING_KEYWORDS = [
    "unsubscribe",
    "tracking",
    "pixel",
    "openrate",
    "emailpreference",       
    "preference-center",
    "preference_center",     
    "social",
    "click.sender",          # common ESP click-tracking domain fragment
    "list-manage",           # Mailchimp list management URLs
    "mandrillapp",           # Mandrill transactional email tracker
    # LinkedIn ESP tracking parameters — confirmed from live test where 30
    # legitimate LinkedIn marketing URLs all passed through to VirusTotal
    # because their tracking params weren't in the keyword list.
    # All LinkedIn bulk email URLs contain these parameter fragments.
    "eml-email_learning",    # LinkedIn Learning email campaign tracker
    "eml-email_",            # broader LinkedIn email campaign prefix
    "trkemail=eml-",         # LinkedIn trkEmail parameter (tracking)
    "midtoken=",             # LinkedIn midToken (message ID tracker)
    "midsig=",               # LinkedIn midSig (message signature tracker)
    "eptoken=",              # LinkedIn epToken (engagement tracker)
    # Generic ESP tracking parameters seen across multiple platforms
    "trk=eml-",              # generic email tracking parameter prefix
    "utm_source=email",      # standard UTM email source tag
    "utm_medium=email",      # standard UTM email medium tag
    "mc_eid=",               # Mailchimp engagement ID
    "mc_cid=",               # Mailchimp campaign ID
]


BLOCKED_DOMAINS = (
    "w3.org",
    "googleusercontent.com",
    "googleapis.com",
    "gstatic.com",
    "sendgrid.net",          # ESP infrastructure
    "mailchimp.com",         # ESP infrastructure
    "list-manage.com",       # Mailchimp list management
    "cloudflare.com",        # CDN assets
    "amazonaws.com",         # AWS asset hosting (not phishing target)
    # Major platform marketing/notification domains — confirmed from live test.
    # URLs from these domains in bulk email are always tracking/navigation links
    # to the platform itself, never phishing targets worth checking with VT.
    # Note: these are the SENDER domains for legitimate bulk email, not targets.
    # A phishing email impersonating LinkedIn would use a DIFFERENT domain,
    # which would NOT be in this list and WOULD be checked by VT.
    "linkedin.com",          # LinkedIn marketing/notification emails
    "twitter.com",           # Twitter/X notification emails
    "x.com",                 # Twitter/X (new domain)
    "facebook.com",          # Meta notification emails
    "instagram.com",         # Instagram notification emails
    "youtube.com",           # Google/YouTube notification emails
    "google.com",            # Google notification emails
    "microsoft.com",         # Microsoft notification emails
    "apple.com",             # Apple notification emails
    "github.com",            # GitHub notification emails
)


MIN_URL_LENGTH = 12


def clean_email_urls(urls: List[str]) -> List[str]:
    """
    Remove non-meaningful URLs from email bodies.
    Returns deduplicated list of URLs likely to be phishing-relevant.
    """
    cleaned: List[str] = []
    
    seen: set = set()

    for url in urls:
        url_lower = url.lower()

        # Minimum length guard
        if len(url) < MIN_URL_LENGTH:
            continue

        # Skip tracking keywords
        if any(k in url_lower for k in TRACKING_KEYWORDS):
            continue

        # Skip asset file extensions
        try:
            parsed = urlparse(url)
            path = parsed.path.lower()
            if path.endswith(BLOCKED_EXTENSIONS):
                continue

            domain = parsed.netloc.lower()

            # Skip blocked infrastructure/asset domains
            if any(blocked in domain for blocked in BLOCKED_DOMAINS):
                continue

        except Exception:
            continue

        # Skip mailto links
        if url_lower.startswith("mailto:"):
            continue

        
        if url not in seen:
            seen.add(url)
            cleaned.append(url)

    return cleaned