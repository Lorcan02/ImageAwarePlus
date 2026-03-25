from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional

HIGH_RISK_TLDS = [
    ".top", ".xyz", ".click", ".zip", ".review",
    ".country", ".kim", ".work", ".gq", ".ml", ".cf", ".tk"
]

BRAND_KEYWORDS = [
    "paypal",
    "amazon",
    "apple",
    "google",
    "microsoft",
    "linkedin",
    "spotify",
    "geeksquad",
    "norton",
    "bestbuy",
    # Gaming/streaming — added after evaluation confirmed Twitch impersonation
    # scored 0 because brand was not monitored in email analysis either.
    "twitch",
    "discord",
]

LEGITIMATE_BRAND_DOMAINS = {
    "paypal":    "paypal.com",
    "amazon":    "amazon.com",
    "apple":     "apple.com",
    "google":    "google.com",
    "microsoft": "microsoft.com",
    "linkedin":  "linkedin.com",
    "spotify":   "spotify.com",
    "geeksquad": "geeksquad.com",
    "norton":    "norton.com",
    "bestbuy":   "bestbuy.com",
    # Gaming/streaming
    "twitch":    "twitch.tv",
    "discord":   "discord.com",
}

# FIX 1: Maximum score cap. The original had no upper bound — a heavily
# crafted phishing email could produce a raw score of 80+ from this module
# alone before scoring.py even runs. Since scoring.py multiplies this value
# by 0.5 and caps at 10, having reliable inputs matters. Capping here keeps
# the value meaningful and predictable.
MAX_EMAIL_SCORE = 100


def _normalise_headers(headers: Dict[str, Any]) -> Dict[str, Any]:
    """
    FIX 2: Header keys from real .eml files are inconsistently cased
    (e.g. 'From', 'FROM', 'from', 'Reply-To', 'reply-to'). The original
    code used raw dict lookups like headers.get("from") and
    headers.get("reply_to") which would silently return None if the key
    came in with different casing or used a hyphen instead of underscore.
    This helper normalises all keys to lowercase with underscores so
    lookups are always consistent.
    """
    return {k.lower().replace("-", "_"): v for k, v in (headers or {}).items()}


def extract_domain(email_address: Optional[str]) -> Optional[str]:
    if not email_address:
        return None

    # Handle "Display Name <user@domain.com>" format
    if "<" in email_address and ">" in email_address:
        email_address = email_address.split("<")[1].split(">")[0]

    if "@" not in email_address:
        return None

    return email_address.split("@")[1].lower().strip()


def extract_display_name(email_address: Optional[str]) -> str:
    if not email_address:
        return ""

    if "<" in email_address:
        return email_address.split("<")[0].strip().strip('"').lower()

    return ""


def extract_urls(text: Optional[str]) -> List[str]:
    """
    Extract URLs from email body text.
    Catches http://, https://, and www. prefixed URLs.
    Splits concatenated URLs before extraction — Apple and other
    senders write plain text with URLs joined back-to-back like:
    "https://a.com/pagehttps://b.com/page"
    """
    if not text:
        return []

    # Split concatenated scheme URLs before extracting
    text = re.sub(r'(?<!^)(?<!\n)(?=https?://)', '\n', text)

    url_pattern = r"https?://[^\s<>\"']+|www\.[^\s<>\"']{4,}"
    urls = re.findall(url_pattern, text, flags=re.IGNORECASE)

    cleaned: List[str] = []
    for u in urls:
        u = u.strip(").,;:'\"[]<>")
        if u.lower().count("http") > 1:
            continue
        if len(u) >= 8:
            cleaned.append(u)

    seen: set = set()
    out: List[str] = []
    for u in cleaned:
        if u not in seen:
            out.append(u)
            seen.add(u)
    return out




def _extract_base_domain_ea(domain: str) -> str:
    # Returns registrable base domain: email.apple.com -> apple.com
    domain = domain.lower().split(":")[0].replace("www.", "")
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def detect_brand_impersonation(sender_domain: Optional[str]) -> Optional[str]:
    if not sender_domain:
        return None

    for brand in BRAND_KEYWORDS:
        legit_domain = LEGITIMATE_BRAND_DOMAINS.get(brand, f"{brand}.com")
        if brand in sender_domain:
            # Suppress if the sender base domain matches the legitimate
            # brand base domain. Prevents false positives on legitimate
            # subdomains: email.apple.com, messages-noreply@linkedin.com
            # The original checked sender_domain != legit_domain exactly,
            # so email.apple.com != apple.com always fired incorrectly.
            sender_base = _extract_base_domain_ea(sender_domain)
            legit_base  = _extract_base_domain_ea(legit_domain)
            if sender_base == legit_base:
                continue
            return brand

    return None


def detect_display_name_spoofing(
    display_name: str,
    sender_domain: Optional[str],
) -> Optional[str]:
    if not display_name or not sender_domain:
        return None

    display_lower = display_name.lower().strip()
    # Remove surrounding quotes that email clients add
    display_lower = display_lower.strip('\"').strip("'")
    name_parts    = display_lower.split()

    for brand in BRAND_KEYWORDS:
        if brand not in display_lower:
            continue
        if brand in sender_domain:
            continue

        # Suppress if the brand word appears only as the LAST word of a
        # multi-word display name — this is almost certainly a surname.
        # e.g. "Scott Norton <nortonsm@yahoo.com>" — Norton is a surname,
        # not Norton Antivirus impersonation.
        # A genuine impersonation puts the brand first or alone:
        # "Norton Security <attacker@evil.com>" or "Norton <attacker@evil.com>"
        if len(name_parts) > 1 and name_parts[-1] == brand:
            continue  # surname — not impersonation

        return brand

    return None


def normalize_for_lookalike(text: str) -> str:
    """Normalise common character substitutions used in homograph attacks."""
    if not text:
        return ""

    substitutions = {
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s",
        "@": "a",
        "$": "s",
        "!": "i",
    }

    return "".join(substitutions.get(ch, ch) for ch in text.lower())


def domain_root(domain: str) -> str:
    if not domain:
        return ""

    parts = domain.lower().split(".")
    if len(parts) >= 2:
        return parts[-2]
    return parts[0]


def similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def detect_lookalike_domain(sender_domain: Optional[str]) -> Optional[Dict[str, Any]]:
    """
    Detects domains that are visually or structurally similar to known brands.
    Examples: paypaI.com, arnazon.com, micros0ft-login.top
    """
    if not sender_domain:
        return None

    root = domain_root(sender_domain)
    normalized_root = normalize_for_lookalike(root)

    for brand, legit_domain in LEGITIMATE_BRAND_DOMAINS.items():
        legit_root = domain_root(legit_domain)

        if sender_domain == legit_domain:
            continue

        sim = similarity(normalized_root, legit_root)
        contains_brandish = (
            legit_root in normalized_root or normalized_root in legit_root
        )

        if sim >= 0.80 or contains_brandish:
            if normalized_root != legit_root:
                return {
                    "brand": brand,
                    "sender_domain": sender_domain,
                    "expected_domain": legit_domain,
                    "similarity": round(sim, 2),
                }

    return None


def _check_spf_dkim_dmarc(headers: Dict[str, Any]) -> List[str]:
    """
    FIX 4: SPF, DKIM, and DMARC authentication results are mentioned
    prominently in the system overview as key email security signals, but
    the original analyze_email() never checked them. Added here as a
    dedicated helper. These headers are set by mail servers during delivery
    and are strong phishing indicators when they fail or are absent.

    Common header names (already normalised to lowercase_underscore by
    _normalise_headers):
      - authentication_results  (contains spf=, dkim=, dmarc= sub-results)
      - received_spf            (dedicated SPF result header)
      - dkim_signature          (presence confirms DKIM signing)
    """
    auth_indicators: List[str] = []

    auth_results = str(headers.get("authentication_results", "")).lower()
    received_spf = str(headers.get("received_spf", "")).lower()

    # SPF check
    if received_spf:
        if "fail" in received_spf or "softfail" in received_spf:
            auth_indicators.append("SPF check failed")
        elif "pass" not in received_spf:
            auth_indicators.append("SPF result absent or neutral")
    elif "spf=fail" in auth_results or "spf=softfail" in auth_results:
        auth_indicators.append("SPF check failed (authentication-results)")
    elif "spf=" not in auth_results and not received_spf:
        auth_indicators.append("No SPF record found in headers")

    # DKIM check
    if "dkim=fail" in auth_results or "dkim=none" in auth_results:
        auth_indicators.append("DKIM signature failed or absent")
    elif "dkim_signature" not in headers and "dkim=" not in auth_results:
        auth_indicators.append("No DKIM signature found in headers")

    # DMARC check
    if "dmarc=fail" in auth_results:
        auth_indicators.append("DMARC check failed")
    elif "dmarc=" not in auth_results:
        auth_indicators.append("No DMARC result in headers")

    return auth_indicators


def analyze_email(
    headers: Dict[str, Any],
    body: str,
) -> Dict[str, Any]:

    indicators: List[str] = []
    score = 0

    # FIX 2 (applied): normalise header keys before any lookups.
    headers = _normalise_headers(headers)

    sender = headers.get("from")
    # FIX 5: The original used headers.get("reply_to") but after normalisation
    # the key is "reply_to" (hyphen → underscore). This is now consistent.
    # Previously, if the raw header came in as "Reply-To", the lookup silently
    # returned None and the reply-to mismatch check never fired.
    reply_to = headers.get("reply_to")

    sender_domain = extract_domain(sender)
    reply_domain = extract_domain(reply_to)
    display_name = extract_display_name(sender)

    # --- High-risk TLD ---
    if sender_domain:
        for tld in HIGH_RISK_TLDS:
            if sender_domain.endswith(tld):
                indicators.append(
                    f"Sender domain uses high-risk TLD: {sender_domain}"
                )
                score += 10
                break

    # --- Reply-To mismatch ---
    if sender_domain and reply_domain and sender_domain != reply_domain:
        indicators.append(
            f"Reply-To domain differs from sender: {reply_domain}"
        )
        score += 12

    # --- Brand impersonation via domain ---
    brand_domain = detect_brand_impersonation(sender_domain)
    if brand_domain:
        indicators.append(
            f"Brand impersonation detected in sender domain: {brand_domain}"
        )
        score += 15

    # --- Display name spoofing ---
    brand_display = detect_display_name_spoofing(display_name, sender_domain)
    if brand_display:
        indicators.append(
            f"Display name spoofing detected: {brand_display}"
        )
        score += 15

    # --- Lookalike / homograph domain ---
    lookalike = detect_lookalike_domain(sender_domain)
    if lookalike:
        indicators.append(
            f"Lookalike sender domain detected: {lookalike['sender_domain']} "
            f"resembles {lookalike['expected_domain']}"
        )
        score += 18

    # --- Body URLs ---
    urls = extract_urls(body)
    if urls:
        indicators.append(f"{len(urls)} URL(s) detected in email body")
        # Cap URL score at 6 URLs before full weight applies.
        # Newsletters and marketing emails legitimately contain 10-100 URLs
        # (navigation, footers, article links) — scoring them identically to
        # a phishing email with 3 malicious URLs inflates FPR.
        # Phishing emails typically have 1-5 targeted URLs, so the score
        # contribution is meaningful at low counts and diminishing above 6.
        effective_url_count = min(len(urls), 6)
        score += min(effective_url_count * 3, 15)

    # FIX 4 (applied): SPF / DKIM / DMARC authentication checks.
    # Each failed auth signal adds 8 points — authentication failure is a
    # strong phishing indicator that the original completely missed.
    auth_indicators = _check_spf_dkim_dmarc(headers)
    for auth_ind in auth_indicators:
        indicators.append(auth_ind)
        score += 8

    # FIX 1 (applied): cap the total score so this module can't produce
    # unreasonably high values that distort the main scoring engine.
    score = min(score, MAX_EMAIL_SCORE)

    return {
        "sender_domain": sender_domain,
        "reply_domain": reply_domain,
        "display_name": display_name,
        "urls": urls,
        "score": score,
        "indicators": indicators,
        "lookalike_domain": lookalike,
        # FIX 6: Added auth_results to the return dict so it appears in the
        # JSON report and PDF forensic output. Previously SPF/DKIM/DMARC
        # findings were invisible even if they had been checked.
        "auth_results": auth_indicators,
    }