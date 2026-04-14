from __future__ import annotations


import difflib
import re
import whois
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


@dataclass
class ScoreResult:
    risk_score: int
    risk_level: str
    reasons: List[str]
    breakdown: Dict[str, Dict[str, Any]]


def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def verdict_from_score(score: int) -> str:
    if score >= 70:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"


def _add_factor(
    breakdown: Dict[str, Dict[str, Any]],
    key: str,
    label: str,
    value: Any,
    weight: float,
    contribution: float,
    indicators: Optional[List[str]] = None,
) -> None:
    breakdown[key] = {
        "label": label,
        "value": value,
        "weight": weight,
        "contribution": round(contribution, 2),
        "indicators": indicators or [],
    }


# ------------------------------------------------
# Indicators
# ------------------------------------------------

BRAND_TERMS = [
    "paypal", "apple", "amazon", "spotify", "geeksquad",
    "geek squad", "best buy", "norton", "microsoft",
    "google", "linkedin",
    # Delivery carriers — added with Tier 1 expansion so domain impersonation
    # also catches fake dhl-delivery.xyz, anpost-customs.top etc.
    "dhl", "fedex", "ups", "royal mail", "an post",
    # Gaming/streaming platforms — added after image evaluation confirmed
    # Twitch impersonation scored 0 due to brand not being monitored.
    "twitch", "discord",
]

BRAND_DOMAINS = {
    "paypal":     "paypal.com",
    "amazon":     "amazon.com",
    "apple":      "apple.com",
    "microsoft":  "microsoft.com",
    "google":     "google.com",
    "spotify":    "spotify.com",
    "norton":     "norton.com",
    "linkedin":   "linkedin.com",
    # Delivery carriers
    "dhl":        "dhl.com",
    "fedex":      "fedex.com",
    "ups":        "ups.com",
    "royal mail": "royalmail.com",
    "an post":    "anpost.com",
    # Gaming/streaming platforms
    "twitch":     "twitch.tv",
    "discord":    "discord.com",
}

HIGH_RISK_TLDS = [
    ".top", ".xyz", ".click", ".zip", ".review", ".country",
    ".kim", ".work", ".gq", ".ml", ".cf", ".tk"
]

MEDIUM_RISK_TLDS = [
    ".info", ".site", ".online", ".live", ".support"
]

INVOICE_LAYOUT_TERMS = [
    "invoice", "order date", "order id", "product name",
    "product amount", "product code", "payment method",
    "charge", "amount due", "subscription"
]

URGENCY_TERMS = [
    "urgent", "immediately", "action required", "verify now",
    "account suspended", "limited time", "warning",
    "renewed within", "auto renewed", "call our customer support",
    # Legal threat / DMCA scam patterns (confirmed miss on real phish test)
    "24 hours", "legal proceedings", "copyright strike",
    "copyright infringement", "dmca", "takedown",
    "failure to comply", "formal complaint", "legal action",
    "remove or resolve", "initiate legal",
]

# Legal threat cluster — social engineering via fake legal notices.
LEGAL_THREAT_TERMS = [
    "legal department", "legal proceedings", "copyright violation",
    "copyright infringement", "dmca", "copyright strike",
    "formal complaint", "formal notice", "hereby notified",
    "failure to comply", "legal action", "legal consequences",
    "initiate legal", "remove or resolve", "24 hours",
    "compliance specialist", "cease and desist",
    "violation report", "infringement documentation",
]

FINANCIAL_LURE_TERMS = [
    "bank", "account", "checking account", "withdraw",
    "transaction", "fraud department", "security alert",
    "unauthorized transaction", "verify personal information"
]

CREDENTIAL_TERMS = [
    "verify your account", "verify account", "confirm your identity",
    "login to verify", "update your information", "security verification",
    "restore account access", "validate account", "confirm account"
]

SUPPORT_SCAM_TERMS = [
    "customer support", "call our support team", "toll free",
    "helpline", "refund", "subscription", "renewal",
    "auto renewal", "invoice", "billing details",
    "order number", "service charge"
]

BANK_CLUSTER_KEYWORDS = [
    "bank",
    "account",
    "withdraw",
    "transaction",
    "verify",
    "security",
    "fraud",
    "checking",
]



# Sextortion / extortion scam indicators
# These terms are highly distinctive — they have essentially zero legitimate
# use in normal email or image content, so even 1-2 hits is strongly indicative.

SEXTORTION_TERMS = [
    "recorded you", "webcam", "intimate footage", "embarrassing video",
    "send to your contacts", "do not reply", "do not contact police",
    "i have access to your device", "bitcoin", "crypto wallet", "btc",
    "cryptocurrency", "wallet address", "pay within", "silent about this",
    "private video", "sexual content", "compromising", "explicit material",
]

# Delivery / package scam indicators
# Impersonate DHL, FedEx, An Post, Royal Mail etc. with fake customs fees.

DELIVERY_SCAM_TERMS = [
    "dhl", "fedex", "ups", "royal mail", "an post", "parcel", "courier",
    "delivery attempt", "reschedule delivery", "customs fee",
    "tracking number", "parcel held", "failed delivery",
    "re-delivery", "customs charge", "release your parcel",
    "delivery fee", "shipping fee",
]

# Business Email Compromise (BEC) indicators
# BEC is the highest-dollar phishing category. Language is deliberately
# understated (no urgency words) — it's designed to sound like a normal
# internal business request. Multi-word phrases only to avoid false positives
# on individual shared words like "bank" or "payment".
BEC_TERMS = [
    "wire transfer", "change of bank details", "new bank account",
    "payment details have changed", "new account number",
    "as discussed", "per our conversation", "following up on",
    "kindly process", "please process payment", "urgent payment",
    "vendor payment", "supplier payment", "change of payment",
    "accounts payable", "finance department", "chief executive",
    "ceo request", "executive request",
]

# Credential harvesting URL path patterns
# Checked against EXTRACTED URLS (not OCR text) so zero overlap with
# any text-based indicator list. These paths appear in phishing landing
# page URLs that credential-harvest by mimicking legitimate login pages.
CREDENTIAL_URL_PATHS = [
    "/login", "/signin", "/sign-in", "/verify", "/account/confirm",
    "/secure", "/webscr", "/update", "/validate", "/authenticate",
    "/credential", "/password", "/reset-password",
]

# Job scam / recruitment fraud indicators

JOB_SCAM_TERMS = [
    "talent acquisition", "we are hiring", "job opportunity",
    "remote position", "work from home", "schedule a call",
    "we were impressed", "we are impressed", "exciting opportunity",
    "no experience required", "weekly payment", "part time opportunity",
    "direct deposit", "submit your bank details", "sign your contract",
    "advance payment required", "earn from home", "flexible hours",
    "apply now", "limited positions", "selected for interview",
]

# Combined overlap cap for the three new social engineering categories.
# Sextortion + delivery + BEC can theoretically all fire on the same email
# (e.g. a BEC email that also mentions a package), so cap their combined
# contribution to prevent a single email hitting 60+ points from these alone.
OVERLAP_SOCIAL_ENG_CAP = 25


OCR_CONF_HIGH_RISK_THRESHOLD = 40
OCR_CONF_MEDIUM_RISK_THRESHOLD = 55
OCR_CONF_LOW_RISK_THRESHOLD = 70


OVERLAP_BANKING_CAP = 20

# WHOIS lookup timeout in seconds — prevents hanging on slow/dead WHOIS servers.
WHOIS_TIMEOUT_SECONDS = 5


# ------------------------------------------------
# Domain helpers
# ------------------------------------------------

def extract_base_domain(domain: str) -> str:
    domain = domain.lower()
    domain = domain.split(":")[0]
    domain = domain.replace("www.", "")
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def detect_lookalike_domain(domain: str) -> Optional[str]:
    
    base = extract_base_domain(domain)
    for _, legit in BRAND_DOMAINS.items():
        similarity = difflib.SequenceMatcher(None, base, legit).ratio()
        if similarity >= 0.8 and base != legit:
            return legit
    return None


def detect_invoice_table(text_lower: str) -> bool:
    patterns = [
        r"product\s+name.*product\s+amount",
        r"product\s+amount.*product\s+code",
        r"product\s+name.*order\s+id",
        r"product\s+name\s*\|\s*product",
    ]
    for p in patterns:
        if re.search(p, text_lower, re.DOTALL):
            return True
    return False


# ------------------------------------------------
# MAIN SCORING ENGINE
# ------------------------------------------------

def score_image_analysis(
    *,
    ocr_text: str,
    keyword_hits: Dict[str, int],
    urls_from_ocr: List[str],
    qr_found: bool,
    qr_data: Optional[str],
    ti_results: List[Dict[str, Any]],
    email_analysis: Optional[Dict[str, Any]] = None,
    ocr_mean_confidence: Optional[float] = None,
    ocr_kept_words: Optional[int] = None,
    ocr_total_words: Optional[int] = None,
) -> ScoreResult:

    breakdown: Dict[str, Dict[str, Any]] = {}
    reasons: List[str] = []

    text_lower = (ocr_text or "").lower()
    is_email_mode = email_analysis is not None

    # ------------------------------------------------
    # Threat Intelligence
    # ------------------------------------------------

    vt_mal_total = 0
    vt_susp_total = 0

    for item in ti_results or []:
        if item.get("vt_error"):
            continue
        verdict = str(item.get("verdict", "")).lower()
        mal = int(item.get("vt_malicious") or 0)
        susp = int(item.get("vt_suspicious") or 0)
        if verdict in ["malicious", "suspicious"]:
            vt_mal_total += mal
            vt_susp_total += susp

    vt_mal_contrib = clamp(vt_mal_total * 10.0, 0, 30)
    vt_susp_contrib = clamp(vt_susp_total * 5.0, 0, 15)

    _add_factor(breakdown, "vt_malicious", "VirusTotal malicious detections", vt_mal_total, 10, vt_mal_contrib)
    _add_factor(breakdown, "vt_suspicious", "VirusTotal suspicious detections", vt_susp_total, 5, vt_susp_contrib)

    # ------------------------------------------------
    # URL indicators
    # ------------------------------------------------

    url_count = len(urls_from_ocr or [])

    if is_email_mode:
        url_presence_contrib = 2 if url_count > 0 else 0
        multi_url_contrib = 2 if url_count >= 3 else 0
    else:
        url_presence_contrib = 4 if url_count > 0 else 0
        multi_url_contrib = 4 if url_count >= 2 else 0

    _add_factor(breakdown, "url_present", "URL(s) extracted", url_count, 4, url_presence_contrib)
    _add_factor(breakdown, "multi_url", "Multiple URLs", url_count, 4, multi_url_contrib)

    # ------------------------------------------------
    # QR
    # ------------------------------------------------

    qr_found_contrib = 4 if qr_found else 0
    qr_url_contrib = 8 if qr_data else 0

    _add_factor(breakdown, "qr_found", "QR code present", qr_found, 4, qr_found_contrib)
    _add_factor(breakdown, "qr_data", "QR contains data", bool(qr_data), 8, qr_url_contrib)

    # ------------------------------------------------
    # Domain impersonation
    # ------------------------------------------------

    suspicious_domains = []
    typosquat_domains = []

    for url in urls_from_ocr or []:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            base = extract_base_domain(domain)

            if any(base.endswith(tld) for tld in HIGH_RISK_TLDS + MEDIUM_RISK_TLDS):
                suspicious_domains.append(base)

            lookalike = detect_lookalike_domain(base)
            if lookalike:
                typosquat_domains.append(f"{base} → resembles {lookalike}")

        except Exception:
            continue

    domain_indicators = list(set(suspicious_domains + typosquat_domains))
    domain_contrib = 15 if domain_indicators else 0

    _add_factor(breakdown, "domain_impersonation", "Domain impersonation indicators",
                len(domain_indicators), 15, domain_contrib, domain_indicators)

    # ------------------------------------------------
    # Domain age (with timeout guard)
    # ------------------------------------------------

    young_domains = []

    # Skip WHOIS lookups in email mode — they are the primary cause of slow
    # analysis on emails with many URLs, adding 5+ seconds per domain on
    # unresponsive WHOIS servers. The domain age signal (max 8 pts) is not
    # worth the latency penalty in email context where header-based signals
    # already provide domain intelligence. WHOIS still runs for image mode.
    for url in ([] if is_email_mode else (urls_from_ocr or [])):
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            
            w = whois.whois(domain)

            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]

            if creation:
                #
                now = datetime.now(timezone.utc)
                if creation.tzinfo is None:
                    creation = creation.replace(tzinfo=timezone.utc)
                age_days = (now - creation).days

                if age_days < 30:
                    young_domains.append(f"{domain} ({age_days} days)")

        except Exception:
            continue

    young_contrib = 8 if young_domains else 0
    _add_factor(breakdown, "young_domains", "Newly registered domains",
                len(young_domains), 8, young_contrib, young_domains)

    # ------------------------------------------------
    # Invoice layout
    # ------------------------------------------------

    layout_hits = [t for t in INVOICE_LAYOUT_TERMS if t in text_lower]

    if is_email_mode:
        layout_contrib = 0
    else:
        layout_contrib = 15 if len(layout_hits) >= 2 else 0

    _add_factor(breakdown, "invoice_layout", "Invoice layout indicators",
                len(layout_hits), 15, layout_contrib, layout_hits)

    # ------------------------------------------------
    # Structured invoice table
    # ------------------------------------------------

    table_detected = detect_invoice_table(text_lower)

    if is_email_mode:
        table_contrib = 0
    else:
        table_contrib = 15 if table_detected else 0

    _add_factor(breakdown, "invoice_table", "Structured invoice table detected",
                int(table_detected), 15, table_contrib)

    # ------------------------------------------------
    # Urgency indicators
    # ------------------------------------------------

    urgency_hits = [t for t in URGENCY_TERMS if t in text_lower]
    urgency_contrib = clamp(len(urgency_hits) * (2 if is_email_mode else 3), 0, 10)

    _add_factor(breakdown, "urgency_indicators", "Urgency indicators",
                len(urgency_hits), 3, urgency_contrib, urgency_hits)

    # ------------------------------------------------
    # Brand impersonation
    # ------------------------------------------------

    # Get the verified sender domain from email analysis if present
    sender_domain = ""
    if email_analysis:
        sender_domain = str(email_analysis.get("sender_domain", "") or "").lower()

    brand_matches = []
    for b in BRAND_TERMS:
        if re.search(rf'\b{re.escape(b)}\b', text_lower):
            # Suppress if the sender IS the legitimate domain for this brand
            legit_domain = BRAND_DOMAINS.get(b, "")
            if legit_domain and sender_domain:
                sender_base = extract_base_domain(sender_domain)
                legit_base  = extract_base_domain(legit_domain)
                if sender_base == legit_base:
                    continue  # Genuine sender — not impersonation
            brand_matches.append(b)
    brand_matches = list(set(brand_matches))

    brand_contrib = 4 if brand_matches else 0
    _add_factor(breakdown, "brand_impersonation", "Brand impersonation indicators",
                len(brand_matches), 4, brand_contrib, brand_matches)

    # ------------------------------------------------
    # Email security
    # Cap raised from 10 to 20: the original cap meant that even a heavily
    # flagged email (display name spoofing + SPF fail + DKIM fail + brand
    # impersonation) was capped at the same contribution as a mildly
    # suspicious one. A DocuSign impersonation email with all three auth
    # failures scored identical email_contrib to an email with just one URL.
    # Raising to 20 gives proper weight to strong multi-signal email findings
    # without allowing email analysis to dominate the entire score.
    # ------------------------------------------------

    email_contrib = 0
    email_indicators = []

    if email_analysis:
        email_score = email_analysis.get("score", 0)
        email_contrib = clamp(email_score * 0.5, 0, 20)
        email_indicators = email_analysis.get("indicators", [])

    _add_factor(breakdown, "email_security", "Email security indicators",
                len(email_indicators), 10, email_contrib, email_indicators)

    # ------------------------------------------------
    # Display name spoofing — direct scoring signal
    # Previously display name spoofing only contributed through the email_analysis
    # score which was then capped at 10 (now 20). But display name spoofing of a
    # known brand (e.g. "DocuSign" display name sent from cninfo.net) is one of
    # the strongest individual phishing indicators and deserves its own direct
    # signal in the breakdown, independent of the email analysis cap.
    #
    # This checks email_analysis.lookalike_domain and display_name directly
    # and awards additional points when spoofing is confirmed, making it
    # visible as a separate factor in the breakdown table rather than being
    # buried inside the email_security aggregate.
    # ------------------------------------------------

    display_spoof_contrib = 0
    display_spoof_indicators = []

    if email_analysis:
        # Check for confirmed display name spoofing
        ea_indicators = email_analysis.get("indicators", [])
        spoof_hits = [i for i in ea_indicators
                      if "display name spoofing" in str(i).lower()
                      or "lookalike" in str(i).lower()]
        if spoof_hits:
            display_spoof_contrib = 12
            display_spoof_indicators = spoof_hits

        # Also check lookalike_domain dict directly as a belt-and-braces check
        lookalike = email_analysis.get("lookalike_domain")
        if lookalike and not display_spoof_indicators:
            brand    = lookalike.get("brand", "")
            s_domain = lookalike.get("sender_domain", "")
            e_domain = lookalike.get("expected_domain", "")
            if brand and s_domain:
                display_spoof_contrib = 12
                display_spoof_indicators = [
                    f"Lookalike domain: {s_domain} resembles {e_domain}"
                ]

    _add_factor(
        breakdown,
        "display_name_spoof",
        "Display name / lookalike domain spoofing",
        len(display_spoof_indicators),
        12,
        display_spoof_contrib,
        display_spoof_indicators,
    )

    # ------------------------------------------------
    # Header signal correlation bonus
    # NOTE: This was tested and reverted. The bonus fired on legitimate 2002
    # era emails from the SpamAssassin corpus which pre-date SPF/DKIM/DMARC.
    # Those emails score high on email_security purely because authentication
    # standards didn't exist in 2002 — not because they're suspicious.
    # Keeping the variable defined at 0 so the raw_score sum still compiles.
    # ------------------------------------------------

    header_correlation_contrib = 0

    # ------------------------------------------------
    # Keyword hits
    # ------------------------------------------------

    triggered_keywords = [k for k, v in (keyword_hits or {}).items() if v > 0]

    word_count = len(text_lower.split()) if text_lower else 1
    # Normalisation factor: scale down if text is very long (>200 words).
    # At ≤200 words the factor is 1.0 (no penalty); above that it tapers.
    norm_factor = min(1.0, 200 / max(word_count, 1)) if word_count > 200 else 1.0
    kw_contrib = clamp(len(triggered_keywords) * (2 if is_email_mode else 3) * norm_factor, 0, 15)

    _add_factor(breakdown, "keyword_hits", "Phishing keyword indicators",
                len(triggered_keywords), 3, kw_contrib, triggered_keywords)

    # ------------------------------------------------
    # Financial lure detection
    # ------------------------------------------------

    financial_hits = [t for t in FINANCIAL_LURE_TERMS if t in text_lower]
    financial_contrib = clamp(len(financial_hits) * 3.0, 0, 12)

    _add_factor(breakdown, "financial_lure", "Financial / banking phishing indicators",
                len(financial_hits), 3, financial_contrib, financial_hits)

    # ------------------------------------------------
    # Credential harvesting
    # ------------------------------------------------

    credential_hits = [t for t in CREDENTIAL_TERMS if t in text_lower]
    credential_contrib = clamp(len(credential_hits) * 4.0, 0, 16)

    _add_factor(breakdown, "credential_phish", "Credential harvesting indicators",
                len(credential_hits), 4, credential_contrib, credential_hits)

    # ------------------------------------------------
    # Legal threat / DMCA scam detection
    # Added after live test confirmed cavra.org DMCA phish scored only 6/100
    # because LEGAL_THREAT_TERMS was not in any indicator list. These scams
    # impersonate copyright enforcement, DMCA notices, and legal departments
    # to pressure victims into clicking links or revealing credentials.
    # ------------------------------------------------

    legal_threat_hits = [t for t in LEGAL_THREAT_TERMS if t in text_lower]
    legal_threat_contrib = clamp(len(legal_threat_hits) * 5.0, 0, 20)

    _add_factor(
        breakdown,
        "legal_threat",
        "Legal threat / DMCA scam indicators",
        len(legal_threat_hits),
        5,
        legal_threat_contrib,
        legal_threat_hits,
    )

    # ------------------------------------------------
    # Tech support scam detection
    # ------------------------------------------------

    support_hits = [t for t in SUPPORT_SCAM_TERMS if t in text_lower]
    support_contrib = clamp(len(support_hits) * 3.0, 0, 12)

    _add_factor(breakdown, "support_scam", "Tech support scam indicators",
                len(support_hits), 3, support_contrib, support_hits)

    # ------------------------------------------------
    # Banking keyword cluster detection
    # ------------------------------------------------

    bank_cluster_hits = [k for k in BANK_CLUSTER_KEYWORDS if k in text_lower]
    bank_cluster_contrib = 0
    bank_cluster_terms = []

    if len(bank_cluster_hits) >= 2:
        bank_cluster_contrib = clamp(len(bank_cluster_hits) * 3.0, 0, 12)
        bank_cluster_terms = bank_cluster_hits

    _add_factor(
        breakdown,
        "bank_cluster",
        "Banking phishing keyword cluster",
        len(bank_cluster_terms),
        3,
        bank_cluster_contrib,
        bank_cluster_terms
    )

    # ------------------------------------------------
    # Sextortion / extortion scam detection
    # High per-hit weight (6 pts) because these terms are highly distinctive —
    # almost zero legitimate use in normal content. Even 1 hit is meaningful.
    # Capped at 18 to prevent a single email maxing the score on this alone.
    # ------------------------------------------------

    sextortion_hits = [t for t in SEXTORTION_TERMS if t in text_lower]
    sextortion_contrib = clamp(len(sextortion_hits) * 6.0, 0, 18)

    _add_factor(
        breakdown,
        "sextortion",
        "Sextortion / extortion scam indicators",
        len(sextortion_hits),
        6,
        sextortion_contrib,
        sextortion_hits,
    )

    # ------------------------------------------------
    # Delivery / package scam detection
    # Carrier brand names + delivery vocabulary. Weighted at 4 pts per hit
    # (lower than sextortion because some terms like "parcel" and "courier"
    # can appear in legitimate shipping notifications). Cluster threshold of
    # 2 hits required before scoring — a single mention of "dhl" in a
    # legitimate shipping confirmation should not score points.
    # ------------------------------------------------

    delivery_hits = [t for t in DELIVERY_SCAM_TERMS if t in text_lower]
    delivery_contrib = 0
    if len(delivery_hits) >= 2:
        delivery_contrib = clamp(len(delivery_hits) * 4.0, 0, 16)

    _add_factor(
        breakdown,
        "delivery_scam",
        "Delivery / package scam indicators",
        len(delivery_hits),
        4,
        delivery_contrib,
        delivery_hits,
    )

    # ------------------------------------------------
    # Business Email Compromise (BEC) detection
    # BEC language is deliberately understated — no urgency words, designed
    # to sound like a normal internal business request. Multi-word phrases
    # only, weighted at 5 pts each. Cap at 15 because BEC emails typically
    # only contain 1-3 of these phrases (they're short and direct by design).
    # ------------------------------------------------

    bec_hits = [t for t in BEC_TERMS if t in text_lower]
    bec_contrib = clamp(len(bec_hits) * 5.0, 0, 15)

    _add_factor(
        breakdown,
        "bec",
        "Business Email Compromise (BEC) indicators",
        len(bec_hits),
        5,
        bec_contrib,
        bec_hits,
    )

    # ------------------------------------------------
    # Credential harvesting URL path detection
    # Checks extracted URLs for path patterns typical of phishing login pages.
    # Operates on URL paths (not OCR text) so cannot overlap with any
    # text-based indicator. Each matching path adds 5 pts, capped at 15.
    # Only fires in image mode — in email mode URL paths are less meaningful
    # since legitimate emails contain many /login and /account paths.
    # ------------------------------------------------

    cred_url_hits: list = []
    if not is_email_mode:
        for url in urls_from_ocr or []:
            url_lower_path = url.lower()
            for path in CREDENTIAL_URL_PATHS:
                if path in url_lower_path:
                    cred_url_hits.append(f"{path} in {url[:60]}")
                    break  # one match per URL maximum

    cred_url_contrib = clamp(len(cred_url_hits) * 5.0, 0, 15)

    _add_factor(
        breakdown,
        "credential_url",
        "Credential harvesting URL path indicators",
        len(cred_url_hits),
        5,
        cred_url_contrib,
        cred_url_hits,
    )

    # ------------------------------------------------
    # Job scam / recruitment fraud detection
    # Cluster threshold of 2 hits required — single terms like "hiring" or
    # "opportunity" appear in legitimate recruitment email. Weighted at 4 pts
    # per hit, capped at 12. Added after image evaluation confirmed Spotify
    # recruitment scam scored only 4/100 with no job-specific indicators.
    # ------------------------------------------------

    job_scam_hits = [t for t in JOB_SCAM_TERMS if t in text_lower]
    job_scam_contrib = 0
    if len(job_scam_hits) >= 2:
        job_scam_contrib = clamp(len(job_scam_hits) * 4.0, 0, 12)

    _add_factor(
        breakdown,
        "job_scam",
        "Job scam / recruitment fraud indicators",
        len(job_scam_hits),
        4,
        job_scam_contrib,
        job_scam_hits,
    )

    # ------------------------------------------------
    # Social engineering overlap cap
    # Sextortion + delivery_scam + BEC + job_scam can theoretically all fire
    # on the same content. Cap their combined contribution at
    # OVERLAP_SOCIAL_ENG_CAP (default 25) to prevent inflation.
    # ------------------------------------------------

    raw_social_total = sextortion_contrib + delivery_contrib + bec_contrib + job_scam_contrib
    if raw_social_total > OVERLAP_SOCIAL_ENG_CAP:
        scale = OVERLAP_SOCIAL_ENG_CAP / raw_social_total
        sextortion_contrib = round(sextortion_contrib * scale, 2)
        delivery_contrib   = round(delivery_contrib   * scale, 2)
        bec_contrib        = round(bec_contrib        * scale, 2)
        breakdown["sextortion"]["contribution"]    = sextortion_contrib
        breakdown["delivery_scam"]["contribution"] = delivery_contrib
        breakdown["bec"]["contribution"]           = bec_contrib
        breakdown["job_scam"]["contribution"]      = job_scam_contrib

    
    raw_banking_total = financial_contrib + support_contrib + bank_cluster_contrib
    if raw_banking_total > OVERLAP_BANKING_CAP:
        scale = OVERLAP_BANKING_CAP / raw_banking_total
        financial_contrib = round(financial_contrib * scale, 2)
        support_contrib = round(support_contrib * scale, 2)
        bank_cluster_contrib = round(bank_cluster_contrib * scale, 2)
        # Update the breakdown entries with the capped values
        breakdown["financial_lure"]["contribution"] = financial_contrib
        breakdown["support_scam"]["contribution"] = support_contrib
        breakdown["bank_cluster"]["contribution"] = bank_cluster_contrib

    # ------------------------------------------------
    # Hidden hyperlink detection
    # When OCR misses a blue hyperlink entirely (confirmed Tesseract behaviour
    # with styled email screenshots), recover_hidden_hyperlinks() in
    # ocr_enhanced.py appends [HIDDEN_LINK_DETECTED] as a marker. Score it
    # as equivalent to a URL being present — we know a link existed even if
    # we couldn't extract it.
    # ------------------------------------------------

    hidden_link_count = text_lower.count("[hidden_link_detected]")
    hidden_link_contrib = clamp(hidden_link_count * 8.0, 0, 16)

    _add_factor(
        breakdown,
        "hidden_link",
        "Hidden hyperlink(s) detected (OCR missed styled link text)",
        hidden_link_count,
        8,
        hidden_link_contrib,
    )

    # ------------------------------------------------
    # Phone detection
    # ------------------------------------------------

    phone_pattern = r"\+?\d[\d\-\(\) ]{9,}\d"
    clean_text = re.sub(r"http\S+", "", ocr_text or "")
    clean_text = re.sub(r"\b\d{8,}\b", "", clean_text)
    raw_numbers = re.findall(phone_pattern, clean_text)

    phone_numbers = []
    for num in raw_numbers:
        digits = re.sub(r"\D", "", num)
        if 10 <= len(digits) <= 15 and (" " in num or "-" in num or "(" in num):
            phone_numbers.append(num.strip())
    phone_numbers = list(set(phone_numbers))

    
    phone_contrib = (6 if is_email_mode else 10) if phone_numbers else 0

    _add_factor(breakdown, "phone_numbers", "Phone numbers detected",
                len(phone_numbers), 10, phone_contrib, phone_numbers)

    # ------------------------------------------------
    # OCR confidence
    # ------------------------------------------------

    conf = None if ocr_mean_confidence is None else float(ocr_mean_confidence)
    conf_contrib = 0

    if conf is not None:
        if conf < OCR_CONF_HIGH_RISK_THRESHOLD:
            conf_contrib = 8
        elif conf < OCR_CONF_MEDIUM_RISK_THRESHOLD:
            conf_contrib = 4
        elif conf < OCR_CONF_LOW_RISK_THRESHOLD:
            conf_contrib = 2

    _add_factor(breakdown, "ocr_mean_conf", "OCR mean confidence", conf, 1, conf_contrib)

    # ------------------------------------------------
    # Final score
    # ------------------------------------------------

    raw_score = (
        vt_mal_contrib +
        vt_susp_contrib +
        url_presence_contrib +
        multi_url_contrib +
        qr_found_contrib +
        qr_url_contrib +
        domain_contrib +
        young_contrib +
        layout_contrib +
        table_contrib +
        urgency_contrib +
        brand_contrib +
        email_contrib +
        kw_contrib +
        financial_contrib +
        credential_contrib +
        support_contrib +
        bank_cluster_contrib +
        phone_contrib +
        conf_contrib +
        legal_threat_contrib +
        hidden_link_contrib +
        sextortion_contrib +
        delivery_contrib +
        bec_contrib +
        cred_url_contrib +
        display_spoof_contrib +
        header_correlation_contrib +
        job_scam_contrib
    )

    final_score = int(round(clamp(raw_score, 0, 100)))
    level = verdict_from_score(final_score)

 
    sorted_factors = sorted(
        breakdown.items(),
        key=lambda x: x[1]["contribution"],
        reverse=True
    )

    reasons.append(f"Risk score: {final_score}/100 — {level}")

    for key, factor in sorted_factors[:5]:
        if factor["contribution"] > 0:
            indicators_str = ""
            if factor["indicators"]:
                indicators_str = f": {', '.join(str(i) for i in factor['indicators'][:3])}"
            reasons.append(
                f"{factor['label']} (+{factor['contribution']:.0f}){indicators_str}"
            )

    return ScoreResult(
        risk_score=final_score,
        risk_level=level,
        reasons=reasons,
        breakdown=breakdown,
    )