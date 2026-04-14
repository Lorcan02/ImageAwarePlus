from __future__ import annotations

import re
from typing import List


MIN_URL_LENGTH = 10


KNOWN_TLDS = r"com|net|org|ie|co\.uk|co|uk|io|edu|gov|top|xyz|click|info|site|online|live"


def _dedupe(items: List[str]) -> List[str]:
    seen: set = set()
    out: List[str] = []
    for x in items:
        if x not in seen:
            out.append(x)
            seen.add(x)
    return out


def repair_ocr_text_for_urls(text: str) -> str:
    """
    Normalise OCR text to make broken URLs more extractable.

    Repairs common OCR URL breakages:
    - "http //", "https //" -> "http://", "https://"
    - "www example com" -> "www.example.com"
    - "trustedbank com" -> "trustedbank.com"
    - line breaks inside URLs -> joined
    """
    t = text

    # Split concatenated scheme URLs before any other processing.
    # Apple and other senders write plain text bodies with URLs joined
    # back-to-back with no whitespace between them, producing strings like:
    # "https://a.com/pagehttps://b.com/page"
    # Insert a newline before each http(s):// that isn't at the start
    # of the string so downstream extraction sees them as separate URLs.
    t = re.sub(r'(?<!^)(?<!\n)(?=https?://)', '\n', t)

    # Normalise whitespace
    t = t.replace("\r", "\n")
    t = re.sub(r"[ \t]+", " ", t)

    # Common OCR: "http //", "https //", "http: //"
    t = re.sub(
        r"\bhttps?\s*:\s*//\s*",
        lambda m: m.group(0).replace(" ", ""),
        t,
        flags=re.IGNORECASE,
    )
    t = re.sub(
        r"\bhttps?\s*//\s*",
        lambda m: m.group(0).replace(" ", ""),
        t,
        flags=re.IGNORECASE,
    )

    # Common OCR: "h t t p" split (rare but happens)
    t = re.sub(
        r"\bh\s*t\s*t\s*p\s*s?\b",
        lambda m: m.group(0).replace(" ", ""),
        t,
        flags=re.IGNORECASE,
    )

    # Join "www . example . com" or "www example com"
    t = re.sub(r"\bwww\s*\.\s*", "www.", t, flags=re.IGNORECASE)

    # Replace " dot " with "." (OCR sometimes outputs 'dot' literally)
    t = re.sub(r"\s+dot\s+", ".", t, flags=re.IGNORECASE)

    # Join common TLD patterns that OCR may split: "example com" -> "example.com"
    # Conservative: only when followed by a known TLD
    t = re.sub(
        r"\b([a-z0-9-]{2,})\s+\.(\s*)?([a-z]{2,})\b",
        r"\1.\3",
        t,
        flags=re.IGNORECASE,
    )
    t = re.sub(
        rf"\b([a-z0-9-]{{2,}})\s+({KNOWN_TLDS})\b",
        r"\1.\2",
        t,
        flags=re.IGNORECASE,
    )

    
    t = re.sub(
        r"(https?://[^\s]*)\s*/\s*",
        lambda m: m.group(0).replace(" ", ""),
        t,
        flags=re.IGNORECASE,
    )

    
    t = re.sub(
        r"(https?://[^\s\n]+)\n([a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;%=-]+)",
        r"\1\2",
        t,
        flags=re.IGNORECASE,
    )
    t = re.sub(
        r"(www\.[^\s\n]+)\n([a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;%=-]+)",
        r"\1\2",
        t,
        flags=re.IGNORECASE,
    )

    
    t = re.sub(
        rf":(?=[a-z0-9-]+\.({KNOWN_TLDS})\b)",
        ": ",
        t,
        flags=re.IGNORECASE,
    )

    # Remove spaces that appear mid-path like "/general...info asp" -> "/general...info.asp"
    t = re.sub(
        r"(/[^ \n]{2,})\s+([a-z]{2,4})\b",
        r"\1.\2",
        t,
        flags=re.IGNORECASE,
    )

    return t


def extract_candidate_urls(text: str) -> List[str]:
    """
    Extract:
    - full scheme URLs: https?://...
    - www. URLs
    - bare domains like trustedbank.com/path
    """
    urls: List[str] = []

    # Split concatenated URLs before extraction.
    # Without this, back-to-back URLs like "https://a.comhttps://b.com"
    # are captured as a single malformed string.
    text = re.sub(r'(?<!^)(?<!\n)(?=https?://)', '\n', text)

    scheme_urls = re.findall(r"(https?://[^\s]+)", text, flags=re.IGNORECASE)
    www_urls = re.findall(r"\b(www\.[^\s]+)", text, flags=re.IGNORECASE)

    
    bare_urls = re.findall(
        rf"\b([a-z0-9-]{{3,}}(?:\.[a-z0-9-]{{2,}})+\.(?:{KNOWN_TLDS})(?:/[^\s]*)?)\b",
        text,
        flags=re.IGNORECASE,
    )

    urls.extend(scheme_urls)
    urls.extend(www_urls)
    urls.extend(bare_urls)

    cleaned: List[str] = []
    for u in urls:
        u = u.strip().strip(").,;:'\"[]{}<>")
        
        if len(u) >= MIN_URL_LENGTH:
            cleaned.append(u)

    return _dedupe(cleaned)


def normalize_url(url: str) -> str:
    """
    Normalise scheme-less URLs to include http:// for threat intelligence checks.
    """
    u = url.strip()

    if u.lower().startswith("http://") or u.lower().startswith("https://"):
        return u

    
    if u.lower().startswith("www."):
        return "http://" + u

    if re.match(
        rf"^[a-z0-9-]{{3,}}(\.[a-z0-9-]{{2,}})+\.({KNOWN_TLDS})(/.*)?$",
        u,
        re.IGNORECASE,
    ) and len(u) >= MIN_URL_LENGTH:
        return "http://" + u

    return u


def extract_urls_robust(ocr_text: str) -> List[str]:
    """
    Robust URL extraction:
    1) Run extraction on raw text first (catches clean URLs before repair)
    2) Repair OCR text and extract again (catches broken/split URLs)
    3) Merge, normalise, and deduplicate
    """
    
    raw_candidates = extract_candidate_urls(ocr_text)

    repaired = repair_ocr_text_for_urls(ocr_text)
    repaired_candidates = extract_candidate_urls(repaired)

    all_candidates = raw_candidates + [
        c for c in repaired_candidates if c not in set(raw_candidates)
    ]

    normalized = [normalize_url(u) for u in all_candidates]
    return _dedupe(normalized)