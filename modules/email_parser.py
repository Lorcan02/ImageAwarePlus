from __future__ import annotations

import email
import os
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any, Dict, List, Optional


# FIX 1: Centralised header extraction into a single shared helper used by
# both parse_eml() and analyze_eml(). The original duplicated this logic in
# two places and — critically — analyze_eml() was missing the reply-to header
# entirely. This broke the email_analysis.py reply-to mismatch detection for
# every single .eml file processed, because the header was never passed in.
# Also added extraction of authentication headers (Authentication-Results,
# Received-SPF, DKIM-Signature) needed by the SPF/DKIM/DMARC checks we added
# to email_analysis.py.
def _extract_headers(msg: email.message.Message) -> Dict[str, Optional[str]]:
    return {
        "subject":                msg.get("subject"),
        "from":                   msg.get("from"),
        "to":                     msg.get("to"),
        "date":                   msg.get("date"),
        "reply-to":               msg.get("reply-to"),
        "authentication-results": msg.get("authentication-results"),
        "received-spf":           msg.get("received-spf"),
        "dkim-signature":         msg.get("dkim-signature"),
    }


def _extract_body(msg: email.message.Message) -> str:
    """
    FIX 2: The original concatenated plain text and HTML parts together
    into one string. This produces garbled output — HTML tags pollute the
    plain text, keyword matching fires on HTML attribute names, and URL
    extraction finds href= values mixed with visible text URLs.

    Strategy: prefer plain text if any part has it. Only fall back to
    HTML (with tags stripped) if there is no plain text part at all.
    HTML stripping uses a simple regex which is sufficient for email bodies
    — we don't need a full HTML parser here.
    """
    plain_parts: List[str] = []
    html_parts:  List[str] = []

    for part in msg.walk():
        content_type = part.get_content_type()
        disposition  = str(part.get("Content-Disposition", ""))
        if "attachment" in disposition:
            continue
        try:
            if content_type == "text/plain":
                plain_parts.append(part.get_content())
            elif content_type == "text/html":
                html_parts.append(part.get_content())
        except Exception:
            continue

    # Always extract href/action URLs from ALL HTML parts, regardless of
    # whether a plain text part also exists. This is the critical fix for
    # emails like DocuSign phishing where:
    # - A plain text part exists but contains only whitespace/garbled text
    # - The actual phishing URL is in an href inside the HTML part
    # - The old code returned the plain text immediately and never saw the href
    # Now we extract hrefs from HTML first, then prefer plain text for the
    # visible body content, and append the hrefs to whatever body we return.
    _href_pat = re.compile(r'href=["\']([ ^"\'\\t\\n\\r>]{8,})["\']', re.IGNORECASE)
    _act_pat  = re.compile(r'action=["\']([ ^"\'\\t\\n\\r>]{8,})["\']', re.IGNORECASE)
    all_hrefs: List[str] = []
    for html_part in html_parts:
        all_hrefs += _href_pat.findall(html_part)
        all_hrefs += _act_pat.findall(html_part)

    seen_href: set = set()
    clean_hrefs: List[str] = []
    for u in all_hrefs:
        # Decode HTML entities before processing
        u = u.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
        u = u.strip()
        u_lower = u.lower()
        if u_lower.startswith(("#", "mailto:", "javascript:", "tel:")):
            continue
        if not (u_lower.startswith("http://") or
                u_lower.startswith("https://") or
                u_lower.startswith("www.")):
            continue
        # If URL contains a redirect (multiple http schemes), extract just
        # the outer/first URL. Phishing links often use redirect chains like:
        # https://attacker.com/redir?url=https://docusign.net/...
        # The outer URL is the phishing domain — that's what we want to score.
        if u_lower.count("http") > 1:
            import re as _re
            parts = _re.split(r'(?<!^)(?=https?://)', u)
            u = parts[0].rstrip("?&=")
            u_lower = u.lower()
        if u not in seen_href:
            seen_href.add(u)
            clean_hrefs.append(u)

    if plain_parts:
        body = "\n\n".join(plain_parts).strip()
        if clean_hrefs:
            body += "\n\n" + "\n".join(clean_hrefs)
        return body


    if html_parts:
        raw_html = "\n\n".join(html_parts)

        # FIX: Extract href URLs from HTML BEFORE stripping tags.
        # When HTML tags are stripped with a regex, anchor tags like
        # <a href="https://phishing-url.com">Sign in</a> become just
        # "Sign in" — the phishing URL is thrown away completely and
        # never reaches VirusTotal/URLScan/PhishTank.
        # Also extracts action= attributes (form submission targets)
        # which phishing pages use to capture credentials silently.
        # Extract href and action URLs using a tighter pattern that
        # stops at whitespace or tag boundaries, preventing adjacent
        # href values from being concatenated into malformed strings.
        # The original [^"']{8,} pattern consumed across newlines and
        # tag boundaries, causing URLs like:
        # "https://a.com/pagehttps://b.com/page" (two joined together)
        # Extract href and action URLs using a tighter pattern.
        # The original pattern consumed across whitespace/tag boundaries
        # causing adjacent URLs to concatenate into malformed strings like:
        # "https://a.com/pagehttps://b.com/page"
        # Fixed by stopping at whitespace (\s) and tag close (>).
        _href_pat = re.compile(r'href=["\']([^"\' \t\n\r>]{8,})["\']', re.IGNORECASE)
        _act_pat  = re.compile(r'action=["\']([^"\' \t\n\r>]{8,})["\']', re.IGNORECASE)
        href_urls: List[str]   = _href_pat.findall(raw_html)
        action_urls: List[str] = _act_pat.findall(raw_html)
        seen_urls: set = set()
        extracted_urls: List[str] = []
        for u in href_urls + action_urls:
            u = u.strip()
            u_lower = u.lower()
            if u_lower.startswith(("#", "mailto:", "javascript:", "tel:")):
                continue
            # Only accept properly formed URLs
            if not (u_lower.startswith("http://") or
                    u_lower.startswith("https://") or
                    u_lower.startswith("www.")):
                continue
            # Reject concatenated URLs (contain more than one scheme)
            if u_lower.count("http") > 1:
                continue
            if u not in seen_urls:
                seen_urls.add(u)
                extracted_urls.append(u)

        # Strip HTML tags and decode common entities
        text = re.sub(r"<[^>]+>", " ", raw_html)
        text = text.replace("&nbsp;", " ")
        text = text.replace("&amp;", "&")
        text = text.replace("&lt;", "<")
        text = text.replace("&gt;", ">")
        text = text.replace("&quot;", '"')
        # Collapse whitespace
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        text = text.strip()

        # Append extracted href/action URLs as plain text so
        # extract_urls_robust() picks them up for threat intel.
        if extracted_urls:
            text += "\n\n" + "\n".join(extracted_urls)

        return text


    return ""


def _extract_images(
    msg: email.message.Message,
    output_dir: str | Path,
) -> List[str]:
    """
    FIX 3: The original used part.get_filename() with a hardcoded fallback
    of "email_image.png" for every unnamed attachment. If an email had two
    unnamed image attachments the second would silently overwrite the first
    on disk, and only one image path would be returned in the list.
    Fixed by appending a counter suffix to guarantee unique filenames.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    saved: List[str] = []
    counter = 0

    for part in msg.walk():
        content_type = part.get_content_type()

        if not content_type.startswith("image/"):
            continue

        filename = part.get_filename()

        if not filename:
            # Derive extension from content type (e.g. image/jpeg → .jpg)
            subtype = content_type.split("/")[-1].lower()
            ext_map = {"jpeg": "jpg", "svg+xml": "svg"}
            ext = ext_map.get(subtype, subtype)
            filename = f"email_image_{counter}.{ext}"
        else:
            # Even named files could collide if an email has duplicates
            stem = Path(filename).stem
            suffix = Path(filename).suffix
            candidate = output_dir / filename
            if candidate.exists():
                filename = f"{stem}_{counter}{suffix}"

        counter += 1
        filepath = output_dir / filename

        try:
            payload = part.get_payload(decode=True)
            if payload:
                filepath.write_bytes(payload)
                saved.append(str(filepath))
        except Exception:
            continue

    return saved


def parse_eml(file_path: str | Path) -> Dict[str, Any]:
    """
    Parse an .eml file and return headers + body text.
    FIX 4: Refactored to use shared helpers, eliminating code duplication
    with analyze_eml() and ensuring consistent header/body extraction.
    """
    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    return {
        "headers": _extract_headers(msg),
        "body": _extract_body(msg),
    }


def analyze_eml(
    file_path: str | Path,
    image_output_dir: str | Path,
) -> Dict[str, Any]:
    """
    Full .eml analysis: extract headers, body text, and embedded images.
    FIX 1 (applied): now returns reply-to and authentication headers.
    FIX 2 (applied): body is clean plain text, not mixed HTML+plain.
    FIX 3 (applied): embedded images get unique filenames, no overwrites.
    FIX 4 (applied): shares helpers with parse_eml(), no duplicated logic.
    """
    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    headers = _extract_headers(msg)
    body = _extract_body(msg)
    images = _extract_images(msg, image_output_dir)

    return {
        "headers": headers,
        "body": body,
        "images": images,
    }