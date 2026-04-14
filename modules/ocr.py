from __future__ import annotations


import re
from dataclasses import dataclass
from typing import Dict, List, Optional

import numpy as np
import pytesseract


import platform
if platform.system() == "Windows":
    pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"



@dataclass
class OCRConfig:
    """Configuration for OCR behaviour."""
    lang: str = "eng"
    psm: int = 6  # Page segmentation mode (6 = block of text)


DEFAULT_PHISH_KEYWORDS = [
    "verify", "verification", "urgent", "immediately", "action required",
    "account suspended", "password", "reset", "login", "sign in",
    "update", "confirm", "security alert", "unauthorized", "invoice",
    "payment", "billing", "microsoft", "paypal", "amazon"
]


def run_ocr(image_gray_or_thresh: np.ndarray, cfg: Optional[OCRConfig] = None) -> str:
    """Run Tesseract OCR on a grayscale/threshold image and return extracted text."""
    cfg = cfg or OCRConfig()
    custom_config = f"--oem 3 --psm {cfg.psm}"
    text = pytesseract.image_to_string(
        image_gray_or_thresh,
        lang=cfg.lang,
        config=custom_config
    )
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text


def extract_urls(text: str) -> List[str]:
    """Extract URLs from OCR text using a simple regex."""
    
    url_regex = r"(https?://[^\s]+|www\.[^\s]{4,})"
    urls = re.findall(url_regex, text, flags=re.IGNORECASE)

    cleaned: List[str] = []
    for u in urls:
        u = u.strip(").,;:'\"[]{}<>")
        
        if len(u) >= 8:
            cleaned.append(u)

    # Deduplicate, preserve order
    seen: set = set()
    out: List[str] = []
    for u in cleaned:
        if u not in seen:
            out.append(u)
            seen.add(u)
    return out


def keyword_hits(text: str, keywords: Optional[List[str]] = None) -> Dict[str, int]:
    """Return a count of keyword matches found in OCR text."""
    keywords = keywords or DEFAULT_PHISH_KEYWORDS
    lower = text.lower()
    hits: Dict[str, int] = {}
    for kw in keywords:
        count = lower.count(kw.lower())
        if count > 0:
            hits[kw] = count
    return hits