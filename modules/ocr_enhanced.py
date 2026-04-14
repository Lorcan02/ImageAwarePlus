from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import numpy as np
import pytesseract

import platform

# Set Tesseract path only on Windows — on Linux (Render/Docker) it is on PATH
if platform.system() == "Windows":
    pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"



@dataclass
class OCRCandidate:
    text: str
    mean_confidence: float
    kept_words: int
    total_words: int
    method: str  # e.g., "adaptive_psm6", "otsu_psm11", "gray_psm6"


def _clean_text(text: str) -> str:
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def ocr_with_confidence(
    img: np.ndarray,
    psm: int,
    label: str,
    conf_threshold: int = 35,
) -> OCRCandidate:
    """
    Uses pytesseract.image_to_data to get per-word confidences, then
    reconstructs text from words that meet the confidence threshold.

    conf_threshold: typical useful range is 30–60 depending on image quality.
    """
    config = f"--oem 3 --psm {psm}"
    data = pytesseract.image_to_data(
        img, output_type=pytesseract.Output.DICT, config=config
    )

    words = data.get("text", [])
    confs = data.get("conf", [])

    kept: List[str] = []
    kept_confs: List[int] = []
    total_words = 0

    for w, c in zip(words, confs):
        w = (w or "").strip()
        if not w:
            continue
        total_words += 1
        try:
            ci = int(float(c))
        except Exception:
            continue
        # Tesseract returns -1 for layout tokens that are not real words
        if ci >= conf_threshold:
            kept.append(w)
            kept_confs.append(ci)

    
    kept_word_list = kept
    kept_words_count = len(kept_word_list)

    mean_conf = float(sum(kept_confs) / len(kept_confs)) if kept_confs else 0.0

    
    reconstructed_lines: List[str] = []
    current_line_words: List[str] = []
    current_line_num = -1
    current_block_num = -1

    block_nums = data.get("block_num", [])
    line_nums = data.get("line_num", [])

    for w, c, bn, ln in zip(words, confs, block_nums, line_nums):
        w = (w or "").strip()
        if not w:
            continue
        try:
            ci = int(float(c))
        except Exception:
            continue
        if ci < conf_threshold:
            continue

        # New block → insert blank line between blocks
        if bn != current_block_num:
            if current_line_words:
                reconstructed_lines.append(" ".join(current_line_words))
                current_line_words = []
            if reconstructed_lines:
                reconstructed_lines.append("")
            current_block_num = bn
            current_line_num = ln

        # New line within same block → flush current line
        elif ln != current_line_num:
            if current_line_words:
                reconstructed_lines.append(" ".join(current_line_words))
                current_line_words = []
            current_line_num = ln

        current_line_words.append(w)

    if current_line_words:
        reconstructed_lines.append(" ".join(current_line_words))

    text = _clean_text("\n".join(reconstructed_lines))

    return OCRCandidate(
        text=text,
        mean_confidence=mean_conf,
        kept_words=kept_words_count,
        total_words=total_words,
        method=label,
    )


def choose_best_ocr(
    *,
    gray: np.ndarray,
    adaptive_thresh: np.ndarray,
    otsu_thresh: np.ndarray,
    psms: Tuple[int, ...] = (6, 11, 4),
    conf_threshold: int = 35,
) -> OCRCandidate:
    """
    Run OCR on multiple image variants × multiple PSMs, return the best
    candidate. Selection is primarily by mean_confidence, with kept_words
    as a tie-breaker.
    """
    candidates: List[OCRCandidate] = []

    for psm in psms:
        candidates.append(ocr_with_confidence(gray, psm, f"gray_psm{psm}", conf_threshold))
        candidates.append(ocr_with_confidence(adaptive_thresh, psm, f"adaptive_psm{psm}", conf_threshold))
        candidates.append(ocr_with_confidence(otsu_thresh, psm, f"otsu_psm{psm}", conf_threshold))

    
    non_empty = [c for c in candidates if c.text.strip()]
    if not non_empty:
        # Return a clearly marked empty result rather than a silent failure
        return OCRCandidate(
            text="",
            mean_confidence=0.0,
            kept_words=0,
            total_words=candidates[0].total_words if candidates else 0,
            method="no_text_detected",
        )

    non_empty.sort(key=lambda c: (c.mean_confidence, c.kept_words), reverse=True)
    return non_empty[0]


# ------------------------------------------------
# Shared keyword / URL helpers
# ------------------------------------------------

DEFAULT_PHISH_KEYWORDS = [
    "verify", "verification", "urgent", "immediately", "action required",
    "account suspended", "password", "reset", "login", "sign in",
    "update", "confirm", "security alert", "unauthorized", "invoice",
    "payment", "billing", "microsoft", "paypal", "amazon",
    # Legal threat / DMCA scam keywords — added after live test showed
    # cavra.org DMCA phish was missed entirely by keyword detection
    "dmca", "copyright", "infringement", "legal proceedings",
    "legal action", "legal consequences", "formal complaint",
    "copyright strike", "takedown", "compliance", "violation report",
    "24 hours", "follow this link", "click here", "access this report",
]


def recover_hidden_hyperlinks(text: str) -> str:
    """
    Post-OCR hyperlink recovery pass.

    Tesseract frequently fails to read blue underlined hyperlink text in
    email screenshots — the styling causes it to skip the line entirely.
    This is confirmed behaviour: in the cavra.org DMCA phish test, the line
    "Follow this link: https://cavra.org/reports" OCR'd as just
    "Follow this link:" with the URL completely absent.

    This function detects these "orphaned link prompts" — lines that contain
    a known link-invitation phrase followed by nothing or just whitespace —
    and appends a placeholder marker so the scoring engine knows a hidden
    URL was present even if it couldn't be extracted.

    The marker [HIDDEN_LINK_DETECTED] is recognised by score_image_analysis()
    as a signal to apply a modest score bump for a likely-present URL.
    """
    LINK_PROMPTS = [
        r"follow\s+this\s+link\s*:?\s*$",
        r"click\s+here\s*:?\s*$",
        r"access\s+this\s+report\s*:?\s*$",
        r"click\s+the\s+link\s*:?\s*$",
        r"visit\s+our\s+website\s*:?\s*$",
        r"go\s+to\s*:?\s*$",
        r"open\s+your\s+report\s*:?\s*$",
    ]

    lines = text.split("\n")
    recovered = []
    for line in lines:
        stripped = line.strip()
        for pattern in LINK_PROMPTS:
            if re.search(pattern, stripped, re.IGNORECASE):
                line = line.rstrip() + " [HIDDEN_LINK_DETECTED]"
                break
        recovered.append(line)
    return "\n".join(recovered)


def extract_urls(text: str) -> List[str]:
    
    url_regex = r"(https?://[^\s]+|www\.[^\s]{4,})"
    urls = re.findall(url_regex, text, flags=re.IGNORECASE)

    cleaned: List[str] = []
    for u in urls:
        u = u.strip(").,;:'\"[]{}<>")
        if len(u) >= 8:
            cleaned.append(u)

    seen: set = set()
    out: List[str] = []
    for u in cleaned:
        if u not in seen:
            out.append(u)
            seen.add(u)
    return out


def keyword_hits(text: str, keywords: Optional[List[str]] = None) -> Dict[str, int]:
    keywords = keywords or DEFAULT_PHISH_KEYWORDS
    lower = text.lower()
    hits: Dict[str, int] = {}
    for kw in keywords:
        count = lower.count(kw.lower())
        if count > 0:
            hits[kw] = count
    return hits