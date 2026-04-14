from __future__ import annotations

import json
from pathlib import Path

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

import cv2

from modules.email_cleaner import clean_email_urls
from modules.url_repair import extract_urls_robust
from modules.urlscan import urlscan_search
from modules.phishtank import phishtank_check
from modules.vt_cache import VTCache
from modules.preprocessing import load_image_bgr, preprocess_for_ocr_and_qr, save_debug_images
from modules.ocr_enhanced import choose_best_ocr, keyword_hits, recover_hidden_hyperlinks
from modules.qr import detect_and_decode_qr, draw_qr_bbox
from modules.scoring import score_image_analysis


MAX_URLS_TO_CHECK = 10


def analyze_image(
    image_path: str | Path,
    out_dir: str | Path = "outputs",
    email_meta: Optional[Dict[str, Any]] = None,
    email_analysis: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:

    image_path = Path(image_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    stem = image_path.stem

    # ------------------------------------------------
    # 1) Load + preprocess
    # ------------------------------------------------

    img_bgr = load_image_bgr(image_path)
    prep = preprocess_for_ocr_and_qr(img_bgr)
    save_debug_images(prep, out_dir, stem=f"{stem}_{timestamp}")

    # ------------------------------------------------
    # 2) OCR or Email Text
    # ------------------------------------------------

    from types import SimpleNamespace

    if email_analysis and email_analysis.get("body_text"):
        ocr_text = email_analysis["body_text"]
        urls_from_ocr = extract_urls_robust(ocr_text)
        kw_hits = keyword_hits(ocr_text)
        best = SimpleNamespace(
            method="email_text",
            mean_confidence=None,
            kept_words=None,
            total_words=None,
        )
    else:
        best = choose_best_ocr(
            gray=prep["gray"],
            adaptive_thresh=prep["thresh"],
            otsu_thresh=prep["otsu"],
            psms=(6, 11, 4),
            conf_threshold=35,
        )
        ocr_text = best.text
        urls_from_ocr = extract_urls_robust(ocr_text)
        kw_hits = keyword_hits(ocr_text)

    # Apply hyperlink recovery pass — detects lines like "Follow this link:"
    # where Tesseract dropped the blue hyperlink URL entirely. Appends
    # [HIDDEN_LINK_DETECTED] marker so scoring can apply a signal even
    # when the URL itself couldn't be read. Confirmed necessary from live
    # test: cavra.org DMCA phish had its URL completely missed by OCR.
    ocr_text = recover_hidden_hyperlinks(ocr_text or "")

   
    ocr_text = ocr_text or ""

    ocr_txt_path = out_dir / f"{stem}_{timestamp}_ocr.txt"
    ocr_txt_path.write_text(ocr_text, encoding="utf-8")

    # ------------------------------------------------
    # 3) QR
    # ------------------------------------------------

    qr = detect_and_decode_qr(prep["resized_bgr"])
    annotated = prep["resized_bgr"].copy()

    if qr.found and qr.points:
        annotated = draw_qr_bbox(annotated, qr.points)

    annotated_path = out_dir / f"{stem}_{timestamp}_annotated.png"
    cv2.imwrite(str(annotated_path), annotated)

    # ------------------------------------------------
    # 4) Threat Intelligence
    # ------------------------------------------------

    urls_to_check: List[str] = []

    if qr.data:
        urls_to_check.append(qr.data)

    urls_to_check.extend(urls_from_ocr)

    if email_analysis and email_analysis.get("urls"):
        urls_to_check.extend(email_analysis.get("urls", []))

    urls_to_check = clean_email_urls(urls_to_check)

    # Deduplicate (preserving order)
    seen: set = set()
    urls_to_check = [u for u in urls_to_check if not (u in seen or seen.add(u))]

    # Cap to prevent VirusTotal rate limit issues
    urls_to_check = urls_to_check[:MAX_URLS_TO_CHECK]

   
    urls_for_scoring = urls_to_check.copy()

    cache = VTCache()
    ti_results: List[Dict[str, Any]] = []

    for url in urls_to_check:

        entry: Dict[str, Any] = {"url": url}

        try:
            vt = cache.get_or_query(url)
            entry.update({
                "url": vt.url,
                "verdict": vt.verdict,
                "vt_malicious": vt.vt_malicious,
                "vt_suspicious": vt.vt_suspicious,
                "vt_harmless": vt.vt_harmless,
                "vt_undetected": vt.vt_undetected,
            })
        except Exception as e:
            entry["vt_error"] = str(e)

        try:
            entry["urlscan"] = urlscan_search(url)
        except Exception as e:
            entry["urlscan_error"] = str(e)

        try:
            entry["phishtank"] = phishtank_check(url)
        except Exception as e:
            entry["phishtank_error"] = str(e)

        ti_results.append(entry)

    # ------------------------------------------------
    # 5) Scoring
    # ------------------------------------------------

    score = score_image_analysis(
        ocr_text=ocr_text,
        keyword_hits=kw_hits,
        urls_from_ocr=urls_for_scoring,
        qr_found=qr.found,
        qr_data=qr.data,
        ti_results=ti_results,
        email_analysis=email_analysis,
        ocr_mean_confidence=getattr(best, "mean_confidence", None),
        ocr_kept_words=getattr(best, "kept_words", None),
        ocr_total_words=getattr(best, "total_words", None),
    )

    # ------------------------------------------------
    # 6) Build report
    # ------------------------------------------------

    report: Dict[str, Any] = {
        "meta": {
            "image": str(image_path),
            
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        },
        "ocr": {
            "text_file": str(ocr_txt_path),
            "method": best.method,
            "mean_confidence": best.mean_confidence,
            "kept_words": best.kept_words,
            "total_words": best.total_words,
            "extracted_urls": urls_for_scoring,
            "keyword_hits": kw_hits,
        },
        "qr": {
            "found": qr.found,
            "data": qr.data,
            "annotated_image": str(annotated_path),
        },
        "threat_intel": ti_results,
        "risk": {
            "score": score.risk_score,
            "level": score.risk_level,
            "reasons": score.reasons,
            "breakdown": score.breakdown,
        },
        "artifacts": {
            "annotated_image": str(annotated_path),
            "ocr_text": str(ocr_txt_path),
        },
    }

    if email_meta:
        report["email"] = email_meta

    if email_analysis:
        report["email_analysis"] = email_analysis

    # ------------------------------------------------
    # 7) Save JSON
    # ------------------------------------------------

    report_path = out_dir / f"{stem}_{timestamp}_report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    return {
        "report_path": str(report_path),
        "annotated_image": str(annotated_path),
        "ocr_text": str(ocr_txt_path),
        "risk_level": score.risk_level,
        "risk_score": score.risk_score,
    }