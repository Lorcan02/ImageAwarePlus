from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import json
# FIX 1: Import timezone so we can use timezone-aware datetimes throughout,
# replacing all deprecated datetime.utcnow() calls (deprecated in Python 3.12+
# and prone to comparison errors with timezone-aware WHOIS/API dates).
from datetime import datetime, timezone
from typing import Any, Dict, List

from flask import Flask, request, render_template, send_from_directory, url_for
from werkzeug.utils import secure_filename

from modules.report import analyze_image
from modules.email_parser import analyze_eml
from modules.email_analysis import analyze_email
from modules.pdf_report_rl import export_pdf_from_report_json
from modules.scoring import score_image_analysis
from modules.ocr_enhanced import keyword_hits
from modules.url_repair import extract_urls_robust
from modules.email_cleaner import clean_email_urls
from modules.urlscan import urlscan_search
from modules.phishtank import phishtank_check
from modules.vt_cache import VTCache

APP_ROOT = Path(__file__).resolve().parent.parent
UPLOAD_DIR = APP_ROOT / "uploads"
OUTPUT_DIR = APP_ROOT / "outputs"
EMAIL_IMG_DIR = UPLOAD_DIR / "email_images"

ALLOWED_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".eml"}

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
EMAIL_IMG_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)


def allowed_file(filename: str) -> bool:
    ext = Path(filename).suffix.lower()
    return ext in ALLOWED_EXTS


def _load_report_json(report_path: str | Path) -> Dict[str, Any]:
    p = Path(report_path)
    return json.loads(p.read_text(encoding="utf-8"))


def _save_report_json(report_path: str | Path, report_data: Dict[str, Any]):
    p = Path(report_path)
    p.write_text(json.dumps(report_data, indent=2), encoding="utf-8")


def _build_threat_intel(urls: List[str]) -> List[Dict[str, Any]]:
    ti_results: List[Dict[str, Any]] = []

    seen: set = set()
    urls = [u for u in urls if u and not (u in seen or seen.add(u))]

    cache = VTCache()

    for url in urls:
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

    return ti_results


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/analyze")
def analyze_form():

    if "image" not in request.files:
        return render_template("index.html", error="No file field named 'image' found."), 400

    f = request.files["image"]

    if not f.filename:
        return render_template("index.html", error="No file selected."), 400

    if not allowed_file(f.filename):
        return render_template("index.html", error="Unsupported file type."), 400

    safe_name = secure_filename(f.filename)

    # FIX 1 (applied): replaced datetime.utcnow() with timezone-aware equivalent.
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    ext = Path(safe_name).suffix.lower()
    saved_name = f"{Path(safe_name).stem}_{ts}{ext}"
    saved_path = UPLOAD_DIR / saved_name
    f.save(str(saved_path))

    email_meta = None
    extracted_images: List[str] = []
    email_analysis_result = None

    # -----------------------------
    # EMAIL FILE ANALYSIS (.eml)
    # -----------------------------

    if ext == ".eml":

        email_data = analyze_eml(saved_path, EMAIL_IMG_DIR)
        email_meta = email_data["headers"]
        extracted_images = email_data["images"]
        email_body = email_data["body"] or ""

        email_analysis_result = analyze_email(email_meta, email_body)

        # CORE FIX: Always score from the email body first, regardless of
        # whether embedded images exist. The previous logic took an either/or
        # approach — if an embedded image was found it ONLY analysed the image
        # and completely ignored the email body text. This caused the Chase
        # phishing email to score 6/100 because the system only saw the Chase
        # logo banner image (2 OCR words) and never read the body text
        # containing "suspicious account activity", "unauthorized transactions",
        # "verify your information" etc.
        #
        # Correct behaviour: always run the full body text through scoring,
        # then ADDITIONALLY run any embedded image through OCR and take the
        # HIGHER of the two scores as the final result. This way no signal
        # is lost regardless of how the phishing content is delivered.

        # Step 1: Always score from email body text
        urls_from_email = extract_urls_robust(email_body)
        kw_hits = keyword_hits(email_body)
        # Filter tracking, infrastructure, and known-safe domains before
        # sending to VirusTotal/URLScan/PhishTank. Without this call,
        # all extracted URLs including legitimate apple.com, linkedin.com
        # etc. hit the TI APIs unnecessarily, wasting quota and inflating
        # URL count scores.
        urls_for_ti = clean_email_urls(urls_from_email)
        ti_results = _build_threat_intel(urls_for_ti)

        body_score = score_image_analysis(
            ocr_text=email_body,
            keyword_hits=kw_hits,
            urls_from_ocr=urls_from_email,
            qr_found=False,
            qr_data=None,
            ti_results=ti_results,
            email_analysis=email_analysis_result,
            ocr_mean_confidence=None,
            ocr_kept_words=0,
            ocr_total_words=0,
        )

        body_txt_path = OUTPUT_DIR / f"{Path(safe_name).stem}_{ts}_email_body.txt"
        body_txt_path.write_text(email_body, encoding="utf-8")

        body_report = {
            "meta": {
                "image": str(saved_path),
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            },
            "ocr": {
                "text_file": str(body_txt_path),
                "method": "email_body",
                "mean_confidence": None,
                "kept_words": 0,
                "total_words": 0,
                "extracted_urls": urls_from_email,
                "keyword_hits": kw_hits,
            },
            "qr": {
                "found": False,
                "data": None,
                "annotated_image": None,
            },
            "threat_intel": ti_results,
            "risk": {
                "score": body_score.risk_score,
                "level": body_score.risk_level,
                "reasons": body_score.reasons,
                "breakdown": body_score.breakdown,
            },
            "artifacts": {
                "annotated_image": None,
                "ocr_text": str(body_txt_path),
            },
            "email": {
                "subject": email_meta.get("subject"),
                "from": email_meta.get("from"),
                "to": email_meta.get("to"),
                "date": email_meta.get("date"),
                "images": extracted_images,
            },
            "email_analysis": email_analysis_result,
        }

        # Step 2: If embedded images exist, ALSO run them through OCR/image
        # analysis and take the higher of the two scores. This means we never
        # lose either signal — body text OR embedded image content.
        if extracted_images:
            image_result = analyze_image(
                extracted_images[0],
                out_dir=OUTPUT_DIR,
                email_meta=email_meta,
                email_analysis=email_analysis_result,
            )
            image_score = image_result.get("risk_score", 0)

            if image_score > body_score.risk_score:
                # Image analysis produced a higher score — use it as primary
                # but preserve the body report's email metadata
                result = image_result
                # Merge email metadata into the image report so it appears
                # in the final output
                if result.get("report_path"):
                    img_report = _load_report_json(result["report_path"])
                    img_report["email"] = body_report["email"]
                    img_report["email_analysis"] = email_analysis_result
                    _save_report_json(result["report_path"], img_report)
            else:
                # Body text analysis produced a higher score — use body report
                report_path = OUTPUT_DIR / f"{Path(safe_name).stem}_{ts}_report.json"
                _save_report_json(report_path, body_report)
                result = {
                    "risk_score": body_score.risk_score,
                    "risk_level": body_score.risk_level,
                    "report_path": str(report_path),
                    "annotated_image": None,
                    "ocr_text": str(body_txt_path),
                }
        else:
            # No embedded images — use body report directly
            report_path = OUTPUT_DIR / f"{Path(safe_name).stem}_{ts}_report.json"
            _save_report_json(report_path, body_report)
            result = {
                "risk_score": body_score.risk_score,
                "risk_level": body_score.risk_level,
                "report_path": str(report_path),
                "annotated_image": None,
                "ocr_text": str(body_txt_path),
            }

    # -----------------------------
    # IMAGE FILE ANALYSIS
    # -----------------------------

    else:
        result = analyze_image(saved_path, out_dir=OUTPUT_DIR)

    # -----------------------------
    # LOAD OR CREATE REPORT JSON
    # -----------------------------

    if result.get("report_path"):
        report_path = result["report_path"]
        report = _load_report_json(report_path)

    else:
        report_path = None
        # FIX 1 (applied): replaced datetime.utcnow().isoformat()
        report = {
            "meta": {
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            },
            "ocr": {
                "method": None,
                "kept_words": 0,
                "total_words": 0,
                "extracted_urls": [],
                "keyword_hits": {},
            },
            "qr": {
                "found": False,
                "data": None,
            },
            "threat_intel": [],
            "artifacts": {},
            "risk": {
                "score": result.get("risk_score", 0),
                "level": result.get("risk_level", "Low"),
                "reasons": [],
                "breakdown": {},
            },
        }

    # -----------------------------
    # ADD EMAIL DATA TO REPORT
    # -----------------------------

    if email_meta:
        report["email"] = {
            "subject": email_meta.get("subject"),
            "from": email_meta.get("from"),
            "to": email_meta.get("to"),
            "date": email_meta.get("date"),
            "images": extracted_images,
        }

    if email_analysis_result:
        report["email_analysis"] = email_analysis_result

    if report_path:
        _save_report_json(report_path, report)

    # -----------------------------
    # GENERATE PDF REPORT
    # -----------------------------

    if report_path:
        pdf_path = export_pdf_from_report_json(report_path)
    else:
        pdf_path = None

    # FIX 2: Added explicit guard before Path().name calls. If any of these
    # values come back as None (e.g. annotated_image not produced for an
    # email-only analysis), calling Path(None).name raises a TypeError that
    # crashes the entire response. The original relied on the ternary `if
    # result.get(...)` but that guard wasn't applied consistently everywhere.
    annotated_raw = result.get("annotated_image")
    report_raw = report_path
    ocr_raw = result.get("ocr_text")

    annotated_name = Path(annotated_raw).name if annotated_raw else None
    report_name = Path(str(report_raw)).name if report_raw else None
    ocr_name = Path(ocr_raw).name if ocr_raw else None
    pdf_name = Path(pdf_path).name if pdf_path else None

    # Keep UI values in sync with the final report
    risk_score = report.get("risk", {}).get("score", result.get("risk_score", 0))
    risk_level = report.get("risk", {}).get("level", result.get("risk_level", "Low"))

    # Extract just the filename from the full image path stored in the report.
    # The template previously used Jinja2's `split` filter for this, but `split`
    # is not a built-in Jinja2 filter and raises a TemplateRuntimeError. Doing
    # the path extraction here in Python and passing it as a dedicated variable
    # is the correct approach.
    raw_image_path = report.get("meta", {}).get("image", "")
    image_filename = Path(str(raw_image_path)).name if raw_image_path else ""

    return render_template(
        "result.html",
        report=report,
        risk_score=risk_score,
        risk_level=risk_level,
        image_filename=image_filename,
        annotated_url=url_for("download_output", filename=annotated_name) if annotated_name else None,
        report_url=url_for("download_output", filename=report_name) if report_name else None,
        ocr_url=url_for("download_output", filename=ocr_name) if ocr_name else None,
        pdf_url=url_for("download_output", filename=pdf_name) if pdf_name else None,
        email=email_meta,
        email_images=extracted_images,
        email_analysis=email_analysis_result,
    )


@app.get("/outputs/<path:filename>")
def download_output(filename: str):
    return send_from_directory(OUTPUT_DIR, filename, as_attachment=False)


@app.get("/uploads/<path:filename>")
def download_upload(filename: str):
    return send_from_directory(UPLOAD_DIR, filename, as_attachment=False)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)