from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import json
import threading
import uuid
# FIX 1: Import timezone so we can use timezone-aware datetimes throughout,
# replacing all deprecated datetime.utcnow() calls (deprecated in Python 3.12+
# and prone to comparison errors with timezone-aware WHOIS/API dates).
from datetime import datetime, timezone
from typing import Any, Dict, List

from flask import Flask, request, render_template, send_from_directory, url_for, jsonify
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

# In-memory job store — holds analysis results keyed by job ID.
# On the free tier, analysis takes 30-60s which exceeds browser timeouts.
# The async pattern: submit → get job_id → poll /status/<job_id> → redirect.
# Simple dict is fine for a single-worker deployment (gunicorn --workers 1).
_jobs: Dict[str, Dict[str, Any]] = {}


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
    return render_template("home.html")


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
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    ext = Path(safe_name).suffix.lower()
    saved_name = f"{Path(safe_name).stem}_{ts}{ext}"
    saved_path = UPLOAD_DIR / saved_name
    f.save(str(saved_path))

    # Create a job ID and start analysis in a background thread so the
    # browser gets an immediate response instead of waiting 30-60 seconds.
    job_id = str(uuid.uuid4())
    _jobs[job_id] = {"status": "processing", "filename": safe_name}

    def run_analysis():
        try:
            result_data = _run_full_analysis(saved_path, safe_name, ts, ext)
            _jobs[job_id] = {"status": "done", **result_data}
        except Exception as e:
            _jobs[job_id] = {"status": "error", "error": str(e)}

    thread = threading.Thread(target=run_analysis, daemon=True)
    thread.start()

    return render_template("processing.html", job_id=job_id, filename=safe_name)


def _run_full_analysis(saved_path, safe_name, ts, ext):
    """
    Full analysis pipeline extracted into a standalone function so it can
    run in a background thread. Returns a dict that gets stored in _jobs.
    """
    email_meta = None
    extracted_images = []
    email_analysis_result = None

    if ext == ".eml":
        email_data = analyze_eml(saved_path, EMAIL_IMG_DIR)
        email_meta = email_data["headers"]
        extracted_images = email_data["images"]
        email_body = email_data["body"] or ""
        email_analysis_result = analyze_email(email_meta, email_body)

        urls_from_email = extract_urls_robust(email_body)
        kw_hits = keyword_hits(email_body)
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
            "meta": {"image": str(saved_path), "timestamp_utc": datetime.now(timezone.utc).isoformat()},
            "ocr": {"text_file": str(body_txt_path), "method": "email_body", "mean_confidence": None, "kept_words": 0, "total_words": 0, "extracted_urls": urls_from_email, "keyword_hits": kw_hits},
            "qr": {"found": False, "data": None, "annotated_image": None},
            "threat_intel": ti_results,
            "risk": {"score": body_score.risk_score, "level": body_score.risk_level, "reasons": body_score.reasons, "breakdown": body_score.breakdown},
            "artifacts": {"annotated_image": None, "ocr_text": str(body_txt_path)},
            "email": {"subject": email_meta.get("subject"), "from": email_meta.get("from"), "to": email_meta.get("to"), "date": email_meta.get("date"), "images": extracted_images},
            "email_analysis": email_analysis_result,
        }

        if extracted_images:
            image_result = analyze_image(extracted_images[0], out_dir=OUTPUT_DIR, email_meta=email_meta, email_analysis=email_analysis_result)
            image_score = image_result.get("risk_score", 0)
            if image_score > body_score.risk_score:
                result = image_result
                if result.get("report_path"):
                    img_report = _load_report_json(result["report_path"])
                    img_report["email"] = body_report["email"]
                    img_report["email_analysis"] = email_analysis_result
                    _save_report_json(result["report_path"], img_report)
            else:
                report_path = OUTPUT_DIR / f"{Path(safe_name).stem}_{ts}_report.json"
                _save_report_json(report_path, body_report)
                result = {"risk_score": body_score.risk_score, "risk_level": body_score.risk_level, "report_path": str(report_path), "annotated_image": None, "ocr_text": str(body_txt_path)}
        else:
            report_path = OUTPUT_DIR / f"{Path(safe_name).stem}_{ts}_report.json"
            _save_report_json(report_path, body_report)
            result = {"risk_score": body_score.risk_score, "risk_level": body_score.risk_level, "report_path": str(report_path), "annotated_image": None, "ocr_text": str(body_txt_path)}
    else:
        result = analyze_image(saved_path, out_dir=OUTPUT_DIR)

    if result.get("report_path"):
        report_path = result["report_path"]
        report = _load_report_json(report_path)
    else:
        report_path = None
        report = {"meta": {"timestamp_utc": datetime.now(timezone.utc).isoformat()}, "ocr": {"method": None, "kept_words": 0, "total_words": 0, "extracted_urls": [], "keyword_hits": {}}, "qr": {"found": False, "data": None}, "threat_intel": [], "artifacts": {}, "risk": {"score": result.get("risk_score", 0), "level": result.get("risk_level", "Low"), "reasons": [], "breakdown": {}}}

    if email_meta:
        report["email"] = {"subject": email_meta.get("subject"), "from": email_meta.get("from"), "to": email_meta.get("to"), "date": email_meta.get("date"), "images": extracted_images}
    if email_analysis_result:
        report["email_analysis"] = email_analysis_result
    if report_path:
        _save_report_json(report_path, report)

    if report_path:
        pdf_path = export_pdf_from_report_json(report_path)
    else:
        pdf_path = None

    annotated_raw = result.get("annotated_image")
    ocr_raw = result.get("ocr_text")
    raw_image_path = report.get("meta", {}).get("image", "")

    return {
        "report":               report,
        "risk_score":           report.get("risk", {}).get("score", result.get("risk_score", 0)),
        "risk_level":           report.get("risk", {}).get("level", result.get("risk_level", "Low")),
        "image_filename":       Path(str(raw_image_path)).name if raw_image_path else "",
        "email_meta":           email_meta,
        "extracted_images":     extracted_images,
        "email_analysis_result": email_analysis_result,
        "annotated_name":       Path(annotated_raw).name if annotated_raw else None,
        "report_name":          Path(str(report_path)).name if report_path else None,
        "ocr_name":             Path(ocr_raw).name if ocr_raw else None,
        "pdf_name":             Path(pdf_path).name if pdf_path else None,
    }

@app.get("/learn")
def learn():
    return render_template("learn.html")


@app.get("/about")
def about():
    return render_template("about.html")


@app.get("/analyse")
def analyse():
    return render_template("analyse.html")


@app.get("/status/<job_id>")
def job_status(job_id: str):
    job = _jobs.get(job_id, {"status": "not_found"})
    return jsonify({"status": job.get("status"), "error": job.get("error")})


@app.get("/result/<job_id>")
def job_result(job_id: str):
    job = _jobs.get(job_id)
    if not job or job.get("status") != "done":
        return render_template("analyse.html", error="Result not found or still processing."), 404

    report         = job.get("report", {})
    risk_score     = job.get("risk_score", 0)
    risk_level     = job.get("risk_level", "Low")
    image_filename = job.get("image_filename", "")
    email_meta     = job.get("email_meta")
    extracted_images = job.get("extracted_images", [])
    email_analysis_result = job.get("email_analysis_result")

    annotated_name = job.get("annotated_name")
    report_name    = job.get("report_name")
    ocr_name       = job.get("ocr_name")
    pdf_name       = job.get("pdf_name")

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
