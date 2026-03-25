from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import requests


@dataclass
class AdapterConfig:
    api_base: str = "http://127.0.0.1:5000"
    threshold: int = 65
    out_dir: Path = Path("outputs") / "integrations" / "kingphisher"


@dataclass
class AdapterResult:
    ok: bool
    status_code: int
    risk_level: Optional[str] = None
    risk_score: Optional[int] = None
    artifacts: Optional[Dict[str, str]] = None
    report: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


def analyze_via_api(image_path: str | Path, cfg: AdapterConfig) -> AdapterResult:
    cfg.out_dir.mkdir(parents=True, exist_ok=True)

    image_path = Path(image_path)
    if not image_path.exists():
        return AdapterResult(ok=False, status_code=0, error=f"Image not found: {image_path}")

    url = cfg.api_base.rstrip("/") + "/api/analyze"

    try:
        with open(image_path, "rb") as f:
            files = {"image": (image_path.name, f)}
            r = requests.post(url, files=files, timeout=180)
    except Exception as e:
        return AdapterResult(ok=False, status_code=0, error=str(e))

    if r.status_code != 200:
        return AdapterResult(ok=False, status_code=r.status_code, error=r.text[:1200])

    try:
        data = r.json()
    except Exception as e:
        return AdapterResult(ok=False, status_code=r.status_code, error=f"JSON parse failed: {e}")

    return AdapterResult(
        ok=True,
        status_code=r.status_code,
        risk_level=data.get("risk_level"),
        risk_score=data.get("risk_score"),
        artifacts=data.get("artifacts"),
        report=data.get("report"),
    )


def should_flag(score: int, threshold: int) -> bool:
    return score >= threshold


def soc_summary(res: AdapterResult) -> str:
    if not res.ok:
        return f"[ImageAware+ Adapter] ERROR status={res.status_code} error={res.error}"

    report = res.report or {}
    urls = []

    # OCR URLs
    urls += (report.get("ocr", {}) or {}).get("extracted_urls", []) or []

    # QR URL/data
    qr_data = (report.get("qr", {}) or {}).get("data")
    if qr_data:
        urls.append(qr_data)

    urls = list(dict.fromkeys(urls))

    pdf = (res.artifacts or {}).get("pdf_report")
    return f"[ImageAware+ Adapter] risk={res.risk_level} score={res.risk_score}/100 urls={len(urls)} pdf={pdf}"


def save_report_snapshot(res: AdapterResult, cfg: AdapterConfig, tag: str = "case") -> Optional[Path]:
    """
    Save a copy of the report JSON into outputs/integrations/kingphisher/
    This simulates how a platform would store investigation artifacts.
    """
    if not res.ok or not res.report:
        return None

    ts = (res.report.get("meta", {}) or {}).get("timestamp_utc", "unknown")
    out_path = cfg.out_dir / f"{tag}_{ts}_report_snapshot.json"
    out_path.write_text(json.dumps(res.report, indent=2), encoding="utf-8")
    return out_path
