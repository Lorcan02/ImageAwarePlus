from __future__ import annotations

import csv
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

# Ensure project root is on the path so modules/ can be found
# regardless of where this file lives within the project
import os
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# Image pipeline
from modules.report import analyze_image

# Email pipeline — same path as app.py uses
from modules.email_parser import analyze_eml
from modules.email_analysis import analyze_email
from modules.scoring import score_image_analysis
from modules.ocr_enhanced import keyword_hits
from modules.url_repair import extract_urls_robust
from modules.email_cleaner import clean_email_urls

# Threat intel imports removed for evaluation mode.
# VT/URLScan/PhishTank are skipped during evaluation to preserve API quota
# and avoid WHOIS timeouts that slow evaluation to a crawl. The scoring
# engine receives empty ti_results, so evaluation measures content-based
# detection only — which is the core capability being evaluated.

# Output directory for evaluation artefacts
EMAIL_IMG_DIR = Path("outputs/eval_images")
EMAIL_IMG_DIR.mkdir(parents=True, exist_ok=True)

# ── Thresholds ────────────────────────────────────────────────────────────────
# Three thresholds evaluated simultaneously:
# High (70)   — only definite High risk flagged. Very conservative.
# Medium (35) — Medium or above flagged. Balanced.
# Low+ (25)   — anything above Low flagged. Aggressive, useful for recall.
PHISH_SCORE_THRESHOLD = 70.0
MEDIUM_THRESHOLD      = 35.0
LOW_PLUS_THRESHOLD    = 25.0

POSITIVE_LABELS = {"phish", "phishing", "malicious"}


def label_to_int(lbl: str) -> int:
    normalised = lbl.strip().lower()
    if normalised in POSITIVE_LABELS:
        return 1
    if normalised in {"benign", "ham", "legit", "safe", "clean", "0"}:
        return 0
    raise ValueError(
        f"Unrecognised label '{lbl}'. "
        f"Expected one of: {POSITIVE_LABELS | {'benign','ham','legit','safe','clean'}}"
    )


@dataclass
class PredRow:
    id:        str
    filepath:  str
    split:     str
    y_true:    int
    score:     float
    level:     str
    y_pred:    int
    y_pred_medium: int          # prediction at Medium threshold (35)
    y_pred_low:    int          # prediction at Low+ threshold (25)
    error:     Optional[str] = None


def load_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def load_splits(splits_csv: Path) -> Dict[str, str]:
    return {r["id"]: r["split"] for r in load_csv(splits_csv)}


def _build_threat_intel(urls: List[str]) -> List[Dict[str, Any]]:
    """
    Disabled during evaluation to preserve API quota and avoid WHOIS
    timeouts. Returns empty list so scoring engine uses content signals only.
    """
    return []


def score_eml(eml_path: Path) -> Dict[str, Any]:
    """
    Score a .eml file using the full email pipeline — identical to app.py.
    Returns a report dict with risk.score and risk.level populated.
    """
    email_data           = analyze_eml(eml_path, EMAIL_IMG_DIR)
    email_meta           = email_data["headers"]
    extracted_images     = email_data["images"]
    email_body           = email_data["body"] or ""
    email_analysis_result = analyze_email(email_meta, email_body)

    # Step 1: Always score from body text
    urls_from_email = extract_urls_robust(email_body)
    kw_hits         = keyword_hits(email_body)
    urls_for_ti     = clean_email_urls(urls_from_email)
    ti_results      = _build_threat_intel(urls_for_ti)

    body_score = score_image_analysis(
        ocr_text          = email_body,
        keyword_hits      = kw_hits,
        urls_from_ocr     = urls_from_email,
        qr_found          = False,
        qr_data           = None,
        ti_results        = ti_results,
        email_analysis    = email_analysis_result,
        ocr_mean_confidence = None,
        ocr_kept_words    = 0,
        ocr_total_words   = 0,
    )

    # Step 2: If embedded images exist, also score those and take the higher
    if extracted_images:
        try:
            image_result = analyze_image(
                extracted_images[0],
                out_dir       = Path("outputs/eval"),
                email_meta    = email_meta,
                email_analysis = email_analysis_result,
            )
            image_score = image_result.get("risk_score", 0)
            if image_score > body_score.risk_score:
                # Load the image report and return it
                img_report = json.loads(
                    Path(image_result["report_path"]).read_text(encoding="utf-8")
                )
                img_report.setdefault("email_analysis", email_analysis_result)
                return img_report
        except Exception:
            pass  # fall through to body score

    # Return a minimal report dict matching the structure app.py produces
    return {
        "risk": {
            "score":     body_score.risk_score,
            "level":     body_score.risk_level,
            "reasons":   body_score.reasons,
            "breakdown": body_score.breakdown,
        },
        "email_analysis": email_analysis_result,
    }


def compute_metrics(rows: List[PredRow], threshold_key: str = "y_pred") -> Dict[str, Any]:
    valid = [r for r in rows if r.error is None]
    pred  = [getattr(r, threshold_key) for r in valid]
    true  = [r.y_true for r in valid]

    tp = sum(1 for p, t in zip(pred, true) if p == 1 and t == 1)
    fp = sum(1 for p, t in zip(pred, true) if p == 1 and t == 0)
    tn = sum(1 for p, t in zip(pred, true) if p == 0 and t == 0)
    fn = sum(1 for p, t in zip(pred, true) if p == 0 and t == 1)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall    = tp / (tp + fn) if (tp + fn) else 0.0
    accuracy  = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0.0
    f1        = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0.0
    fpr       = fp / (fp + tn) if (fp + tn) else 0.0

    return {
        "counts":  {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "metrics": {
            "precision": round(precision, 4),
            "recall":    round(recall,    4),
            "accuracy":  round(accuracy,  4),
            "f1":        round(f1,        4),
            "fpr":       round(fpr,       4),
        },
        "errors": len([r for r in rows if r.error is not None]),
    }


def evaluate(
    labels_csv: str  = "dataset/labels.csv",
    splits_csv: str  = "dataset/splits.csv",
    out_dir:    str  = "outputs/eval",
    threshold:  float = PHISH_SCORE_THRESHOLD,
    split:      str  = "test",
) -> Dict[str, Any]:

    labels_csv   = Path(labels_csv)
    splits_csv   = Path(splits_csv)
    out_dir      = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    labels       = load_csv(labels_csv)
    splits       = load_splits(splits_csv)
    dataset_root = labels_csv.parent
    n_total      = len(labels)

    pred_csv  = out_dir / "predictions.csv"
    pred_file = pred_csv.open("w", newline="", encoding="utf-8")
    pred_writer = csv.writer(pred_file)
    pred_writer.writerow([
        "id","filepath","split","y_true",
        "score","level","y_pred","y_pred_medium","y_pred_low","error"
    ])

    preds: List[PredRow] = []

    try:
        for i, r in enumerate(labels, 1):
            sid      = r["id"]
            sp       = splits.get(sid, "unknown")
            img_path = (dataset_root / r["filepath"]).resolve()

            try:
                y_true = label_to_int(r["label"])
            except ValueError as e:
                print(f"[ERROR] Row {sid}: {e}", file=sys.stderr)
                continue

            score     = 0.0
            level     = "Low"
            y_pred    = 0
            y_pred_m  = 0
            y_pred_l  = 0
            error_msg: Optional[str] = None

            print(
                f"[{i}/{n_total}] {r['filepath']} "
                f"(label={r['label']})",
                file=sys.stderr,
            )

            if not img_path.exists():
                error_msg = f"File not found: {img_path}"
                print(f"  -> SKIP: {error_msg}", file=sys.stderr)
            else:
                try:
                    ext = img_path.suffix.lower()

                    if ext == ".eml":
                        # Full email pipeline — same as app.py
                        report = score_eml(img_path)
                    else:
                        # Image pipeline
                        analysis    = analyze_image(img_path, out_dir=out_dir)
                        report_path = Path(analysis["report_path"])
                        report      = json.loads(
                            report_path.read_text(encoding="utf-8")
                        )

                    score  = float(report["risk"]["score"])
                    level  = str(report["risk"]["level"])
                    y_pred   = 1 if score >= threshold          else 0
                    y_pred_m = 1 if score >= MEDIUM_THRESHOLD   else 0
                    y_pred_l = 1 if score >= LOW_PLUS_THRESHOLD else 0

                    print(
                        f"  -> score={score:.1f} level={level} "
                        f"pred_high={'PHISH' if y_pred else 'benign'} "
                        f"pred_medium={'PHISH' if y_pred_m else 'benign'}",
                        file=sys.stderr,
                    )

                except Exception as e:
                    error_msg = str(e)
                    print(f"  -> ERROR: {error_msg}", file=sys.stderr)

            row = PredRow(
                id=sid, filepath=r["filepath"], split=sp,
                y_true=y_true, score=score, level=level,
                y_pred=y_pred, y_pred_medium=y_pred_m,
                y_pred_low=y_pred_l,
                error=error_msg,
            )
            preds.append(row)
            pred_writer.writerow([
                row.id, row.filepath, row.split,
                row.y_true, row.score, row.level,
                row.y_pred, row.y_pred_medium, row.y_pred_low,
                row.error or "",
            ])
            pred_file.flush()

    finally:
        pred_file.close()

    # ── Metrics ───────────────────────────────────────────────────────────────
    eval_rows = [p for p in preds if p.split == split]

    # Metrics at all three thresholds
    high_metrics   = compute_metrics(eval_rows, "y_pred")
    medium_metrics = compute_metrics(eval_rows, "y_pred_medium")
    low_metrics    = compute_metrics(eval_rows, "y_pred_low")

    summary = {
        "threshold_high":     threshold,
        "threshold_medium":   MEDIUM_THRESHOLD,
        "threshold_low_plus": LOW_PLUS_THRESHOLD,
        "split":              split,
        "n_total":            len(preds),
        "n_eval":             len(eval_rows),
        "at_high_threshold":    high_metrics,
        "at_medium_threshold":  medium_metrics,
        "at_low_plus_threshold": low_metrics,
    }

    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )

    # FP / FN lists at both thresholds
    for thresh_key, name in [("y_pred", "high"), ("y_pred_medium", "medium"), ("y_pred_low", "low_plus")]:
        fp_rows = [p for p in eval_rows
                   if p.y_true == 0 and getattr(p, thresh_key) == 1
                   and p.error is None]
        fn_rows = [p for p in eval_rows
                   if p.y_true == 1 and getattr(p, thresh_key) == 0
                   and p.error is None]
        for label, rows in [("fp", fp_rows), ("fn", fn_rows)]:
            path = out_dir / f"errors_{label}_{name}.csv"
            with path.open("w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["id", "filepath", "score", "level"])
                for p in rows:
                    w.writerow([p.id, p.filepath, p.score, p.level])

    # ── Print summary ─────────────────────────────────────────────────────────
    hm = high_metrics.get("metrics", {})
    mm = medium_metrics.get("metrics", {})
    lm = low_metrics.get("metrics", {})
    hc = high_metrics.get("counts", {})
    mc = medium_metrics.get("counts", {})
    lc = low_metrics.get("counts", {})

    print(f"""
=== Evaluation complete (split={split}, n={len(eval_rows)}) ===

  -- At HIGH threshold (score >= {threshold}) --
  Precision : {hm.get('precision',0):.4f}
  Recall    : {hm.get('recall',0):.4f}
  F1        : {hm.get('f1',0):.4f}
  Accuracy  : {hm.get('accuracy',0):.4f}
  FPR       : {hm.get('fpr',0):.4f}
  TP={hc.get('tp',0)}  FP={hc.get('fp',0)}  TN={hc.get('tn',0)}  FN={hc.get('fn',0)}

  -- At MEDIUM threshold (score >= {MEDIUM_THRESHOLD}) --
  Precision : {mm.get('precision',0):.4f}
  Recall    : {mm.get('recall',0):.4f}
  F1        : {mm.get('f1',0):.4f}
  Accuracy  : {mm.get('accuracy',0):.4f}
  FPR       : {mm.get('fpr',0):.4f}
  TP={mc.get('tp',0)}  FP={mc.get('fp',0)}  TN={mc.get('tn',0)}  FN={mc.get('fn',0)}

  -- At LOW+ threshold (score >= {LOW_PLUS_THRESHOLD}) --
  Precision : {lm.get('precision',0):.4f}
  Recall    : {lm.get('recall',0):.4f}
  F1        : {lm.get('f1',0):.4f}
  Accuracy  : {lm.get('accuracy',0):.4f}
  FPR       : {lm.get('fpr',0):.4f}
  TP={lc.get('tp',0)}  FP={lc.get('fp',0)}  TN={lc.get('tn',0)}  FN={lc.get('fn',0)}

  Results saved to {out_dir}/
""")

    return summary


if __name__ == "__main__":
    evaluate()