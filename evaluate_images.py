"""
Image pipeline evaluation — runs every image through analyze_image()
and computes precision, recall, F1, accuracy, FPR at three thresholds.
Run from project root: python evaluate_images.py
"""
import csv
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

from modules.report import analyze_image

# ── Thresholds ────────────────────────────────────────────────────────────────
HIGH_THRESHOLD   = 70.0
MEDIUM_THRESHOLD = 35.0
LOW_THRESHOLD    = 25.0

POSITIVE_LABELS = {"phish", "phishing", "malicious"}


def label_to_int(lbl: str) -> int:
    if lbl.strip().lower() in POSITIVE_LABELS:
        return 1
    return 0


@dataclass
class PredRow:
    id:           str
    filepath:     str
    y_true:       int
    score:        float
    level:        str
    y_pred_high:  int
    y_pred_med:   int
    y_pred_low:   int
    breakdown:    Dict[str, Any]
    error:        Optional[str] = None


def compute_metrics(rows: List[PredRow], pred_attr: str) -> Dict[str, Any]:
    valid = [r for r in rows if r.error is None]
    tp = sum(1 for r in valid if r.y_true == 1 and getattr(r, pred_attr) == 1)
    fp = sum(1 for r in valid if r.y_true == 0 and getattr(r, pred_attr) == 1)
    tn = sum(1 for r in valid if r.y_true == 0 and getattr(r, pred_attr) == 0)
    fn = sum(1 for r in valid if r.y_true == 1 and getattr(r, pred_attr) == 0)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall    = tp / (tp + fn) if (tp + fn) else 0.0
    f1        = (2*precision*recall) / (precision+recall) if (precision+recall) else 0.0
    accuracy  = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0.0
    fpr       = fp / (fp + tn) if (fp + tn) else 0.0

    return {
        "counts":  {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "metrics": {
            "precision": round(precision, 4),
            "recall":    round(recall,    4),
            "f1":        round(f1,        4),
            "accuracy":  round(accuracy,  4),
            "fpr":       round(fpr,       4),
        },
    }


def evaluate_images(
    labels_csv: str = "dataset/image_labels.csv",
    splits_csv: str = "dataset/image_splits.csv",
    out_dir:    str = "outputs/eval_images_results",
):
    labels_csv = Path(labels_csv)
    splits_csv = Path(splits_csv)
    out_dir    = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    dataset_root = labels_csv.parent

    with labels_csv.open(newline="", encoding="utf-8") as f:
        labels = list(csv.DictReader(f))

    n_total = len(labels)
    preds: List[PredRow] = []

    print(f"=== Image Pipeline Evaluation ({n_total} images) ===\n")

    for i, r in enumerate(labels, 1):
        img_path = (dataset_root / r["filepath"]).resolve()
        y_true   = label_to_int(r["label"])

        print(f"[{i}/{n_total}] {r['filepath']} (label={r['label']})")

        score     = 0.0
        level     = "Low"
        breakdown = {}
        error_msg = None

        if not img_path.exists():
            error_msg = f"File not found: {img_path}"
            print(f"  -> SKIP: {error_msg}")
        else:
            try:
                result      = analyze_image(img_path, out_dir=out_dir)
                report_path = Path(result["report_path"])
                report      = json.loads(report_path.read_text(encoding="utf-8"))
                score       = float(report["risk"]["score"])
                level       = str(report["risk"]["level"])
                breakdown   = report["risk"].get("breakdown", {})

                # Show top contributing indicators
                top = sorted(breakdown.items(),
                             key=lambda x: x[1].get("contribution", 0),
                             reverse=True)[:4]
                contrib_str = "  ".join(
                    f"+{v['contribution']} {v['label'][:25]}"
                    for k, v in top if v.get("contribution", 0) > 0
                )
                print(f"  -> score={score:.0f} level={level}")
                if contrib_str:
                    print(f"     {contrib_str}")

            except Exception as e:
                error_msg = str(e)
                print(f"  -> ERROR: {error_msg}")

        row = PredRow(
            id          = r["id"],
            filepath    = r["filepath"],
            y_true      = y_true,
            score       = score,
            level       = level,
            y_pred_high = 1 if score >= HIGH_THRESHOLD   else 0,
            y_pred_med  = 1 if score >= MEDIUM_THRESHOLD else 0,
            y_pred_low  = 1 if score >= LOW_THRESHOLD    else 0,
            breakdown   = breakdown,
            error       = error_msg,
        )
        preds.append(row)

    # ── Write predictions CSV ─────────────────────────────────────────────────
    pred_path = out_dir / "image_predictions.csv"
    with pred_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id","filepath","y_true","score","level",
                    "y_pred_high","y_pred_med","y_pred_low","error"])
        for p in preds:
            w.writerow([p.id, p.filepath, p.y_true, p.score, p.level,
                        p.y_pred_high, p.y_pred_med, p.y_pred_low,
                        p.error or ""])

    # ── Metrics ───────────────────────────────────────────────────────────────
    high_m = compute_metrics(preds, "y_pred_high")
    med_m  = compute_metrics(preds, "y_pred_med")
    low_m  = compute_metrics(preds, "y_pred_low")

    summary = {
        "n_total": n_total,
        "at_high_threshold":    high_m,
        "at_medium_threshold":  med_m,
        "at_low_plus_threshold": low_m,
    }
    (out_dir / "image_summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )

    # ── Per-image score table ─────────────────────────────────────────────────
    print(f"\n{'='*65}")
    print(f"{'ID':<35} {'Label':<8} {'Score':<7} {'Level'}")
    print(f"{'='*65}")
    for p in sorted(preds, key=lambda x: x.score, reverse=True):
        marker = "✓" if (p.y_true == 1 and p.y_pred_med == 1) else \
                 "✗" if (p.y_true == 1 and p.y_pred_med == 0) else \
                 "FP" if (p.y_true == 0 and p.y_pred_med == 1) else " "
        label  = "phish" if p.y_true == 1 else "benign"
        print(f"  {marker} {p.id:<33} {label:<8} {p.score:<7.0f} {p.level}")

    hm = high_m["metrics"]; hc = high_m["counts"]
    mm = med_m["metrics"];  mc = med_m["counts"]
    lm = low_m["metrics"];  lc = low_m["counts"]

    print(f"""
=== Image Evaluation Results (n={n_total}) ===

  -- At HIGH threshold (score >= {HIGH_THRESHOLD}) --
  Precision : {hm['precision']:.4f}
  Recall    : {hm['recall']:.4f}
  F1        : {hm['f1']:.4f}
  Accuracy  : {hm['accuracy']:.4f}
  FPR       : {hm['fpr']:.4f}
  TP={hc['tp']}  FP={hc['fp']}  TN={hc['tn']}  FN={hc['fn']}

  -- At MEDIUM threshold (score >= {MEDIUM_THRESHOLD}) --
  Precision : {mm['precision']:.4f}
  Recall    : {mm['recall']:.4f}
  F1        : {mm['f1']:.4f}
  Accuracy  : {mm['accuracy']:.4f}
  FPR       : {mm['fpr']:.4f}
  TP={mc['tp']}  FP={mc['fp']}  TN={mc['tn']}  FN={mc['fn']}

  -- At LOW+ threshold (score >= {LOW_THRESHOLD}) --
  Precision : {lm['precision']:.4f}
  Recall    : {lm['recall']:.4f}
  F1        : {lm['f1']:.4f}
  Accuracy  : {lm['accuracy']:.4f}
  FPR       : {lm['fpr']:.4f}
  TP={lc['tp']}  FP={lc['fp']}  TN={lc['tn']}  FN={lc['fn']}

  Results saved to {out_dir}/
""")

    return summary


if __name__ == "__main__":
    evaluate_images()