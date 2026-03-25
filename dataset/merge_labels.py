import csv
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────
PHISHING_LABELS = "phishing_labels.csv"
BENIGN_LABELS   = "benign_labels.csv"
OUT_LABELS      = "labels.csv"
OUT_SPLITS      = "splits.csv"

# ── Load both label files ─────────────────────────────────────────────────────
samples = []

for csv_path in [PHISHING_LABELS, BENIGN_LABELS]:
    p = Path(csv_path)
    if not p.exists():
        print(f"[SKIP] {csv_path} not found")
        continue
    with open(p, newline="", encoding="utf-8") as f:
        samples.extend(list(csv.DictReader(f)))

print(f"Total samples: {len(samples)}")

phish_count  = sum(1 for s in samples if s["label"] in ("phish","phishing","malicious"))
benign_count = sum(1 for s in samples if s["label"] in ("benign","ham","legit","safe","clean"))
print(f"  Phishing: {phish_count}")
print(f"  Benign:   {benign_count}")

# ── All samples go to test split ──────────────────────────────────────────────
# Rule-based system has no training phase — everything is evaluation data.
splits = [{"id": s["id"], "split": "test"} for s in samples]

# ── Write combined labels.csv ─────────────────────────────────────────────────
with open(OUT_LABELS, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["id", "filepath", "label", "split"])
    w.writeheader()
    w.writerows(samples)
print(f"\nLabels written to {OUT_LABELS}")

# ── Write splits.csv ──────────────────────────────────────────────────────────
with open(OUT_SPLITS, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["id", "split"])
    w.writeheader()
    w.writerows(splits)
print(f"Splits written to {OUT_SPLITS}")
print(f"\nDataset ready for evaluation.")
print(f"Run: python evaluation.py")