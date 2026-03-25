"""
Generate labels.csv and splits.csv for the image pipeline evaluation.
Run from the project root: python generate_image_labels.py
"""
import csv
from pathlib import Path

PHISH_DIR  = Path("dataset/images/phish")
BENIGN_DIR = Path("dataset/images/benign")

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".webp"}

samples = []

# Phishing images
for f in sorted(PHISH_DIR.iterdir()):
    if f.suffix.lower() in IMAGE_EXTS:
        samples.append({
            "id":       f.stem,
            "filepath": f"images/phish/{f.name}",
            "label":    "phish",
            "split":    "test",
        })

# Benign images
for f in sorted(BENIGN_DIR.iterdir()):
    if f.suffix.lower() in IMAGE_EXTS:
        samples.append({
            "id":       f.stem,
            "filepath": f"images/benign/{f.name}",
            "label":    "benign",
            "split":    "test",
        })

# Write labels.csv
labels_path = Path("dataset/image_labels.csv")
with open(labels_path, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["id", "filepath", "label", "split"])
    w.writeheader()
    w.writerows(samples)

# Write splits.csv
splits_path = Path("dataset/image_splits.csv")
with open(splits_path, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["id", "split"])
    w.writeheader()
    w.writerows([{"id": s["id"], "split": s["split"]} for s in samples])

phish_count  = sum(1 for s in samples if s["label"] == "phish")
benign_count = sum(1 for s in samples if s["label"] == "benign")

print(f"Image dataset ready:")
print(f"  Phishing images : {phish_count}")
print(f"  Benign images   : {benign_count}")
print(f"  Total           : {len(samples)}")
print(f"  Labels  -> {labels_path}")
print(f"  Splits  -> {splits_path}")
print(f"\nSamples:")
for s in samples:
    print(f"  [{s['label']:<7}] {s['filepath']}")