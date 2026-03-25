from pathlib import Path
import csv

DATASET_DIR = Path("dataset")
PHISH_DIR = DATASET_DIR / "images" / "phish"
BENIGN_DIR = DATASET_DIR / "images" / "benign"
OUT = DATASET_DIR / "labels.csv"

def list_images(folder: Path):
    exts = {".png", ".jpg", ".jpeg", ".webp", ".bmp"}
    files = [p for p in folder.iterdir() if p.is_file() and p.suffix.lower() in exts]
    return sorted(files, key=lambda p: p.name.lower())

rows = []
i = 1

for p in list_images(PHISH_DIR):
    sid = f"{i:04d}"
    rows.append({
        "id": sid,
        "filepath": str(p.relative_to(DATASET_DIR)).replace("\\", "/"),
        "label": "phish",
        "source": "manual_collection",
        "notes": ""
    })
    i += 1

for p in list_images(BENIGN_DIR):
    sid = f"{i:04d}"
    rows.append({
        "id": sid,
        "filepath": str(p.relative_to(DATASET_DIR)).replace("\\", "/"),
        "label": "benign",
        "source": "manual_collection",
        "notes": ""
    })
    i += 1

DATASET_DIR.mkdir(parents=True, exist_ok=True)
with OUT.open("w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["id", "filepath", "label", "source", "notes"])
    w.writeheader()
    w.writerows(rows)

print(f"Wrote {OUT} with {len(rows)} rows")