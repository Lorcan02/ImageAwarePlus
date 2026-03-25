import csv
import hashlib
from pathlib import Path

LABELS = Path("dataset/labels.csv")
OUT = Path("dataset/splits.csv")

def split_for_id(sample_id: str) -> str:
    # Stable hash -> 0..99
    h = hashlib.sha256(sample_id.encode("utf-8")).hexdigest()
    v = int(h[:8], 16) % 100
    if v < 60:
        return "train"
    elif v < 80:
        return "val"
    else:
        return "test"

rows = []
with LABELS.open(newline="", encoding="utf-8") as f:
    rows = list(csv.DictReader(f))

with OUT.open("w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["id", "split"])
    for r in rows:
        w.writerow([r["id"], split_for_id(r["id"])])

print(f"Wrote {OUT} with {len(rows)} rows")