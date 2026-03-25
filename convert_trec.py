"""
Convert TREC 2007 ham (benign) emails from email_origin.csv to .eml files.
Label 0 = ham (benign), Label 1 = spam — we only want label 0.
"""
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# ── Config ────────────────────────────────────────────────────────────────────
INPUT_CSV  = Path("archive/email_origin.csv")
OUT_DIR    = Path("dataset/benign_eml")
MAX_EMAILS = 150

OUT_DIR.mkdir(parents=True, exist_ok=True)

# ── Convert ───────────────────────────────────────────────────────────────────
labels  = []
counter = 0
skipped = 0
scanned = 0

print(f"[READING] {INPUT_CSV}")
print(f"[INFO] Extracting up to {MAX_EMAILS} ham (label=0) emails...")

with open(INPUT_CSV, newline="", encoding="utf-8", errors="replace") as f:
    reader = csv.DictReader(f)

    for row in reader:
        scanned += 1

        # Only process ham emails (label = 0)
        if str(row.get("label", "1")).strip() != "0":
            continue

        if counter >= MAX_EMAILS:
            print(f"[STOP] Reached cap of {MAX_EMAILS} emails")
            break

        content = row.get("origin", "").strip()
        if not content:
            skipped += 1
            continue

        # Basic sanity check
        content_lower = content[:500].lower()
        if not any(h in content_lower for h in
                   ["from:", "to:", "subject:", "date:", "received:"]):
            skipped += 1
            continue

        stem     = f"benign_{counter:04d}"
        out_path = OUT_DIR / f"{stem}.eml"

        try:
            out_path.write_text(content, encoding="utf-8", errors="replace")
            labels.append({
                "id":       stem,
                "filepath": f"benign_eml/{stem}.eml",
                "label":    "benign",
                "split":    "test",
            })
            counter += 1
            if counter % 25 == 0:
                print(f"  -> {counter} emails converted...")
        except Exception as e:
            print(f"  [SKIP] row {scanned}: {e}")
            skipped += 1

# ── Write labels CSV ──────────────────────────────────────────────────────────
labels_path = Path("dataset/benign_labels.csv")
with open(labels_path, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["id", "filepath", "label", "split"])
    w.writeheader()
    w.writerows(labels)

print(f"\nDone.")
print(f"  Scanned {scanned:,} total rows")
print(f"  {counter} benign .eml files saved to {OUT_DIR}/")
print(f"  {skipped} rows skipped")
print(f"  Labels written to {labels_path}")
print(f"\nNext step: python dataset/merge_labels.py")