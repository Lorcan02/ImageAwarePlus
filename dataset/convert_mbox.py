import mailbox
import csv
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────
MBOX_FILE  = "raw/phishing-2025"   # path relative to dataset/ folder
OUT_DIR    = Path("phishing_eml")
MAX_EMAILS = 150                   # cap to avoid slow VT evaluation runs

OUT_DIR.mkdir(parents=True, exist_ok=True)

# ── Convert ───────────────────────────────────────────────────────────────────
labels  = []
counter = 0
skipped = 0

p = Path(MBOX_FILE)
if not p.exists():
    print(f"[ERROR] File not found: {MBOX_FILE}")
    print(f"        Make sure phishing-2025 is saved at: dataset/raw/phishing-2025")
    exit(1)

print(f"[READING] {MBOX_FILE} ...")
mbox = mailbox.mbox(str(p))

for msg in mbox:

    if counter >= MAX_EMAILS:
        print(f"[STOP] Reached cap of {MAX_EMAILS} emails")
        break

    stem     = f"phish_{counter:04d}"
    out_path = OUT_DIR / f"{stem}.eml"

    try:
        with open(out_path, "wb") as f:
            f.write(msg.as_bytes())

        labels.append({
            "id":       stem,
            "filepath": f"phishing_eml/{stem}.eml",
            "label":    "phish",
            "split":    "test",
        })
        counter += 1

        if counter % 25 == 0:
            print(f"  → {counter} emails converted...")

    except Exception as e:
        print(f"  [SKIP] email {counter + skipped}: {e}")
        skipped += 1

# ── Write labels CSV ──────────────────────────────────────────────────────────
labels_path = Path("phishing_labels.csv")
with open(labels_path, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["id", "filepath", "label", "split"])
    w.writeheader()
    w.writerows(labels)

print(f"\nDone.")
print(f"  {counter} .eml files saved to {OUT_DIR}/")
print(f"  {skipped} emails skipped due to errors")
print(f"  Labels written to {labels_path}")