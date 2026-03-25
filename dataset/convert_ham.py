import csv
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────
HAM_FOLDERS = [
    "raw/20021010_easy_ham/easy_ham",
    "raw/20021010_hard_ham/hard_ham",
    "raw/20030228_easy_ham/easy_ham",   # skip if not downloaded
    "raw/20030228_hard_ham/hard_ham",   # skip if not downloaded
]
OUT_DIR    = Path("benign_eml")
MAX_EMAILS = 150

OUT_DIR.mkdir(parents=True, exist_ok=True)

# ── Convert ───────────────────────────────────────────────────────────────────
labels  = []
counter = 0
skipped = 0

for folder_path in HAM_FOLDERS:

    p = Path(folder_path)
    if not p.exists():
        print(f"[SKIP] Folder not found: {folder_path}")
        continue

    files = [f for f in p.iterdir() if f.is_file()]
    print(f"[READING] {folder_path} — {len(files)} files found")

    for file_path in sorted(files):

        if counter >= MAX_EMAILS:
            print(f"[STOP] Reached cap of {MAX_EMAILS} emails")
            break

        if file_path.name == "cmds":
            continue

        try:
            content = file_path.read_bytes()

            content_start = content[:500].lower()
            if not any(h in content_start for h in
                       [b"from:", b"to:", b"subject:", b"date:"]):
                skipped += 1
                continue

            stem     = f"benign_{counter:04d}"
            out_path = OUT_DIR / f"{stem}.eml"
            out_path.write_bytes(content)

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
            print(f"  [SKIP] {file_path.name}: {e}")
            skipped += 1

# ── Write labels CSV ──────────────────────────────────────────────────────────
labels_path = Path("benign_labels.csv")
with open(labels_path, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["id", "filepath", "label", "split"])
    w.writeheader()
    w.writerows(labels)

print(f"\nDone.")
print(f"  {counter} benign .eml files saved to {OUT_DIR}/")
print(f"  {skipped} files skipped")
print(f"  Labels written to {labels_path}")