"""
Run this FIRST to inspect the TREC 2007 dataset structure
before running the full conversion.
"""
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

ARCHIVE_DIR = Path("archive")

print("=== FILES IN ARCHIVE FOLDER ===")
for f in sorted(ARCHIVE_DIR.rglob("*")):
    if f.is_file():
        size_kb = f.stat().st_size // 1024
        print(f"  {f}  ({size_kb:,} KB)")

print("\n=== INSPECTING email_text ===")
# Try as CSV first
for ext in [".csv", ".xlsx", ""]:
    p = ARCHIVE_DIR / f"email_text{ext}"
    if p.exists():
        print(f"Found: {p}")
        try:
            with open(p, newline="", encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)
                headers = next(reader, [])
                print(f"  Columns: {headers}")
                print(f"  First 3 rows:")
                for i, row in enumerate(reader):
                    if i >= 3:
                        break
                    print(f"    {[str(c)[:80] for c in row]}")
        except Exception as e:
            print(f"  Error reading as CSV: {e}")
        break

print("\n=== INSPECTING email_origin ===")
for ext in [".csv", ".xlsx", ""]:
    p = ARCHIVE_DIR / f"email_origin{ext}"
    if p.exists():
        print(f"Found: {p}")
        try:
            with open(p, newline="", encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)
                headers = next(reader, [])
                print(f"  Columns: {headers}")
                print(f"  First 5 rows:")
                for i, row in enumerate(reader):
                    if i >= 5:
                        break
                    print(f"    {row}")
        except Exception as e:
            print(f"  Error reading as CSV: {e}")
        break

print("\n=== CHECKING trec07p ARCHIVE ===")
trec_archive = ARCHIVE_DIR / "trec07p"
if trec_archive.exists():
    if trec_archive.is_dir():
        contents = list(trec_archive.iterdir())
        print(f"  trec07p is a folder with {len(contents)} items:")
        for item in sorted(contents)[:10]:
            print(f"    {item.name} ({'dir' if item.is_dir() else 'file'})")
    else:
        print(f"  trec07p is a file ({trec_archive.stat().st_size // 1024:,} KB)")
        print(f"  Suffix: {trec_archive.suffix}")