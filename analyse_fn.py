import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from modules.email_parser import analyze_eml

# ── Show lowest scoring phishing emails ──────────────────────────────────────
rows = list(csv.DictReader(open('outputs/eval/predictions.csv')))
phish_rows = [r for r in rows if r['y_true'] == '1']
phish_sorted = sorted(phish_rows, key=lambda x: float(x['score']))

print("=== 20 LOWEST SCORING PHISHING EMAILS ===\n")
print(f"{'ID':<20} {'Score':<8} {'Filepath'}")
print("-" * 60)
for r in phish_sorted[:20]:
    print(f"{r['id']:<20} {r['score']:<8} {r['filepath']}")

print("\n=== CONTENT OF 5 LOWEST SCORING EMAILS ===\n")

for r in phish_sorted[:5]:
    filepath = Path("dataset") / r["filepath"]
    print(f"\n{'='*60}")
    print(f"ID: {r['id']}  Score: {r['score']}")
    print(f"File: {filepath}")
    print("-" * 60)

    if not filepath.exists():
        print("[FILE NOT FOUND]")
        continue

    try:
        data = analyze_eml(filepath, Path("outputs/eval_images"))
        headers = data["headers"]
        body    = data["body"] or ""
        images  = data["images"]

        print(f"Subject : {headers.get('subject', '[none]')}")
        print(f"From    : {headers.get('from', '[none]')}")
        print(f"Date    : {headers.get('date', '[none]')}")
        print(f"Images  : {len(images)} embedded image(s)")
        print(f"Body ({len(body)} chars):")
        if body.strip():
            print(body[:400])
        else:
            print("[EMPTY BODY]")
    except Exception as e:
        print(f"[ERROR reading email: {e}]")

print("\n=== SCORE DISTRIBUTION ===\n")
buckets = {"0-9": 0, "10-19": 0, "20-29": 0, "30-34": 0, "35-49": 0, "50-69": 0, "70+": 0}
for r in phish_rows:
    s = float(r['score'])
    if s < 10:    buckets["0-9"]   += 1
    elif s < 20:  buckets["10-19"] += 1
    elif s < 30:  buckets["20-29"] += 1
    elif s < 35:  buckets["30-34"] += 1
    elif s < 50:  buckets["35-49"] += 1
    elif s < 70:  buckets["50-69"] += 1
    else:         buckets["70+"]   += 1

for bucket, count in buckets.items():
    bar = "█" * count
    print(f"  {bucket:<8} {count:>3}  {bar}")