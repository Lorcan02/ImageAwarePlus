import sys
import csv
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from modules.email_parser import analyze_eml
from modules.email_analysis import analyze_email

# Load false positives at medium threshold
rows = list(csv.DictReader(open('outputs/eval/predictions.csv')))
fp_rows = [r for r in rows if r['y_true'] == '0' and r['y_pred_medium'] == '1']

print(f"=== FALSE POSITIVES AT MEDIUM THRESHOLD: {len(fp_rows)} ===\n")

for r in fp_rows:
    filepath = Path("dataset") / r["filepath"]
    print(f"ID: {r['id']}  Score: {r['score']}")

    if not filepath.exists():
        print("  [FILE NOT FOUND]")
        continue

    try:
        data    = analyze_eml(filepath, Path("outputs/eval_images"))
        headers = data["headers"]
        body    = data["body"] or ""
        ea      = analyze_email(headers, body)

        print(f"  Subject : {headers.get('subject','[none]')[:80]}")
        print(f"  From    : {headers.get('from','[none]')[:80]}")
        print(f"  SPF     : {headers.get('received-spf','[none]')}")
        print(f"  DKIM    : {'Present' if headers.get('dkim-signature') else 'Absent'}")
        print(f"  EA Score: {ea.get('score',0)}")
        print(f"  EA Indicators: {ea.get('indicators',[])}")
        print(f"  Body (100 chars): {body[:100].strip()}")
    except Exception as e:
        print(f"  [ERROR: {e}]")
    print()