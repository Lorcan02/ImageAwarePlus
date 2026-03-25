import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from modules.email_parser import analyze_eml
from modules.url_repair import extract_urls_robust
from modules.email_cleaner import clean_email_urls
import re

# ── Diagnose phish_0025 ───────────────────────────────────────────────────────
eml_path = Path("dataset/phishing_eml/phish_0025.eml")
print(f"Analysing: {eml_path}\n")

# Step 1: Read raw email bytes to check what HTML looks like
with open(eml_path, "rb") as f:
    raw = f.read()

# Find href attributes in raw email
print("=== RAW HREF ATTRIBUTES IN EMAIL ===")
hrefs = re.findall(rb'href=["\']([^"\']{8,})["\']', raw, flags=re.IGNORECASE)
for h in hrefs:
    try:
        decoded = h.decode("utf-8", errors="replace")
        print(f"  {decoded[:120]}")
    except:
        print(f"  [binary]")
print(f"Total hrefs in raw email: {len(hrefs)}\n")

# Step 2: Run through email_parser
data = analyze_eml(eml_path, Path("outputs/eval_images"))
body = data["body"] or ""

print("=== PARSED BODY ===")
print(repr(body[:600]))
print(f"\nBody length: {len(body)} chars\n")

# Step 3: URLs extracted from body
print("=== URLS EXTRACTED FROM BODY ===")
urls = extract_urls_robust(body)
print(f"extract_urls_robust found: {len(urls)} URLs")
for u in urls:
    print(f"  {u}")

# Step 4: After cleaning
cleaned = clean_email_urls(urls)
print(f"\nAfter email_cleaner: {len(cleaned)} URLs")
for u in cleaned:
    print(f"  {u}")

# Step 5: Check if the issue is in the HTML parsing
print("\n=== HTML PARTS IN EMAIL ===")
import email
from email import policy
from email.parser import BytesParser

with open(eml_path, "rb") as f:
    msg = BytesParser(policy=policy.default).parse(f)

for part in msg.walk():
    ct = part.get_content_type()
    if ct == "text/html":
        try:
            html_content = part.get_content()
            print(f"HTML part found ({len(html_content)} chars)")
            # Find hrefs in this HTML part
            part_hrefs = re.findall(
                r'href=["\']([^"\']{8,})["\']',
                html_content,
                flags=re.IGNORECASE
            )
            print(f"Hrefs in HTML part: {len(part_hrefs)}")
            for h in part_hrefs[:5]:
                print(f"  {h[:120]}")
        except Exception as e:
            print(f"Error reading HTML part: {e}")
    elif ct == "text/plain":
        try:
            plain = part.get_content()
            plain_urls = re.findall(r'https?://[^\s]+', plain)
            print(f"Plain text part ({len(plain)} chars), URLs: {len(plain_urls)}")
        except Exception as e:
            print(f"Error reading plain part: {e}")