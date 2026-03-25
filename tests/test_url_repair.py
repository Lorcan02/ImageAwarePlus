from pathlib import Path
from modules.url_repair import extract_urls_robust, repair_ocr_text_for_urls

def main():
    ocr_path = Path("outputs")
    ocr_files = sorted(ocr_path.glob("*_ocr.txt"), key=lambda p: p.stat().st_mtime, reverse=True)

    if not ocr_files:
        print("❌ No OCR text files found in outputs/. Run the pipeline first.")
        return

    latest = ocr_files[0]
    print("Using OCR file:", latest)

    text = latest.read_text(encoding="utf-8", errors="ignore")
    repaired = repair_ocr_text_for_urls(text)
    urls = extract_urls_robust(text)

    print("\n--- Extracted URLs (robust) ---")
    print(urls if urls else "None")

    # Optional: show a small snippet for debugging
    print("\n--- Repaired text snippet ---")
    print(repaired[:600])

if __name__ == "__main__":
    main()
