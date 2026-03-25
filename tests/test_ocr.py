from pathlib import Path
import cv2

from modules.preprocessing import load_image_bgr, preprocess_for_ocr_and_qr
from modules.ocr import run_ocr, extract_urls, keyword_hits, OCRConfig

TEST_IMAGE = Path("samples") / "test_image.png"

def main():
    if not TEST_IMAGE.exists():
        print(f"❌ Put an image at: {TEST_IMAGE}")
        return

    # Load and preprocess
    img_bgr = load_image_bgr(TEST_IMAGE)
    outputs = preprocess_for_ocr_and_qr(img_bgr)
    thresh = outputs["thresh"]

    # OCR
    text = run_ocr(thresh, OCRConfig(psm=6))
    print("\n===== OCR TEXT (START) =====\n")
    print(text)
    print("\n===== OCR TEXT (END) =====\n")

    # Extract URLs + keywords
    urls = extract_urls(text)
    hits = keyword_hits(text)

    print("URLs found:", urls if urls else "None")
    print("Keyword hits:", hits if hits else "None")

    # Save OCR text output for documentation
    out_txt = Path("outputs") / f"{TEST_IMAGE.stem}_ocr.txt"
    out_txt.write_text(text, encoding="utf-8")
    print(f"✅ Saved OCR text to {out_txt}")

if __name__ == "__main__":
    main()
