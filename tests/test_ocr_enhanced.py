from pathlib import Path

from modules.preprocessing import load_image_bgr, preprocess_for_ocr_and_qr
from modules.ocr_enhanced import choose_best_ocr, extract_urls, keyword_hits


TEST_IMAGE = Path("samples") / "test_image.png"

def main():
    if not TEST_IMAGE.exists():
        print(f"❌ Put an image at: {TEST_IMAGE}")
        return

    img_bgr = load_image_bgr(TEST_IMAGE)
    outputs = preprocess_for_ocr_and_qr(img_bgr)

    best = choose_best_ocr(
        gray=outputs["gray"],
        adaptive_thresh=outputs["thresh"],
        otsu_thresh=outputs["otsu"],
        psms=(6, 11, 4),
        conf_threshold=35
    )

    print("\n=== BEST OCR RESULT ===")
    print("Method:", best.method)
    print("Mean confidence:", round(best.mean_confidence, 2))
    print("Kept words:", best.kept_words, "/", best.total_words)
    print("\n--- TEXT ---\n")
    print(best.text)

    urls = extract_urls(best.text)
    hits = keyword_hits(best.text)

    print("\nURLs found:", urls if urls else "None")
    print("Keyword hits:", hits if hits else "None")

if __name__ == "__main__":
    main()
