from pathlib import Path

from modules.preprocessing import (
    load_image_bgr,
    preprocess_for_ocr_and_qr,
    save_debug_images,
    PreprocessConfig,
)

# Change this to a real image path you have
TEST_IMAGE = Path("samples") / "test_image.png"

def main():
    if not TEST_IMAGE.exists():
        print(f"❌ Put an image at: {TEST_IMAGE}")
        print("   (Any screenshot / phishing image sample is fine.)")
        return

    img = load_image_bgr(TEST_IMAGE)

    cfg = PreprocessConfig(
        max_width=1200,
        denoise=True,
        threshold_method="adaptive"  # try "otsu" too
    )

    outputs = preprocess_for_ocr_and_qr(img, cfg)
    save_debug_images(outputs, out_dir="outputs", stem=TEST_IMAGE.stem)

    print("✅ Preprocessing complete.")
    print("✅ Saved debug images to outputs/")

if __name__ == "__main__":
    main()
