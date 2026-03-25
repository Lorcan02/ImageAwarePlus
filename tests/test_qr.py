from pathlib import Path
import cv2

from modules.preprocessing import load_image_bgr, preprocess_for_ocr_and_qr, save_debug_images
from modules.qr import detect_and_decode_qr, draw_qr_bbox

TEST_IMAGE = Path("samples") / "test_qr.png"  # use an image that contains a QR code

def main():
    if not TEST_IMAGE.exists():
        print(f"❌ Put a QR image at: {TEST_IMAGE}")
        print("   (Any QR code screenshot is fine.)")
        return

    img_bgr = load_image_bgr(TEST_IMAGE)

    # Preprocess (sometimes helps QR too)
    outputs = preprocess_for_ocr_and_qr(img_bgr)
    resized = outputs["resized_bgr"]

    qr = detect_and_decode_qr(resized)

    if qr.found:
        print("✅ QR Found!")
        print("Decoded data:", qr.data)

        annotated = draw_qr_bbox(resized, qr.points)
        out_path = Path("outputs") / f"{TEST_IMAGE.stem}_qr_annotated.png"
        cv2.imwrite(str(out_path), annotated)
        print(f"✅ Saved annotated QR image to {out_path}")
    else:
        print("❌ No QR detected in the image.")

if __name__ == "__main__":
    main()
