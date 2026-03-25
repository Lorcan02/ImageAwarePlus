from pathlib import Path
from modules.report import analyze_image

def main():
    TEST_IMAGE = Path("samples") / "test_image.png"  # or any phishing/QR sample

    if not TEST_IMAGE.exists():
        print(f"❌ Put an image at: {TEST_IMAGE}")
        return

    result = analyze_image(TEST_IMAGE)

    print("✅ Analysis complete.")
    print("Report path:", result["report_path"])
    print("Annotated image:", result["annotated_image"])
    print("OCR text:", result["ocr_text"])
    print("Risk level:", result["risk_level"])
    print("Risk score:", result["risk_score"])

if __name__ == "__main__":
    main()
