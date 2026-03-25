from pathlib import Path
from modules.pdf_report_rl import export_pdf_from_report_json


def main():
    out_dir = Path("outputs")
    reports = sorted(out_dir.glob("*_report.json"), key=lambda p: p.stat().st_mtime, reverse=True)

    if not reports:
        print("❌ No *_report.json found in outputs/. Run the pipeline first.")
        return

    latest = reports[0]
    print("Using report:", latest)

    pdf_path = export_pdf_from_report_json(latest)
    print("✅ PDF generated:", pdf_path)


if __name__ == "__main__":
    main()
