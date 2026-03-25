from pathlib import Path
from integrations.kingphisher_adapter import (
    AdapterConfig,
    analyze_via_api,
    should_flag,
    soc_summary,
    save_report_snapshot,
)

def main():
    # Flask server must be running: python web/app.py
    cfg = AdapterConfig(
        api_base="http://127.0.0.1:5000",
        threshold=65,
    )

    img = Path("samples") / "test_image.png"
    res = analyze_via_api(img, cfg)

    print("OK:", res.ok)
    print("Status:", res.status_code)
    print("Risk:", res.risk_level, res.risk_score)
    print("Flagged?:", should_flag(res.risk_score or 0, cfg.threshold))
    print(soc_summary(res))

    snap = save_report_snapshot(res, cfg, tag="demo")
    if snap:
        print("✅ Saved report snapshot:", snap)
    else:
        print("❌ No snapshot saved (analysis failed?)")

    if res.artifacts:
        print("\nArtifacts returned by API:")
        for k, v in res.artifacts.items():
            print("-", k, "=>", v)

if __name__ == "__main__":
    main()
