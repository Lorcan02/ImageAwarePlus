from modules.url_analysis import query_virustotal_url
from modules.scoring import score_image_analysis


def main():
    urls = [
        "https://example.com",
        "http://testphp.vulnweb.com",
    ]

    for url in urls:
        print("=" * 70)
        print("URL:", url)

        vt = query_virustotal_url(url)

        ti_results = [{
            "url": vt.url,
            "verdict": vt.verdict,
            "vt_malicious": vt.vt_malicious,
            "vt_suspicious": vt.vt_suspicious,
            "vt_harmless": vt.vt_harmless,
            "vt_undetected": vt.vt_undetected,
        }]

        score = score_image_analysis(
            ocr_text="Please login to verify your account",
            keyword_hits={"login": 1, "verify": 1, "account": 1},
            urls_from_ocr=[url],
            qr_found=False,
            qr_data=None,
            ti_results=ti_results,
        )

        print("VirusTotal verdict:", vt.verdict)
        print("VT stats -> malicious:", vt.vt_malicious, "suspicious:", vt.vt_suspicious, "harmless:", vt.vt_harmless)
        print("Risk score:", score.risk_score, "| Risk level:", score.risk_level)
        print("Reasons:")
        for r in score.reasons:
            print("-", r)


if __name__ == "__main__":
    main()
