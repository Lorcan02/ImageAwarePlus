from modules.url_analysis import query_virustotal_url

def main():
    # Test URLs
    urls = [
        "https://example.com",
        "http://testphp.vulnweb.com",  # often flagged by scanners
    ]

    for url in urls:
        print("=" * 60)
        print("Checking:", url)
        result = query_virustotal_url(url)

        print("Verdict:", result.verdict)
        print("Malicious:", result.vt_malicious)
        print("Suspicious:", result.vt_suspicious)
        print("Harmless:", result.vt_harmless)
        print("Undetected:", result.vt_undetected)

if __name__ == "__main__":
    main()
