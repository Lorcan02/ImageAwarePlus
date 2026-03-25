from modules.vt_cache import VTCache

def main():
    cache = VTCache(ttl_days=7)

    url = "https://example.com"

    print("First call (should query VirusTotal if not cached yet)...")
    rep1 = cache.get_or_query(url)
    print("Verdict:", rep1.verdict, "| malicious:", rep1.vt_malicious, "| suspicious:", rep1.vt_suspicious)

    print("\nSecond call (should use cache, should be fast)...")
    rep2 = cache.get_or_query(url)
    print("Verdict:", rep2.verdict, "| malicious:", rep2.vt_malicious, "| suspicious:", rep2.vt_suspicious)

    print("\n✅ If the second call returns instantly, caching is working.")
    print("Cache DB:", cache.db_path)

if __name__ == "__main__":
    main()
