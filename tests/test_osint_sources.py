from __future__ import annotations

from modules.urlscan import urlscan_search
from modules.phishtank import phishtank_check


def main():
    test_url = "http://example.com"

    print("URLScan search:")
    try:
        print(urlscan_search(test_url))
    except Exception as e:
        print("urlscan error:", e)

    print("\nPhishTank check:")
    try:
        print(phishtank_check(test_url))
    except Exception as e:
        print("phishtank error:", e)


if __name__ == "__main__":
    main()
