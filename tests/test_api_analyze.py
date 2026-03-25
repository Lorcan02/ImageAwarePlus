import requests

URL = "http://127.0.0.1:5000/api/analyze"
IMAGE_PATH = r"C:\Users\lorca\Desktop\ImageAwarePlus\samples\test_image.png"

def main():
    with open(IMAGE_PATH, "rb") as f:
        files = {"image": f}
        r = requests.post(URL, files=files)

    print("Status:", r.status_code)
    print("Response (first 1000 chars):")
    print(r.text[:1000])

    # Try JSON parse
    try:
        data = r.json()
        print("\nParsed JSON keys:", list(data.keys()))
        print("risk_level:", data.get("risk_level"))
        print("risk_score:", data.get("risk_score"))
        print("artifact links:", data.get("artifacts"))
    except Exception as e:
        print("\n❌ JSON parse failed:", e)

if __name__ == "__main__":
    main()
