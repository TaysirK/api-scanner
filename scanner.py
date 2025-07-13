import requests

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy"
]

def scan_url(url):
    try:
        response = requests.get(url, timeout=10)
        print(f"\n[*] Scanning {url}")
        print(f"[+] Status Code: {response.status_code}")
        print(f"[+] Final URL after redirects: {response.url}")
        print("[+] Response Headers:\n")

        for header, value in response.headers.items():
            print(f"  {header}: {value}")

        print("\n[!] Checking for missing security headers:")
        for header in SECURITY_HEADERS:
            if header not in response.headers:
                print(f"  [-] {header} is missing!")
            else:
                print(f"  [+] {header} is present ✅")

    except requests.RequestException as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    url = input("Enter a URL to scan (e.g., https://example.com): ")
    if not url.startswith("http"):
        url = "https://" + url
    scan_url(url)
