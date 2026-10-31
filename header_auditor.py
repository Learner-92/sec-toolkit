import argparse
import sys
import requests

requests.packages.urllib3.disable_warnings()

# Crucial WebApp security headers to inspect
MANDATORY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy"
]

def load_targets(filepath):
    try:
        with open(filepath, "r") as f:
            targets = [line.strip() for line in f if line.strip()]
            return sorted(list(set(targets)))
    except FileNotFoundError:
        print(f"[!] File not found: {filepath}")
        sys.exit(1)

def audit_target(target):
    url = target if target.startswith(("http://", "https://")) else f"https://{target}"
    print(f"\n[*] Target: {url}")
    print("-" * 50)
    
    try:
        # Follow redirects here so we inspect the final landing response
        resp = requests.get(url, timeout=7, verify=False, allow_redirects=True)
    except requests.RequestException as e:
        print(f"[-] Request failed: {e}")
        return

    # 1. Security Headers Audit
    headers = {k.lower(): v for k, v in resp.headers.items()}
    missing_headers = []
    
    for h in MANDATORY_HEADERS:
        if h.lower() not in headers:
            missing_headers.append(h)
            
    if missing_headers:
        print("[!] Missing Security Headers:")
        for mh in missing_headers:
            print(f"    - {mh}")
    else:
        print("[+] All baseline security headers are present!")

    # 2. Cookie Security Audit
    cookies = resp.cookies
    if not cookies:
        print("[i] No cookies set in response.")
    else:
        print(f"[+] Found {len(cookies)} cookies:")
        for c in cookies:
            flaws = []
            if not c.secure:
                flaws.append("Missing 'Secure'")
            if not c.has_nonstandard_attr("httponly"):
                flaws.append("Missing 'HttpOnly'")
            
            # SameSite attribute check
            samesite = c._rest.get("samesite", None) if hasattr(c, "_rest") else None
            if not samesite:
                flaws.append("Missing 'SameSite'")

            status = f"[VULN] {', '.join(flaws)}" if flaws else "[OK] Hardened"
            print(f"    - Cookie '{c.name}': {status}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Day 3: Baseline Header & Cookie Auditor")
    parser.add_argument("-f", "--file", required=True, help="Path to targets file")
    args = parser.parse_args()

    targets = load_targets(args.file)
    for t in targets:
        audit_target(t)
    print("\n" + "=" * 50 + "\n[+] Audit Complete.")