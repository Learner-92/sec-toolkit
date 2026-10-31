import argparse
import sys
import re
import requests

requests.packages.urllib3.disable_warnings()

# Common patterns for sensitive keys & tokens
SECRET_PATTERNS = {
    "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "JWT Token": r"ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
    "Generic API Key / Secret": r"(?i)(?:api_key|apikey|secret|token|password)[\"'\s:=]+[\"']([a-zA-Z0-9_\-]{16,})[\"']",
    "Internal Endpoint": r"['\"](\/(?:api|v[0-9]|auth|admin)[a-zA-Z0-9_\-\/]*)['\"]"
}

def scan_for_secrets(url):
    target_url = url if url.startswith(("http://", "https://")) else f"https://{url}"
    print(f"\n[*] Scanning for Secrets: {target_url}")
    print("-" * 50)
    
    headers = {"User-Agent": "SecAuditor/1.0"}
    try:
        resp = requests.get(target_url, headers=headers, timeout=8, verify=False, allow_redirects=True)
        content = resp.text
    except requests.RequestException as e:
        print(f"[-] Failed to fetch: {e}")
        return

    findings_count = 0
    for name, pattern in SECRET_PATTERNS.items():
        matches = set(re.findall(pattern, content))
        if matches:
            print(f"[!] Potential {name} Found ({len(matches)}):")
            for m in list(matches)[:5]:  # Top 5 unique matches print karein
                # Agar match tuple hai (regex groups ki wajah se), pehla element lein
                match_str = m if isinstance(m, str) else m[0]
                print(f"    -> {match_str.strip()}")
            findings_count += len(matches)

    if findings_count == 0:
        print("[+] No exposed secrets or patterns matched.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Day 4: Web Source Regex Secrets Harvester")
    parser.add_argument("-u", "--url", required=True, help="Target URL or JS file URL")
    args = parser.parse_args()

    scan_for_secrets(args.url)