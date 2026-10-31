import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

requests.packages.urllib3.disable_warnings()

# 1. Standard Audit Headers
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy"
]

# 2. Baseline Recon Endpoints
RECON_PATHS = [
    "robots.txt",
    "sitemap.xml",
    ".well-known/security.txt",
    "api",
    "swagger.json"
]

def check_security_headers(response):
    headers_lower = {k.lower(): v for k, v in response.headers.items()}
    missing = [h for h in SECURITY_HEADERS if h.lower() not in headers_lower]
    return {
        "status": "PASS" if not missing else "FLAG",
        "missing_headers": missing
    }

def inspect_forms(html_text, base_url):
    soup = BeautifulSoup(html_text, "html.parser")
    forms_data = []
    
    for f in soup.find_all("form"):
        action = f.get("action", "")
        method = f.get("method", "GET").upper()
        inputs = [
            {
                "name": inp.get("name", ""),
                "type": inp.get("type", "text"),
                "is_hidden": inp.get("type", "").lower() == "hidden"
            }
            for inp in f.find_all("input")
        ]
        forms_data.append({
            "action": urljoin(base_url, action),
            "method": method,
            "inputs": inputs
        })
    return forms_data

def probe_path(base_url, path):
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    try:
        r = requests.get(url, timeout=5, verify=False, allow_redirects=False)
        if r.status_code != 404:
            return {"path": path, "status": r.status_code, "size": len(r.content)}
    except requests.RequestException:
        pass
    return None

def run_audit(target_url, output_file=None):
    url = target_url if target_url.startswith(("http://", "https://")) else f"https://{target_url}"
    print(f"\n[*] Starting Security Baseline Audit: {url}")
    print("=" * 60)

    audit_report = {
        "target": url,
        "base_probe": {},
        "header_audit": {},
        "discovered_endpoints": [],
        "forms": []
    }

    # Step A: Base Probe & Headers
    try:
        resp = requests.get(url, timeout=8, verify=False, allow_redirects=True)
        audit_report["base_probe"] = {
            "status_code": resp.status_code,
            "server": resp.headers.get("Server", "Unknown"),
            "content_length": len(resp.content)
        }
        print(f"[+] Base Connection: HTTP {resp.status_code} | Server: {audit_report['base_probe']['server']}")

        header_res = check_security_headers(resp)
        audit_report["header_audit"] = header_res
        if header_res["missing_headers"]:
            print(f"[!] Missing Headers ({len(header_res['missing_headers'])}): {', '.join(header_res['missing_headers'])}")
        else:
            print("[+] All baseline security headers are present.")

        # Step B: Parse Forms
        forms = inspect_forms(resp.text, url)
        audit_report["forms"] = forms
        print(f"[+] Forms Detected: {len(forms)}")

    except requests.RequestException as e:
        print(f"[-] Target unavailable: {e}")
        return

    # Step C: Parallel Endpoint Probing
    print(f"[*] Probing {len(RECON_PATHS)} baseline endpoints in parallel...")
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(probe_path, url, p) for p in RECON_PATHS]
        for f in as_completed(futures):
            res = f.result()
            if res:
                audit_report["discovered_endpoints"].append(res)
                print(f"    -> [HTTP {res['status']}] /{res['path']}")

    # Step D: Save JSON Report
    if output_file:
        with open(output_file, "w") as jf:
            json.dump(audit_report, jf, indent=4)
        print(f"\n[+] Full JSON report exported to: {output_file}")
    
    print("=" * 60)
    print("[+] Audit Run Complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Day 7 Capstone: Web Audit Baseline CLI Engine")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., https://example.com)")
    parser.add_argument("-o", "--output", default="report.json", help="Path to output JSON file (default: report.json)")
    args = parser.parse_args()

    run_audit(args.url, args.output)