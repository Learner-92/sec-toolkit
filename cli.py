import argparse
import json
import sys
from sec_toolkit.prober import audit_headers_and_cookies
from sec_toolkit.scraper import extract_forms

def main():
    parser = argparse.ArgumentParser(description="SecToolkit - Modular WebApp Security Auditor")
    parser.add_argument("-u", "--url", required=True, help="Target URL to audit")
    parser.add_argument("-o", "--output", help="Optional JSON report output file")
    args = parser.parse_args()

    print(f"\n[*] Auditing Target: {args.url}")
    print("=" * 55)

    # 1. Probing & Headers
    res = audit_headers_and_cookies(args.url)
    if "error" in res:
        print(f"[-] Connection Error: {res['error']}")
        sys.exit(1)

    print(f"[+] Status Code : {res['status_code']}")
    print(f"[+] Server Header: {res['server']}")
    
    if res["missing_headers"]:
        print(f"[!] Missing Headers ({len(res['missing_headers'])}): {', '.join(res['missing_headers'])}")
    else:
        print("[+] All baseline security headers present.")

    # 2. Extract Forms
    forms = extract_forms(res["html_content"], args.url)
    print(f"[+] Forms Found  : {len(forms)}")

    # 3. Save Report
    if args.output:
        report_data = {
            "target": args.url,
            "status_code": res["status_code"],
            "server": res["server"],
            "missing_headers": res["missing_headers"],
            "cookies": res["cookies"],
            "forms": forms
        }
        with open(args.output, "w") as f:
            json.dump(report_data, f, indent=4)
        print(f"\n[+] Report saved to {args.output}")

    print("=" * 55)
    print("[+] Audit finished successfully.")

if __name__ == "__main__":
    main()