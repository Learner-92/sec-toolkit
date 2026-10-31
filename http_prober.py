import argparse
import sys
import requests

# Disable insecure HTTPS warnings if needed
requests.packages.urllib3.disable_warnings()

def load_targets(filepath):
    try:
        with open(filepath, "r") as f:
            targets = [line.strip() for line in f if line.strip()]
            return sorted(list(set(targets)))
    except FileNotFoundError:
        print(f"[!] Error: File '{filepath}' nahi mili.")
        sys.exit(1)

def probe_target(target):
    # Ensure protocol
    url = target if target.startswith(("http://", "https://")) else f"https://{target}"
    
    custom_headers = {
        "User-Agent": "SecAuditor/1.0 (WebApp Security Audit)"
    }
    
    try:
        # allow_redirects=False taaki real status (301/302) pata chale
        resp = requests.get(url, headers=custom_headers, timeout=5, verify=False, allow_redirects=False)
        server = resp.headers.get("Server", "Unknown Server")
        content_len = len(resp.content)
        
        # Color coding for terminal output
        print(f"[{resp.status_code}] {url} | Server: {server} | Size: {content_len} bytes")
        
    except requests.exceptions.Timeout:
        print(f"[TIMEOUT] {url}")
    except requests.exceptions.ConnectionError:
        print(f"[CONN_ERR] {url}")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] {url} -> {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Day 2: Simple HTTP Status Prober")
    parser.add_argument("-f", "--file", required=True, help="Path to targets file")
    args = parser.parse_args()

    targets = load_targets(args.file)
    print(f"\n[*] Probing {len(targets)} targets...\n" + "-"*50)
    
    for t in targets:
        probe_target(t)
    print("-"*50 + "\n[+] Audit scan finished.")