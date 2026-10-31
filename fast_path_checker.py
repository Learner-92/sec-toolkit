import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

requests.packages.urllib3.disable_warnings()

# Common web paths to check for exposure / status
COMMON_PATHS = [
    "robots.txt",
    "sitemap.xml",
    ".well-known/security.txt",
    "api",
    "api/v1",
    "swagger.json",
    "openapi.json",
    "admin",
    "login",
    "health",
    "status",
    "metrics"
]

def check_endpoint(base_url, path):
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    headers = {"User-Agent": "SecAuditor/1.0"}
    
    try:
        resp = requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=False)
        return {
            "url": url,
            "status": resp.status_code,
            "size": len(resp.content)
        }
    except requests.RequestException:
        return None

def run_concurrent_scan(base_url, threads=5):
    target = base_url if base_url.startswith(("http://", "https://")) else f"https://{base_url}"
    print(f"\n[*] Probing {len(COMMON_PATHS)} endpoints on: {target}")
    print(f"[*] Thread Pool Size: {threads}")
    print("-" * 55)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        # Schedule all requests in parallel
        futures = {executor.submit(check_endpoint, target, p): p for p in COMMON_PATHS}
        
        for future in as_completed(futures):
            res = future.result()
            if res:
                status = res["status"]
                url = res["url"]
                size = res["size"]
                
                # Highlight responses that are not 404
                if status != 404:
                    print(f"[STATUS {status}] {url:<40} ({size} bytes)")

    print("-" * 55)
    print("[+] Concurrency check finished.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Day 6: Multi-Threaded Endpoint Prober")
    parser.add_argument("-u", "--url", required=True, help="Base target URL")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of parallel threads (default: 5)")
    args = parser.parse_args()

    run_concurrent_scan(args.url, args.threads)