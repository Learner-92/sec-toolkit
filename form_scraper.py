import argparse
import sys
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

requests.packages.urllib3.disable_warnings()

def scrape_forms(target_url):
    url = target_url if target_url.startswith(("http://", "https://")) else f"https://{target_url}"
    print(f"\n[*] Parsing forms on: {url}")
    print("-" * 50)
    
    headers = {"User-Agent": "SecAuditor/1.0"}
    try:
        resp = requests.get(url, headers=headers, timeout=8, verify=False, allow_redirects=True)
        soup = BeautifulSoup(resp.text, "html.parser")
    except requests.RequestException as e:
        print(f"[-] Connection failed: {e}")
        return

    forms = soup.find_all("form")
    if not forms:
        print("[i] No <form> elements found on this page.")
        return

    print(f"[+] Total forms found: {len(forms)}\n")
    for idx, form in enumerate(forms, start=1):
        action = form.get("action", "")
        full_action = urljoin(url, action) if action else url
        method = form.get("method", "GET").upper()
        
        print(f"--- Form #{idx} [{method}] -> {full_action} ---")
        
        inputs = form.find_all("input")
        if not inputs:
            print("    (No input fields inside this form)")
            continue

        for field in inputs:
            name = field.get("name", "<unnamed>")
            field_type = field.get("type", "text")
            val = field.get("value", "")
            
            # Highlight hidden fields as they are relevant for audit review
            tag = "[HIDDEN]" if field_type.lower() == "hidden" else "[FIELD] "
            print(f"    {tag} Name: {name:<20} | Type: {field_type:<10} | Value: {val}")
        print()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Day 5: HTML Form & Input Inspector")
    parser.add_argument("-u", "--url", required=True, help="Target page URL")
    args = parser.parse_args()

    scrape_forms(args.url)