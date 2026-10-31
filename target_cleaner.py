import argparse
import sys

def process_targets(filepath):
    try:
        with open(filepath, "r") as f:
            raw_lines = [line.strip() for line in f if line.strip()]
            unique_targets = sorted(list(set(raw_lines)))
    except FileNotFoundError:
        print(f"[!] Error: File '{filepath}' nahi mili.")
        sys.exit(1)

    print(f"\n[+] Total unique targets parsed: {len(unique_targets)}")
    
    sanitized_urls = []
    for item in unique_targets:
        if not item.startswith(("http://", "https://")):
            url = f"https://{item}"
        else:
            url = item
        sanitized_urls.append(url)
        print(f" -> {url}")
        
    return sanitized_urls

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Web Audit Target Sanitizer")
    parser.add_argument("-f", "--file", required=True, help="Path to targets file")
    
    args = parser.parse_args()
    process_targets(args.file)