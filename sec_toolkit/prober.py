import requests

requests.packages.urllib3.disable_warnings()

MANDATORY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy"
]

def audit_headers_and_cookies(url):
    target = url if url.startswith(("http://", "https://")) else f"https://{url}"
    headers = {"User-Agent": "SecToolkit/1.0"}
    
    try:
        resp = requests.get(target, headers=headers, timeout=8, verify=False, allow_redirects=True)
    except requests.RequestException as e:
        return {"error": str(e)}

    # Headers Check
    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
    missing = [h for h in MANDATORY_HEADERS if h.lower() not in resp_headers]

    # Cookies Check
    cookie_issues = []
    for c in resp.cookies:
        issues = []
        if not c.secure:
            issues.append("Missing 'Secure'")
        if not c.has_nonstandard_attr("httponly"):
            issues.append("Missing 'HttpOnly'")
        samesite = c._rest.get("samesite", None) if hasattr(c, "_rest") else None
        if not samesite:
            issues.append("Missing 'SameSite'")
        
        cookie_issues.append({
            "name": c.name,
            "status": "Hardened" if not issues else f"Issues: {', '.join(issues)}"
        })

    return {
        "status_code": resp.status_code,
        "server": resp.headers.get("Server", "Unknown"),
        "missing_headers": missing,
        "cookies": cookie_issues,
        "html_content": resp.text
    }