from flask import Flask, render_template, request, jsonify
from sec_toolkit.prober import audit_headers_and_cookies
from sec_toolkit.scraper import extract_forms
from guardrail import LLMGuardrail

app = Flask(__name__)
guard = LLMGuardrail()

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/api/audit", methods=["POST"])
def api_audit():
    data = request.get_json() or {}
    target = data.get("url", "").strip()
    
    if not target:
        return jsonify({"error": "URL parameter is required"}), 400

    # 1. Probing & Headers
    res = audit_headers_and_cookies(target)
    if "error" in res:
        return jsonify({"status": "FAILED", "error": res["error"]}), 400

    # 2. Scrape Forms
    forms = extract_forms(res.get("html_content", ""), target)

    report = {
        "status": "SUCCESS",
        "target": target,
        "status_code": res["status_code"],
        "server": res["server"],
        "missing_headers": res["missing_headers"],
        "cookies": res["cookies"],
        "forms_detected": len(forms),
        "forms": forms
    }
    return jsonify(report)

@app.route("/api/guardrail", methods=["POST"])
def api_guardrail():
    data = request.get_json() or {}
    prompt = data.get("prompt", "").strip()

    if not prompt:
        return jsonify({"error": "Prompt is required"}), 400

    # Inbound evaluation
    is_allowed, reason = guard.validate_input(prompt)

    return jsonify({
        "inbound_allowed": is_allowed,
        "verdict": "BLOCKED" if not is_allowed else "PASSED",
        "message": reason if not is_allowed else "Input cleared for LLM consumption."
    })

if __name__ == "__main__":
    print("[+] SecToolkit Web Dashboard starting on http://127.0.0.1:5000 ...")
    app.run(debug=True, port=5000)