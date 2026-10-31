from bs4 import BeautifulSoup
from urllib.parse import urljoin

def extract_forms(html_text, base_url):
    soup = BeautifulSoup(html_text, "html.parser")
    forms_list = []

    for f in soup.find_all("form"):
        action = f.get("action", "")
        method = f.get("method", "GET").upper()
        inputs = []
        for inp in f.find_all("input"):
            inputs.append({
                "name": inp.get("name", "<unnamed>"),
                "type": inp.get("type", "text"),
                "is_hidden": inp.get("type", "").lower() == "hidden"
            })
        forms_list.append({
            "action": urljoin(base_url, action),
            "method": method,
            "inputs": inputs
        })
    return forms_list