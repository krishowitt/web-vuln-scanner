import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def get_forms(url):
    soup = BeautifulSoup(requests.get(url).content, "html.parser")
    return soup.find_all("form")

def form_details(form):
    details = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, value):
    target_url = urljoin(url, form_details["action"])
    data = {}
    for input in form_details["inputs"]:
        if input["type"] == "text" or input["type"] == "search":
            data[input["name"]] = value
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)

def scan_xss(url):
    forms = get_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    js_script = "<script>alert('XSS')</script>"
    is_vulnerable = False
    for form in forms:
        details = form_details(form)
        response = submit_form(details, url, js_script)
        if js_script in response.text:
            print(f"[!] XSS vulnerability detected in form: {details}")
            is_vulnerable = True
    return is_vulnerable

def scan_sql_injection(url):
    forms = get_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    sql_payload = "' OR '1'='1"
    is_vulnerable = False
    for form in forms:
        details = form_details(form)
        response = submit_form(details, url, sql_payload)
        errors = ["you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark"]
        for error in errors:
            if error in response.text.lower():
                print(f"[!] SQL Injection vulnerability detected in form: {details}")
                is_vulnerable = True
    return is_vulnerable

if __name__ == "__main__":
    target = input("Enter URL to scan: ")
    print("\n--- Scanning for XSS ---")
    scan_xss(target)
    print("\n--- Scanning for SQL Injection ---")
    scan_sql_injection(target)
