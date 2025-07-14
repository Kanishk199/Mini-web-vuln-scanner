# mini_web_vuln_scanner.py

import requests
import socket
import re
import sys
import os
from urllib.parse import urlparse
from bs4 import BeautifulSoup

def get_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception as e:
        return f"Error resolving IP: {e}"

def check_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers
        findings = []

        if 'X-Frame-Options' not in headers:
            findings.append("Missing X-Frame-Options (Clickjacking protection)")

        if 'Content-Security-Policy' not in headers:
            findings.append("Missing Content-Security-Policy")

        if 'X-Content-Type-Options' not in headers:
            findings.append("Missing X-Content-Type-Options")

        if 'Strict-Transport-Security' not in headers:
            findings.append("Missing Strict-Transport-Security (HSTS)")

        return findings
    except Exception as e:
        return [f"Header check failed: {e}"]

def check_open_redirects(url):
    try:
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        test_url = base_url + "/?next=http://evil.com"
        response = requests.get(test_url, allow_redirects=False)
        if response.status_code in [301, 302] and 'evil.com' in response.headers.get('Location', ''):
            return ["Potential Open Redirect vulnerability detected"]
        return []
    except Exception as e:
        return [f"Open Redirect check failed: {e}"]

def check_input_fields(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        if not forms:
            return ["No forms found on the page"]

        findings = []
        for form in forms:
            inputs = form.find_all('input')
            for i in inputs:
                if i.get('type') in ['text', 'search']:
                    findings.append("Form with text/search input found — test for XSS or SQLi manually")
        return findings
    except Exception as e:
        return [f"Input field check failed: {e}"]

def main():
    if len(sys.argv) != 2:
        print("Usage: python mini_web_vuln_scanner.py <url>")
        return

    url = sys.argv[1]
    if not url.startswith('http'):
        url = 'http://' + url

    parsed = urlparse(url)
    domain = parsed.netloc

    print(f"\n[+] Scanning: {url}")
    print(f"[+] Domain: {domain}")
    print(f"[+] IP Address: {get_ip(domain)}")

    print("\n--- Security Header Checks ---")
    for finding in check_headers(url):
        print(f"[*] {finding}")

    print("\n--- Open Redirect Check ---")
    for finding in check_open_redirects(url):
        print(f"[*] {finding}")

    print("\n--- Form Input Check ---")
    for finding in check_input_fields(url):
        print(f"[*] {finding}")

    print("\nScan completed. Note: Manual testing is always recommended.")

if __name__ == "__main__":
    main()
