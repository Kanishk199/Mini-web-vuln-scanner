# Mini Web Vulnerability Scanner 

A lightweight Python tool to scan websites for basic web application vulnerabilities like:

- Missing security headers
- Open redirect vulnerabilities
- Form inputs (potential XSS/SQLi entry points)

## 🔧 Technologies Used
- Python 3
- Requests
- BeautifulSoup4

## How to Use

```bash
pip install -r requirements.txt
python mini_web_vuln_scanner.py https://example.com
```

##  Sample Output

```
[+] Scanning: https://example.com
[+] Domain: example.com
[+] IP Address: 93.184.216.34

--- Security Header Checks ---
[*] Missing X-Frame-Options (Clickjacking protection)
[*] Missing Content-Security-Policy

--- Open Redirect Check ---
[*] Potential Open Redirect vulnerability detected

--- Form Input Check ---
[*] Form with text/search input found — test for XSS or SQLi manually
```

---

##  Author
kanishk — 3rd year Cybersecurity Student
