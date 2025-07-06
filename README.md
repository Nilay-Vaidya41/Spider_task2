INDEX 
LEVEL 1
basic_recon_automate.py
basic_example.com.txt

LEVEL 2 
intermediate.py
example.com_recon.json 

LEVEL 3 folder 
# 🛡️ Recon Tool – Spider R&D Cybersecurity Task (Level 3)

A professional-grade reconnaissance toolkit written in Python, designed for automating recon tasks across subdomains, DNS, WHOIS, GeoIP, port scanning, email harvesting, and more — all with structured reporting and optional Flask UI.

---

## 📦 Features

| Module                | Description                                                                 |
|-----------------------|-----------------------------------------------------------------------------|
| Subdomain Enumeration | Uses crt.sh to find related subdomains                                     |
| DNS Records           | Fetches A, MX, NS DNS entries                                               |
| WHOIS Lookup          | Displays domain registration info                                           |
| HTTP Headers          | Grabs HTTP banner and headers                                               |
| GeoIP Lookup          | Gets geographical info from IP address                                      |
| Port Scan             | Runs Nmap for open ports + service banners                                  |
| Tech Detection        | Uses WhatWeb to identify tech stack                                         |
| Email Harvesting      | Finds public email IDs using theHarvester                                   |
| WAF/CDN Detection     | Uses wafw00f to detect security frontends                                    |
| Vulnerability Scan    | Uses Nikto to find known web server vulnerabilities                         |
| Screenshots           | Uses gowitness to screenshot subdomains                                     |
| HTML Report           | Generates a styled HTML report using Jinja2                                 |
| Flask Web UI          | (Bonus) Web dashboard to run recon from the browser                         |
| Docker Support        | (Bonus) Fully containerized for easy deployment                             |

---

## 🔧 Setup Instructions (Local)

### 1. Install Python + Pip + Git (Kali)

```bash
sudo apt update
sudo apt install python3-pip git -y
 git clone <your_repo_url>
cd recon_tool/
pip3 install -r requirements.txt
sudo apt install gowitness wafw00f nikto theharvester whatweb -y
 CLI USAGE 
python3 intermediate_recon.py example.com \
  --subdomains --dns --whois --headers --geoip --portscan \
  --tech --emails --screenshots --waf --vulnscan --output json
 OUTPUT 
reports/<domain>_report.json

reports/<domain>_report.html

reports/screenshots/*.png

reports/vuln/<domain>_nikto.txt
 Nikto vulnscan and wafw00f are not being able to download through dockerfile so a manual download of those is necessary
 
